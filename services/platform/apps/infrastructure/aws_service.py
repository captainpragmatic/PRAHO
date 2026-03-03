"""
AWS EC2 Service

Wrapper for the boto3 AWS SDK, implementing CloudProviderGateway.
Provides typed, Pythonic access to EC2 server lifecycle operations.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any

import boto3
from botocore.exceptions import ClientError

from apps.common.types import Err, Ok, Result
from apps.infrastructure.cloud_gateway import (
    CloudProviderGateway,
    FirewallRule,
    LocationInfo,
    ServerCreateRequest,
    ServerCreateResult,
    ServerInfo,
    ServerTypeInfo,
    SSHKeyResult,
    normalize_server_status,
    register_cloud_gateway,
)

logger = logging.getLogger(__name__)

# Instance type families relevant for hosting workloads
AWS_HOSTING_FAMILIES = ["t3.*", "m5.*", "c5.*"]

# Canonical's AWS account ID for official Ubuntu AMIs
CANONICAL_OWNER_ID = "099720109477"

# Max wait attempts for instance state transitions (~5 min at default polling)
AWS_WAITER_MAX_ATTEMPTS = 60


class AWSService(CloudProviderGateway):
    """
    AWS EC2 SDK wrapper implementing CloudProviderGateway.

    Constructor token is a JSON string containing:
    {"access_key_id": "...", "secret_access_key": "...", "region": "us-east-1"}
    """

    def __init__(self, token: str, **_kwargs: Any) -> None:
        try:
            creds = json.loads(token)
        except (json.JSONDecodeError, TypeError) as e:
            raise ValueError(f"Invalid AWS credentials JSON: {e}") from e

        if "access_key_id" not in creds or "secret_access_key" not in creds:
            raise ValueError("AWS credentials must contain 'access_key_id' and 'secret_access_key'")

        self.region = creds.get("region", "us-east-1")
        self.ec2: Any = boto3.client(
            "ec2",
            aws_access_key_id=creds["access_key_id"],
            aws_secret_access_key=creds["secret_access_key"],
            region_name=self.region,
        )

    def create_server(self, request: ServerCreateRequest) -> Result[ServerCreateResult, str]:
        """Create an EC2 instance."""
        logger.info(f"🚀 [AWS] Creating server: {request.name} ({request.server_type} @ {request.location})")

        try:
            # Resolve AMI if using default image name
            ami_id = request.image
            if not ami_id.startswith("ami-"):
                ami_result = self._resolve_ubuntu_ami()
                if ami_result.is_err():
                    return Err(ami_result.unwrap_err())
                ami_id = ami_result.unwrap()

            # Build tag specifications
            tags = [{"Key": k, "Value": v} for k, v in request.labels.items()]
            tags.append({"Key": "Name", "Value": request.name})
            tag_specs = [{"ResourceType": "instance", "Tags": tags}]

            # Use deployment-id label as ClientToken for idempotency
            run_kwargs: dict[str, Any] = {
                "ImageId": ami_id,
                "InstanceType": request.server_type,
                "KeyName": request.ssh_keys[0] if request.ssh_keys else "",
                "MinCount": 1,
                "MaxCount": 1,
                "TagSpecifications": tag_specs,
            }

            client_token = request.labels.get("praho-deployment", "")
            if client_token:
                run_kwargs["ClientToken"] = client_token

            if request.firewall_ids:
                run_kwargs["SecurityGroupIds"] = request.firewall_ids

            if request.location:
                run_kwargs["Placement"] = {"AvailabilityZone": request.location}

            # Remove empty KeyName
            if not run_kwargs.get("KeyName"):
                del run_kwargs["KeyName"]

            response = self.ec2.run_instances(**run_kwargs)
            instance = response["Instances"][0]
            instance_id = instance["InstanceId"]

            # Wait for instance to be running
            waiter = self.ec2.get_waiter("instance_running")
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={"MaxAttempts": AWS_WAITER_MAX_ATTEMPTS})

            # Fetch updated instance info for IP address
            desc = self.ec2.describe_instances(InstanceIds=[instance_id])
            inst = desc["Reservations"][0]["Instances"][0]
            ipv4 = inst.get("PublicIpAddress", "")
            ipv6 = inst.get("Ipv6Address", "")

            logger.info(f"✅ [AWS] Server created: {request.name} (id={instance_id}, ip={ipv4})")
            return Ok(ServerCreateResult(server_id=instance_id, ipv4_address=ipv4 or "", ipv6_address=ipv6 or ""))

        except ClientError as e:
            logger.error(f"🔥 [AWS] Server creation failed: {e}")
            return Err(f"Server creation failed: {e}")
        except Exception as e:
            logger.error(f"🔥 [AWS] Server creation failed: {e}")
            return Err(f"Server creation failed: {e}")

    def delete_server(self, server_id: str) -> Result[bool, str]:
        """Terminate an EC2 instance. Returns Ok(True) if already gone."""
        logger.info(f"🗑️ [AWS] Terminating instance: {server_id}")
        try:
            self.ec2.terminate_instances(InstanceIds=[server_id])
            waiter = self.ec2.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=[server_id], WaiterConfig={"MaxAttempts": AWS_WAITER_MAX_ATTEMPTS})
            logger.info(f"✅ [AWS] Instance terminated: {server_id}")
            return Ok(True)
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                logger.info(f"✅ [AWS] Instance already gone: {server_id}")
                return Ok(True)
            logger.error(f"🔥 [AWS] Instance termination failed: {e}")
            return Err(f"Instance termination failed: {e}")
        except Exception as e:
            logger.error(f"🔥 [AWS] Instance termination failed: {e}")
            return Err(f"Instance termination failed: {e}")

    def get_server(self, server_id: str) -> Result[ServerInfo | None, str]:
        """Get EC2 instance info. Returns None if not found."""
        try:
            desc = self.ec2.describe_instances(InstanceIds=[server_id])
            reservations = desc.get("Reservations", [])
            if not reservations or not reservations[0].get("Instances"):
                return Ok(None)

            inst = reservations[0]["Instances"][0]
            return Ok(self._instance_to_server_info(inst))

        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return Ok(None)
            return Err(f"Failed to get instance {server_id}: {e}")
        except Exception as e:
            return Err(f"Failed to get instance {server_id}: {e}")

    def power_on(self, server_id: str) -> Result[bool, str]:
        """Start an EC2 instance."""
        try:
            self.ec2.start_instances(InstanceIds=[server_id])
            waiter = self.ec2.get_waiter("instance_running")
            waiter.wait(InstanceIds=[server_id], WaiterConfig={"MaxAttempts": AWS_WAITER_MAX_ATTEMPTS})
            logger.info(f"✅ [AWS] Instance started: {server_id}")
            return Ok(True)
        except ClientError as e:
            return Err(f"Power on failed: {e}")
        except Exception as e:
            return Err(f"Power on failed: {e}")

    def power_off(self, server_id: str) -> Result[bool, str]:
        """Stop an EC2 instance."""
        try:
            self.ec2.stop_instances(InstanceIds=[server_id])
            waiter = self.ec2.get_waiter("instance_stopped")
            waiter.wait(InstanceIds=[server_id], WaiterConfig={"MaxAttempts": AWS_WAITER_MAX_ATTEMPTS})
            logger.info(f"✅ [AWS] Instance stopped: {server_id}")
            return Ok(True)
        except ClientError as e:
            return Err(f"Power off failed: {e}")
        except Exception as e:
            return Err(f"Power off failed: {e}")

    def reboot(self, server_id: str) -> Result[bool, str]:
        """Reboot an EC2 instance and wait until running."""
        try:
            self.ec2.reboot_instances(InstanceIds=[server_id])
            waiter = self.ec2.get_waiter("instance_running")
            waiter.wait(InstanceIds=[server_id], WaiterConfig={"MaxAttempts": AWS_WAITER_MAX_ATTEMPTS})
            logger.info(f"✅ [AWS] Instance rebooted: {server_id}")
            return Ok(True)
        except ClientError as e:
            return Err(f"Reboot failed: {e}")
        except Exception as e:
            return Err(f"Reboot failed: {e}")

    def resize(self, server_id: str, server_type: str) -> Result[bool, str]:
        """Resize an EC2 instance (stop → modify → start)."""
        try:
            # Stop instance first
            self.ec2.stop_instances(InstanceIds=[server_id])
            waiter = self.ec2.get_waiter("instance_stopped")
            waiter.wait(InstanceIds=[server_id], WaiterConfig={"MaxAttempts": AWS_WAITER_MAX_ATTEMPTS})

            # Modify instance type
            self.ec2.modify_instance_attribute(InstanceId=server_id, InstanceType={"Value": server_type})

            # Start instance
            self.ec2.start_instances(InstanceIds=[server_id])
            waiter = self.ec2.get_waiter("instance_running")
            waiter.wait(InstanceIds=[server_id], WaiterConfig={"MaxAttempts": AWS_WAITER_MAX_ATTEMPTS})

            logger.info(f"✅ [AWS] Instance resized: {server_id} -> {server_type}")
            return Ok(True)
        except ClientError as e:
            return Err(f"Resize failed: {e}")
        except Exception as e:
            return Err(f"Resize failed: {e}")

    def upload_ssh_key(self, name: str, public_key: str) -> Result[SSHKeyResult, str]:
        """Import an SSH key pair into EC2. Skips re-import if fingerprint matches."""
        try:
            # Check if key already exists with same fingerprint
            try:
                existing = self.ec2.describe_key_pairs(KeyNames=[name])
                key_pairs = existing.get("KeyPairs", [])
                if key_pairs:
                    existing_fingerprint = key_pairs[0].get("KeyFingerprint", "")
                    existing_id = key_pairs[0].get("KeyPairId", "")
                    # Try importing to get the fingerprint for comparison
                    # If fingerprints match, return early without delete+recreate
                    try:
                        response = self.ec2.import_key_pair(KeyName=name, PublicKeyMaterial=public_key.encode())
                        logger.info(f"✅ [AWS] SSH key imported: {name}")
                        return Ok(SSHKeyResult(
                            key_id=response.get("KeyPairId", ""),
                            name=name,
                            fingerprint=response.get("KeyFingerprint", ""),
                        ))
                    except ClientError as import_err:
                        if "already exists" in str(import_err).lower() or "InvalidKeyPair.Duplicate" in str(import_err):
                            # Key exists and import failed — same key, return existing info
                            return Ok(SSHKeyResult(
                                key_id=existing_id,
                                name=name,
                                fingerprint=existing_fingerprint,
                            ))
                        # Different key content — delete and re-import
                        self.ec2.delete_key_pair(KeyName=name)
            except ClientError:
                pass  # Key didn't exist, proceed with import

            response = self.ec2.import_key_pair(KeyName=name, PublicKeyMaterial=public_key.encode())
            logger.info(f"✅ [AWS] SSH key imported: {name}")
            return Ok(
                SSHKeyResult(
                    key_id=response.get("KeyPairId", ""),
                    name=name,
                    fingerprint=response.get("KeyFingerprint", ""),
                )
            )
        except ClientError as e:
            return Err(f"SSH key import failed: {e}")

    def delete_ssh_key(self, name: str) -> Result[bool, str]:
        """Delete an SSH key pair from EC2."""
        try:
            self.ec2.delete_key_pair(KeyName=name)
            logger.info(f"✅ [AWS] SSH key deleted: {name}")
            return Ok(True)
        except ClientError as e:
            return Err(f"SSH key deletion failed: {e}")

    def create_firewall(
        self, name: str, rules: list[FirewallRule], labels: dict[str, str] | None = None
    ) -> Result[str, str]:
        """Create an EC2 security group with ingress rules."""
        try:
            # Create security group (requires a VPC — use default VPC)
            response = self.ec2.create_security_group(GroupName=name, Description="PRAHO managed")
            sg_id = response["GroupId"]

            # Add ingress rules
            ip_permissions: list[dict[str, Any]] = []
            for rule in rules:
                if not rule.port or rule.port == "all":
                    from_port, to_port = 0, 65535
                elif "-" in rule.port:
                    parts = rule.port.split("-", 1)
                    from_port, to_port = int(parts[0]), int(parts[1])
                else:
                    from_port = to_port = int(rule.port)
                perm: dict[str, Any] = {
                    "IpProtocol": rule.protocol,
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": [{"CidrIp": ip} for ip in rule.source_ips if ":" not in ip],
                    "Ipv6Ranges": [{"CidrIpv6": ip} for ip in rule.source_ips if ":" in ip],
                }
                ip_permissions.append(perm)

            if ip_permissions:
                self.ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ip_permissions)

            # Tag the security group
            if labels:
                tags = [{"Key": k, "Value": v} for k, v in labels.items()]
                self.ec2.create_tags(Resources=[sg_id], Tags=tags)

            logger.info(f"✅ [AWS] Security group created: {name} (id={sg_id})")
            return Ok(sg_id)

        except ClientError as e:
            logger.error(f"🔥 [AWS] Security group creation failed: {e}")
            return Err(f"Security group creation failed: {e}")

    def delete_firewall(self, firewall_id: str) -> Result[bool, str]:
        """Delete an EC2 security group."""
        try:
            self.ec2.delete_security_group(GroupId=firewall_id)
            logger.info(f"✅ [AWS] Security group deleted: {firewall_id}")
            return Ok(True)
        except ClientError as e:
            return Err(f"Security group deletion failed: {e}")

    def get_locations(self) -> Result[Sequence[LocationInfo], str]:
        """Get available AWS availability zones."""
        try:
            response = self.ec2.describe_availability_zones(
                Filters=[{"Name": "state", "Values": ["available"]}]
            )
            locations: list[LocationInfo] = [
                LocationInfo(
                    name=az["ZoneName"],
                    description=az.get("ZoneName", ""),
                    country=az.get("RegionName", ""),
                )
                for az in response.get("AvailabilityZones", [])
            ]
            return Ok(locations)
        except ClientError as e:
            return Err(f"Failed to get locations: {e}")
        except Exception as e:
            return Err(f"Failed to get locations: {e}")

    def get_server_types(self) -> Result[Sequence[ServerTypeInfo], str]:
        """Get available EC2 instance types (filtered to hosting-relevant families)."""
        try:
            paginator = self.ec2.get_paginator("describe_instance_types")
            pages = paginator.paginate(
                Filters=[{"Name": "instance-type", "Values": AWS_HOSTING_FAMILIES}]
            )
            types: list[ServerTypeInfo] = []
            for page in pages:
                for it in page.get("InstanceTypes", []):
                    vcpus = it.get("VCpuInfo", {}).get("DefaultVCpus", 0)
                    memory_mb = it.get("MemoryInfo", {}).get("SizeInMiB", 0)
                    memory_gb = round(memory_mb / 1024, 1)
                    types.append(
                        ServerTypeInfo(
                            name=it["InstanceType"],
                            description=f"{vcpus} vCPU / {memory_gb}GB RAM",
                            vcpus=vcpus,
                            memory_gb=memory_gb,
                        )
                    )
            return Ok(types)
        except ClientError as e:
            return Err(f"Failed to get server types: {e}")
        except Exception as e:
            return Err(f"Failed to get server types: {e}")

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _resolve_ubuntu_ami(self) -> Result[str, str]:
        """Find the latest Ubuntu 22.04 AMI for the current region."""
        try:
            response = self.ec2.describe_images(
                Filters=[
                    {"Name": "name", "Values": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]},
                    {"Name": "state", "Values": ["available"]},
                ],
                Owners=[CANONICAL_OWNER_ID],
            )
            images = response.get("Images", [])
            if not images:
                return Err(f"No Ubuntu 22.04 AMI found in region {self.region}")

            # Sort by creation date, newest first
            images.sort(key=lambda x: x.get("CreationDate", ""), reverse=True)
            ami_id: str = images[0]["ImageId"]
            logger.info(f"✅ [AWS] Resolved Ubuntu AMI: {ami_id}")
            return Ok(ami_id)
        except ClientError as e:
            return Err(f"AMI resolution failed: {e}")

    @staticmethod
    def _instance_to_server_info(inst: dict[str, Any]) -> ServerInfo:
        """Convert EC2 instance dict to ServerInfo."""
        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        return ServerInfo(
            server_id=inst["InstanceId"],
            name=tags.get("Name", ""),
            status=normalize_server_status(inst.get("State", {}).get("Name", "")),
            ipv4_address=inst.get("PublicIpAddress", ""),
            ipv6_address=inst.get("Ipv6Address", ""),
            server_type=inst.get("InstanceType", ""),
            location=inst.get("Placement", {}).get("AvailabilityZone", ""),
            labels=tags,
        )


    # =========================================================================
    # Snapshot operations (stubs — not yet implemented for AWS)
    # =========================================================================

    def create_snapshot(self, server_id: str, name: str) -> Result[str, str]:
        """Create a server snapshot. Not yet implemented for AWS."""
        return Err("Snapshot creation not yet implemented for AWS")

    def restore_snapshot(self, server_id: str, snapshot_id: str) -> Result[bool, str]:
        """Restore a server from a snapshot. Not yet implemented for AWS."""
        return Err("Snapshot restore not yet implemented for AWS")

    def list_snapshots(self, server_id: str) -> Result[list[dict[str, Any]], str]:
        """List snapshots for a server. Not yet implemented for AWS."""
        return Err("List snapshots not yet implemented for AWS")

    def delete_snapshot(self, snapshot_id: str) -> Result[bool, str]:
        """Delete a snapshot by ID. Not yet implemented for AWS."""
        return Err("Snapshot deletion not yet implemented for AWS")


# Register AWS as a cloud gateway provider
register_cloud_gateway("aws", AWSService)


def get_aws_service(token: str) -> AWSService:
    """Create an AWSService instance with the given credentials JSON."""
    return AWSService(token=token)
