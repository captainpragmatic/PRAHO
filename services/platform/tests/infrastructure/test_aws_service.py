"""
Tests for AWS EC2 Service (CloudProviderGateway implementation).

All AWS API calls are mocked via unittest.mock — no real AWS credentials needed.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError
from django.test import TestCase

from apps.infrastructure.cloud_gateway import FirewallRule, ServerCreateRequest


# Test credentials JSON
AWS_CREDS = json.dumps({
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-east-1",
})


def _make_client_error(code: str, message: str = "error") -> ClientError:
    """Helper to create a botocore ClientError."""
    return ClientError(
        error_response={"Error": {"Code": code, "Message": message}},
        operation_name="TestOp",
    )


class TestAWSServiceInit(TestCase):
    """Test AWSService constructor."""

    @patch("apps.infrastructure.aws_service.boto3")
    def test_init_parses_json_credentials(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        svc = AWSService(token=AWS_CREDS)

        mock_boto3.client.assert_called_once_with(
            "ec2",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region_name="us-east-1",
        )
        assert svc.region == "us-east-1"

    @patch("apps.infrastructure.aws_service.boto3")
    def test_init_defaults_region(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        creds = json.dumps({"access_key_id": "x", "secret_access_key": "y"})
        svc = AWSService(token=creds)
        assert svc.region == "us-east-1"


class TestAWSServiceCreateServer(TestCase):
    """Test create_server with ClientToken idempotency."""

    @patch("apps.infrastructure.aws_service.boto3")
    def test_create_server_success(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2

        # Mock AMI resolution
        mock_ec2.describe_images.return_value = {
            "Images": [{"ImageId": "ami-12345", "CreationDate": "2025-01-01"}],
        }
        # Mock run_instances
        mock_ec2.run_instances.return_value = {
            "Instances": [{"InstanceId": "i-abc123"}],
        }
        # Mock waiter
        mock_waiter = MagicMock()
        mock_ec2.get_waiter.return_value = mock_waiter
        # Mock describe_instances for IP
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-abc123", "PublicIpAddress": "1.2.3.4"}]}],
        }

        svc = AWSService(token=AWS_CREDS)
        request = ServerCreateRequest(
            name="test-server",
            server_type="t3.micro",
            location="us-east-1a",
            ssh_keys=["my-key"],
            labels={"praho-deployment": "dep-123"},
        )
        result = svc.create_server(request)

        assert result.is_ok()
        val = result.unwrap()
        assert val.server_id == "i-abc123"
        assert val.ipv4_address == "1.2.3.4"

        # Verify ClientToken was used for idempotency
        call_kwargs = mock_ec2.run_instances.call_args[1]
        assert call_kwargs["ClientToken"] == "dep-123"

    @patch("apps.infrastructure.aws_service.boto3")
    def test_create_server_uses_praho_deployment_label(self, mock_boto3: MagicMock) -> None:
        """C9: AWS must use 'praho-deployment' label for idempotency, matching other providers."""
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_images.return_value = {"Images": [{"ImageId": "ami-1", "CreationDate": "2025-01-01"}]}
        mock_ec2.run_instances.return_value = {"Instances": [{"InstanceId": "i-x"}]}
        mock_ec2.get_waiter.return_value = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": [{"Instances": [{"InstanceId": "i-x"}]}]}

        svc = AWSService(token=AWS_CREDS)
        # Using 'praho-deployment' — the correct key
        request = ServerCreateRequest(
            name="s", server_type="t3.micro", location="us-east-1a",
            ssh_keys=[], labels={"praho-deployment": "unique-dep-id"},
        )
        svc.create_server(request)

        call_kwargs = mock_ec2.run_instances.call_args[1]
        assert call_kwargs["ClientToken"] == "unique-dep-id"

    @patch("apps.infrastructure.aws_service.boto3")
    def test_create_server_no_client_token_when_no_deployment_id(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_images.return_value = {"Images": [{"ImageId": "ami-1", "CreationDate": "2025-01-01"}]}
        mock_ec2.run_instances.return_value = {"Instances": [{"InstanceId": "i-x"}]}
        mock_ec2.get_waiter.return_value = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": [{"Instances": [{"InstanceId": "i-x"}]}]}

        svc = AWSService(token=AWS_CREDS)
        request = ServerCreateRequest(name="s", server_type="t3.micro", location="us-east-1a", ssh_keys=[])
        svc.create_server(request)

        call_kwargs = mock_ec2.run_instances.call_args[1]
        assert "ClientToken" not in call_kwargs


class TestAWSServiceDeleteServer(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_delete_server_success(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.get_waiter.return_value = MagicMock()

        svc = AWSService(token=AWS_CREDS)
        result = svc.delete_server("i-abc123")

        assert result.is_ok()
        mock_ec2.terminate_instances.assert_called_once_with(InstanceIds=["i-abc123"])


class TestAWSServiceGetServer(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_get_server_found(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-abc123",
                    "InstanceType": "t3.micro",
                    "State": {"Name": "running"},
                    "PublicIpAddress": "1.2.3.4",
                    "Placement": {"AvailabilityZone": "us-east-1a"},
                    "Tags": [{"Key": "Name", "Value": "test"}],
                }],
            }],
        }

        svc = AWSService(token=AWS_CREDS)
        result = svc.get_server("i-abc123")

        assert result.is_ok()
        info = result.unwrap()
        assert info is not None
        assert info.server_id == "i-abc123"
        assert info.status == "running"
        assert info.ipv4_address == "1.2.3.4"

    @patch("apps.infrastructure.aws_service.boto3")
    def test_get_server_not_found(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_instances.side_effect = _make_client_error("InvalidInstanceID.NotFound")

        svc = AWSService(token=AWS_CREDS)
        result = svc.get_server("i-nonexistent")

        assert result.is_ok()
        assert result.unwrap() is None


class TestAWSServicePowerOps(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_power_on(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.get_waiter.return_value = MagicMock()

        svc = AWSService(token=AWS_CREDS)
        result = svc.power_on("i-abc123")
        assert result.is_ok()
        mock_ec2.start_instances.assert_called_once()

    @patch("apps.infrastructure.aws_service.boto3")
    def test_power_off(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.get_waiter.return_value = MagicMock()

        svc = AWSService(token=AWS_CREDS)
        result = svc.power_off("i-abc123")
        assert result.is_ok()
        mock_ec2.stop_instances.assert_called_once()

    @patch("apps.infrastructure.aws_service.boto3")
    def test_reboot(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2

        svc = AWSService(token=AWS_CREDS)
        result = svc.reboot("i-abc123")
        assert result.is_ok()
        mock_ec2.reboot_instances.assert_called_once()


class TestAWSServiceResize(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_resize_stop_modify_start(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.get_waiter.return_value = MagicMock()

        svc = AWSService(token=AWS_CREDS)
        result = svc.resize("i-abc123", "t3.large")

        assert result.is_ok()
        mock_ec2.stop_instances.assert_called_once()
        mock_ec2.modify_instance_attribute.assert_called_once_with(
            InstanceId="i-abc123", InstanceType={"Value": "t3.large"}
        )
        mock_ec2.start_instances.assert_called_once()


class TestAWSServiceSSHKeys(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_upload_ssh_key(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.import_key_pair.return_value = {
            "KeyPairId": "key-123",
            "KeyFingerprint": "aa:bb:cc",
        }

        svc = AWSService(token=AWS_CREDS)
        result = svc.upload_ssh_key("my-key", "ssh-rsa AAAA...")

        assert result.is_ok()
        val = result.unwrap()
        assert val.key_id == "key-123"
        assert val.name == "my-key"
        mock_ec2.import_key_pair.assert_called_once()

    @patch("apps.infrastructure.aws_service.boto3")
    def test_delete_ssh_key(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2

        svc = AWSService(token=AWS_CREDS)
        result = svc.delete_ssh_key("my-key")

        assert result.is_ok()
        mock_ec2.delete_key_pair.assert_called_once_with(KeyName="my-key")


class TestAWSServiceFirewall(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_create_firewall(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.create_security_group.return_value = {"GroupId": "sg-123"}

        svc = AWSService(token=AWS_CREDS)
        rules = [FirewallRule(protocol="tcp", port="22", source_ips=["0.0.0.0/0", "::/0"])]
        result = svc.create_firewall("test-sg", rules)

        assert result.is_ok()
        assert result.unwrap() == "sg-123"
        mock_ec2.authorize_security_group_ingress.assert_called_once()

    @patch("apps.infrastructure.aws_service.boto3")
    def test_delete_firewall(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2

        svc = AWSService(token=AWS_CREDS)
        result = svc.delete_firewall("sg-123")

        assert result.is_ok()
        mock_ec2.delete_security_group.assert_called_once_with(GroupId="sg-123")


class TestAWSServiceLocations(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_get_locations(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_availability_zones.return_value = {
            "AvailabilityZones": [
                {"ZoneName": "us-east-1a", "RegionName": "us-east-1", "State": "available"},
                {"ZoneName": "us-east-1b", "RegionName": "us-east-1", "State": "available"},
            ],
        }

        svc = AWSService(token=AWS_CREDS)
        result = svc.get_locations()

        assert result.is_ok()
        locs = result.unwrap()
        assert len(locs) == 2
        assert locs[0].name == "us-east-1a"


class TestAWSServiceServerTypes(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_get_server_types(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2

        # Mock paginator
        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "InstanceTypes": [
                    {
                        "InstanceType": "t3.micro",
                        "VCpuInfo": {"DefaultVCpus": 2},
                        "MemoryInfo": {"SizeInMiB": 1024},
                    },
                ],
            },
        ]

        svc = AWSService(token=AWS_CREDS)
        result = svc.get_server_types()

        assert result.is_ok()
        types = result.unwrap()
        assert len(types) == 1
        assert types[0].name == "t3.micro"
        assert types[0].vcpus == 2


class TestAWSServiceWaiterTimeout(TestCase):
    @patch("apps.infrastructure.aws_service.boto3")
    def test_create_server_waiter_timeout(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_images.return_value = {"Images": [{"ImageId": "ami-1", "CreationDate": "2025-01-01"}]}
        mock_ec2.run_instances.return_value = {"Instances": [{"InstanceId": "i-x"}]}

        mock_waiter = MagicMock()
        mock_waiter.wait.side_effect = Exception("Waiter timed out")
        mock_ec2.get_waiter.return_value = mock_waiter

        svc = AWSService(token=AWS_CREDS)
        request = ServerCreateRequest(name="s", server_type="t3.micro", location="us-east-1a", ssh_keys=[])
        result = svc.create_server(request)

        assert result.is_err()
        assert "timed out" in result.unwrap_err().lower()


class TestAWSServiceGetServerGenericException(TestCase):
    """H9: get_server must catch generic Exception, not just ClientError."""

    @patch("apps.infrastructure.aws_service.boto3")
    def test_get_server_generic_exception_returns_err(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        # Simulate a network timeout (not a ClientError)
        mock_ec2.describe_instances.side_effect = ConnectionError("Network timeout")

        svc = AWSService(token=AWS_CREDS)
        result = svc.get_server("i-abc123")

        assert result.is_err()
        assert "Network timeout" in result.unwrap_err()


class TestAWSServiceUploadSshKeyFingerprint(TestCase):
    """H12: upload_ssh_key should check fingerprint before unconditional delete."""

    @patch("apps.infrastructure.aws_service.boto3")
    def test_upload_ssh_key_checks_fingerprint_before_delete(self, mock_boto3: MagicMock) -> None:
        """If key already exists and import fails with duplicate, return existing info."""
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2

        # Key already exists
        mock_ec2.describe_key_pairs.return_value = {
            "KeyPairs": [{"KeyPairId": "key-existing", "KeyFingerprint": "aa:bb:cc", "KeyName": "my-key"}],
        }
        # import_key_pair fails because key already exists with same content
        mock_ec2.import_key_pair.side_effect = _make_client_error(
            "InvalidKeyPair.Duplicate", "Key pair 'my-key' already exists."
        )

        svc = AWSService(token=AWS_CREDS)
        result = svc.upload_ssh_key("my-key", "ssh-rsa AAAA...")

        assert result.is_ok()
        val = result.unwrap()
        assert val.key_id == "key-existing"
        assert val.fingerprint == "aa:bb:cc"
        # Key should NOT have been deleted
        mock_ec2.delete_key_pair.assert_not_called()

    @patch("apps.infrastructure.aws_service.boto3")
    def test_upload_ssh_key_new_key_no_existing(self, mock_boto3: MagicMock) -> None:
        """New key import when no existing key found."""
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2

        # No existing key
        mock_ec2.describe_key_pairs.side_effect = _make_client_error("InvalidKeyPair.NotFound")
        mock_ec2.import_key_pair.return_value = {
            "KeyPairId": "key-new",
            "KeyFingerprint": "dd:ee:ff",
        }

        svc = AWSService(token=AWS_CREDS)
        result = svc.upload_ssh_key("my-key", "ssh-rsa AAAA...")

        assert result.is_ok()
        assert result.unwrap().key_id == "key-new"


class TestAWSServiceDeleteServerAlreadyGone(TestCase):
    """delete_server returns Ok(True) for already-terminated instances."""

    @patch("apps.infrastructure.aws_service.boto3")
    def test_delete_server_already_gone(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.terminate_instances.side_effect = _make_client_error("InvalidInstanceID.NotFound")

        svc = AWSService(token=AWS_CREDS)
        result = svc.delete_server("i-gone")

        assert result.is_ok()
        assert result.unwrap() is True


class TestAWSServiceStatusNormalization(TestCase):
    """Verify AWS normalizes EC2 status values."""

    @patch("apps.infrastructure.aws_service.boto3")
    def test_pending_normalized_to_initializing(self, mock_boto3: MagicMock) -> None:
        from apps.infrastructure.aws_service import AWSService

        mock_ec2 = MagicMock()
        mock_boto3.client.return_value = mock_ec2
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-x",
                    "InstanceType": "t3.micro",
                    "State": {"Name": "pending"},
                    "Placement": {"AvailabilityZone": "us-east-1a"},
                    "Tags": [],
                }],
            }],
        }

        svc = AWSService(token=AWS_CREDS)
        result = svc.get_server("i-x")
        assert result.is_ok()
        info = result.unwrap()
        assert info is not None
        assert info.status == "initializing"  # 'pending' → 'initializing'
