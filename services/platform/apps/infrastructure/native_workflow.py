"""Exact manifest-bound Platform fixtures and real public native workflows.

The preparation leg installs repository roles. Registration resumes through the
public deployment service; no successful DNS/provider result is manufactured.
This does not certify the separate fresh deploy_node/DNS/create acceptance leg.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
from pathlib import Path
from typing import Any
from uuid import UUID

from django.db import connection, transaction

from apps.common.credential_vault import CredentialData, get_credential_vault
from apps.infrastructure.deployment_preflight import validate_deployment_dns_zone
from apps.infrastructure.models import CloudProvider, NodeDeployment, NodeRegion, NodeSize, PanelType
from apps.infrastructure.native_lab import (
    NativeAuthority,
    native_authority,
    native_driver,
    native_run_lock,
    write_private,
)


def _database_identity() -> str:
    values = connection.settings_dict
    return hashlib.sha256(
        json.dumps(
            {key: str(values.get(key, "")) for key in ("ENGINE", "HOST", "PORT", "NAME")}, sort_keys=True
        ).encode()
    ).hexdigest()


def _credential(kind: str, identifier: str, username: str, password: str, metadata: dict[str, Any]) -> str:
    vault = get_credential_vault()
    existing = vault.get_credential(
        service_type=kind, service_identifier=identifier, reason="Owned native acceptance fixture"
    )
    if existing.is_ok():
        old_user, old_password, old_metadata = existing.unwrap()
        if (
            old_user != username
            or not isinstance(old_metadata, dict)
            or old_metadata.get("native_run") != metadata["native_run"]
        ):
            raise ValueError("The native fixture credential belongs to a different authority")
        if kind == "ssh" and old_password != password:
            raise ValueError("The original native fixture SSH identity changed")
        return ""
    stored = vault.store_credential(
        CredentialData(
            service_type=kind,
            service_identifier=identifier,
            username=username,
            password=password,
            metadata=metadata,
            reason="Private manifest-bound native acceptance fixture",
            create_only=True,
        )
    )
    if stored.is_err():
        raise ValueError("The native fixture credential could not be stored; inspect the private vault")
    return str(stored.unwrap().pk)


def bind_native_fixture(authority: NativeAuthority, *, dns_zone: str) -> NodeDeployment:
    """Database-only fixture setup, after the management command's isolation guard.

    A replay reuses its encrypted secret and original provider/key identity. A
    changed manifest or conflicting row refuses, including after an interrupted
    manifest publication. No native network operation runs in this transaction.
    """
    from apps.users.models import User  # noqa: PLC0415 -- Fixture authority after Django initialization.

    validated = validate_deployment_dns_zone(dns_zone)
    if validated.is_err():
        raise ValueError("Provide the approved native test DNS zone; no customer DNS is created")
    zone, manifest = validated.unwrap(), authority.manifest
    run = UUID(manifest["run"])
    number = run.int % 999 + 1
    hostname = f"dev-sha-lab-xx-natv-{number:03d}"
    with transaction.atomic():
        deployment = NodeDeployment.objects.select_for_update(of=("self",)).filter(correlation_id=run).first()
        if deployment is not None:
            if (
                deployment.external_node_id != str(manifest["server_id"])
                or deployment.ipv4_address != manifest["ipv4"]
                or deployment.fqdn != hostname + "." + zone
                or deployment.display_name != "Native quota acceptance " + str(run)
            ):
                raise ValueError("The manifest-bound Platform resource changed; inspect the fixture")
        else:
            provider, _ = CloudProvider.objects.get_or_create(
                code="lab",
                defaults={
                    "name": "Native quota acceptance",
                    "provider_type": "hetzner",
                    "credential_identifier": "owned-native-lab",
                    "config": {"native_acceptance": True},
                },
            )
            if provider.provider_type != "hetzner" or provider.config != {"native_acceptance": True}:
                raise ValueError("The native fixture provider namespace is already owned")
            region, _ = NodeRegion.objects.get_or_create(
                provider=provider,
                provider_region_id="native-fixture",
                defaults={
                    "name": "Manifest-owned native fixture",
                    "normalized_code": "natv",
                    "country_code": "xx",
                    "city": "Native fixture",
                },
            )
            size, _ = NodeSize.objects.get_or_create(
                provider=provider,
                name="Native fixture",
                defaults={
                    "display_name": "Manifest-owned native fixture",
                    "provider_type_id": "native-fixture",
                    "vcpus": 1,
                    "memory_gb": 1,
                    "disk_gb": 1,
                    "hourly_cost_eur": 0,
                    "monthly_cost_eur": 0,
                    "max_domains": 10,
                    "max_bandwidth_gb": 100,
                },
            )
            panel, _ = PanelType.objects.get_or_create(
                name="Native fixture Virtualmin",
                defaults={
                    "panel_type": "virtualmin",
                    "ansible_playbook": "virtualmin.yml",
                },
            )
            if NodeDeployment.objects.filter(hostname=hostname).exists():
                raise ValueError("The native fixture hostname is already owned by another run")
            deployment = NodeDeployment.objects.create(
                provider=provider,
                region=region,
                node_size=size,
                panel_type=panel,
                hostname=hostname,
                environment="dev",
                node_type="sha",
                node_number=number,
                correlation_id=run,
                external_node_id=str(manifest["server_id"]),
                ipv4_address=manifest["ipv4"],
                dns_zone=zone,
                display_name="Native quota acceptance " + str(run),
                backup_enabled=False,
                backup_storage="platform",
                ssh_port=manifest["ssh_port"],
                ssh_host_keys=manifest["host_public_key"],
                server_create_state="created",
            )
        binding = manifest.get("platform_fixture")
        expected = {
            "schema": 1,
            "deployment_id": deployment.pk,
            "fqdn": deployment.fqdn,
            "run": str(run),
            "database": _database_identity(),
        }
        if binding is not None and binding != expected:
            raise ValueError("The manifest-bound Platform resource changed; inspect the fixture")
        credential_id = _credential(
            "ssh",
            "node-" + hostname,
            authority.public_key,
            authority.key.decode(),
            {"native_run": str(run), "deployment_id": str(deployment.pk), "purpose": "node_deployment"},
        )
        if credential_id:
            deployment.ssh_key_credential_id = credential_id
            deployment.save(update_fields=["ssh_key_credential_id", "updated_at"])
        _credential(
            "virtualmin",
            deployment.fqdn,
            "praho-api-native",
            secrets.token_urlsafe(48),
            {"native_run": str(run), "deployment_id": str(deployment.pk), "pending_registration": True},
        )
        User.objects.get_or_create(
            email="native-" + str(run) + "@example.invalid",
            defaults={
                "staff_role": "admin",
                "is_staff": True,
                "is_active": True,
            },
        )
    manifest["platform_fixture"] = expected
    native_driver().write_manifest(authority.path, manifest)
    return deployment


def _bound_deployment(authority: NativeAuthority) -> NodeDeployment:
    binding = authority.manifest.get("platform_fixture")
    if not isinstance(binding, dict) or binding.get("database") != _database_identity():
        raise ValueError("Prepare the exact manifest in this isolated Platform database first")
    deployment = NodeDeployment.objects.get(pk=binding["deployment_id"], correlation_id=authority.manifest["run"])
    if (
        deployment.external_node_id != str(authority.manifest["server_id"])
        or deployment.ipv4_address != authority.manifest["ipv4"]
        or deployment.fqdn != binding["fqdn"]
    ):
        raise ValueError("The manifest-bound Platform resource changed; native work is refused")
    return deployment


def require_fixture_dns(deployment: NodeDeployment, ipv4: str) -> None:
    """Use real DNS, with no hosts/resolver override and no DNS publication."""
    try:
        addresses = {value[4][0] for value in socket.getaddrinfo(deployment.fqdn, 10000, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise ValueError(
            "The approved native test FQDN is unresolved; inspect the private platform_fixture binding"
        ) from error
    if addresses != {ipv4}:
        raise ValueError("The approved native test FQDN must resolve only to the exact owned VM IPv4")


def _prepare(authority: NativeAuthority, *, dns_zone: str) -> None:
    from apps.infrastructure.registration_service import NodeRegistrationService  # noqa: PLC0415
    from apps.settings.services import SettingsService  # noqa: PLC0415 -- Only the isolated fixture DB is configured.

    deployment = bind_native_fixture(authority, dns_zone=dns_zone)
    if deployment.virtualmin_server_id is not None:
        raise ValueError("This fixture is already registered; use register/workflow rather than reinstalling its node")
    require_fixture_dns(deployment, authority.manifest["ipv4"])
    write_private(authority.path.parent / (authority.manifest["run"] + ".operator.pub"), authority.public_key + "\n")
    if SettingsService.update_setting(
        "infrastructure.node_admin_allowed_cidrs", [authority.manifest["admin_cidr"]]
    ).is_err():
        raise ValueError("The private native fixture admin allowlist could not be configured")
    stored = get_credential_vault().get_credential(
        service_type="virtualmin",
        service_identifier=deployment.fqdn,
        reason="Install the original native fixture API identity",
    )
    if stored.is_err():
        raise ValueError("The original native fixture API identity is unavailable")
    username, password, _metadata = stored.unwrap()

    def verify_before_hardening() -> None:
        current = native_authority(authority.path)
        deployment.ssh_port = current.manifest["ssh_port"]
        deployment.save(update_fields=["ssh_port", "updated_at"])
        require_fixture_dns(deployment, authority.manifest["ipv4"])
        proof = NodeRegistrationService().verify_provisioned_api(deployment)
        if proof.is_err():
            raise ValueError("The public dedicated-credential proof failed; native hardening was not issued")

    native_driver().provision(
        authority.path,
        deployment_id=deployment.pk,
        fqdn=deployment.fqdn,
        api_username=username,
        api_password=password,
        before_harden=verify_before_hardening,
    )
    # Fixture installation is complete. This deliberately enters ONLY the real
    # public registration-resume leg; it never fakes an initial deploy/DNS result.
    current = native_authority(authority.path)
    deployment.status, deployment.registration_state = "failed", "started"
    deployment.ssh_port = current.manifest["ssh_port"]
    deployment.last_successful_phase = "native_fixture_roles"
    deployment.save(update_fields=["status", "registration_state", "ssh_port", "last_successful_phase", "updated_at"])


def _register(authority: NativeAuthority) -> NodeDeployment:
    from apps.infrastructure.deployment_service import NodeDeploymentService  # noqa: PLC0415
    from apps.infrastructure.registration_service import NodeRegistrationService  # noqa: PLC0415
    from apps.provisioning.hosting_node_bundle import helper_bundle  # noqa: PLC0415
    from apps.provisioning.hosting_node_tasks import review_node_hosting  # noqa: PLC0415
    from apps.users.models import User  # noqa: PLC0415

    deployment = _bound_deployment(authority)
    require_fixture_dns(deployment, authority.manifest["ipv4"])
    actor = User.objects.get(email="native-" + authority.manifest["run"] + "@example.invalid", is_active=True)
    if deployment.status == "failed":
        result = NodeDeploymentService().retry_deployment(
            deployment, {"api_token": os.environ.get("HCLOUD_TOKEN", "")}, user=actor
        )
        if result.is_err():
            raise ValueError("Public native registration resume refused; inspect its private deployment log")
    deployment.refresh_from_db()
    if (
        deployment.status == "completed"
        and deployment.virtualmin_server is not None
        and deployment.virtualmin_server.status == "disabled"
    ):
        activation = NodeRegistrationService().verify_and_activate(deployment.virtualmin_server)
        if activation.is_err():
            raise ValueError("Public native activation refused; inspect the private deployment record")
        deployment.refresh_from_db()
    if (
        deployment.status != "completed"
        or deployment.registration_state not in {"registered", "activated"}
        or deployment.virtualmin_server is None
        or deployment.virtualmin_server.status != "active"
    ):
        raise ValueError("Public registration did not verify and activate the owned native node")
    prepared = review_node_hosting(
        str(deployment.virtualmin_server_id),
        str(actor.pk),
        "prepare_helpers",
        {
            "helper_bundle_digest": helper_bundle()["helper_bundle_digest"],
            "reason": "Prepare the exact reviewed helpers on this disposable native acceptance VM",
        },
    )
    if prepared.get("outcome") != "verified":
        raise ValueError("Public inspection-helper preparation did not verify")
    return deployment


def run_workflow(path: Path, action: str, *, dns_zone: str = "") -> None:
    authority = native_authority(path)
    with native_run_lock(authority):
        native_driver().owned_server(path)  # Exact provider ownership before any private DB fixture or native action.
        if action == "prepare":
            _prepare(authority, dns_zone=dns_zone)
        elif action == "register":
            _register(authority)
        elif action == "workflow":
            from apps.infrastructure.native_workflow_scenarios import exercise_public_lifecycle  # noqa: PLC0415

            deployment = _register(authority)
            exercise_public_lifecycle(authority, deployment)
        else:
            raise ValueError("Unsupported native workflow phase")
