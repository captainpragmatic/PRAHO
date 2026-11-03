"""One intent-first VM, created by the real deployment service and verified from live evidence."""

from __future__ import annotations

import json
import os
import stat
from typing import TYPE_CHECKING
from uuid import UUID

from django.db import transaction

from .deployment_lifecycle import provider_token_fingerprint
from .deployment_preflight import validate_deployment_dns_zone
from .native_lab import PRIVATE_MODE, native_driver, write_private

if TYPE_CHECKING:
    from .models import NodeDeployment
    from .native_lab import NativeAuthority


REQUIRED_STAGES = frozenset(
    {
        "ssh_key",
        "provision_server",
        "configuring_dns",
        "ansible_base",
        "ansible_panel",
        "ansible_harden",
        "validation",
        "registration",
        "complete",
    }
)


def _credentials() -> tuple[str, str, str]:
    values = tuple(
        os.environ.get(name, "")
        for name in (
            "HCLOUD_TOKEN",
            "PRAHO_NATIVE_CLOUDFLARE_TOKEN",
            "PRAHO_NATIVE_CLOUDFLARE_ZONE_ID",
        )
    )
    if not all(values):
        raise ValueError("Explicit native creating provider token, approved DNS token and zone ID are required")
    return values[0], values[1], values[2]


def verify_fresh_vm(authority: NativeAuthority) -> None:
    """Check database provenance, provider/DNS state and real SSH/runtime evidence afresh."""
    from apps.provisioning.hosting_node_policy import verify_quota_evidence  # noqa: PLC0415
    from apps.provisioning.hosting_node_tasks import collect_hosting_inspection  # noqa: PLC0415

    from .deployment_lifecycle import unique_dns_owner_tag  # noqa: PLC0415
    from .dns_gateway import get_dns_gateway  # noqa: PLC0415
    from .models import NodeDeploymentLog  # noqa: PLC0415
    from .native_workflow import require_fixture_dns  # noqa: PLC0415
    from .validation_service import get_validation_service  # noqa: PLC0415

    provider_token, dns_token, zone_id = _credentials()
    deployment = _fresh_deployment(authority, provider_token=provider_token, zone_id=zone_id)
    _completed_provenance(deployment, provider_token)
    manifest, _server = native_driver().owned_server(authority.path)
    if str(manifest["server_id"]) != deployment.external_node_id or manifest["ipv4"] != deployment.ipv4_address:
        raise ValueError("The native VM changed from the public deployment's exact resource")
    _approved_dns(deployment.dns_zone, dns_token, zone_id)
    listed = get_dns_gateway("cloudflare", dns_token).find_records_by_name(zone_id, deployment.fqdn)
    if listed.is_err():
        raise ValueError("The live public deployment DNS records could not be verified")
    records = listed.unwrap()
    owned = unique_dns_owner_tag(deployment.correlation_id)
    if (
        not records
        or any(item.get("comment") != owned or item.get("name") != deployment.fqdn for item in records)
        or not any(item.get("type") == "A" and item.get("content") == deployment.ipv4_address for item in records)
        or any(item.get("type") not in {"A", "AAAA"} for item in records)
    ):
        raise ValueError("The exact public-created DNS records and ownership are not verified")
    require_fixture_dns(deployment, str(deployment.ipv4_address))
    validation = get_validation_service().validate_node(deployment)
    if validation.is_err() or not validation.unwrap().all_passed:
        raise ValueError("Live public SSH/port/Virtualmin/TLS validation is incomplete")
    server = deployment.virtualmin_server
    if server is None:
        raise ValueError("The registered public Virtualmin server is missing")
    evidence = collect_hosting_inspection(server)
    verify_quota_evidence(evidence["quota"], evidence["identity"])
    state = json.loads(native_driver().remote(authority.path, "/bin/cat /root/praho-native-quota-state.json"))
    if state.get("run") != manifest["run"] or any(
        state.get(name) is not True for name in ("initial", "reboot", "packages_updated", "update")
    ):
        raise ValueError("The original VM's real UID/PHP/database/reboot/update scenarios have not completed")
    NodeDeploymentLog.objects.create(
        deployment=deployment,
        level="INFO",
        phase="native_fresh_verified",
        message="Fresh public deployment and live DNS/runtime/native quota controls verified",
        details={
            "run": manifest["run"],
            "server_id": deployment.external_node_id,
            "connection_identity": evidence["identity"],
            "zone_id": zone_id,
        },
    )


def destroy_fresh_vm(authority: NativeAuthority) -> None:
    """Destroy only this original public deployment using its actual approval and teardown services."""
    from .cloud_destroy_service import DestroyApproval, approve_destroy, inspect_destroy  # noqa: PLC0415
    from .deployment_service import NodeDeploymentService  # noqa: PLC0415
    from .native_workflow import native_fixture_actor  # noqa: PLC0415

    provider_token, _dns_token, zone_id = _credentials()
    deployment = _fresh_deployment(authority, provider_token=provider_token, zone_id=zone_id)
    actor = native_fixture_actor(authority.manifest["run"])
    if deployment.status == "destroyed":
        authority.manifest["phase"] = "destroyed"
        native_driver().write_manifest(authority.path, authority.manifest)
        return
    preview = inspect_destroy(deployment, provider_token)
    plan = approve_destroy(
        deployment,
        provider_token,
        actor,
        DestroyApproval(
            hostname=deployment.hostname,
            digest=preview.digest,
            restore_point_policy="delete",
            reason="Destroy the exact disposable native acceptance deployment and its owned restore points",
        ),
    )
    result = NodeDeploymentService().destroy_node(
        deployment,
        {"api_token": provider_token},
        user=actor,
        plan_id=plan.pk,
    )
    if result.is_err() or not result.unwrap():
        raise ValueError("Public native teardown is incomplete; preserve the original authority and reconcile it")
    deployment.refresh_from_db()
    if deployment.status != "destroyed":
        raise ValueError("Public native teardown has not confirmed all owned resources absent")
    authority.manifest["phase"] = "destroyed"
    native_driver().write_manifest(authority.path, authority.manifest)


def _approved_dns(dns_zone: str, token: str, zone_id: str) -> None:
    from .dns_gateway import get_dns_gateway  # noqa: PLC0415

    validated = validate_deployment_dns_zone(dns_zone)
    if validated.is_err():
        raise ValueError("An approved DNS subzone is required")
    zone = get_dns_gateway("cloudflare", token).get_zone_name(zone_id)
    if zone.is_err():
        raise ValueError("The approved DNS provider zone could not be read")
    parent, requested = zone.unwrap().rstrip(".").lower(), validated.unwrap()
    if not parent or (requested != parent and not requested.endswith("." + parent)):
        raise ValueError("The approved DNS subzone is outside the creating provider zone")


def deploy_fresh_vm(authority: NativeAuthority, *, dns_zone: str) -> None:
    """Create the sole VM through the real deployment/FSM/DNS/registration pipeline.

    Interrupted or failed operations retain the original intent and vault key.
    They require public reconciliation/teardown; this harness never invents a
    second deployment to hide an uncertain first create.
    """
    from apps.settings.services import SettingsService  # noqa: PLC0415

    from .deployment_service import NodeDeploymentService  # noqa: PLC0415
    from .models import NodeDeploymentLog  # noqa: PLC0415
    from .native_workflow import native_fixture_actor  # noqa: PLC0415
    from .provider_sync import sync_hetzner_provider  # noqa: PLC0415

    if authority.manifest.get("origin") != "platform_fresh":
        raise ValueError("A raw provider VM cannot be reused as a fresh public deployment")
    provider_token, dns_token, zone_id = _credentials()
    _approved_dns(dns_zone, dns_token, zone_id)
    synced = sync_hetzner_provider(provider_token)
    if synced.is_err():
        raise ValueError("The live native provider catalogue could not be synchronized")
    deployment = bind_fresh_deployment(authority, dns_zone=dns_zone, provider_token=provider_token, zone_id=zone_id)
    actor = native_fixture_actor(authority.manifest["run"])
    write_private(authority.path.parent / (authority.manifest["run"] + ".operator.pub"), authority.public_key + "\n")
    for key, value in (
        ("infrastructure.node_admin_allowed_cidrs", [authority.manifest["admin_cidr"]]),
        ("node_deployment.dns_cloudflare_api_token", dns_token),
        ("node_deployment.dns_cloudflare_zone_id", zone_id),
    ):
        if SettingsService.update_setting(key, value).is_err():
            raise ValueError("The isolated native deployment configuration could not be saved")
    if deployment.status == "pending" and not deployment.external_node_id and deployment.server_create_state == "none":
        result = NodeDeploymentService().deploy_node(
            deployment,
            {"api_token": provider_token},
            cloudflare_api_token=dns_token,
            user=actor,
        )
        if result.is_err():
            raise ValueError("Public native deployment refused or failed: " + result.unwrap_err())
        completed = result.unwrap()
        report = completed.validation_report
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="INFO",
            phase="native_fresh_result",
            message="Recorded the real public deployment result; runtime proof remains separate",
            details={
                "source": "NodeDeploymentService.deploy_node",
                "stages": completed.stages_completed,
                "success": completed.success,
                "validation_passed": report is not None and report.all_passed,
                "validation_checks": [item.check_name for item in report.checks if item.passed] if report else [],
            },
        )
    elif deployment.status != "completed":
        raise ValueError(
            "The original deployment needs public reconciliation or exact teardown; no second VM is allowed"
        )
    publish_fresh_vm(authority, provider_token=provider_token, zone_id=zone_id)


def _fresh_deployment(authority: NativeAuthority, *, provider_token: str, zone_id: str) -> NodeDeployment:
    from .models import NodeDeployment  # noqa: PLC0415
    from .native_workflow import _database_identity, native_fixture_actor  # noqa: PLC0415

    binding = authority.manifest.get("platform_fixture")
    run = UUID(authority.manifest["run"])
    fingerprint = provider_token_fingerprint(provider_token)
    if (
        authority.manifest.get("origin") != "platform_fresh"
        or not isinstance(binding, dict)
        or binding.get("origin") != "platform_fresh"
        or binding.get("database") != _database_identity()
        or binding.get("creator_fingerprint") != fingerprint
        or binding.get("zone_id") != zone_id
    ):
        raise ValueError("The original database and creating provider/DNS authority are required")
    actor = native_fixture_actor(run)
    deployment = NodeDeployment.objects.get(pk=binding["deployment_id"], correlation_id=run, initiated_by=actor)
    intent = deployment.logs.filter(phase="native_fresh_intent").first()
    if (
        intent is None
        or intent.details
        != {
            "run": str(run),
            "database": _database_identity(),
            "zone_id": zone_id,
            "creator_fingerprint": fingerprint,
            "initial_external_node_id": "",
            "initial_server_create_state": "none",
        }
        or deployment.fqdn != binding.get("fqdn")
    ):
        raise ValueError("The original pre-create database intent is missing or changed")
    return deployment


def _completed_provenance(deployment: NodeDeployment, provider_token: str) -> dict[str, str]:
    """Require public FSM state and immutable first-create records before any lab ownership labels."""
    fingerprint = provider_token_fingerprint(provider_token)
    result = deployment.logs.filter(phase="native_fresh_result").order_by("-created_at").first()
    details = result.details if result else {}
    if (
        deployment.status != "completed"
        or deployment.server_create_state != "created"
        or deployment.registration_state not in {"registered", "activated"}
        or deployment.virtualmin_server is None
        or not deployment.external_node_id
        or deployment.virtualmin_server.status != "active"
        or not deployment.ipv4_address
        or not deployment.ssh_host_keys
        or deployment.operation_token is not None
        or deployment.provider_token_fingerprint != fingerprint
        or details.get("source") != "NodeDeploymentService.deploy_node"
        or details.get("success") is not True
        or details.get("validation_passed") is not True
        or not REQUIRED_STAGES.issubset(details.get("stages", []))
        or not {"ssh", "ports", "virtualmin", "ssl"}.issubset(details.get("validation_checks", []))
    ):
        raise ValueError("The actual public deployment, registration and validation result are not complete")
    ownership = list(
        deployment.resource_ownership.filter(
            provider=deployment.provider,
            token_fingerprint=fingerprint,
            deployment_correlation_id=deployment.correlation_id,
        ).values("kind", "resource_id", "provenance")
    )
    servers = [item for item in ownership if item["kind"] == "server"]
    keys = [item for item in ownership if item["kind"] == "ssh_key"]
    if (
        len(servers) != 1
        or servers[0]["resource_id"] != deployment.external_node_id
        or servers[0]["provenance"] != "create_response"
        or len(keys) != 1
        or keys[0]["provenance"] != "create_response"
        or not deployment.server_lifetimes.filter(
            server_id=deployment.external_node_id,
            correlation_id=deployment.correlation_id,
            legacy=False,
            ended_at__isnull=True,
        ).exists()
    ):
        raise ValueError("The exact fresh server/key creation records and open billable lifetime are required")
    return {"server_id": servers[0]["resource_id"], "ssh_key_id": keys[0]["resource_id"]}


def publish_fresh_vm(authority: NativeAuthority, *, provider_token: str, zone_id: str) -> None:
    """Export the same public-created VM for native checks, never adopt a labelled arbitrary VM."""
    from .native_workflow import require_fixture_dns  # noqa: PLC0415

    deployment = _fresh_deployment(authority, provider_token=provider_token, zone_id=zone_id)
    resources = _completed_provenance(deployment, provider_token)
    host_keys = deployment.ssh_host_keys
    if not host_keys:
        raise ValueError("The original public deployment host enrollment is missing")
    require_fixture_dns(deployment, str(deployment.ipv4_address))
    driver, manifest = native_driver(), authority.manifest
    cloud = driver.client()
    server = cloud.servers.get_by_id(int(resources["server_id"]))
    key = cloud.ssh_keys.get_by_id(int(resources["ssh_key_id"]))
    production_labels = {"managed-by": "praho", "praho-deployment": manifest["run"]}
    if (
        server is None
        or key is None
        or server.name != deployment.hostname
        or server.public_net.ipv4.ip != deployment.ipv4_address
        or any(
            server.labels.get(name) != value or key.labels.get(name) != value
            for name, value in production_labels.items()
        )
        or key.public_key.strip() != authority.public_key
    ):
        raise ValueError("The live provider server and original key do not match the recorded fresh deployment")
    labels = {"praho-native-run": manifest["run"], "praho-native-owner": driver.OWNER}
    server.update(labels={**server.labels, **labels})
    cloud.ssh_keys.update(key, labels={**key.labels, **labels})
    manifest.update(
        {
            "server_id": int(resources["server_id"]),
            "ssh_key_id": int(resources["ssh_key_id"]),
            "ipv4": deployment.ipv4_address,
            "ssh_port": deployment.ssh_port,
            "host_public_key": host_keys,
            "phase": "prepared",
        }
    )
    _key_path, trust = driver.paths(authority.path, manifest)
    trust_value = "".join(
        f"{deployment.ipv4_address} {line}\n[{deployment.ipv4_address}]:{deployment.ssh_port} {line}\n"
        for line in host_keys.splitlines()
        if line.strip()
    )
    # The original private key is retained; host trust comes from the real deployment's durable enrollment.
    descriptor = os.open(trust, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r+") as target:
        info = os.fstat(target.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != PRIVATE_MODE
            or info.st_uid != os.getuid()
            or info.st_size > driver.MAX_MANIFEST
        ):
            raise ValueError("The original native host trust must be private and bounded")
        previous = target.read()
        if previous and previous != trust_value:
            raise ValueError("The original native host trust changed")
        target.seek(0)
        target.write(trust_value)
        target.truncate()
        target.flush()
        os.fsync(target.fileno())
    driver.write_manifest(authority.path, manifest)


def bind_fresh_deployment(
    authority: NativeAuthority, *, dns_zone: str, provider_token: str, zone_id: str
) -> NodeDeployment:
    """Bind one private intent to a pending deployment before any provider mutation."""
    from .models import (  # noqa: PLC0415
        CloudProvider,
        NodeDeployment,
        NodeDeploymentLog,
        NodeRegion,
        NodeSize,
        PanelType,
    )
    from .native_workflow import _credential, _database_identity, native_fixture_actor  # noqa: PLC0415

    manifest = authority.manifest
    if manifest.get("origin") != "platform_fresh":
        raise ValueError("A raw provider VM cannot certify a fresh public deployment")
    validated = validate_deployment_dns_zone(dns_zone)
    if validated.is_err() or not provider_token or not zone_id:
        raise ValueError("An approved DNS zone and creating provider/DNS authority are required")
    run = UUID(manifest["run"])
    fingerprint = provider_token_fingerprint(provider_token)
    with transaction.atomic():
        if NodeDeployment.objects.exclude(correlation_id=run).exists():
            raise ValueError("Fresh native acceptance requires a database containing only this deployment run")
        provider = CloudProvider.objects.get(provider_type="hetzner", is_active=True)
        region = NodeRegion.objects.get(provider=provider, provider_region_id=manifest["location"], is_active=True)
        size = NodeSize.objects.get(provider=provider, provider_type_id=manifest["server_type"], is_active=True)
        if not size.is_offered_in(region):
            raise ValueError("The approved native size is not offered in its selected region")
        panel = PanelType.objects.get(name="Virtualmin GPL", panel_type="virtualmin", is_active=True)
        actor = native_fixture_actor(run, create=True)
        deployment = NodeDeployment.objects.select_for_update(of=("self",)).filter(correlation_id=run).first()
        if deployment is None:
            if (
                manifest.get("phase") != "fresh-intent"
                or manifest.get("platform_fixture") is not None
                or any(manifest.get(name) is not None for name in ("server_id", "ssh_key_id", "firewall_id", "ipv4"))
            ):
                raise ValueError("An existing provider resource or orphaned binding cannot start a fresh deployment")
            deployment = NodeDeployment.objects.create(
                provider=provider,
                region=region,
                node_size=size,
                panel_type=panel,
                environment="dev",
                node_type="sha",
                node_number=NodeDeployment.get_next_node_number(
                    environment="dev",
                    node_type="sha",
                    provider=provider,
                    region=region,
                ),
                correlation_id=run,
                dns_zone=validated.unwrap(),
                initiated_by=actor,
                display_name="Native fresh quota acceptance " + str(run),
                backup_enabled=False,
                backup_storage="platform",
            )
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="info",
                phase="native_fresh_intent",
                message="Bound a fresh native deployment before its first provider operation",
                details={
                    "run": str(run),
                    "database": _database_identity(),
                    "zone_id": zone_id,
                    "creator_fingerprint": fingerprint,
                    "initial_external_node_id": "",
                    "initial_server_create_state": "none",
                },
            )
        if any(
            manifest.get(name) is not None and str(manifest[name]) != str(expected)
            for name, expected in (("server_id", deployment.external_node_id), ("ipv4", deployment.ipv4_address))
        ):
            raise ValueError("The original fresh deployment cannot adopt a different existing provider resource")
        if (
            deployment.provider_id != provider.pk
            or deployment.region_id != region.pk
            or deployment.node_size_id != size.pk
            or deployment.dns_zone != validated.unwrap()
            or deployment.display_name != "Native fresh quota acceptance " + str(run)
            or deployment.initiated_by_id != actor.pk
        ):
            raise ValueError("The original fresh deployment configuration or actor changed")
        expected = {
            "schema": 1,
            "origin": "platform_fresh",
            "deployment_id": deployment.pk,
            "fqdn": deployment.fqdn,
            "run": str(run),
            "database": _database_identity(),
            "zone_id": zone_id,
            "creator_fingerprint": fingerprint,
        }
        recorded = manifest.get("platform_fixture")
        if recorded is not None and recorded != expected:
            raise ValueError("The creating authority or original fresh deployment binding changed")
        intent = deployment.logs.get(phase="native_fresh_intent").details
        if intent != {
            "run": str(run),
            "database": _database_identity(),
            "zone_id": zone_id,
            "creator_fingerprint": fingerprint,
            "initial_external_node_id": "",
            "initial_server_create_state": "none",
        }:
            raise ValueError("The initial fresh provider intent is missing or changed")
        credential_id = _credential(
            "ssh",
            "node-" + deployment.hostname,
            authority.public_key,
            authority.key.decode(),
            {"native_run": str(run), "deployment_id": str(deployment.pk), "purpose": "node_deployment"},
        )
        if credential_id:
            deployment.ssh_key_credential_id = credential_id
            deployment.save(update_fields=["ssh_key_credential_id", "updated_at"])
    manifest["platform_fixture"] = expected
    native_driver().write_manifest(authority.path, manifest)
    return deployment
