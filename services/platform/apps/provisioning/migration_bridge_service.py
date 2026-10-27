"""Verified TLS bridges between provider nodes (ADR-0061 P2.5).

HTTP goes through a migration-owned TLS origin on existing443, then loopback HTTP.
HTTPS reaches the actual customer's 443 vhost with Host and SNI preserved.
Private customer keys stay on their source, copied outside Virtualmin's deletion paths.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from cryptography import x509

from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from .account_hostname_config import bridge_window_hours
from .account_hostname_models import AccountHostname
from .virtualmin_gateway import listing_attribute
from .virtualmin_migration_models import VirtualminMigration

if TYPE_CHECKING:
    from apps.infrastructure.ansible_service import AnsibleService
    from apps.infrastructure.models import NodeDeployment

BRIDGE_PLAYBOOK = "virtualmin_bridge.yml"
BRIDGE_TIMEOUT_SECONDS = 600
MAX_HOSTNAME_LENGTH = 253
_RESULT = re.compile(r"BRIDGE_RESULT=([A-Za-z0-9+/=]+)")


@dataclass(frozen=True)
class BridgePreparation:
    origin_certificate: str
    certificate_not_after: datetime
    dns_names: tuple[str, ...] = ()


def _runner() -> AnsibleService:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415

    return AnsibleService()


def _variables(migration: VirtualminMigration, action: str) -> Result[dict[str, Any], str]:
    remote = (migration.pre_migration_snapshot or {}).get("remote") or {}
    domain_id = str(listing_attribute(remote.get("attributes") or {}, "ID") or "")
    if not domain_id.isdigit():
        return Err("The migration snapshot has no node domain id", retriability=Retriability.NOT_RETRIABLE)
    source_deployment = getattr(migration.source_server, "node_deployment", None)
    source_ip = migration.source_server.ipv4_address or getattr(source_deployment, "ipv4_address", "")
    if not migration.target_server.ipv4_address or not source_ip:
        return Err("Both bridge nodes need IPv4 addresses", retriability=Retriability.NOT_RETRIABLE)
    hostname = AccountHostname.objects.filter(account_id=migration.account_id, retired_at__isnull=True).first()
    return Ok(
        {
            "bridge_action": action,
            "bridge_id": str(migration.pk),
            "bridge_domain": migration.account.domain,
            "bridge_account_name": hostname.fqdn if hostname else "",
            "bridge_target_ipv4": migration.target_server.ipv4_address,
            "bridge_source_ipv4": source_ip,
            "bridge_certificate_min_seconds": (bridge_window_hours() + 1) * 3600,
        }
    )


def _step(
    deployment: NodeDeployment, variables: dict[str, Any], *, timeout_seconds: int = BRIDGE_TIMEOUT_SECONDS
) -> Result[Any, str]:
    result = _runner().run_playbook(deployment, BRIDGE_PLAYBOOK, variables, timeout_seconds=timeout_seconds)
    if result.is_err():
        return Err(
            f"Bridge {variables['bridge_action']} could not run: {result.unwrap_err()}",
            retriability=retriability_of(result),
        )
    run = result.unwrap()
    if not run.success:
        return Err("The bridge playbook failed; its state is uncertain", retriability=Retriability.UNKNOWN)
    try:
        lines = set(_RESULT.findall(run.stdout))
        if len(lines) != 1:
            raise ValueError("expected one structured result")
        payload = json.loads(base64.b64decode(lines.pop(), validate=True))
        if not isinstance(payload, dict):
            raise ValueError("result is not an object")
        if (payload.get("identity"), payload.get("action")) != (variables["bridge_id"], variables["bridge_action"]):
            raise ValueError("result belongs to another migration or action")
        return Ok(payload["payload"])
    except (ValueError, TypeError, KeyError, binascii.Error) as error:
        return Err(f"The bridge result is uncertain: {error}", retriability=Retriability.UNKNOWN)


def _deployments(migration: VirtualminMigration) -> Result[tuple[NodeDeployment, NodeDeployment], str]:
    source = getattr(migration.source_server, "node_deployment", None)
    target = getattr(migration.target_server, "node_deployment", None)
    if source is None or target is None:
        return Err("Both bridge nodes need managed node_deployments", retriability=Retriability.NOT_RETRIABLE)
    return Ok((source, target))


def _prepare(  # noqa: PLR0911  # Fail-closed guards at each external boundary.
    migration: VirtualminMigration, variables: dict[str, Any], *, activation_record: dict[str, Any] | None = None
) -> Result[BridgePreparation, str]:
    deployments = _deployments(migration)
    if deployments.is_err():
        return Err(deployments.unwrap_err(), retriability=retriability_of(deployments))
    source, target = deployments.unwrap()
    prepared = _step(source, {**variables, "bridge_action": "prepare"})
    if prepared.is_err():
        return Err(prepared.unwrap_err(), retriability=retriability_of(prepared))
    if not isinstance(prepared.unwrap(), dict):
        return Err("The source returned no bridge manifest", retriability=Retriability.UNKNOWN)
    origin = _step(target, {**variables, "bridge_action": "origin_install", "bridge_manifest": prepared.unwrap()})
    if origin.is_err():
        return Err(origin.unwrap_err(), retriability=retriability_of(origin))
    if not isinstance(origin.unwrap(), str) or not origin.unwrap():
        return Err("The target returned no origin trust", retriability=Retriability.UNKNOWN)
    proven = _step(
        source, {**variables, "bridge_action": "origin_verify", "bridge_origin_certificate": origin.unwrap()}
    )
    if proven.is_err():
        return Err(proven.unwrap_err(), retriability=retriability_of(proven))
    try:
        certificates = [
            origin.unwrap(),
            *(item["public_certificate"] for item in prepared.unwrap()["vhosts"] if item.get("public_certificate")),
        ]
        deadline = min(x509.load_pem_x509_certificate(pem.encode()).not_valid_after_utc for pem in certificates)
        dns_names = tuple(sorted({name for item in prepared.unwrap()["vhosts"] for name in item["names"]}))
        if any(
            not isinstance(name, str)
            or len(name) > MAX_HOSTNAME_LENGTH
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", name)
            for name in dns_names
        ):
            raise ValueError("Invalid frontend DNS name")
    except (KeyError, ValueError, TypeError, AttributeError):
        return Err(
            "The bridge's certificate lifetime or frontend names could not be verified",
            retriability=Retriability.UNKNOWN,
        )
    if activation_record is not None:
        staged = _stage_target(migration, source, target, variables, activation_record)
        if staged.is_err():
            return Err(staged.unwrap_err(), retriability=retriability_of(staged))
    return Ok(
        BridgePreparation(origin_certificate=origin.unwrap(), certificate_not_after=deadline, dns_names=dns_names)
    )


def _original_record(migration: VirtualminMigration) -> Result[dict[str, Any], str]:
    from .migration_barrier import BarrierRecord  # noqa: PLC0415

    record = BarrierRecord.from_state((migration.barrier_state or {}).get("record"))
    if record.is_err():
        return Err(
            "The target cannot be prepared or activated without the original barrier record",
            retriability=Retriability.NOT_RETRIABLE,
        )
    return Ok(record.unwrap().as_state())


def _stage_target(
    migration: VirtualminMigration,
    source: NodeDeployment,
    target: NodeDeployment,
    variables: dict[str, Any],
    record: dict[str, Any],
) -> Result[str, str]:
    """Move the saved original cron privately while compensation can still return to the source."""
    domain_id = str(listing_attribute(migration.pre_migration_snapshot["remote"].get("attributes") or {}, "ID"))
    try:
        saved = str(UUID(str((migration.barrier_state or {}).get("token") or migration.pk)))
    except ValueError:
        return Err("The saved cron operation token is invalid", retriability=Retriability.NOT_RETRIABLE)
    if not domain_id.isdigit():
        return Err("The saved source domain id is invalid", retriability=Retriability.NOT_RETRIABLE)
    with tempfile.TemporaryDirectory(prefix="praho-prepare-activation-") as scratch:
        spool = str(Path(scratch) / "original.crontab")
        fetched = _step(
            source,
            {
                **variables,
                "bridge_action": "fetch_crontab",
                "bridge_crontab_source": f"/var/lib/praho/migration/migration-{domain_id}.{saved}.crontab",
                "bridge_crontab_spool": spool,
            },
        )
        if fetched.is_err():
            return Err(fetched.unwrap_err(), retriability=retriability_of(fetched))
        if not Path(spool).is_file():
            return Err("The private original cron was not staged by the source")
        Path(spool).chmod(0o600)
        staged = _step(
            target,
            {
                **variables,
                "bridge_action": "stage_activation",
                "bridge_crontab_spool": spool,
                "bridge_owner": migration.account.virtualmin_username,
                "bridge_barrier_record": record,
            },
        )
        if staged.is_err():
            return Err(staged.unwrap_err(), retriability=retriability_of(staged))
    return Ok("staged")


def prepare_bridge(migration: VirtualminMigration) -> Result[BridgePreparation, str]:
    """Preserve source evidence and prepare the restricted origin before commit; no public source vhost."""
    variables = _variables(migration, "prepare")
    if variables.is_err():
        return Err(variables.unwrap_err(), retriability=retriability_of(variables))
    record = _original_record(migration)
    if record.is_err():
        return Err(record.unwrap_err(), retriability=retriability_of(record))
    return _prepare(migration, variables.unwrap(), activation_record=record.unwrap())


def install_bridge(migration: VirtualminMigration) -> Result[str, str]:
    variables = _variables(migration, "install")
    if variables.is_err():
        return Err(variables.unwrap_err(), retriability=retriability_of(variables))
    origin = _prepare(migration, variables.unwrap())
    if origin.is_err():
        return Err(origin.unwrap_err(), retriability=retriability_of(origin))
    source = _deployments(migration).unwrap()[0]
    installed = _step(source, {**variables.unwrap(), "bridge_origin_certificate": origin.unwrap().origin_certificate})
    if installed.is_err():
        return Err(installed.unwrap_err(), retriability=retriability_of(installed))
    return Ok("installed")


def verify_bridge(migration: VirtualminMigration) -> Result[str, str]:
    variables, deployments = _variables(migration, "verify"), _deployments(migration)
    if variables.is_err():
        return Err(variables.unwrap_err(), retriability=retriability_of(variables))
    if deployments.is_err():
        return Err(deployments.unwrap_err(), retriability=retriability_of(deployments))
    checked = _step(deployments.unwrap()[0], variables.unwrap())
    if checked.is_err():
        return Err(checked.unwrap_err(), retriability=retriability_of(checked))
    return Ok("verified")


def remove_bridge(migration: VirtualminMigration, *, source_removed: bool = False) -> Result[str, str]:
    variables, deployments = _variables(migration, "remove"), _deployments(migration)
    if variables.is_err():
        return Err(variables.unwrap_err(), retriability=retriability_of(variables))
    if deployments.is_err():
        return Err(deployments.unwrap_err(), retriability=retriability_of(deployments))
    source, target = deployments.unwrap()
    fields = variables.unwrap()
    if source_removed:
        domain_id = listing_attribute(migration.pre_migration_snapshot["remote"].get("attributes") or {}, "ID")
        try:
            saved = str(UUID(str((migration.barrier_state or {}).get("token") or migration.pk)))
        except ValueError:
            return Err("The original source record token is invalid")
        fields = {**fields, "cleanup_source_record": f"/var/lib/praho/migration/migration-{domain_id}.{saved}.crontab"}
    for deployment, action in ((source, "remove"), (target, "origin_remove")):
        removed = _step(deployment, {**fields, "bridge_action": action})
        if removed.is_err():
            return Err(removed.unwrap_err(), retriability=retriability_of(removed))
    return Ok("removed")


def activate_target(migration: VirtualminMigration, *, enabled: bool | None = None) -> Result[str, str]:
    """After commit, activate only the target using its precommit-staged, domain-id-bound record."""
    if migration.cutover_committed_at is None:
        return Err("The target cannot be activated before the cutover commit")
    target = getattr(migration.target_server, "node_deployment", None)
    if target is None:
        return Err("The target needs a managed deployment", retriability=Retriability.NOT_RETRIABLE)
    record = _original_record(migration)
    if record.is_err():
        return Err(record.unwrap_err(), retriability=retriability_of(record))
    activated = _step(
        target,
        {
            "bridge_action": "activate",
            "bridge_id": str(migration.pk),
            "bridge_domain": migration.account.domain,
            "bridge_owner": migration.account.virtualmin_username,
            "bridge_barrier_record": record.unwrap(),
            **({"bridge_enabled": enabled} if enabled is not None else {}),
        },
    )
    if activated.is_err():
        return Err(activated.unwrap_err(), retriability=retriability_of(activated))
    return Ok("activated")


def enforce_target_policy(migration: VirtualminMigration, enabled: bool) -> Result[str, str]:
    """Apply only current native enabled policy after one-time activation; no original data replay."""
    target = getattr(migration.target_server, "node_deployment", None)
    domain_id = str(migration.barrier_state.get("target_domain_id", ""))
    if target is None or migration.cutover_committed_at is None or not domain_id.isdigit():
        return Err(
            "The current target policy needs committed, bound node ownership", retriability=Retriability.NOT_RETRIABLE
        )
    result = _step(
        target,
        {
            "bridge_action": "reconcile_policy",
            "bridge_id": str(migration.pk),
            "bridge_domain": migration.account.domain,
            "bridge_owner": migration.account.virtualmin_username,
            "bridge_domain_id": domain_id,
            "bridge_enabled": enabled,
        },
        timeout_seconds=300,
    )
    if result.is_err():
        return Err(result.unwrap_err(), retriability=retriability_of(result))
    proof = result.unwrap()
    if (
        not isinstance(proof, dict)
        or proof.get("domain_id") != domain_id
        or proof.get("owner") != migration.account.virtualmin_username
        or proof.get("enabled") is not enabled
    ):
        return Err(
            "The target policy did not return its exact identity and enabled proof", retriability=Retriability.UNKNOWN
        )
    return Ok("reconciled")


def retire_target_activation_data(migration: VirtualminMigration) -> Result[str, str]:
    """Retire exact UUID-owned target secrets after a determinate exit; keep replay fencing forever."""
    target = getattr(migration.target_server, "node_deployment", None)
    if target is None:
        return Err("The target needs a managed deployment", retriability=Retriability.NOT_RETRIABLE)
    retired = _step(
        target,
        {
            "bridge_action": "retire_activation",
            "bridge_id": str(migration.pk),
            "bridge_domain": migration.account.domain,
        },
    )
    if retired.is_err():
        return Err(retired.unwrap_err(), retriability=retriability_of(retired))
    return Ok("retired")
