"""Reconcile a node deployment: prove, or attest, that nothing it owned remains.

Flagged rows (``needs_reconciliation``) are the main case. An unflagged failed or destroyed row can be reconciled
too, to record the proof re-deploy needs (``resources_proved_absent_for``): with a never-created attestation for
an unknown create outcome, or, for a destroyed row, by the same search.

Teardown flags a row it cannot prove torn down, typically one whose server-create outcome is unknown under a
provider token that was never recorded. Retry, the sweeps and re-deploy refuse flagged rows. An operator runs
this from the platform host (``manage.py reconcile_deployment``); shell access there is the authorization
boundary, and the named operator must hold the destroy permission.

The row must be quiet (unwritten for longer than any lifecycle task can run, so no worker or provider call is
still in flight), carry no server id and have no linked node. The command then claims it, searches the provider
project and the DNS zones for anything it may own, revokes its vault key, and settles it destroyed in one
transaction with its log and audit event. Anything found, any failed lookup or any unreadable zone refuses and
leaves the row flagged. Without a recorded provider token, absence needs an evidence-backed attestation. The
creator provenance and the create state are kept as history; what was proved or attested goes to
``reconciliation_record``.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.audit_service import InfrastructureAuditContext, InfrastructureAuditService
from apps.infrastructure.cloud_gateway import get_cloud_gateway
from apps.infrastructure.deployment_lifecycle import (
    OperationOwnershipLostError,
    attempt_resource_names,
    claim_operation,
    legacy_resource_names,
    owned_transition,
    owned_update,
    provider_token_fingerprint,
    recorded_provider_resources,
    unique_dns_owner_tag,
)
from apps.infrastructure.dns_gateway import get_dns_gateway
from apps.infrastructure.permissions import can_destroy_nodes
from apps.infrastructure.provider_config import get_provider_token
from apps.infrastructure.server_lifetimes import close_server_lifetimes, delete_unconfirmed_lifetimes
from apps.infrastructure.ssh_key_manager import get_ssh_key_manager
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

logger = logging.getLogger(__name__)

RECONCILABLE_STATES = ("failed", "destroying")
# An unflagged row: a never-created attestation (failed or destroyed), or an absence proof for a destroyed row.
UNFLAGGED_STATES = ("failed", "destroyed")
# Messages and log phases deploy_node writes only once the provider returned a server.
_CREATED_MESSAGES = ("Server created successfully", "Server provisioned with IP", "Server already exists")
_POST_CREATE_PHASES = (
    "update_deployment",
    "configuring_dns",
    "ansible_base",
    "ansible_panel",
    "ansible_harden",
    "ansible_backup",
    "validation",
    "registration",
    "complete",
)


def quiet_window() -> timedelta:
    """Longer than any lifecycle task may run: the queue kills a worker at its task timeout."""
    from apps.infrastructure.tasks import (  # noqa: PLC0415  # Deferred: tasks imports the service layer
        NODE_DEPLOYMENT_TASK_TIMEOUT_SECONDS,
        NODE_DESTROY_TASK_TIMEOUT_SECONDS,
    )

    return timedelta(seconds=max(NODE_DEPLOYMENT_TASK_TIMEOUT_SECONDS, NODE_DESTROY_TASK_TIMEOUT_SECONDS) + 15 * 60)


@dataclass
class ReconcileRequest:
    hostname: str
    operator_email: str
    evidence: str = ""
    attest_no_resources: bool = False
    attest_never_created: bool = False
    dry_run: bool = False
    invoker: dict[str, str] = field(default_factory=dict)


@dataclass
class ReconcileReport:
    hostname: str
    provenance: str
    searched: list[str] = field(default_factory=list)
    settled: bool = False


class _RefusalError(Exception):
    """Reconciliation found something, or could not look; the row stays flagged."""


def creation_evidence(deployment: NodeDeployment) -> list[str]:
    """Durable signs that a server was created for this deployment at some point."""
    from apps.infrastructure.models import NodeDeploymentLog  # noqa: PLC0415  # Deferred: avoids circular import

    signs = []
    if deployment.server_create_state == "created":
        signs.append("create state is 'created'")
    names = ("ipv4_address", "ipv6_address", "completed_at", "virtualmin_server_id", "external_node_id")
    signs.extend(f"{name} is set" for name in names if getattr(deployment, name))
    logs = NodeDeploymentLog.objects.filter(deployment=deployment)
    if logs.filter(phase__in=_POST_CREATE_PHASES).exists() or any(
        logs.filter(message__startswith=m).exists() for m in _CREATED_MESSAGES
    ):
        signs.append("the deployment log records a created server")
    confirmed = deployment.server_lifetimes.filter(ended_at__isnull=True).exclude(server_id="")
    signs.extend(f"server {lt.server_id} has an open billable lifetime" for lt in confirmed)
    return signs


def _md5_fingerprint(public_key: str) -> str:
    """The fingerprint Hetzner reports for an OpenSSH public key (MD5 of the key blob, colon-separated)."""
    blob = base64.b64decode(public_key.split()[1])
    digest = hashlib.md5(blob, usedforsecurity=False).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _scope_refusal(deployment: NodeDeployment, *, never_created: bool) -> str:
    """A flagged row, or an unflagged one this request can settle (never-created, or a destroyed row's proof)."""
    if deployment.needs_reconciliation:
        if deployment.status not in RECONCILABLE_STATES:
            return f"Cannot reconcile a deployment in status '{deployment.status}'"
        return ""
    if deployment.status not in UNFLAGGED_STATES:
        return "The deployment is not flagged for reconciliation"
    if deployment.dns_record_ids:
        return "The deployment still holds DNS records and is not flagged; destroy it instead"
    if deployment.status == "failed" and not never_created:
        return (
            "The deployment is not flagged for reconciliation; destroy it, or attest that its server was never "
            "created with --attest-never-created"
        )
    return ""


def _precondition_refusal(deployment: NodeDeployment, *, quiet_since: Any, never_created: bool) -> str:
    """Whether the row may be searched."""
    scope = _scope_refusal(deployment, never_created=never_created)
    if scope:
        return scope
    if deployment.external_node_id:
        return (
            "The deployment still has a server id: restore the provider token that created it, "
            "then run Destroy again to resume the teardown"
        )
    if deployment.virtualmin_server_id:
        return "The deployment is still linked to its Virtualmin node; destroy it instead"
    if deployment.updated_at >= quiet_since:
        return "The deployment was written too recently; a worker may still be running. Try again later"
    return ""


def _request_refusal(request: ReconcileRequest, deployment: NodeDeployment, credential_fingerprint: str) -> str:
    stored = deployment.provider_token_fingerprint
    if stored and stored != credential_fingerprint:
        return "The deployment was created with a different provider token; restore it and destroy the node"
    if (request.attest_no_resources or request.attest_never_created) and not request.evidence.strip():
        return "An attestation needs --evidence"
    if not stored and not request.attest_no_resources:
        return (
            "No provider token was recorded for this deployment, so a search cannot prove absence; "
            "check the provider console and pass --attest-no-resources with --evidence"
        )
    if request.attest_never_created:
        if deployment.server_create_state not in ("unknown", "intent"):
            return f"Never-created applies only to an unknown create outcome, not '{deployment.server_create_state}'"
        signs = creation_evidence(deployment)
        if signs:
            return f"A server was created for this deployment: {'; '.join(signs)}"
    return ""


def _operator(email: str) -> Any:
    user = get_user_model().objects.filter(email=email, is_active=True, is_staff=True).first()
    if user is None or not can_destroy_nodes(user):
        return None
    return user


def _search_provider(deployment: NodeDeployment, api_token: str, ssh_manager: Any) -> list[str]:
    """Look for anything the deployment may own in the token's project; raise _RefusalError on any find or error."""
    gateway = get_cloud_gateway(deployment.provider.provider_type, api_token)
    corr, host = deployment.correlation_id, deployment.hostname
    recorded = recorded_provider_resources(deployment)
    # Every name the deployment's resources may carry: this attempt's, the legacy ones, and any an
    # earlier attempt recorded (a re-deploy rotates the attempt).
    key_names = {attempt_resource_names(host, corr)[0], legacy_resource_names(host)[0], *recorded["ssh_key_names"]}
    firewall_names = {
        attempt_resource_names(host, corr)[1],
        legacy_resource_names(host)[1],
        *recorded["firewall_names"],
    }
    lookups: list[tuple[str, Any]] = [
        (
            f"servers labelled praho-deployment={corr}",
            lambda: gateway.find_servers_by_label(f"praho-deployment={corr}"),
        ),
        (f"servers named {host}", lambda: gateway.find_servers_by_name(host)),
        (f"firewalls labelled deployment-id={corr}", lambda: gateway.find_firewalls_by_label(f"deployment-id={corr}")),
        (
            f"SSH keys labelled praho-deployment={corr}",
            lambda: gateway.find_ssh_keys_by_label(f"praho-deployment={corr}"),
        ),
    ]
    lookups += [(f"firewalls named {n}", lambda n=n: gateway.find_firewalls_by_name(n)) for n in sorted(firewall_names)]
    lookups += [(f"SSH keys named {n}", lambda n=n: gateway.find_ssh_keys_by_name(n)) for n in sorted(key_names)]
    if deployment.ssh_key_credential_id:
        key = ssh_manager.get_deployment_key(deployment)
        if key.is_err():
            raise _RefusalError(f"Cannot read the deployment's vault key to search for it: {key.unwrap_err()}")
        fingerprint = _md5_fingerprint(key.unwrap().public_key)
        lookups.append(
            (f"SSH keys with fingerprint {fingerprint}", lambda: gateway.find_ssh_keys_by_fingerprint(fingerprint))
        )
    searched = []
    for label, lookup in lookups:
        found = lookup()
        if found.is_err():
            raise _RefusalError(f"Lookup of {label} failed: {found.unwrap_err()}")
        if found.unwrap():
            raise _RefusalError(f"Found {label}: {found.unwrap()}")
        searched.append(label)
    for firewall_id in recorded["firewall_ids"]:
        exists = gateway.firewall_exists(firewall_id)
        if exists.is_err() or exists.unwrap():
            raise _RefusalError(f"Recorded firewall {firewall_id} still exists or could not be checked")
        searched.append(f"recorded firewall {firewall_id}")
    return searched


def _prove_dns_absent(deployment: NodeDeployment) -> list[str]:
    """Prove none of the deployment's DNS remains, in every stored zone and the configured one."""
    entries = deployment.dns_record_ids or []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("zone_id") or not entry.get("name"):
            raise _RefusalError(f"A stored DNS entry has no zone or name: {entry}")
    token = str(SettingsService.get_setting("node_deployment.dns_cloudflare_api_token") or "").strip()
    configured_zone = str(SettingsService.get_setting("node_deployment.dns_cloudflare_zone_id") or "").strip()
    zones = {str(e["zone_id"]) for e in entries} | ({configured_zone} if configured_zone else set())
    if not token or not zones:
        raise _RefusalError("No DNS token or zone is configured, so DNS absence cannot be proved")
    try:
        gateway = get_dns_gateway("cloudflare", token)
    except ValueError as exc:
        raise _RefusalError(f"DNS provider unavailable: {exc}") from exc
    names = {str(e["name"]) for e in entries} | {deployment.fqdn}
    own_tag = unique_dns_owner_tag(deployment.correlation_id)
    searched = []
    for zone in sorted(zones):
        if gateway.get_zone_name(zone).is_err():
            raise _RefusalError(f"DNS zone {zone} cannot be read")
        for entry in (e for e in entries if e["zone_id"] == zone and e.get("record_id")):
            record = gateway.get_record(zone, str(entry["record_id"]))
            if record.is_err() or record.unwrap() is not None:
                raise _RefusalError(f"DNS record {entry['record_id']} in zone {zone} still exists or could not be read")
        for name in sorted(names):
            found = gateway.find_records_by_name(zone, name)
            if found.is_err() or found.unwrap():
                raise _RefusalError(f"DNS records for {name} in zone {zone} exist or could not be listed")
        owned = gateway.confirm_no_owned_records(zone, own_tag)
        if owned.is_err() or not owned.unwrap():
            raise _RefusalError(f"Records tagged {own_tag} remain in zone {zone} or could not be listed")
        searched.append(f"DNS zone {zone}: {', '.join(sorted(names))}")
    return searched


def _post_claim_refusal(locked: NodeDeployment, target: str, record: dict[str, Any]) -> str:
    """The claimed row must be the one that was searched: same flag, identifiers, DNS, token and create state."""
    expected = {name: value for name, value in record["snapshot"].items() if name != "status"}
    current = {name: getattr(locked, name) for name in expected}
    if locked.status != target or current != expected:
        return "The deployment changed while it was being reconciled"
    return ""


def _claim_and_settle(
    deployment: NodeDeployment, quiet_since: Any, record: dict[str, Any], operator: Any, ssh_manager: Any
) -> None:
    """Claim, re-check and settle destroyed with its log and audit event, all in one transaction.

    The search ran before this without a claim, so a refusal never moves the row. The claim re-checks the
    quiet window: any write to the row since the search began (a destroy, a sweep, another reconcile)
    refuses the claim. Any failure, the audit event included, undoes everything.
    """
    from apps.infrastructure.models import NodeDeployment as Model  # noqa: PLC0415  # Deferred: circular import
    from apps.infrastructure.models import NodeDeploymentLog  # noqa: PLC0415

    searched_status = record["snapshot"]["status"]
    flagged = record["snapshot"]["needs_reconciliation"]
    # A destroyed row stays destroyed: the claim takes it without a transition, and the settlement only records.
    target = "destroyed" if searched_status == "destroyed" else "destroying"
    with transaction.atomic():
        claim = claim_operation(
            deployment.pk,
            from_states=RECONCILABLE_STATES if flagged else (searched_status,),
            to_status=target,
            kind="reconcile",
            stale_before=quiet_since,
        )
        if claim.is_err():
            raise _RefusalError(claim.unwrap_err())
        lease = claim.unwrap()
        locked = Model.objects.get(pk=deployment.pk)
        refusal = _post_claim_refusal(locked, target, record)
        if refusal:
            raise _RefusalError(refusal)
        # Revoked after the claim: the vault write touches the row, and before the claim it would break
        # the quiet-window check. Inside the transaction, a later failure undoes it too.
        revoked = ssh_manager.delete_deployment_key(locked, user=operator)
        if revoked.is_err():
            raise _RefusalError(f"SSH key revocation failed: {revoked.unwrap_err()}")
        locked.refresh_from_db()
        if record["never_created_attested"]:
            delete_unconfirmed_lifetimes(locked)  # Attested never created: those windows billed nothing.
        else:
            close_server_lifetimes(lease, locked)  # Proved gone: every window ends here.
        settled = {
            "dns_record_ids": [],
            "needs_reconciliation": False,
            "reconciliation_reason": "",
            "reconciliation_record": record,
            "resources_proved_absent_for": locked.correlation_id,
        }
        if target == "destroyed":
            owned_update(
                lease,
                locked,
                operation_token=None,
                operation_kind="",
                destroyed_at=locked.destroyed_at or timezone.now(),
                **settled,
            )
        else:
            owned_transition(
                lease,
                locked,
                "destroyed",
                "Reconciled: nothing it owned remains",
                release=True,
                destroyed_at=timezone.now(),
                **settled,
            )
        NodeDeploymentLog.objects.create(
            deployment=locked,
            level="INFO",
            phase="reconcile",
            message=f"Reconciled by {record['operator']} ({record['provenance']}); settled destroyed",
        )
        InfrastructureAuditService.log_destroy_completed(
            locked,
            InfrastructureAuditContext(user=operator, metadata={"mode": "reconcile", "flagged": flagged, **record}),
        )


def _record_refusal(deployment: NodeDeployment, message: str, operator: Any, record: dict[str, Any]) -> Err[str]:
    """Record why reconciliation refused, with the search so far; the row is left as it was."""
    from apps.infrastructure.node_teardown import record_destroy_failure  # noqa: PLC0415  # Deferred import

    record_destroy_failure(
        deployment,
        f"Reconcile refused: {message}",
        InfrastructureAuditContext(user=operator, metadata={"mode": "reconcile", **record}),
    )
    return Err(message)


def reconcile_deployment(request: ReconcileRequest) -> Result[ReconcileReport, str]:  # noqa: PLR0911  # One refusal per check.
    from apps.infrastructure.models import NodeDeployment as Model  # noqa: PLC0415  # Deferred: circular import

    deployment = Model.objects.select_related("provider").filter(hostname=request.hostname).first()
    if deployment is None:
        return Err(f"No deployment named {request.hostname}")
    operator = _operator(request.operator_email)
    if operator is None:
        return Err(f"{request.operator_email} is not an active staff user with the destroy permission")
    quiet_since = timezone.now() - quiet_window()
    refusal = _precondition_refusal(deployment, quiet_since=quiet_since, never_created=request.attest_never_created)
    if refusal:
        return Err(refusal)
    token = get_provider_token(deployment.provider)
    if token.is_err():
        return Err(f"Cannot read the provider token: {token.unwrap_err()}")
    api_token = token.unwrap()
    credential = provider_token_fingerprint(api_token)
    refusal = _request_refusal(request, deployment, credential)
    if refusal:
        return Err(refusal)
    provenance = "matched" if deployment.provider_token_fingerprint == credential else "attested"
    report = ReconcileReport(hostname=deployment.hostname, provenance=provenance)
    ssh_manager = get_ssh_key_manager()

    if request.dry_run:
        try:
            report.searched = _search_provider(deployment, api_token, ssh_manager) + _prove_dns_absent(deployment)
        except _RefusalError as found:
            return Err(str(found))
        return Ok(report)

    record: dict[str, Any] = {
        "operator": operator.email,
        "invoker": request.invoker,
        "at": timezone.now().isoformat(),
        "evidence": request.evidence,
        "provenance": provenance,
        "attested_no_resources": request.attest_no_resources,
        "never_created_attested": request.attest_never_created,
        "correlation_id": str(deployment.correlation_id),
        "credential_fingerprint": credential,
        "snapshot": {
            "status": deployment.status,
            "needs_reconciliation": deployment.needs_reconciliation,
            "external_node_id": deployment.external_node_id,
            "virtualmin_server_id": deployment.virtualmin_server_id,
            "dns_record_ids": deployment.dns_record_ids,
            "provider_token_fingerprint": deployment.provider_token_fingerprint,
            "server_create_state": deployment.server_create_state,
            "reconciliation_reason": deployment.reconciliation_reason,
        },
    }
    try:
        report.searched = _search_provider(deployment, api_token, ssh_manager) + _prove_dns_absent(deployment)
        record["searched"] = report.searched
        _claim_and_settle(deployment, quiet_since, record, operator, ssh_manager)
    except (_RefusalError, OperationOwnershipLostError) as refused:
        return _record_refusal(deployment, str(refused), operator, record)
    except Exception as error:  # An audit or database fault undoes the settlement; the row is left as it was.
        logger.exception(f"🔥 [Reconcile:{deployment.hostname}] Settlement failed: {error}")
        return _record_refusal(deployment, f"Settlement failed: {error}", operator, record)
    report.settled = True
    logger.info(f"✅ [Reconcile:{deployment.hostname}] Settled destroyed ({provenance})")
    if request.attest_never_created:
        # Costs recorded while the create outcome was unknown described a server attested never to have existed.
        from apps.infrastructure.cost_service import recalculate_recorded_costs  # noqa: PLC0415  # Deferred import

        try:
            recalculate_recorded_costs(Model.objects.get(pk=deployment.pk))
        except Exception as error:  # The settlement stands; the next recalculation of those periods corrects them.
            logger.warning(f"⚠️ [Reconcile:{deployment.hostname}] Cost records not recalculated: {error}")
    return Ok(report)
