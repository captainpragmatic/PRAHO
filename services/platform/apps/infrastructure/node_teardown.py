"""One repeatable teardown for a node deployment, shared by destroy, the sweeps and compensation.

The claim and the workload guard run in one transaction, so a refused teardown changes nothing. After
that every step either proves its resources gone or stops with the row still ``destroying`` and every
identifier it has not proven gone kept, so the next run resumes where this one stopped:

  unregister -> withdraw DNS -> delete servers (confirmed) -> firewalls -> SSH keys -> clear identifiers
  -> revoke the vault key -> destroyed

DNS is withdrawn before any server is deleted, so no record ever points at a released address. Provider
"not found" answers count as proof only under the token that created the resources.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.cloud_gateway import get_cloud_gateway
from apps.infrastructure.deployment_lifecycle import (
    OperationLease,
    claim_operation,
    owned_transition,
    owned_update,
    provider_token_fingerprint,
    recorded_provider_resources,
)
from apps.infrastructure.server_lifetimes import close_server_lifetimes

if TYPE_CHECKING:
    from apps.infrastructure.cloud_gateway import CloudProviderGateway
    from apps.infrastructure.models import NodeDeployment
    from apps.users.models import User

logger = logging.getLogger(__name__)

DESTROYABLE_STATES = ("completed", "failed", "stopped")
# A teardown parked for reconciliation keeps "destroying"; Destroy resumes it (see claim_teardown).
PARKED_TEARDOWN_STATES = ("destroying",)
PROVENANCE_MISMATCH_REFUSAL = (
    "This deployment's provider resources were created with a different provider token; restore that token, "
    "then run Destroy again to resume the teardown"
)


# Job retriabilities that prove a create_domain did not take effect on the node (see Retriability).
_NOT_APPLIED = frozenset({"retriable", "not_retriable"})


def _never_reached_node(account: Any) -> list[tuple[Any, int]] | None:
    """The failed create jobs proving an "error" account never reached the node, or None when unproven.

    Conservative: it needs at least one create_domain job, every one of them failed or cancelled, and each
    failed one either refused before taking effect (a retriable or not-retriable failure) or rolled back
    successfully. An account that was ever provisioned, or has any other evidence, still counts (None).
    The failed jobs returned, as (id, retry_count), are the ones the guard must fence against a retry.
    """
    if account.status != "error" or account.provisioned_at is not None:
        return None
    jobs = list(account.provisioning_jobs.filter(operation="create_domain"))
    if not jobs:
        return None
    failed = []
    for job in jobs:
        if job.status == "cancelled":
            continue
        rolled_back = job.rollback_executed and job.rollback_status == "success"
        refused = (job.result or {}).get("retriability") in _NOT_APPLIED
        if job.status != "failed" or not (rolled_back or refused):
            return None
        failed.append((job.pk, job.retry_count))
    return failed


def _fence_create_retries(jobs: list[tuple[Any, int]]) -> bool:
    """Cancel exactly the failed create jobs the evidence relied on, as they were, so no retry runs them.

    A retry claims a failed job with a conditional update from "failed" that also counts the attempt; this
    fence matches the same id, "failed" and the attempt count the evidence saw, so a job retried since
    (even one that failed again with another outcome) is not cancelled. Returns False when any job
    changed: the node is then occupied.
    """
    from apps.provisioning.virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415  # Circular

    now = timezone.now()
    for job_id, retry_count in jobs:
        fenced = VirtualminProvisioningJob.objects.filter(pk=job_id, status="failed", retry_count=retry_count).update(
            status="cancelled", next_retry_at=None, updated_at=now
        )
        if fenced != 1:
            return False
    return True


def close_node_admission(virtualmin_server_id: Any, *, force: bool = False) -> Result[None, str]:
    """Under the server row lock admission takes: refuse while work lives there, else close the node.

    Every account that is not terminated still lives on the node, including one still provisioning,
    except an "error" account whose jobs prove it never reached the node; those jobs are fenced against
    a retry before the node closes. An in-flight migration touching the server (as source or target) has
    no local account row yet. A refusal writes nothing.
    """
    if not virtualmin_server_id:
        return Ok(None)
    from apps.provisioning.virtualmin_drain_service import server_has_active_migration  # noqa: PLC0415  # Circular
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # Circular: app registry

    occupied_message = "Node has undrained accounts; drain it or explicitly force"
    with transaction.atomic():
        server = VirtualminServer.objects.select_for_update().get(pk=virtualmin_server_id)
        evidence = [_never_reached_node(account) for account in server.accounts.exclude(status="terminated")]
        occupied = any(jobs is None for jobs in evidence)
        migrating = server_has_active_migration(server)
        if (occupied or migrating) and not force:
            return Err(
                "Node has an in-flight migration; resolve it or explicitly force" if migrating else occupied_message
            )
        if not force:
            observed = [job for jobs in evidence if jobs for job in jobs]
            if not _fence_create_retries(observed):
                transaction.set_rollback(True)  # a retry won: undo the jobs this fence already cancelled
                return Err(occupied_message)
        # fsm-bypass: VirtualminServer CharField; close admission before provider I/O.
        server.status, server.failed_by_health_check = "disabled", False
        server.save(update_fields=["status", "failed_by_health_check", "updated_at"])
    return Ok(None)


def deactivate_api_credential(deployment: NodeDeployment) -> int:
    """Deactivate the node's Virtualmin API credential, stored before the panel install.

    Unregistration deactivates it only for a registered node; a deploy that failed before registration
    still left it in the vault. Returns how many credentials were deactivated.
    """
    from apps.common.credential_vault import EncryptedCredential  # noqa: PLC0415  # Circular: cross-app

    count = EncryptedCredential.objects.filter(
        service_type="virtualmin", service_identifier=deployment.fqdn, is_active=True
    ).update(is_active=False, updated_at=timezone.now())
    if count:
        logger.info(f"🔐 [Teardown:{deployment.hostname}] Deactivated the Virtualmin API credential")
    return count


def claim_teardown(  # noqa: PLR0913  # One argument per claim condition
    deployment: NodeDeployment,
    *,
    kind: str,
    from_states: Iterable[str],
    stale_before: datetime | None = None,
    expected_token: uuid.UUID | None = None,
    credential_fingerprint: str | None = None,
) -> Result[OperationLease, str]:
    """Claim the row into ``destroying`` and close the node's admission, or change nothing.

    With ``credential_fingerprint`` (Destroy), a teardown parked for reconciliation in "destroying" is
    resumed: only when the token that created its resources is the current one again, or was never
    recorded (the teardown then deletes only what this token can see). The flag is cleared inside the
    claim; the guard and the teardown's own provenance checks run as for any destroy.
    """
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Deferred: avoids circular import

    with transaction.atomic():
        row = NodeDeployment.objects.select_for_update().get(pk=deployment.pk)
        resuming = credential_fingerprint is not None and row.status == "destroying" and row.needs_reconciliation
        if resuming:
            stored = row.provider_token_fingerprint
            if stored and stored != credential_fingerprint:
                return Err(PROVENANCE_MISMATCH_REFUSAL)
            from_states = (*from_states, *PARKED_TEARDOWN_STATES)
        claim = claim_operation(
            deployment.pk,
            from_states=from_states,
            to_status="destroying",
            kind=kind,
            stale_before=stale_before,
            expected_token=expected_token,
        )
        if claim.is_err():
            return claim
        if resuming:
            owned_update(claim.unwrap(), deployment, needs_reconciliation=False, reconciliation_reason="")

        server_id = NodeDeployment.objects.values_list("virtualmin_server_id", flat=True).get(pk=deployment.pk)
        guard = close_node_admission(server_id)
        if guard.is_err():
            transaction.set_rollback(True)  # the claim must not survive a refused guard
            return Err(guard.unwrap_err())
    return claim


class NodeTeardown:
    """The teardown steps, run only by the holder of ``lease``."""

    def __init__(  # noqa: PLR0913  # The teardown's collaborators, injected for its callers and tests.
        self,
        deployment: NodeDeployment,
        lease: OperationLease,
        *,
        api_token: str,
        ssh_manager: Any,
        registration: Any,
        user: User | None = None,
    ) -> None:
        self.deployment = deployment
        self.lease = lease
        self.api_token = api_token
        self.ssh_manager = ssh_manager
        self.registration = registration
        self.user = user
        # Set by the cloud step when it proved nothing remains: the row never reached the provider, or the
        # token that created its resources searched and deleted them. Re-deploy needs this proof.
        self.proved_absent = False

    def run(self) -> Result[bool, str]:
        from apps.infrastructure.deployment_service import NodeDeploymentService  # noqa: PLC0415  # Circular

        deployment = self.deployment
        if deployment.virtualmin_server_id:
            unregistered = self.registration.unregister_node(deployment=deployment, delete_server=True, user=self.user)
            if unregistered.is_err():
                return Err(f"Unregistration failed: {unregistered.unwrap_err()}")
        deactivate_api_credential(deployment)
        dns = NodeDeploymentService._delete_owned_dns(deployment, self.lease)
        if dns.is_err():
            return Err(f"DNS withdrawal incomplete: {dns.unwrap_err()}")
        cloud = self._delete_cloud_resources()
        if cloud.is_err():
            return cloud
        revoked = self.ssh_manager.delete_deployment_key(deployment, user=self.user)
        if revoked.is_err():
            return Err(f"SSH key revocation failed: {revoked.unwrap_err()}")
        proof = {"resources_proved_absent_for": deployment.correlation_id} if self.proved_absent else {}
        owned_transition(
            self.lease, deployment, "destroyed", "Node destroyed", release=True, destroyed_at=timezone.now(), **proof
        )
        return Ok(True)

    # -- Provider resources -------------------------------------------------

    def _may_hold_server(self) -> bool:
        return bool(self.deployment.external_node_id) or self.deployment.server_create_state in ("intent", "unknown")

    def _reconcile(self, reason: str) -> Result[bool, str]:
        owned_update(self.lease, self.deployment, needs_reconciliation=True, reconciliation_reason=reason)
        return Err(reason)

    def _delete_cloud_resources(self) -> Result[bool, str]:
        deployment = self.deployment
        # The fingerprint is recorded before the first provider write, so a key or firewall whose
        # create answer was lost is still discovered even when no server was ever requested.
        reached_provider = bool(deployment.provider_token_fingerprint) or self._may_hold_server()
        if not reached_provider and not self._recorded_firewall_ids():
            self.proved_absent = True
            return Ok(True)  # never reached the provider
        if not self.api_token:
            return Err("No provider API token for teardown")
        stored = deployment.provider_token_fingerprint
        trusted = bool(stored) and stored == provider_token_fingerprint(self.api_token)
        if stored and not trusted:
            return self._reconcile(PROVENANCE_MISMATCH_REFUSAL)

        gateway = get_cloud_gateway(deployment.provider.provider_type, self.api_token)
        servers = self._delete_servers(gateway, trusted=trusted)
        if servers.is_err():
            return servers
        # Every server is proved gone: its billable lifetimes end here.
        close_server_lifetimes(self.lease, deployment, external_node_id="", ipv4_address=None, ipv6_address=None)
        firewalls = self._delete_firewalls(gateway)
        if firewalls.is_err():
            return firewalls
        keys = self._delete_ssh_keys(gateway)
        self.proved_absent = keys.is_ok() and trusted
        return keys

    def _delete_servers(self, gateway: CloudProviderGateway, *, trusted: bool) -> Result[bool, str]:
        deployment = self.deployment
        found = gateway.find_servers_by_label(f"praho-deployment={deployment.correlation_id}")
        if found.is_err():
            return Err(f"Server discovery failed: {found.unwrap_err()}")
        ids = {info.server_id for info in found.unwrap()}
        if deployment.external_node_id:
            ids.add(deployment.external_node_id)
        if not trusted:
            # Unknown provenance: only a server this token can see proves it belongs here, and an
            # empty search proves nothing about an outcome that may have billed elsewhere.
            if not ids and deployment.server_create_state in ("intent", "unknown"):
                return self._reconcile("Server-create outcome unknown and provider token never recorded")
            for server_id in sorted(ids):
                seen = gateway.get_server(server_id)
                if seen.is_err():
                    return Err(f"Cannot verify server {server_id}: {seen.unwrap_err()}")
                if seen.unwrap() is None:
                    return self._reconcile(f"Server {server_id} not visible to this provider token")
        for server_id in sorted(ids):
            deleted = gateway.delete_server(server_id)
            if deleted.is_err():
                return Err(f"Server {server_id} deletion unconfirmed: {deleted.unwrap_err()}")
        return Ok(True)

    def _recorded_firewall_ids(self) -> list[str]:
        """Firewall ids recorded in the deployment log before firewalls were labelled for discovery."""
        return recorded_provider_resources(self.deployment)["firewall_ids"]

    def _delete_firewalls(self, gateway: CloudProviderGateway) -> Result[bool, str]:
        found = gateway.find_firewalls_by_label(f"deployment-id={self.deployment.correlation_id}")
        if found.is_err():
            return Err(f"Firewall discovery failed: {found.unwrap_err()}")
        for firewall_id in sorted({*found.unwrap(), *self._recorded_firewall_ids()}):
            deleted = gateway.delete_firewall(firewall_id)
            if deleted.is_err():
                return Err(f"Firewall {firewall_id} deletion failed: {deleted.unwrap_err()}")
        return Ok(True)

    def _delete_ssh_keys(self, gateway: CloudProviderGateway) -> Result[bool, str]:
        found = gateway.find_ssh_keys_by_label(f"praho-deployment={self.deployment.correlation_id}")
        if found.is_err():
            return Err(f"SSH key discovery failed: {found.unwrap_err()}")
        for key_id in found.unwrap():
            deleted = gateway.delete_ssh_key_by_id(key_id)
            if deleted.is_err():
                return Err(f"SSH key {key_id} deletion failed: {deleted.unwrap_err()}")
        # A key uploaded before keys were labelled is left in place: its name can collide with another
        # deployment's, and nothing here proves which one it is.
        return Ok(True)


def record_destroy_failure(deployment: NodeDeployment, error_msg: str, audit_ctx: Any = None) -> Result[bool, str]:
    """Record a refused or stopped teardown in the deployment log and the audit trail."""
    from apps.infrastructure.audit_service import InfrastructureAuditService  # noqa: PLC0415  # Circular
    from apps.infrastructure.models import NodeDeploymentLog  # noqa: PLC0415  # Deferred: avoids circular import

    logger.warning(f"⚠️ [Destroy:{deployment.hostname}] {error_msg}")
    NodeDeploymentLog.objects.create(deployment=deployment, level="ERROR", message=error_msg, phase="destroying")
    try:
        InfrastructureAuditService.log_destroy_failed(deployment, error_msg, audit_ctx)
    except Exception:
        logger.warning(f"⚠️ [Destroy:{deployment.hostname}] Failed to log audit: destroy failed")
    return Err(error_msg)


def run_claimed_teardown(  # noqa: PLR0913  # The teardown's collaborators, injectable for the service and tests.
    deployment: NodeDeployment,
    lease: OperationLease,
    api_token: str,
    *,
    ssh_manager: Any = None,
    registration: Any = None,
    user: User | None = None,
    audit_ctx: Any = None,
) -> Result[bool, str]:
    """Run the teardown for a claimed row; a stop leaves it destroying, logged and audited."""
    from apps.infrastructure.audit_service import InfrastructureAuditService  # noqa: PLC0415  # Circular
    from apps.infrastructure.deployment_lifecycle import OperationOwnershipLostError  # noqa: PLC0415
    from apps.infrastructure.models import NodeDeploymentLog  # noqa: PLC0415  # Deferred: avoids circular import
    from apps.infrastructure.registration_service import get_registration_service  # noqa: PLC0415  # Circular
    from apps.infrastructure.ssh_key_manager import get_ssh_key_manager  # noqa: PLC0415  # Circular

    try:
        InfrastructureAuditService.log_destroy_started(deployment, audit_ctx)
    except Exception:
        logger.warning(f"⚠️ [Destroy:{deployment.hostname}] Failed to log audit: destroy started")
    NodeDeploymentLog.objects.create(
        deployment=deployment, level="INFO", message="Starting node destruction", phase="destroying"
    )
    teardown = NodeTeardown(
        deployment,
        lease,
        api_token=api_token,
        ssh_manager=ssh_manager or get_ssh_key_manager(),
        registration=registration or get_registration_service(),
        user=user,
    )
    try:
        result = teardown.run()
    except OperationOwnershipLostError as lost:
        logger.warning(f"⚠️ [Destroy:{deployment.hostname}] Stopped without writing: {lost}")
        return Err(f"Destruction stopped: {lost}")
    except Exception as e:
        logger.exception(f"🔥 [Destroy:{deployment.hostname}] Destruction failed: {e}")
        result = Err(f"Destruction failed: {e}")
    if result.is_err():
        return record_destroy_failure(deployment, result.unwrap_err(), audit_ctx)

    NodeDeploymentLog.objects.create(
        deployment=deployment, level="INFO", message="Node destroyed successfully", phase="destroyed"
    )
    try:
        InfrastructureAuditService.log_destroy_completed(deployment, audit_ctx)
    except Exception:
        logger.warning(f"⚠️ [Destroy:{deployment.hostname}] Failed to log audit: destroy completed")
    logger.info(f"✅ [Destroy:{deployment.hostname}] Node destroyed")
    return Ok(True)


def teardown_stale_deployment(deployment: NodeDeployment, *, stale_before: datetime) -> Result[bool, str]:
    """The sweeps' and the cleanup command's entry: a failed or stranded row untouched since ``stale_before``.

    A row flagged for reconciliation is left to the operator: running it again proves nothing new.
    """
    from apps.infrastructure.provider_config import get_provider_token  # noqa: PLC0415  # Circular

    if deployment.needs_reconciliation:
        return Err(f"{deployment.hostname} needs reconciliation: {deployment.reconciliation_reason}")
    claim = claim_teardown(deployment, kind="teardown", from_states=("failed", "destroying"), stale_before=stale_before)
    if claim.is_err():
        return Err(f"Cannot start teardown for {deployment.hostname}: {claim.unwrap_err()}")
    lease = claim.unwrap()
    deployment.refresh_from_db()
    try:
        token_result = get_provider_token(deployment.provider)
        api_token = token_result.unwrap() if token_result.is_ok() else ""
    except Exception as e:  # A corrupt stored credential raises under fail-closed decryption (#346).
        return record_destroy_failure(deployment, f"Teardown provider token read raised: {type(e).__name__}")
    return run_claimed_teardown(deployment, lease, api_token)
