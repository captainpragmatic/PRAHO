"""Differential-chain state transitions (docs/domain/virtualmin-incremental-contract.md).

Virtualmin keeps ONE differential snapshot per domain. PRAHO's view of it lives on the
account row: ``chain_base`` (the base backup job whose snapshot is still on the node),
``chain_base_fingerprint`` and ``chain_epoch``. The rules, in the order they act:

1. Invalidate first. Admission of anything that can reset or lose the snapshot (a restore,
   a new base, a migration, a delete) clears the chain and bumps the epoch in the same
   transaction that creates its job, before any dispatch.
2. A base is linked only after its archive and manifest are published, by one transaction
   fenced by the job's execution token and the epoch it was admitted at, and only when the
   node step showed a fresh snapshot (fp_after present and different from fp_before).
3. A differential is pinned at admission to the base, fingerprint and epoch it extends, and
   re-checks them right before dispatch and again in its completion transaction.
4. Evidence from the node (a fingerprint mismatch, a snapshot a differential moved) ends the
   live chain, fenced by epoch so an older job can never clear a newer chain.

Callers that mutate chain state hold the account row lock (``select_for_update``).
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import TYPE_CHECKING, Any

from django.db import models, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

ROLE_STANDALONE = "standalone"
ROLE_BASE = "base"
ROLE_DIFFERENTIAL = "differential"

_NO_SNAPSHOT = ("", "ABSENT")

# The input alphabets of the node step. The playbook asserts them and the node script
# re-validates them before touching anything; a value either rejects is refused here, in
# Python, before dispatch, so a bad domain can never park a job as "uncertain" for an input
# error. A test pins that all three copies are the same strings.
CHAIN_DOMAIN_PATTERN = r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
CHAIN_DOMAIN_ID_PATTERN = r"^[0-9]{1,30}$"
CHAIN_RUN_ID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
CHAIN_ARCHIVE_PATTERN = r"^virtualmin_backup_[0-9a-f]{32}\.tar\.gz$"
# A differential needs a real snapshot: ABSENT is never an acceptable expectation.
CHAIN_EXPECTED_FP_PATTERN = r"^[0-9a-f]{64}:[0-9]+$"
CHAIN_ROLES_ON_NODE = ("base", "differential")


def is_chain_domain(value: object) -> bool:
    """True when ``value`` is a domain name the node step accepts."""
    return isinstance(value, str) and re.fullmatch(CHAIN_DOMAIN_PATTERN, value) is not None


def chain_step_input_error(variables: Mapping[str, Any]) -> str | None:
    """Why the node step would refuse these playbook variables, or None when it would accept them."""
    checks: list[tuple[str, str]] = [
        ("chain_domain", CHAIN_DOMAIN_PATTERN),
        ("chain_domain_id", CHAIN_DOMAIN_ID_PATTERN),
        ("chain_token", CHAIN_RUN_ID_PATTERN),
    ]
    action = variables.get("chain_action")
    if action not in ("run", "cancel"):
        return f"Unknown chain action {action!r}"
    if action == "run":
        checks.append(("chain_archive", CHAIN_ARCHIVE_PATTERN))
        if variables.get("chain_mode") not in CHAIN_ROLES_ON_NODE:
            return f"Unknown chain mode {variables.get('chain_mode')!r}"
        if variables.get("chain_mode") == ROLE_DIFFERENTIAL:
            checks.append(("chain_expected_fp", CHAIN_EXPECTED_FP_PATTERN))
    for name, pattern in checks:
        value = variables.get(name)
        if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
            return f"The chain step input {name} is not acceptable to the node"
    return None


def invalidate_chain(locked: VirtualminAccount) -> int:
    """Clear the live chain and bump the epoch. The caller holds the account row lock.

    Returns the new epoch. The in-memory account is updated to match.
    """
    VirtualminAccount.objects.filter(pk=locked.pk).update(
        chain_base=None, chain_base_fingerprint="", chain_epoch=models.F("chain_epoch") + 1
    )
    locked.chain_base = None
    locked.chain_base_fingerprint = ""
    locked.chain_epoch += 1
    logger.info("✅ [Chain] Invalidated chain: account=%s epoch=%s", locked.pk, locked.chain_epoch)
    return locked.chain_epoch


def invalidate_chain_if_epoch(account_id: Any, epoch: int) -> int:
    """Evidence-driven invalidation, fenced: only the chain this job was pinned to is cleared."""
    rows = VirtualminAccount.objects.filter(pk=account_id, chain_epoch=epoch).update(
        chain_base=None, chain_base_fingerprint="", chain_epoch=models.F("chain_epoch") + 1
    )
    if rows:
        logger.warning("⚠️ [Chain] Node evidence ended the chain: account=%s epoch=%s", account_id, epoch)
    return rows


def base_backup_id(account: VirtualminAccount) -> str:
    """The backup id a differential would be taken against, or "" when the base left no usable evidence.

    The live base must have recorded both its backup id and the fingerprint of the snapshot it left,
    and that fingerprint must be the one the account pins. Admission and the scheduler ask the same
    question, so a differential the admission would refuse is never scheduled.
    """
    base = account.chain_base
    if base is None or not account.chain_base_fingerprint:
        return ""
    result = base.result or {}
    backup_id = str(result.get("backup_id", ""))
    if not backup_id or result.get("fp_after") != account.chain_base_fingerprint:
        return ""
    return backup_id


def admit_chain_role(locked: VirtualminAccount, role: str) -> Result[dict[str, object], str]:
    """The pins a base or differential job is admitted with; invalidates first for a base.

    Runs inside the admission transaction, after the exclusion check, with the account locked.
    """
    token = str(uuid.uuid4())
    if role == ROLE_BASE:
        return Ok({"chain_token": token, "chain_epoch": invalidate_chain(locked)})
    base = locked.chain_base
    if base is None or not locked.chain_base_fingerprint:
        return Err("This account has no live base backup; take a base backup first")
    backup_id = base_backup_id(locked)
    if not backup_id:
        return Err("The base backup left no usable evidence for its snapshot; take a new base backup")
    return Ok(
        {
            "chain_token": token,
            "chain_epoch": locked.chain_epoch,
            "base_job_id": str(base.pk),
            "base_backup_id": backup_id,
            "expected_fp": locked.chain_base_fingerprint,
        }
    )


def pins_hold(account: Mapping[str, Any], role: str, parameters: Mapping[str, Any]) -> bool:
    """True when the account's chain still matches what a job was admitted against.

    ``account`` carries chain_epoch, chain_base_id and chain_base_fingerprint.
    """
    if account["chain_epoch"] != int(parameters.get("chain_epoch", -1)):
        return False
    if role == ROLE_BASE:
        return account["chain_base_id"] is None
    return (
        account["chain_base_id"] is not None
        and str(account["chain_base_id"]) == str(parameters.get("base_job_id"))
        and account["chain_base_fingerprint"] == parameters.get("expected_fp")
    )


CHAIN_STATE_INTACT = "intact"
CHAIN_STATE_MOVED = "moved"


def chain_state_after_failure(job: VirtualminProvisioningJob) -> str:
    """Whether a failed chain job left the account's chain as it found it.

    ``intact``: the chain still matches the pins the job was admitted against, so the failure was
    operational (the node was busy, a metadata read failed) and says nothing about the snapshot.
    ``moved``: the chain no longer matches, because the node's evidence ended it (the snapshot was
    absent or different) or something else invalidated it while the job ran. The scheduler counts
    only ``intact`` failures toward its backoff and its alert, and decides what to take next from
    the chain itself.
    """
    if job.account_id is None:
        return CHAIN_STATE_MOVED
    state = (
        VirtualminAccount.objects.filter(pk=job.account_id)
        .values("chain_epoch", "chain_base_id", "chain_base_fingerprint")
        .first()
    )
    parameters = job.parameters or {}
    role = str(parameters.get("chain_role", ROLE_STANDALONE))
    if state is None or not pins_hold(state, role, parameters):
        return CHAIN_STATE_MOVED
    return CHAIN_STATE_INTACT


def complete_chain_job(job: VirtualminProvisioningJob, token: Any, result: dict[str, Any]) -> str:
    """Link a base (or just complete a differential) and finish the job, in one transaction.

    Returns "completed", "attention" (the archive is published, but the chain it would join
    moved or the node showed no fresh snapshot, so nothing is linked and the exclusion stays
    until an operator resolves it) or "superseded" (this runner no longer owns the job; nothing
    was written).
    """
    if job.account_id is None:
        return "superseded"
    parameters = job.parameters or {}
    role = str(parameters.get("chain_role", ROLE_STANDALONE))
    with transaction.atomic():
        locked = VirtualminAccount.objects.select_for_update().get(pk=job.account_id)
        if not VirtualminProvisioningJob.objects.filter(pk=job.pk, execution_token=token, status="running").exists():
            return "superseded"
        state = {
            "chain_epoch": locked.chain_epoch,
            "chain_base_id": locked.chain_base_id,
            "chain_base_fingerprint": locked.chain_base_fingerprint,
        }
        problem = ""
        if not pins_hold(state, role, parameters):
            problem = "The chain changed while this backup ran; the archive is published but not linked"
        elif role == ROLE_BASE:
            fp_before, fp_after = str(result.get("fp_before", "")), str(result.get("fp_after", ""))
            if fp_after in _NO_SNAPSHOT or fp_after == fp_before:
                problem = "The node showed no fresh snapshot after the base; the archive is not linked"
        if problem:
            rows = VirtualminProvisioningJob.finish_execution(job.pk, token, "attention", problem, result)
            if not rows:
                transaction.set_rollback(True)
                return "superseded"
            return "attention"
        if role == ROLE_BASE:
            locked.chain_base_id = job.pk
            locked.chain_base_fingerprint = str(result["fp_after"])
            locked.save(update_fields=["chain_base", "chain_base_fingerprint", "updated_at"])
        rows = VirtualminProvisioningJob.finish_execution(job.pk, token, "completed", "", result)
        if not rows:
            # The link above must not outlive a job we no longer own.
            transaction.set_rollback(True)
            return "superseded"
    return "completed"


def is_chain_job(operation: str, parameters: Mapping[str, Any]) -> bool:
    """True for a base or differential backup job: remotely mutating, never read-only."""
    return operation == "backup_domain" and str(parameters.get("chain_role", ROLE_STANDALONE)) != ROLE_STANDALONE


def resolve_chain_job(job: VirtualminProvisioningJob, *, resolved_by: str, note: str) -> Result[bool, str]:
    """Operator "confirm stopped" for a chain job parked in attention.

    In this order: the job's cancel marker is written on the node under the per-domain lock
    (a delayed or waiting run of that token can then never start), the chain is invalidated,
    and only then is the account released, the last two in one transaction. If the marker
    cannot be written, nothing changes and the account stays held. A step is dispatched only
    after its domain id reached the job row (and while the job was still owned), so a job without
    one never started a step; one whose step already concluded has nothing left to cancel.
    Neither needs the node.
    """
    from .virtualmin_backup_service import VirtualminBackupService  # noqa: PLC0415  # Circular

    if job.account_id is None:
        return Err("The job has no account")
    parameters = job.parameters or {}
    domain_id = str(parameters.get("virtualmin_domain_id", ""))
    token = str(parameters.get("chain_token", ""))
    step_concluded = bool((job.result or {}).get("fp_after"))
    cancel_variables = {
        "chain_action": "cancel",
        "chain_domain": job.account.domain if job.account is not None else "",
        "chain_domain_id": domain_id,
        "chain_token": token,
        "chain_lock_wait_seconds": 30,
    }
    # Inputs the node refuses were refused by dispatch too, so no step of that job ever ran.
    if domain_id and token and not step_concluded and chain_step_input_error(cancel_variables) is None:
        stopped = VirtualminBackupService(job.server).run_chain_step(
            cancel_variables, token=token, mode="cancel", domain_id=domain_id
        )
        if stopped.is_err() or stopped.unwrap().outcome != "cancelled":
            detail = stopped.unwrap_err() if stopped.is_err() else stopped.unwrap().reason
            return Err(f"Could not confirm the node step is stopped ({detail}); the account stays held")
    with transaction.atomic():
        locked = VirtualminAccount.objects.select_for_update().get(pk=job.account_id)
        rows = VirtualminProvisioningJob.objects.filter(
            pk=job.pk, status="attention"
        ).update(  # fsm-bypass: CharField job status; attention -> failed is the only edge
            status="failed",
            status_message=f"Manually resolved by {resolved_by}: {note}",
            next_retry_at=None,
            updated_at=timezone.now(),
        )
        if not rows:
            transaction.set_rollback(True)
            return Err("Only a job awaiting attention can be resolved.")
        invalidate_chain(locked)
    # The cancel marker is on the node, so the step can never start again: whatever it left
    # staged (the archive and its .dom sidecar with database passwords) can go.
    remove_stranded_archive(job)
    return Ok(True)


def remove_stranded_archive(job: VirtualminProvisioningJob) -> str:
    """Remove the archive a stopped chain step may have left staged; returns a warning or "".

    A cleanup failure never holds the account: it is logged and appended to the job's message
    for the operator, because the staged files then still need removing by hand.
    """
    from .virtualmin_backup_service import VirtualminBackupService  # noqa: PLC0415  # Circular

    archive_name = str((job.parameters or {}).get("archive_name", ""))
    if not archive_name:
        return ""
    removed = VirtualminBackupService(job.server).remove_staged_archive(archive_name)
    if removed.is_ok():
        logger.info("✅ [Chain] Removed stranded archive %s for job %s", archive_name, job.pk)
        return ""
    warning = f"staged archive cleanup failed for {archive_name}: {removed.unwrap_err()}"
    logger.warning("⚠️ [Chain] %s (job %s)", warning, job.pk)
    message = VirtualminProvisioningJob.objects.filter(pk=job.pk).values_list("status_message", flat=True).first() or ""
    VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
        status_message=f"{message} ({warning})".strip(), updated_at=timezone.now()
    )
    return warning


def deployment_destroyed(server: VirtualminServer) -> bool:
    deployment = getattr(server, "node_deployment", None)
    return bool(deployment is not None and deployment.is_destroyed)


def node_lost_refusal(server: VirtualminServer) -> str | None:
    """Why this node may NOT be declared lost, or None when it may.

    A node is lost when PRAHO has itself marked its server failed, or its deployment has been
    destroyed (decommissioned). Any other state means the node may still be running the step,
    and only "confirm stopped" (which proves it with a cancel marker) can release the job.
    """
    if server.status == "failed" or deployment_destroyed(server):
        return None
    return "The node is not marked failed or decommissioned; confirm the step stopped instead"


def resolve_chain_job_node_lost(job: VirtualminProvisioningJob, *, resolved_by: str, note: str) -> Result[bool, str]:
    """Operator "node lost" for a chain job in attention whose node can no longer be reached.

    "Confirm stopped" needs the node to write a cancel marker, which a lost node cannot. This
    path is allowed only while the job's server is failed or its deployment destroyed. In one
    transaction under the account lock it fails the job, ROTATES the job's execution token
    (a late runner that comes back can no longer publish or link anything) and invalidates the
    chain, so a base or differential made later starts from a fresh epoch.
    """
    if job.account_id is None:
        return Err("The job has no account")
    if not is_chain_job(job.operation, job.parameters or {}):
        return Err("Only a base or differential backup can be resolved as node lost")
    with transaction.atomic():
        locked = VirtualminAccount.objects.select_for_update().get(pk=job.account_id)
        server = VirtualminServer.objects.select_related("node_deployment").get(pk=job.server_id)
        refusal = node_lost_refusal(server)
        if refusal is not None:
            transaction.set_rollback(True)
            return Err(refusal)
        rows = VirtualminProvisioningJob.objects.filter(
            pk=job.pk, status="attention"
        ).update(  # fsm-bypass: CharField job status; attention -> failed is the only edge
            status="failed",
            status_message=f"Node lost; resolved by {resolved_by}: {note}",
            execution_token=uuid.uuid4(),
            next_retry_at=None,
            updated_at=timezone.now(),
        )
        if not rows:
            transaction.set_rollback(True)
            return Err("Only a job awaiting attention can be resolved.")
        invalidate_chain(locked)
    logger.warning("⚠️ [Chain] Node declared lost: job=%s server=%s by=%s", job.pk, job.server_id, resolved_by)
    # If the node is still reachable (a failed health check is not proof it is gone) its staging
    # is cleaned in the background; the request never waits on a node declared lost.
    if (job.parameters or {}).get("archive_name") and not deployment_destroyed(server):
        from django_q.tasks import async_task  # noqa: PLC0415

        async_task("apps.provisioning.virtualmin_tasks.remove_chain_job_archive", str(job.pk))
    return Ok(True)
