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
import uuid
from typing import TYPE_CHECKING, Any

from django.db import models, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result

from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)

ROLE_STANDALONE = "standalone"
ROLE_BASE = "base"
ROLE_DIFFERENTIAL = "differential"

_NO_SNAPSHOT = ("", "ABSENT")


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
    backup_id = str((base.result or {}).get("backup_id", ""))
    if not backup_id or (base.result or {}).get("fp_after") != locked.chain_base_fingerprint:
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
    if domain_id and token and not step_concluded and job.account is not None:
        stopped = VirtualminBackupService(job.server).run_chain_step(
            {
                "chain_action": "cancel",
                "chain_domain": job.account.domain,
                "chain_domain_id": domain_id,
                "chain_token": token,
                "chain_lock_wait_seconds": 30,
            },
            token=token,
            mode="cancel",
            domain_id=domain_id,
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
    return Ok(True)
