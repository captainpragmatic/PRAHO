"""Receipt-bound OFF recovery for a create whose hosting intent was revoked."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from django.db import transaction
from django.utils import timezone
from django_q.tasks import async_task

from apps.common.types import Err, Ok, Result, Retriability

from .virtualmin_create_retry_policy import create_retry_policy
from .virtualmin_migration_models import account_has_active_operation
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

if TYPE_CHECKING:
    from .virtualmin_create_retry_policy import CreateRetryPolicy

OFF_SOURCE_KEY = "revoked_create_job_id"
RECEIPT_KEY = "revoked_creation"


@dataclass(frozen=True)
class OffClaim:
    job_id: UUID
    claimed_at: datetime
    started_at: datetime


def owns_off_claim(claim: OffClaim) -> bool:
    return VirtualminProvisioningJob.objects.filter(
        pk=claim.job_id,
        status="running",
        claimed_at=claim.claimed_at,
        started_at=claim.started_at,
    ).exists()


def off_claim(job: VirtualminProvisioningJob) -> OffClaim | None:
    if job.status != "running" or job.claimed_at is None or job.started_at is None:
        return None
    claim = OffClaim(job.pk, job.claimed_at, job.started_at)
    return claim if owns_off_claim(claim) else None


def off_source_id(job: VirtualminProvisioningJob) -> str | None:
    if job.operation != "suspend_domain":
        return None
    value = (job.parameters or {}).get(OFF_SOURCE_KEY)
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


def receipt_off_id(receipt: dict[str, object]) -> UUID | None:
    value = receipt.get("off_job_id")
    if not isinstance(value, str):
        return None
    try:
        return UUID(value)
    except ValueError:
        return None


def bound_receipt(
    source: VirtualminProvisioningJob, account: VirtualminAccount, off: VirtualminProvisioningJob | None = None
) -> dict[str, object] | None:
    receipt = (source.result or {}).get(RECEIPT_KEY)
    if not isinstance(receipt, dict):
        return None
    expected = {
        "version": 1,
        "source_job_id": str(source.pk),
        "account_id": str(account.pk),
        "service_id": account.service_id,
        "server_id": str(account.server_id),
        "domain": account.domain,
        "owner": account.virtualmin_username,
    }
    if (
        source.operation != "create_domain"
        or source.account_id != account.pk
        or source.server_id != account.server_id
        or any(
            type(receipt.get(key)) is not type(value) or receipt.get(key) != value for key, value in expected.items()
        )
        or receipt.get("native_outcome") not in ("created", "adopted")
        or (
            off is not None
            and (
                off.account_id != account.pk
                or off.server_id != account.server_id
                or receipt.get("off_job_id") != str(off.pk)
                or off_source_id(off) != str(source.pk)
            )
        )
    ):
        return None
    return receipt


def off_authority(
    job: VirtualminProvisioningJob, account: VirtualminAccount
) -> tuple[VirtualminProvisioningJob, dict[str, object], CreateRetryPolicy] | None:
    source_id = off_source_id(job)
    source = VirtualminProvisioningJob.objects.filter(pk=source_id).first() if source_id else None
    if source is None or source.status != "attention":
        return None
    receipt = bound_receipt(source, account, job)
    if receipt is None:
        return None
    policy = create_retry_policy(account, source)
    return source, receipt, policy


def receipt_off_can_retry(job: VirtualminProvisioningJob) -> bool:
    """Only an unfinished known-retriable recovery may be explicitly rearmed."""
    account = VirtualminAccount.objects.filter(pk=job.account_id).first() if job.account_id else None
    authority = off_authority(job, account) if account is not None else None
    return (
        authority is not None
        and authority[1].get("phase") == "pending"
        and "verified_off_review" not in (job.result or {})
    )


def retire_closed_off_claim(job: VirtualminProvisioningJob, *, claim: OffClaim | None = None) -> Result[bool, str]:
    """Discard this exact pending/running delivery when its receipt is already closed.

    Staff eligibility can become stale before its due-date write. Retirement is
    therefore enforced again by consumers and exhausted unissued recovery. It
    changes no source evidence, resource state or consumed attempt count.
    """
    source_id = off_source_id(job)
    if not source_id or not job.account_id:
        return Ok(False)
    expected = (
        ("running", claim.claimed_at, claim.started_at)
        if claim is not None
        else (job.status, job.claimed_at, job.started_at)
    )
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().get(pk=job.account_id)
        source = VirtualminProvisioningJob.objects.select_for_update().filter(pk=source_id).first()
        current = VirtualminProvisioningJob.objects.select_for_update().get(pk=job.pk)
        receipt = bound_receipt(source, account, current) if source is not None else None
        if receipt is None or receipt.get("phase") not in ("disabled", "restored"):
            return Ok(False)
        if (
            expected[0] not in ("pending", "running")
            or (current.status, current.claimed_at, current.started_at) != expected
            or (claim is not None and claim.job_id != current.pk)
        ):
            return Err("Closed receipt delivery no longer owns its claim")
        current.mark_failed(
            "Recovery receipt already closed; delivery retired without native work",
            dict(current.result or {}),
            retriability=Retriability.NOT_RETRIABLE,
        )
    return Ok(True)


def queue_revoked_create_off(
    account_id: UUID, source_id: UUID, *, native_outcome: Literal["created", "adopted"]
) -> Result[str, str]:
    """Publish at most one normal nonce-claimed OFF job; never run native I/O here."""
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().get(pk=account_id)
        source = VirtualminProvisioningJob.objects.select_for_update().get(pk=source_id)
        existing = bound_receipt(source, account)
        if existing is not None and "off_job_id" in existing:
            existing_id = receipt_off_id(existing)
            off = VirtualminProvisioningJob.objects.filter(pk=existing_id).first() if existing_id else None
            return (
                Ok(str(off.pk))
                if off is not None and bound_receipt(source, account, off)
                else Err("OFF receipt linkage changed")
            )
        if (
            source.operation != "create_domain"
            or source.account_id != account.pk
            or source.server_id != account.server_id
            or source.status != "completed"
        ):
            return Err("Only a verified completed creation may publish its OFF recovery")
        policy = create_retry_policy(account, source)
        if policy.allowed:
            return Err("Hosting intent was restored before OFF publication")
        if not policy.revoked:
            source.mark_attention("Creation provenance needs review; no automatic OFF authority was granted")
            return Err("Unknown creation provenance is not automatic OFF authority")
        receipt: dict[str, object] = {
            "version": 1,
            "source_job_id": str(source.pk),
            "account_id": str(account.pk),
            "service_id": account.service_id,
            "server_id": str(account.server_id),
            "domain": account.domain,
            "owner": account.virtualmin_username,
            "native_outcome": native_outcome,
            "service_status": policy.service_status,
            "customer_held": policy.customer_held,
            "phase": "pending",
        }
        if account_has_active_operation(account, ignore_job_id=source.pk):
            source.mark_attention(
                "Created resource needs OFF review; another operation owns the account",
                {**source.result, RECEIPT_KEY: {**receipt, "phase": "blocked"}},
            )
            return Err("Another operation owns the account; OFF recovery was not issued")
        claimed_at = timezone.now()
        off = VirtualminProvisioningJob(
            operation="suspend_domain",
            account=account,
            server_id=account.server_id,
            parameters={
                "domain": account.domain,
                "reason": "Hosting intent revoked during creation",
                OFF_SOURCE_KEY: str(source.pk),
                "task_budget_seconds": source.parameters.get("task_budget_seconds", 900),
            },
            correlation_id=f"revoked_create_off_{source.pk}",
            claimed_at=claimed_at,
        )
        off.save()
        receipt["off_job_id"] = str(off.pk)
        source.mark_attention(
            "Created resource awaits receipt-bound OFF verification; creation will not replay",
            {**source.result, RECEIPT_KEY: receipt},
        )
        transaction.on_commit(
            lambda: _publish_off(str(off.pk), claimed_at.isoformat(), int(off.parameters["task_budget_seconds"])),
            robust=True,
        )
        return Ok(str(off.pk))


def _publish_off(job_id: str, nonce: str, timeout: int) -> None:
    task_id = async_task(
        "apps.provisioning.virtualmin_tasks.retry_virtualmin_job", job_id, nonce, timeout=timeout, sync=False
    )
    VirtualminProvisioningJob.record_dispatch(job_id, task_id)


def settle_off(
    job: VirtualminProvisioningJob,
    claim: OffClaim,
    *,
    phase: Literal["disabled", "uncertain", "restored", "pending", "refused"],
    message: str = "",
    data: dict[str, object] | None = None,
) -> bool:
    """Settle the exact normal claim and its source atomically, never resurrecting either."""
    source_id = off_source_id(job)
    if not source_id or not job.account_id:
        return False
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().get(pk=job.account_id)
        source = VirtualminProvisioningJob.objects.select_for_update().get(pk=source_id)
        current = VirtualminProvisioningJob.objects.select_for_update().get(pk=job.pk)
        receipt = bound_receipt(source, account, current)
        if (
            source.status != "attention"
            or receipt is None
            or current.status != "running"
            or current.claimed_at != claim.claimed_at
            or current.started_at != claim.started_at
            or current.pk != claim.job_id
        ):
            return False
        if phase == "disabled":
            account.status = "suspended"  # fsm-bypass: Exact native OFF accepted or freshly observed.
            account.status_message = "Receipt-bound creation recovery verified OFF"
            account.save(update_fields=["status", "status_message", "updated_at"])
            current.mark_completed(dict(data or {}))
        elif phase in ("uncertain", "refused") or (phase == "pending" and current.retry_count >= current.max_retries):
            current.mark_attention(
                message or "Receipt-bound OFF needs operator verification", {**current.result, **dict(data or {})}
            )
        else:
            current.mark_failed(
                message or "OFF intent superseded",
                {**current.result, **dict(data or {})},
                retriability=Retriability.RETRIABLE if phase == "pending" else Retriability.NOT_RETRIABLE,
            )
        source.mark_attention(
            "Created resource OFF verified; operator review remains"
            if phase == "disabled"
            else f"Created resource OFF outcome: {phase}; operator review required",
            {**source.result, RECEIPT_KEY: {**receipt, "phase": phase}},
        )
        return True
