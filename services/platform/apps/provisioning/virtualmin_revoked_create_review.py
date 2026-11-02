"""Verified operator release of a receipt-bound, uncertain native OFF."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.types import Err, Ok, Result

from .virtualmin_create_retry_policy import create_retry_policy
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from .virtualmin_revoked_create import RECEIPT_KEY, bound_receipt, off_source_id, receipt_off_id

if TYPE_CHECKING:
    from apps.users.models import User


@dataclass(frozen=True)
class OffReview:
    account: VirtualminAccount
    source: VirtualminProvisioningJob
    off: VirtualminProvisioningJob
    receipt: dict[str, object]

    def fingerprint(self) -> str:
        policy = create_retry_policy(self.account, self.source)
        payload = {
            "receipt": self.receipt,
            "source_status": self.source.status,
            "source_updated": self.source.updated_at.isoformat(),
            "off_status": self.off.status,
            "off_updated": self.off.updated_at.isoformat(),
            "policy": {
                "allowed": policy.allowed,
                "revoked": policy.revoked,
                "service_status": policy.service_status,
                "customer_held": policy.customer_held,
            },
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _review(job: VirtualminProvisioningJob) -> OffReview | None:
    source_id = off_source_id(job)
    if not source_id or not job.account_id or job.status != "attention":
        return None
    account = VirtualminAccount.objects.select_related("server").filter(pk=job.account_id).first()
    source = VirtualminProvisioningJob.objects.filter(pk=source_id, status="attention").first()
    if account is None or source is None:
        return None
    receipt = bound_receipt(source, account, job)
    return OffReview(account, source, job, receipt) if receipt is not None else None


def off_review_fingerprint(job: VirtualminProvisioningJob) -> str | None:
    review = _review(job)
    return review.fingerprint() if review is not None else None


def creation_review_off_id(job: VirtualminProvisioningJob) -> str | None:
    if job.operation != "create_domain" or not job.account_id:
        return None
    account = VirtualminAccount.objects.filter(pk=job.account_id).first()
    receipt = bound_receipt(job, account) if account is not None else None
    off_id = receipt_off_id(receipt) if receipt is not None else None
    off = VirtualminProvisioningJob.objects.filter(pk=off_id).first() if off_id else None
    return (
        str(off.pk)
        if off is not None and account is not None and bound_receipt(job, account, off) is not None
        else None
    )


def _staff_allowed(actor: User) -> bool:
    from apps.users.models import User  # noqa: PLC0415  # Fresh permission check after native I/O.

    current = User.objects.filter(pk=actor.pk, is_active=True).first()
    return current is not None and current.is_staff_user


def resolve_off_review(  # noqa: PLR0913  # Bind independent operator attestations and reviewed snapshot to the actor.
    job: VirtualminProvisioningJob,
    *,
    actor: User,
    reason: str,
    commands_stopped: bool,
    resource_confirmed: bool,
    fingerprint: str,
) -> Result[None, str]:
    """Read native proof outside locks, then recheck the exact operator-reviewed snapshot."""
    from .virtualmin_service import VirtualminProvisioningService  # noqa: PLC0415  # Native transport only.

    if not _staff_allowed(actor) or not reason.strip() or not commands_stopped or not resource_confirmed:
        return Err(_("A reason and both operator confirmations are required to release this OFF review."))
    current = VirtualminProvisioningJob.objects.get(pk=job.pk)
    preview = _review(current)
    if preview is None or not fingerprint or preview.fingerprint() != fingerprint:
        return Err(_("The recorded OFF resource changed. Reload and inspect the current review."))
    observed = (
        VirtualminProvisioningService(preview.account.server)._get_gateway().get_domain_state(preview.account.domain)
    )
    if observed.is_err():
        return Err(_("Native ownership and disabled state could not be verified. The hold remains."))
    state = observed.unwrap()
    if (
        state.get("exists") is not True
        or state.get("owner") != preview.account.virtualmin_username
        or state.get("enabled") is not False
    ):
        return Err(_("The exact recorded owner and disabled domain were not verified. The hold remains."))
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().get(pk=preview.account.pk)
        source = VirtualminProvisioningJob.objects.select_for_update().get(pk=preview.source.pk)
        off = VirtualminProvisioningJob.objects.select_for_update().get(pk=current.pk)
        receipt = bound_receipt(source, account, off)
        locked = OffReview(account, source, off, receipt) if receipt is not None else None
        if (
            source.status != "attention"
            or off.status != "attention"
            or receipt is None
            or locked is None
            or locked.fingerprint() != fingerprint
            or not _staff_allowed(actor)
        ):
            return Err(_("The OFF review or your authority changed during verification. The hold remains."))
        proof = {
            "actor_id": str(actor.pk),
            "reason": reason.strip(),
            "commands_stopped": True,
            "resource_confirmed": True,
            "verified_at": timezone.now().isoformat(),
        }
        # fsm-bypass: CharField status after native OFF proof and operator stopped confirmation.
        account.status = "suspended"
        account.status_message = _("Native OFF verified by an operator")
        account.save(update_fields=["status", "status_message", "updated_at"])
        VirtualminProvisioningJob.objects.filter(pk=off.pk, status="attention").update(
            status="failed",
            next_retry_at=None,
            updated_at=timezone.now(),  # fsm-bypass: Verified operator resolution.
            status_message=_("Native OFF verified; this operation will not replay"),
            result={**off.result, "verified_off_review": proof},
        )
        source.mark_attention(
            _("Created resource OFF verified; creation review remains"),
            {**source.result, RECEIPT_KEY: {**receipt, "phase": "disabled", "operator_review": proof}},
        )
        policy = create_retry_policy(account, source)
        if policy.allowed:
            from .virtualmin_tasks import reconcile_virtualmin_service_state_async  # noqa: PLC0415

            transaction.on_commit(
                lambda: reconcile_virtualmin_service_state_async(str(account.service_id)), robust=True
            )
    return Ok(None)


def resolve_creation_review(job: VirtualminProvisioningJob, *, actor: User, reason: str) -> Result[bool, str]:
    """A parent receipt cannot be acknowledged while its linked OFF owns the account."""
    if job.operation != "create_domain" or RECEIPT_KEY not in (job.result or {}):
        return Ok(False)
    if not job.account_id or not _staff_allowed(actor) or not reason.strip():
        return Err(_("Creation recovery requires an active staff reviewer and a reason."))
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update().get(pk=job.account_id)
        source = VirtualminProvisioningJob.objects.select_for_update().get(pk=job.pk)
        receipt = bound_receipt(source, account)
        off_id = receipt_off_id(receipt) if receipt is not None else None
        off = VirtualminProvisioningJob.objects.select_for_update().filter(pk=off_id).first() if off_id else None
        if (
            source.status != "attention"
            or receipt is None
            or off is None
            or bound_receipt(source, account, off) is None
        ):
            return Err(_("The creation recovery receipt needs investigation before resolution."))
        verified = off.status in ("completed", "failed") and receipt.get("phase") == "disabled"
        restored = (
            off.status == "failed"
            and receipt.get("phase") == "restored"
            and create_retry_policy(account, source).allowed
        )
        if not verified and not restored:
            return Err(_("Verify and resolve the linked OFF operation before acknowledging this creation."))
        VirtualminProvisioningJob.objects.filter(pk=source.pk, status="attention").update(
            status="failed",
            next_retry_at=None,
            updated_at=timezone.now(),  # fsm-bypass: Existing staff acknowledgement.
            status_message=_("Creation recovery reviewed: %(reason)s") % {"reason": reason.strip()},
        )
    return Ok(True)
