"""ANAF register evidence for a customer's Romanian CUI.

When a tax profile's CUI is saved, a task asks ANAF for the company and records its registered
name, VAT registration and status on the profile, with an audit event. ANAF is asked outside any
transaction; the answer is written under a row lock, and only while the profile still has the CUI
that was asked about. An unavailable or busy ANAF is asked again later (30 s, 2 min, 10 min, 1 h),
then the lookup is deferred: staff can ask again from the customer's page.

Only a Romanian operator looks companies up, and only while billing.anaf_lookup_enabled is on.
The evidence informs staff; it does not change invoicing.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.billing.config import anaf_lookup_enabled
from apps.billing.gateways.anaf_gateway import AnafGateway, transport_enabled
from apps.common.cui_validator import is_romanian_cui
from apps.common.operator import operator_is_romanian
from apps.customers.profile_models import CustomerTaxProfile

logger = logging.getLogger(__name__)

TASK = "apps.customers.anaf_verification.verify_tax_profile_with_anaf"
RETRY_DELAYS = (timedelta(seconds=30), timedelta(minutes=2), timedelta(minutes=10), timedelta(hours=1))


def lookups_enabled() -> bool:
    """A Romanian operator, with the setting on and ANAF reachable (never in development or tests)."""
    return operator_is_romanian() and anaf_lookup_enabled() and transport_enabled()


def schedule_lookup(tax_profile_id: str, *, attempt: int = 1, delay: timedelta | None = None) -> None:
    """Queue a lookup, now or after delay."""
    if delay is None:
        from django_q.tasks import async_task  # noqa: PLC0415  # Deferred: keeps the queue out of import time

        async_task(TASK, tax_profile_id, attempt)
        return
    from django_q.tasks import schedule  # noqa: PLC0415

    schedule(TASK, tax_profile_id, attempt, schedule_type="O", next_run=timezone.now() + delay)


def verify_tax_profile_with_anaf(tax_profile_id: str, attempt: int = 1) -> str:
    """Record ANAF's answer for the profile's CUI; returns what happened, for the task log."""
    if not lookups_enabled():
        return "disabled"
    profile = CustomerTaxProfile.objects.filter(pk=tax_profile_id).only("cui", "customer_id").first()
    if profile is None or not is_romanian_cui(profile.cui):
        return "skipped"
    cui = profile.cui

    answer = AnafGateway.lookup([cui])
    if not answer.api_available:
        if attempt <= len(RETRY_DELAYS):
            schedule_lookup(tax_profile_id, attempt=attempt + 1, delay=RETRY_DELAYS[attempt - 1])
            return "rescheduled"
        _audit(profile, "anaf_lookup_deferred", "ANAF lookup deferred: ANAF did not answer", {"cui": cui})
        return "deferred"

    company = answer.companies.get(cui)
    with transaction.atomic():
        locked = CustomerTaxProfile.objects.select_for_update().filter(pk=tax_profile_id).first()
        if locked is None or locked.cui != cui:
            return "stale"  # The CUI changed meanwhile: its own lookup records its own evidence.
        Status = CustomerTaxProfile.AnafStatus  # noqa: N806
        locked.anaf_status = (Status.ACTIVE if company.active else Status.INACTIVE) if company else Status.NOT_FOUND
        locked.anaf_verified_name = company.name if company else ""
        locked.anaf_vat_registered = company.vat_registered if company else None
        locked.anaf_verified_at = timezone.now()
        locked.save(
            update_fields=["anaf_status", "anaf_verified_name", "anaf_vat_registered", "anaf_verified_at", "updated_at"]
        )
        _audit(
            locked,
            "anaf_lookup_completed",
            f"ANAF lookup: {locked.anaf_status}",
            {
                "cui": cui,
                "status": locked.anaf_status,
                "name": locked.anaf_verified_name,
                "vat_registered": locked.anaf_vat_registered,
                "registration_number": company.registration_number if company else "",
            },
        )
    logger.info("✅ [ANAF] Tax profile %s: %s", tax_profile_id, locked.anaf_status)
    return str(locked.anaf_status)


def _audit(profile: CustomerTaxProfile, event_type: str, description: str, metadata: dict[str, object]) -> None:
    from apps.audit.services import AuditService  # noqa: PLC0415  # ADR-0007: cross-app service at call time

    AuditService.log_simple_event(
        event_type,
        content_object=profile,
        actor_type="system",
        description=description,
        metadata={**metadata, "customer_id": str(profile.customer_id)},
    )
