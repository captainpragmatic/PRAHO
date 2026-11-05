"""Phase intentions reuse the existing durable mail delivery and retry subsystem."""

from __future__ import annotations

import logging
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from apps.customers.services import get_customer_locale
from apps.notifications.services import EmailResult, EmailService, EmailSuppressionService
from apps.provisioning.hosting_limit_policy import HostingAssignmentTerms
from apps.provisioning.hosting_limit_selectors import hosting_limits_summary, prime_current_verification

from .invoice_models import Invoice
from .plan_change_lifecycle import _cancel_context
from .plan_change_models import PlanChange
from .plan_change_notice_models import PlanChangeNotice

if TYPE_CHECKING:
    from apps.customers.models import Customer


def publish_plan_change_notice(change: PlanChange, phase: str) -> PlanChangeNotice:
    if phase not in PlanChangeNotice.Phase.values:
        raise ValueError("Unknown plan-change notification phase")
    notice, _created = PlanChangeNotice.objects.get_or_create(change_id=change.pk, phase=phase)
    if _created:
        transaction.on_commit(lambda: _enqueue_notice(str(notice.pk)), robust=True)
    return notice


def _enqueue_notice(notice_id: str) -> None:
    from django_q.tasks import async_task  # noqa: PLC0415  # Durable row is published before broker I/O.

    async_task("apps.billing.plan_change_notices.process_plan_change_notice", notice_id)


def plan_change_for_document(
    *, proforma_id: UUID | str | int | None = None, invoice_id: UUID | str | int | None = None
) -> PlanChange | None:
    if invoice_id is not None:
        from .invoice_models import Invoice  # noqa: PLC0415  # Only non-null document identities may match.

        proforma_id = (
            Invoice.objects.filter(pk=str(invoice_id)).values_list("converted_from_proforma_id", flat=True).first()
        )
        query = Q(invoice_id=invoice_id)
        if proforma_id is not None:
            query |= Q(proforma_id=proforma_id)
        return PlanChange.objects.filter(query).first()
    if proforma_id is not None:
        return PlanChange.objects.filter(Q(proforma_id=proforma_id)).first()
    return None


def publish_document_notice(*, invoice_id: UUID | str | int, phase: str) -> bool:
    change = plan_change_for_document(invoice_id=invoice_id)
    if change is None:
        return False
    publish_plan_change_notice(change, phase)
    return True


OPERATIONAL_PHASES = frozenset({"scheduled", "completed", "attention"})
logger = logging.getLogger(__name__)


def dispatch_plan_change_notices(*, limit: int = 50) -> int:
    """Broker-loss/configuration recovery; transport retries retain their original EmailLog."""
    identifiers = list(
        PlanChangeNotice.objects.filter(state="pending", due_at__lte=timezone.now())
        .order_by("due_at", "pk")
        .values_list("pk", flat=True)[:limit]
    )
    linked = 0
    for identifier in identifiers:
        try:
            linked += int(process_plan_change_notice(identifier))
        except Exception:
            logger.exception("Plan-change phase processing failed: %s", identifier)
            # A failed render/link transaction has rolled back. This separate
            # technical backoff takes no financial locks and cannot send mail.
            with transaction.atomic():
                notice = PlanChangeNotice.objects.select_for_update(of=("self",)).get(pk=identifier)
                if notice.state == "pending":
                    notice.refusal_reason = "plan_change_notice_processing_failed"
                    notice.due_at = timezone.now() + timedelta(minutes=15)
                    notice.save(update_fields=["refusal_reason", "due_at", "updated_at"])
    return linked


def _allowance(amount: int, locale: str) -> str:
    if amount == 0:
        return "Nelimitat" if locale == "ro" else "Unlimited"
    value = format(Decimal(amount) / 1024, "f").rstrip("0").rstrip(".") if amount % 1024 else str(amount // 1024)
    return f"{value} GiB"


def plan_change_notice_context(change: PlanChange, customer: Customer) -> dict[str, Any]:
    """Only public purchased terms enter mail; native identity and headroom never do."""
    terms = HostingAssignmentTerms.from_snapshot(change.quote_snapshot.get("accepted_limits"))
    labels = change.quote_snapshot.get("labels", {})
    recurring = change.quote_snapshot["next_recurring"]
    locale = get_customer_locale(customer)
    return {
        "is_plan_change": True,
        "customer_name": customer.get_billing_name(),
        "target_plan_name": str(labels.get("to", "")),
        "disk_allowance": _allowance(terms.disk_allowance_mib, locale),
        "bandwidth_allowance": _allowance(terms.bandwidth_allowance_mib, locale),
        "next_recurring_amount": f"{Decimal(change.target_period_price_cents) / 100:.2f}",
        "next_recurring_total": f"{Decimal(recurring['total_cents']) / 100:.2f}",
        "next_recurring_tax": f"{Decimal(recurring['tax_cents']) / 100:.2f}",
        "currency": change.currency_id,
        "effective_date": timezone.localtime(change.effective_at).isoformat(),
        "plan_change_status": change.status,
    }


def _preference_allows(customer: Customer, phase: str) -> bool:
    from apps.notifications.models import EmailPreference  # noqa: PLC0415  # ADR-0007: runtime model.

    if phase not in OPERATIONAL_PHASES:
        return True  # The existing fiscal document pipeline owns its category policy.
    preference = EmailPreference.objects.filter(customer=customer).first() or EmailPreference(customer=customer)
    return preference.can_receive("service")


def _notice_invoice(change: PlanChange) -> Invoice | None:
    """Legal issuance can precede paid convergence and its immutable PC invoice binding."""
    if change.proforma_id is None:
        return None
    scope = (
        Q(pk=change.invoice_id) if change.invoice_id is not None else Q(converted_from_proforma_id=change.proforma_id)
    )
    invoices = list(Invoice.objects.filter(scope).order_by("pk")[:2])
    if len(invoices) != 1:
        return None
    invoice = invoices[0]
    if (
        invoice.converted_from_proforma_id != change.proforma_id
        or invoice.customer_id != change.customer_id
        or invoice.currency_id != change.currency_id
        or invoice.document_kind != "invoice"
        or (invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents)
        != (change.net_cents, change.tax_cents, change.total_cents)
    ):
        return None
    return invoice


def _fiscal_phase_refusal(change: PlanChange, phase: str) -> str | None:
    invoice = _notice_invoice(change)
    if invoice is None:
        return "plan_change_document_missing"
    if not invoice.number or invoice.status not in {"issued", "overdue", "paid"}:
        return "plan_change_document_not_issued"
    if phase == "payment_received" and invoice.status != "paid":
        return "plan_change_document_not_paid"
    return None


def notice_refusal(change: PlanChange, phase: str, customer: Customer) -> str | None:  # noqa: PLR0911 -- Separate current lifecycle, preference, phase and verification refusals.
    from apps.provisioning.models import Service, VirtualminAccount  # noqa: PLC0415  # ADR-0007: runtime model.

    service = Service.objects.select_related("hosting_limits").get(pk=change.service_id)
    if (
        customer.deleted_at is not None
        or customer.anonymized_at is not None
        or service.customer_id != change.customer_id
    ):
        return "plan_change_customer_unavailable"
    if not customer.primary_email:
        return "plan_change_recipient_missing"
    if not _preference_allows(customer, phase):
        return "plan_change_service_opt_out"
    if EmailSuppressionService.is_suppressed(customer.primary_email):
        return "plan_change_recipient_suppressed"
    if phase in {"invoice_issued", "payment_received"}:
        return _fiscal_phase_refusal(change, phase)
    states = {
        "proforma": {"awaiting_payment", "payment_in_flight"},
        "scheduled": {"scheduled"},
        "completed": {"completed"},
        "attention": {"limits_attention", "paid_review"},
    }
    if change.status not in states[phase]:
        return "plan_change_phase_obsolete"
    if phase == "proforma" and change.proforma_id is None:
        return "plan_change_document_missing"
    if phase == "completed":
        account = (
            VirtualminAccount.objects.filter(service_id=service.pk).select_related("server__hosting_policy").first()
        )
        prime_current_verification([service], {service.pk: account} if account is not None else {})
        application = change.limit_application
        if (
            application is None
            or application.revision != service.hosting_limits.revision
            or hosting_limits_summary(service)["state"] != "verified"
        ):
            return "plan_change_verification_changed"
    return None


def process_plan_change_notice(notice_id: UUID | str) -> bool:
    from apps.customers.models import Customer  # noqa: PLC0415  # ADR-0007: runtime model.

    hint = PlanChangeNotice.objects.get(pk=notice_id)
    with _cancel_context(hint.change_id) as change:
        notice = PlanChangeNotice.objects.select_for_update(of=("self",)).get(pk=notice_id)
        if notice.state != "pending":
            return notice.state == "linked"
        if notice.due_at > timezone.now():
            return False
        customer = Customer.all_objects.get(pk=change.customer_id)
        if reason := notice_refusal(change, notice.phase, customer):
            notice.state, notice.refusal_reason = "suppressed", reason
            notice.save(update_fields=["state", "refusal_reason", "updated_at"])
            return False
        result = _queue_notice(change, notice.phase, customer)
        if result.email_log_id:
            notice.email_log_id = UUID(result.email_log_id)
            notice.state, notice.refusal_reason = "linked", ""
        else:
            notice.refusal_reason = "plan_change_email_not_queued"
            notice.due_at = timezone.now() + timedelta(minutes=15)
        notice.save(update_fields=["email_log", "state", "refusal_reason", "due_at", "updated_at"])
        return notice.state == "linked"


def _queue_notice(change: PlanChange, phase: str, customer: Customer) -> EmailResult:
    context = plan_change_notice_context(change, customer)
    if phase == "proforma":
        from .proforma_service import queue_proforma_message  # noqa: PLC0415  # Existing PDF and message pipeline.

        return queue_proforma_message(change.proforma, customer.primary_email, customer=customer, context=context)
    if phase not in OPERATIONAL_PHASES:
        from .signals import _invoice_email_context  # noqa: PLC0415  # Preserve legal document fields and templates.

        invoice = _notice_invoice(change)
        if invoice is None:
            raise ValueError("The fiscal notification has no bound invoice")
        context = {**_invoice_email_context(invoice), **context}
    return EmailService.send_template_email(
        template_key=f"plan_change_{phase}" if phase in OPERATIONAL_PHASES else phase,
        recipient=customer.primary_email,
        context=context,
        locale=get_customer_locale(customer),
        customer=customer,
        async_send=True,
        require_async=True,
    )
