"""Required invoice consumer for standalone paid plan changes, before cycle convergence."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.promotions.renewals import end_locked_benefit
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.hosting_limit_policy import HostingAssignmentTerms

from .invoice_models import Invoice
from .plan_change_coverage import invoice_has_paid_coverage, load_plan_coverage
from .plan_change_models import PlanChange
from .subscription_models import Subscription

if TYPE_CHECKING:
    from apps.provisioning.models import Service


def _review(change: PlanChange, invoice: Invoice, reason: str) -> None:
    change.invoice = invoice
    change.review_reason = reason[:255]
    change.require_review()
    change.save(update_fields=["invoice", "review_reason", "status", "updated_at"])


def _validate_current_terms(change: PlanChange, subscription: Subscription, service: Service) -> None:
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.provisioning.hosting_limit_models import ServiceHostingLimits  # noqa: PLC0415

    now = timezone.now()
    if (
        change.direction != "upgrade"
        or change.status not in {"awaiting_payment", "payment_in_flight"}
        or change.confirmed_at is None
        or now >= change.authority_expires_at
        or now >= change.current_period_end
    ):
        raise ValidationError(_("The paid quote no longer has current application authority."))
    if (
        subscription.customer_id != change.customer_id
        or service.customer_id != change.customer_id
        or subscription.service_id != service.pk
        or subscription.product_id != change.from_product_id
        or service.service_plan_id != change.from_plan_id
        or subscription.currency_id != change.currency_id
        or service.currency_id != change.currency_id
        or subscription.quantity != 1
        or subscription.billing_cycle != change.quote_snapshot.get("billing_cycle")
        or subscription.cancel_at_period_end
        or subscription.status != "active"
        or service.status != "active"
    ):
        raise ValidationError(_("The service's accepted owner, period or commercial terms changed."))
    customer = Customer.all_objects.filter(pk=change.customer_id).first()
    if (
        customer is None
        or customer.status != "active"
        or customer.anonymized_at is not None
        or customer.deleted_at is not None
    ):
        raise ValidationError(_("The customer no longer permits an automatic plan application."))
    limits = ServiceHostingLimits.objects.get(service_id=service.pk)
    if limits.revision != change.expected_limit_revision:
        raise ValidationError(_("Another resource assignment superseded this paid quote."))
    coverage = load_plan_coverage(subscription, at=change.quoted_at)
    if coverage.evidence != change.quote_snapshot.get("coverage"):
        raise ValidationError(_("Original period coverage changed after the quote was accepted."))
    if sum(part.net_cents for part in change.intervals.all()) != change.net_cents:
        raise ValidationError(_("The accepted interval allocations do not match the settled amount."))


def _commit_accepted_terms(  # noqa: PLR0913 -- Invoice, scheduled authority and native refusal remain explicit.
    change: PlanChange,
    subscription: Subscription,
    service: Service,
    *,
    invoice: Invoice | None = None,
    scheduled: bool = False,
    native_refusal: str | None = None,
) -> None:
    """One assignment writer serves settled money and explicit no-charge acceptance."""
    from apps.promotions.models import RenewalBenefit  # noqa: PLC0415

    accepted = HostingAssignmentTerms.from_snapshot(change.quote_snapshot.get("accepted_limits"))
    authority = {
        "kind": "scheduled_plan_change" if scheduled else "paid_plan_change" if invoice else "zero_due_plan_change",
        "plan_change_id": str(change.pk),
    }
    if invoice is not None:
        authority["invoice_id"] = str(invoice.pk)
    application = (
        request_service_plan_change(
            service=service,
            target_plan_id=change.to_plan_id,
            expected_revision=change.expected_limit_revision,
            submission_id=change.submission_id,
            reason="Accepted scheduled hosting plan change" if scheduled else "Accepted paid hosting plan change",
            authority=authority,
            accepted_terms=accepted,
        )
        if native_refusal is None
        else None
    )
    subscription.product_id = change.to_product_id
    subscription.unit_price_cents = change.target_period_price_cents
    subscription.locked_price_cents = None
    subscription.locked_price_reason = ""
    subscription.locked_price_expires_at = None
    subscription.save(
        update_fields=[
            "product",
            "unit_price_cents",
            "locked_price_cents",
            "locked_price_reason",
            "locked_price_expires_at",
            "updated_at",
        ]
    )
    service.price = Decimal(change.target_period_price_cents) / 100
    service.save(update_fields=["price", "updated_at"])
    # Reserved uses and frozen document amounts remain evidence of their original
    # obligation. An ended benefit cannot discount a later newly prepared cycle.
    for benefit in RenewalBenefit.objects.filter(subscription_id=subscription.pk, ended_at__isnull=True).order_by("pk"):
        end_locked_benefit(benefit)
    change.invoice = invoice
    change.limit_application = application
    change.committed_at = timezone.now()
    change.commit_limits()
    fields = ["invoice", "limit_application", "committed_at", "status", "updated_at"]
    if native_refusal is not None:
        change.review_reason = native_refusal[:255]
        change.limits_failed()
        fields.append("review_reason")
    change.save(update_fields=fields)


def commit_scheduled_plan_change(change: PlanChange, *, at: datetime | None = None) -> None:
    """Honor accepted renewal prices at the date; native drift never authorizes stale limits."""
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.provisioning.models import Service  # noqa: PLC0415

    from .plan_change_financial import (  # noqa: PLC0415 -- Immediate disputed-source gate.
        validate_preserved_plan_coverage,
    )

    if not transaction.get_connection(change._state.db).in_atomic_block:
        raise RuntimeError("Scheduled plan activation requires its commercial-context transaction")
    now = timezone.now() if at is None else at
    if (
        change.direction != "downgrade"
        or change.status != "scheduled"
        or change.confirmed_at is None
        or now < change.effective_at
        or change.proforma_id is not None
        or change.invoice_id is not None
        or hasattr(change, "payment_attempt")
    ):
        raise ValidationError(_("Only an accepted scheduled downgrade can activate at its recorded renewal date."))
    customer = Customer.all_objects.get(pk=change.customer_id)
    subscription = Subscription.objects.get(pk=change.subscription_id)
    service = Service.objects.get(pk=change.service_id)
    validate_preserved_plan_coverage(change)
    if (
        customer.deleted_at is not None
        or customer.anonymized_at is not None
        or customer.status not in {"active", "suspended"}
        or subscription.customer_id != customer.pk
        or service.customer_id != customer.pk
        or subscription.service_id != service.pk
        or subscription.product_id != change.from_product_id
        or subscription.currency_id != change.currency_id
        or service.currency_id != change.currency_id
        or subscription.quantity != 1
        or subscription.billing_cycle != change.quote_snapshot.get("billing_cycle")
        or subscription.status not in {"active", "past_due", "paused"}
        or subscription.cancel_at_period_end
        or service.status not in {"active", "suspended"}
    ):
        raise ValidationError(_("The scheduled downgrade's current owner or billing lifecycle requires review."))
    resource_refusal = _scheduled_resource_refusal(change, service)
    _commit_accepted_terms(change, subscription, service, scheduled=True, native_refusal=resource_refusal)


def _scheduled_resource_refusal(change: PlanChange, service: Service) -> str | None:
    from apps.products.models import Product  # noqa: PLC0415
    from apps.provisioning.hosting_limit_models import ServiceHostingLimits  # noqa: PLC0415
    from apps.provisioning.models import ServicePlan  # noqa: PLC0415

    from .plan_change_quote_service import _profile  # noqa: PLC0415 -- Frozen configuration, not live pricing.

    products = {
        product.pk: product
        for product in Product.objects.select_for_update(of=("self",), no_key=True)
        .filter(pk__in=(change.from_product_id, change.to_product_id))
        .order_by("pk")
    }
    plan = ServicePlan.objects.select_for_update(of=("self",), no_key=True).get(pk=change.to_plan_id)
    limits = ServiceHostingLimits.objects.select_for_update(of=("self",)).get(service_id=service.pk)
    resource_refusal = None
    if limits.revision != change.expected_limit_revision or service.service_plan_id != change.from_plan_id:
        resource_refusal = _("Another resource assignment superseded the accepted downgrade; review its limits.")
    elif (
        not plan.is_active
        or products[change.to_product_id].default_service_plan_id != change.to_plan_id
        or {"source": _profile(change.from_product_id), "target": _profile(change.to_product_id)}
        != change.quote_snapshot.get("catalog_profile")
    ):
        resource_refusal = _("The accepted hosting profile changed; the lower price remains and limits need review.")
    return resource_refusal


def resume_scheduled_plan_limits(change: PlanChange, subscription: Subscription, service: Service) -> bool:
    """Retry only an unissued accepted resource intent after its profile is repaired."""
    if (
        change.direction != "downgrade"
        or change.status != "limits_attention"
        or change.committed_at is None
        or change.limit_application_id is not None
        or subscription.customer_id != change.customer_id
        or service.customer_id != change.customer_id
        or subscription.service_id != service.pk
        or subscription.product_id != change.to_product_id
        or subscription.unit_price_cents != change.target_period_price_cents
        or subscription.currency_id != change.currency_id
        or service.currency_id != change.currency_id
        or _scheduled_resource_refusal(change, service) is not None
    ):
        return False
    accepted = HostingAssignmentTerms.from_snapshot(change.quote_snapshot.get("accepted_limits"))
    application = request_service_plan_change(
        service=service,
        target_plan_id=change.to_plan_id,
        expected_revision=change.expected_limit_revision,
        submission_id=change.submission_id,
        reason="Accepted scheduled hosting plan change",
        authority={"kind": "scheduled_plan_change", "plan_change_id": str(change.pk)},
        accepted_terms=accepted,
    )
    change.limit_application = application
    change.review_reason = _("Your agreed plan is waiting for resource verification.")
    change.save(update_fields=["limit_application", "review_reason", "updated_at"])
    return True


def _apply_paid_quote(change: PlanChange, invoice: Invoice) -> None:
    """The shared document context already acquired Sub→Service→Change before Payment."""
    from apps.provisioning.models import Service  # noqa: PLC0415

    if not invoice_has_paid_coverage(invoice):
        raise ValidationError(_("The plan-change invoice has no undisputed paid coverage."))
    if (
        change.proforma_id is None
        or invoice.customer_id != change.customer_id
        or invoice.currency_id != change.currency_id
        or invoice.converted_from_proforma_id != change.proforma_id
        or (invoice.subtotal_cents, invoice.tax_cents, invoice.total_cents)
        != (change.net_cents, change.tax_cents, change.total_cents)
    ):
        raise ValidationError(_("The settled document does not match the accepted plan quote."))
    subscription = Subscription.objects.get(pk=change.subscription_id)
    service = Service.objects.get(pk=change.service_id)
    _validate_current_terms(change, subscription, service)
    _commit_accepted_terms(change, subscription, service, invoice=invoice)


def converge_plan_change_invoice(invoice: Invoice) -> None:
    """Retain late money for review; never pretend a node failure undoes payment."""
    if not transaction.get_connection(invoice._state.db).in_atomic_block:
        raise RuntimeError("Plan-change settlement requires the existing document transaction")
    scope = Q(invoice_id=invoice.pk)
    if invoice.converted_from_proforma_id:
        scope |= Q(proforma_id=invoice.converted_from_proforma_id)
    changes = list(PlanChange.objects.filter(scope).order_by("pk"))
    for change in changes:
        if change.committed_at is not None:
            # Replaying this original settlement cannot revert a later plan.
            if change.invoice_id != invoice.pk:
                raise ValidationError(_("The accepted plan change is bound to another invoice."))
            continue
        try:
            with transaction.atomic():
                _apply_paid_quote(change, invoice)
        except (ValidationError, ValueError) as error:
            # Discard in-memory changes made inside the rolled-back savepoint.
            fresh_change = PlanChange.objects.get(pk=change.pk)
            _review(fresh_change, invoice, str(error))


def commit_zero_due_plan_change(change: PlanChange) -> None:
    """Accept a rounded-zero upgrade under the existing commercial row locks."""
    from apps.provisioning.models import Service  # noqa: PLC0415

    if not transaction.get_connection(change._state.db).in_atomic_block:
        raise RuntimeError("No-charge acceptance requires its commercial-context transaction")
    if (
        (change.net_cents, change.tax_cents, change.total_cents) != (0, 0, 0)
        or change.proforma_id is not None
        or change.invoice_id is not None
        or hasattr(change, "payment_attempt")
    ):
        raise ValidationError(
            _("Only a confirmed zero-due quote without payment evidence can use no-charge acceptance.")
        )
    if change.committed_at is not None:
        if (
            change.status not in {"applying_limits", "completed", "limits_attention"}
            or change.limit_application_id is None
        ):
            raise ValidationError(_("The no-charge assignment requires review."))
        return
    if timezone.now() >= change.expires_at:
        raise ValidationError(_("The no-charge quote expired before acceptance."))
    subscription = Subscription.objects.get(pk=change.subscription_id)
    service = Service.objects.get(pk=change.service_id)
    _validate_current_terms(change, subscription, service)
    _commit_accepted_terms(change, subscription, service)
