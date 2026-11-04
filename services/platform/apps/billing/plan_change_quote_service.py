"""Pinned standalone plan quotes, with separate document-first replay."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, cast
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.tax_service import TaxService, VATCalculationResult
from apps.customers.models import Customer
from apps.products.models import Product, ProductPrice
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_policy import BYTES_PER_MIB
from apps.provisioning.models import Service, ServicePlan

from .metering_models import BillingCycle
from .plan_change_catalog import PlanTarget, eligible_plan_targets
from .plan_change_coverage import PlanCoverage, load_plan_coverage
from .plan_change_models import PlanChange, PlanChangeInterval
from .plan_change_pricing import quote_supplements
from .plan_change_validation import (
    PlanChangeConflict,
    _validate_collection_boundary,
    _validate_native_claim,
    require_plan_change_acceptance,
    validate_customer_actor,
)
from .services import _build_customer_vat_info
from .subscription_models import Subscription
from .tax_evidence import derive_tax_category
from .validators import log_security_event

QUOTE_TTL = timedelta(minutes=15)
PAYMENT_AUTHORITY = timedelta(hours=1)
PROFILE_FIELDS = ("plan_type", "features", "email_accounts", "databases", "domains", "cpu_cores", "ram_gb")


class PlanChangeSafetyUnavailable(ValidationError):  # noqa: N818 -- Typed API refusal alongside ValidationError.
    def __init__(self) -> None:
        super().__init__(
            _("Refresh this service's bound native safety observation before accepting a downgrade."),
            code="fresh_native_safety_required",
        )


def _require_downgrade_fit(service: Service, target: PlanTarget, *, effective_at: datetime) -> None:
    try:
        from .plan_change_safety import (  # noqa: PLC0415 -- Read-only current observation and bounded R.
            current_safety_used_bytes,
            downgrade_allowance_mib,
        )
    except ModuleNotFoundError as error:
        if error.name != "apps.billing.plan_change_safety":
            raise
        raise PlanChangeSafetyUnavailable() from error
    used = current_safety_used_bytes(service)
    if type(used) is not int or used < 0:
        raise PlanChangeSafetyUnavailable()
    allowance = downgrade_allowance_mib(service, target.limits.disk_allowance_mib, effective_at=effective_at)
    if allowance and used > allowance * BYTES_PER_MIB:
        raise ValidationError(
            _("Current usage exceeds the proposed assigned disk allowance."), code="usage_exceeds_target"
        )


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _time(at: datetime | None) -> datetime:
    value = timezone.now() if at is None else at
    if timezone.is_naive(value):
        raise ValueError("A commercial quote instant requires a timezone")
    return value


def _calculate_tax(customer: Customer, net_lines: list[int]) -> tuple[dict[str, Any], VATCalculationResult]:
    if any(type(value) is not int or value < 0 for value in net_lines):
        raise ValueError("Quote lines require nonnegative integer NET cents")
    information = _build_customer_vat_info(customer, record_vies_refusal=False)
    decisions = [TaxService.calculate_vat_for_document(value, information) for value in net_lines or [0]]

    def policy(result: VATCalculationResult) -> dict[str, Any]:
        return {
            "scenario": result.scenario.value,
            "category": derive_tax_category(result),
            "country_code": result.country_code,
            "vat_rate_percent": str(result.vat_rate),
            "is_business": result.is_business,
        }

    selected = policy(decisions[0])
    if any(policy(item) != selected for item in decisions):
        raise PlanChangeConflict(_("Tax policy changed while calculating this quote. Request a fresh quote."))
    taxes = [item.vat_cents for item in decisions] if net_lines else []
    net, tax = sum(net_lines), sum(taxes)
    # PRAHO's undiscounted documents preserve the sum of independently rounded line taxes.
    result = replace(decisions[0], subtotal_cents=net, vat_cents=tax, total_cents=net + tax)
    return {"policy": selected, "taxes": taxes, "net_cents": net, "tax_cents": tax, "total_cents": net + tax}, result


def _tax_quote(customer: Customer, net_lines: list[int]) -> dict[str, Any]:
    return _calculate_tax(customer, net_lines)[0]


@contextmanager
def _commercial_context(
    service_id: int, *, customer_id: int, actor_id: int
) -> Iterator[tuple[Customer, Subscription, Service]]:
    """New unpublished work owns no existing financial document lock."""
    with transaction.atomic():
        Customer.all_objects.select_for_update(of=("self",), no_key=True).get(pk=customer_id)
        customer = validate_customer_actor(customer_id, actor_id)
        try:
            subscription = Subscription.objects.select_for_update(of=("self",), no_key=True).get(
                service_id=service_id,
                customer_id=customer_id,
                status="active",
            )
        except (Subscription.DoesNotExist, Subscription.MultipleObjectsReturned) as error:
            raise ValidationError(_("This service has no single active billing subscription.")) from error
        service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=service_id)
        if service.customer_id != customer_id or service.status != "active" or subscription.quantity != 1:
            raise ValidationError(_("Only an active independently billed service can change plans."))
        yield customer, subscription, service


def _validate_scope(subscription: Subscription, service: Service) -> None:
    if subscription.cancel_at_period_end or subscription.currency_id != service.currency_id:
        raise ValidationError(_("Resolve cancellation or currency changes before changing this plan."))
    _validate_collection_boundary(subscription)
    _validate_native_claim(service)


def _lock_catalog(subscription: Subscription, target_product_id: UUID) -> None:
    products = list(
        Product.objects.select_for_update(of=("self",), no_key=True)
        .filter(pk__in=(subscription.product_id, target_product_id))
        .order_by("pk")
    )
    if subscription.product_id == target_product_id or {row.pk for row in products} != {
        subscription.product_id,
        target_product_id,
    }:
        raise ValidationError(_("Choose a different available product from the curated plan targets."))
    list(
        ServicePlan.objects.select_for_update(of=("self",), no_key=True)
        .filter(pk__in=[row.default_service_plan_id for row in products])
        .order_by("pk")
    )
    list(
        ProductPrice.objects.select_for_update(of=("self",), no_key=True)
        .filter(product_id__in=[row.pk for row in products], currency_id=subscription.currency_id)
        .order_by("pk")
    )


def _profile(product_id: UUID) -> str:
    product = Product.objects.select_related("default_service_plan").get(pk=product_id)
    plan = product.default_service_plan
    if plan is None:
        raise ValidationError(_("The selected product has no compatible service plan."))
    # Bind configuration without copying privileged module settings into immutable customer evidence.
    return _digest(
        {
            "module": product.module,
            "module_config": product.module_config,
            "plan": {field: getattr(plan, field) for field in PROFILE_FIELDS},
        }
    )


def _target(subscription: Subscription, product_id: UUID) -> PlanTarget:
    for target in eligible_plan_targets(subscription):
        if target.product_id == product_id:
            return target
    raise PlanChangeConflict(_("This curated product, price or assigned allowance changed. Request a fresh quote."))


def validate_frozen_catalog(change: PlanChange, subscription: Subscription) -> PlanTarget:
    """Before first claim only; a durably issued attempt must retain its frozen request."""
    _lock_catalog(subscription, change.to_product_id)
    target = _target(subscription, change.to_product_id)
    if (
        target.direction != change.direction
        or target.period_price_cents != change.target_period_price_cents
        or target.limits.as_snapshot() != change.quote_snapshot.get("accepted_limits")
        or {"source": _profile(subscription.product_id), "target": _profile(target.product_id)}
        != change.quote_snapshot.get("catalog_profile")
    ):
        raise PlanChangeConflict(
            _("The quoted catalog configuration changed before acceptance. Request a fresh quote.")
        )
    return target


def first_uncommitted_renewal(subscription: Subscription, coverage: PlanCoverage, *, at: datetime) -> datetime:
    boundary = next(part.end for part in coverage.intervals if part.start <= at < part.end)
    cycles = (
        BillingCycle.objects.filter(subscription=subscription, period_start__gte=boundary)
        .filter(
            Q(terms_frozen_at__isnull=False) | Q(invoice__isnull=False) | Q(proforma__isnull=False),
        )
        .order_by("period_start", "pk")
    )
    for cycle in cycles:
        if cycle.period_start != boundary:
            raise ValidationError(_("Committed renewal periods have a gap or overlap and require staff review."))
        boundary = cycle.period_end
    return boundary


def plan_change_options(
    service_id: int, *, customer_id: int, actor_id: int, at: datetime | None = None
) -> list[dict[str, Any]]:
    require_plan_change_acceptance()
    with _commercial_context(service_id, customer_id=customer_id, actor_id=actor_id) as (
        customer,
        subscription,
        service,
    ):
        _validate_scope(subscription, service)
        coverage = load_plan_coverage(subscription, at=_time(at))
        options = []
        for target in eligible_plan_targets(subscription):
            recurring = _tax_quote(customer, [target.period_price_cents])
            effective_at = (
                _time(at)
                if target.direction == "upgrade"
                else first_uncommitted_renewal(subscription, coverage, at=_time(at))
            )
            refusal_code = None
            if target.direction == "downgrade":
                try:
                    _require_downgrade_fit(service, target, effective_at=effective_at)
                except ValidationError as error:
                    refusal_code = getattr(error, "code", "usage_exceeds_target")
            options.append(
                {
                    "product_id": str(target.product_id),
                    "name": target.name,
                    "direction": target.direction,
                    "period_price_cents": target.period_price_cents,
                    "currency": subscription.currency.code,
                    "next_recurring_total_cents": recurring["total_cents"],
                    "allowances": target.limits.as_snapshot(),
                    "effective_at": effective_at.isoformat(),
                    "expected_limit_revision": ServiceHostingLimits.objects.get(service=service).revision,
                    "available": refusal_code is None,
                    "refusal_code": refusal_code,
                }
            )
        return options


def _build_quote(  # noqa: PLR0913 -- Locked scope plus explicit submission/revision authority.
    customer: Customer,
    subscription: Subscription,
    service: Service,
    *,
    actor_id: int,
    target_product_id: UUID,
    submission_id: UUID,
    expected_limit_revision: int,
    at: datetime,
) -> PlanChange:
    """Financial core; caller owns the commercial context and has proved native admission."""
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("A commercial quote requires its locked business context")
    request = {
        "service_id": service.pk,
        "customer_id": customer.pk,
        "actor_id": actor_id,
        "target_product_id": str(target_product_id),
        "expected_limit_revision": expected_limit_revision,
    }
    fingerprint = _digest(request)
    existing = PlanChange.objects.filter(
        customer=customer, requested_by_id=actor_id, submission_id=submission_id
    ).first()
    if existing is not None:
        if existing.request_fingerprint != fingerprint:
            log_security_event(
                "plan_change_submission_conflict", {"service_id": service.pk, "submission_id": str(submission_id)}
            )
            raise PlanChangeConflict(_("This submission was already used for a different plan-change request."))
        return existing
    active = PlanChange.objects.filter(service=service, status__in=PlanChange.ACTIVE_STATES).first()
    if active is not None:
        if active.status == "quoted" and active.expires_at <= at and active.proforma_id is None:
            active.expire()
            active.save(update_fields=["status", "updated_at"])
        else:
            raise PlanChangeConflict(_("Resolve the existing service plan change before requesting another."))
    limits = ServiceHostingLimits.objects.get(service=service)
    if limits.revision != expected_limit_revision:
        raise PlanChangeConflict(_("The assigned resource revision changed. Reload the available plans."))
    _lock_catalog(subscription, target_product_id)
    target = _target(subscription, target_product_id)
    coverage = load_plan_coverage(subscription, at=at)
    effective_at = at if target.direction == "upgrade" else first_uncommitted_renewal(subscription, coverage, at=at)
    if target.direction == "downgrade":
        _require_downgrade_fit(service, target, effective_at=effective_at)
    current = next(part for part in coverage.intervals if part.start <= at < part.end)
    parts = (
        quote_supplements(
            intervals=coverage.intervals,
            quoted_at=at,
            current_period_price_cents=coverage.current_period_price_cents,
            target_period_price_cents=target.period_price_cents,
        )
        if target.direction == "upgrade"
        else ()
    )
    taxes = _tax_quote(customer, [part.net_cents for part in parts])
    authority = min(at + PAYMENT_AUTHORITY, current.end)
    profile = {"source": _profile(subscription.product_id), "target": _profile(target.product_id)}
    recurring = _tax_quote(customer, [target.period_price_cents])
    change = PlanChange.objects.create(
        customer=customer,
        requested_by_id=actor_id,
        service=service,
        subscription=subscription,
        submission_id=submission_id,
        request_fingerprint=fingerprint,
        from_product_id=subscription.product_id,
        to_product_id=target.product_id,
        from_plan_id=service.service_plan_id,
        to_plan_id=target.limits.plan_id,
        currency_id=subscription.currency_id,
        expected_limit_revision=limits.revision,
        direction=target.direction,
        quoted_at=at,
        expires_at=min(at + QUOTE_TTL, authority),
        authority_expires_at=authority,
        effective_at=effective_at,
        current_period_start=current.start,
        current_period_end=current.end,
        old_period_price_cents=coverage.current_period_price_cents,
        target_period_price_cents=target.period_price_cents,
        net_cents=taxes["net_cents"],
        tax_cents=taxes["tax_cents"],
        total_cents=taxes["total_cents"],
        quote_snapshot={
            "version": 1,
            "request": request,
            "billing_cycle": subscription.billing_cycle,
            "quantity": 1,
            "accepted_limits": target.limits.as_snapshot(),
            "coverage": coverage.evidence,
            "catalog_profile": profile,
            "tax_quote": taxes,
            "next_recurring": recurring,
            "labels": {
                "from": subscription.product.name,
                "to": target.name,
                "to_sku": Product.objects.get(pk=target.product_id).slug,
            },
        },
    )
    by_id = {part.evidence_id: part for part in coverage.intervals}
    for ordinal, part in enumerate(parts):
        original = by_id[part.evidence_id]
        PlanChangeInterval.objects.create(
            change=change,
            ordinal=ordinal,
            period_start=original.start,
            period_end=original.end,
            slice_start=part.start,
            base_net_cents=original.base_net_cents,
            prior_supplement_cents=original.settled_supplement_cents,
            net_cents=part.net_cents,
            current_slice=part.current_slice,
            evidence=coverage.evidence[part.evidence_id],
        )
    return change


def quote_plan_change(  # noqa: PLR0913 -- Authenticated scope, target, submission and revision are mandatory.
    service_id: int,
    *,
    customer_id: int,
    actor_id: int,
    target_product_id: UUID | str,
    submission_id: UUID | str,
    expected_limit_revision: int,
    at: datetime | None = None,
) -> PlanChange:
    require_plan_change_acceptance()
    now = _time(at)
    with _commercial_context(service_id, customer_id=customer_id, actor_id=actor_id) as (
        customer,
        subscription,
        service,
    ):
        _validate_scope(subscription, service)
        return _build_quote(
            customer,
            subscription,
            service,
            actor_id=actor_id,
            target_product_id=UUID(str(target_product_id)),
            submission_id=UUID(str(submission_id)),
            expected_limit_revision=expected_limit_revision,
            at=now,
        )


def _validate_quoted_terms(
    change: PlanChange, subscription: Subscription, service: Service, *, at: datetime
) -> PlanTarget:
    if change.status != "quoted" or at >= min(change.expires_at, change.authority_expires_at):
        raise PlanChangeConflict(_("This quote is no longer awaiting acceptance. Request a fresh quote."))
    if (
        subscription.pk != change.subscription_id
        or service.pk != change.service_id
        or subscription.product_id != change.from_product_id
        or service.service_plan_id != change.from_plan_id
        or subscription.currency_id != change.currency_id
        or service.currency_id != change.currency_id
        or subscription.billing_cycle != change.quote_snapshot.get("billing_cycle")
        or ServiceHostingLimits.objects.get(service=service).revision != change.expected_limit_revision
    ):
        raise PlanChangeConflict(_("This service's original quoted terms changed. Request a fresh quote."))
    coverage = load_plan_coverage(subscription, at=change.quoted_at)
    if coverage.evidence != change.quote_snapshot.get("coverage"):
        raise PlanChangeConflict(_("The committed period coverage changed. Request a fresh quote."))
    target = validate_frozen_catalog(change, subscription)
    if change.direction == "downgrade":
        _require_downgrade_fit(service, target, effective_at=change.effective_at)
        if first_uncommitted_renewal(subscription, coverage, at=at) != change.effective_at:
            raise PlanChangeConflict(_("Another renewal was committed. Request its current downgrade date."))
    return target


def _create_proforma(change: PlanChange, customer: Customer, service: Service) -> None:
    from .currency_service import assert_currency_issuable  # noqa: PLC0415
    from .fiscal_identity import get_customer_fiscal_identity  # noqa: PLC0415
    from .proforma_models import ProformaInvoice, ProformaLine, ProformaSequence  # noqa: PLC0415
    from .tax_evidence import capture_vat_evidence  # noqa: PLC0415

    parts = list(change.intervals.order_by("ordinal"))
    tax_quote, tax_result = _calculate_tax(customer, [part.net_cents for part in parts])
    if tax_quote != change.quote_snapshot.get("tax_quote"):
        raise PlanChangeConflict(_("The fiscal tax classification or amounts changed. Request a fresh quote."))
    assert_currency_issuable(change.currency_id, timezone.localdate())
    sequence, _created = ProformaSequence.objects.get_or_create(scope="plan_change")
    sequence = ProformaSequence.objects.select_for_update(of=("self",)).get(pk=sequence.pk)
    identity = get_customer_fiscal_identity(customer)
    address = customer.get_billing_address()
    proforma = ProformaInvoice.objects.create(
        customer=customer,
        currency_id=change.currency_id,
        number=sequence.get_next_number("PRO-PC"),
        subtotal_cents=change.net_cents,
        tax_cents=change.tax_cents,
        total_cents=change.total_cents,
        valid_until=change.authority_expires_at,
        vat_evidence=capture_vat_evidence(tax_result),
        bill_to_name=customer.get_billing_name(),
        bill_to_email=customer.primary_email,
        bill_to_tax_id=identity.business_tax_id,
        bill_to_cnp=identity.cnp,
        bill_to_country=tax_result.country_code,
        bill_to_address1=getattr(address, "address_line1", ""),
        bill_to_address2=getattr(address, "address_line2", ""),
        bill_to_city=getattr(address, "city", ""),
        bill_to_region=getattr(address, "county", ""),
        bill_to_postal=getattr(address, "postal_code", ""),
        meta={
            "source": "hosting_plan_change",
            "plan_change_id": str(change.pk),
            "quote_fingerprint": change.request_fingerprint,
        },
    )
    rate = Decimal(tax_quote["policy"]["vat_rate_percent"]) / 100
    for part, tax in zip(parts, tax_quote["taxes"], strict=True):
        if part.net_cents == 0:
            continue
        ProformaLine.objects.create(
            proforma=proforma,
            service=service,
            billing_cycle=None,
            kind="service",
            quantity=1,
            description=(
                f"{str(change.quote_snapshot['labels']['from'])[:160]} -> "
                f"{str(change.quote_snapshot['labels']['to'])[:160]}: "
                f"{part.slice_start.isoformat()} - {part.period_end.isoformat()}"
            ),
            unit_price_cents=part.net_cents,
            tax_rate=rate,
            tax_cents=tax,
            line_total_cents=part.net_cents + tax,
            period_start=timezone.localdate(part.slice_start),
            period_end=timezone.localdate(part.period_end),
            tax_category_code=tax_quote["policy"]["category"],
            sort_order=part.ordinal,
        )
    proforma.send_proforma()
    proforma.accept()
    proforma.save(update_fields=["status"])
    change.proforma = proforma


def _confirm_new_quote(  # noqa: PLR0913 -- Explicit locked business context and no-charge consent.
    change: PlanChange,
    customer: Customer,
    subscription: Subscription,
    service: Service,
    *,
    at: datetime,
    accept_zero_due: bool,
) -> PlanChange:
    _validate_quoted_terms(change, subscription, service, at=at)
    if change.direction == "downgrade":
        change.schedule()
        change.save(update_fields=["status", "updated_at"])
        return change
    if change.total_cents == 0:
        if accept_zero_due is not True:
            raise ValidationError(_("Explicitly confirm this no-charge upgrade."), code="zero_due_acceptance_required")
        from .plan_change_settlement import commit_zero_due_plan_change  # noqa: PLC0415

        change.confirm()
        change.save(update_fields=["status", "updated_at"])
        commit_zero_due_plan_change(change)
        return change
    _create_proforma(change, customer, service)
    change.confirm()
    change.save(update_fields=["proforma", "status", "updated_at"])
    return change


def _confirm_binding(change: PlanChange, *, customer_id: int, actor_id: int, expected_fingerprint: str) -> None:
    if change.customer_id != customer_id or change.requested_by_id != actor_id:
        raise ValidationError(_("This accepted quote belongs to another customer or requester."))
    validate_customer_actor(customer_id, actor_id)
    if change.request_fingerprint != expected_fingerprint:
        raise PlanChangeConflict(_("This quote fingerprint changed. Reload the original quote."))


def confirm_plan_change(  # noqa: PLR0913 -- Authenticated scope, exact quote and explicit zero-due consent.
    change_id: UUID | str,
    *,
    customer_id: int,
    actor_id: int,
    expected_fingerprint: str,
    accept_zero_due: bool = False,
    at: datetime | None = None,
) -> PlanChange:
    hint = PlanChange.objects.values("service_id", "proforma_id").get(pk=change_id)
    if cast("UUID | None", hint["proforma_id"]) is not None:
        from .plan_change_payment_service import _locked_change  # noqa: PLC0415 -- Existing document owns ordering.

        with _locked_change(change_id) as (change, _document):
            _confirm_binding(
                change, customer_id=customer_id, actor_id=actor_id, expected_fingerprint=expected_fingerprint
            )
            return change
    with _commercial_context(hint["service_id"], customer_id=customer_id, actor_id=actor_id) as context:
        _customer, subscription, service = context
        change = PlanChange.objects.select_for_update(of=("self",), no_key=True).get(pk=change_id)
        _confirm_binding(change, customer_id=customer_id, actor_id=actor_id, expected_fingerprint=expected_fingerprint)
        if change.proforma_id is not None:
            # A racing confirmer won before this business lock; release it and
            # re-enter through document-first rather than invert the lock order.
            retry_document = True
        else:
            retry_document = False
            if change.confirmed_at is not None:
                return change
            require_plan_change_acceptance()
            _validate_scope(subscription, service)
            return _confirm_new_quote(change, *context, at=_time(at), accept_zero_due=accept_zero_due)
    if retry_document:
        return confirm_plan_change(
            change_id,
            customer_id=customer_id,
            actor_id=actor_id,
            expected_fingerprint=expected_fingerprint,
            accept_zero_due=accept_zero_due,
            at=at,
        )
    raise RuntimeError("The quote confirmation lost its commercial context")
