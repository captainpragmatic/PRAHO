"""Immutable commercial quotes and separately evolving settlement/application state."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, router
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition


class PlanChangeQuerySet(models.QuerySet["PlanChange"]):
    def update(self, **kwargs: Any) -> int:
        raise ValidationError(_("Plan changes require audited lifecycle transitions."))

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Plan changes require audited lifecycle transitions."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[PlanChange]:
        raise ValidationError(_("Plan changes must be accepted and audited individually."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Commercial plan-change evidence cannot be deleted."))


class PlanChange(ConcurrentTransitionMixin, models.Model):
    ACTIVE_STATES: ClassVar[tuple[str, ...]] = (
        "quoted",
        "awaiting_payment",
        "payment_in_flight",
        "scheduled",
        "applying_limits",
        "limits_attention",
    )
    STATES: ClassVar[tuple[str, ...]] = (*ACTIVE_STATES, "completed", "cancelled", "expired", "paid_review")
    QUOTE_FIELDS: ClassVar[tuple[str, ...]] = (
        "customer_id",
        "requested_by_id",
        "service_id",
        "subscription_id",
        "submission_id",
        "request_fingerprint",
        "from_product_id",
        "to_product_id",
        "from_plan_id",
        "to_plan_id",
        "currency_id",
        "expected_limit_revision",
        "direction",
        "quoted_at",
        "expires_at",
        "authority_expires_at",
        "effective_at",
        "current_period_start",
        "current_period_end",
        "old_period_price_cents",
        "target_period_price_cents",
        "net_cents",
        "tax_cents",
        "total_cents",
        "quote_snapshot",
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey("customers.Customer", on_delete=models.PROTECT, related_name="plan_changes")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="plan_changes")
    service = models.ForeignKey("provisioning.Service", on_delete=models.PROTECT, related_name="plan_changes")
    subscription = models.ForeignKey("billing.Subscription", on_delete=models.PROTECT, related_name="plan_changes")
    submission_id = models.UUIDField()
    request_fingerprint = models.CharField(max_length=64)
    from_product = models.ForeignKey("products.Product", on_delete=models.PROTECT, related_name="changes_from")
    to_product = models.ForeignKey("products.Product", on_delete=models.PROTECT, related_name="changes_to")
    from_plan = models.ForeignKey("provisioning.ServicePlan", on_delete=models.PROTECT, related_name="changes_from")
    to_plan = models.ForeignKey("provisioning.ServicePlan", on_delete=models.PROTECT, related_name="changes_to")
    currency = models.ForeignKey("billing.Currency", on_delete=models.PROTECT)
    expected_limit_revision = models.PositiveBigIntegerField()
    direction = models.CharField(max_length=10, choices=(("upgrade", "Upgrade"), ("downgrade", "Downgrade")))
    status = FSMField(max_length=24, choices=[(state, state) for state in STATES], default="quoted", protected=True)
    quoted_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    authority_expires_at = models.DateTimeField()
    effective_at = models.DateTimeField()
    current_period_start = models.DateTimeField()
    current_period_end = models.DateTimeField()
    old_period_price_cents = models.PositiveBigIntegerField()
    target_period_price_cents = models.PositiveBigIntegerField()
    net_cents = models.PositiveBigIntegerField()
    tax_cents = models.PositiveBigIntegerField()
    total_cents = models.PositiveBigIntegerField()
    quote_snapshot = models.JSONField()
    confirmed_at = models.DateTimeField(null=True)
    proforma = models.OneToOneField(
        "billing.ProformaInvoice", on_delete=models.PROTECT, null=True, related_name="plan_change"
    )
    invoice = models.OneToOneField("billing.Invoice", on_delete=models.PROTECT, null=True, related_name="plan_change")
    limit_application = models.OneToOneField(
        "provisioning.HostingLimitApplication", on_delete=models.PROTECT, null=True, related_name="plan_change"
    )
    committed_at = models.DateTimeField(null=True)
    applied_at = models.DateTimeField(null=True)
    next_reconcile_at = models.DateTimeField(null=True, db_index=True)
    staff_escalated_at = models.DateTimeField(null=True, editable=False)
    review_reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = PlanChangeQuerySet.as_manager()

    class Meta:
        db_table = "billing_plan_changes"
        db_table_comment = "Accepted hosting plan agreements with independent financial and resource progress."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["customer", "requested_by", "submission_id"], name="plan_change_submission_unique"
            ),
            models.UniqueConstraint(
                fields=["service"],
                condition=models.Q(
                    status__in=[
                        "quoted",
                        "awaiting_payment",
                        "payment_in_flight",
                        "scheduled",
                        "applying_limits",
                        "limits_attention",
                    ]
                ),
                name="plan_change_one_active_service",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    status__in=[
                        "quoted",
                        "awaiting_payment",
                        "payment_in_flight",
                        "scheduled",
                        "applying_limits",
                        "limits_attention",
                        "completed",
                        "cancelled",
                        "expired",
                        "paid_review",
                    ]
                ),
                name="plan_change_status_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(total_cents=models.F("net_cents") + models.F("tax_cents")),
                name="plan_change_total_matches",
            ),
            models.CheckConstraint(
                condition=models.Q(current_period_end__gt=models.F("current_period_start")),
                name="plan_change_period_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(expires_at__gt=models.F("quoted_at")), name="plan_change_quote_expiry_valid"
            ),
        ]
        indexes: ClassVar[list[models.Index]] = [models.Index(fields=["status", "authority_expires_at"])]

    def save(self, *args: Any, **kwargs: Any) -> None:
        using = kwargs.get("using") or router.db_for_write(type(self), instance=self)
        if self._state.adding:
            kwargs["force_insert"] = True
        else:
            bindings = (
                "proforma_id",
                "invoice_id",
                "limit_application_id",
                "confirmed_at",
                "committed_at",
                "staff_escalated_at",
            )
            original = type(self).objects.using(using).filter(pk=self.pk).values(*self.QUOTE_FIELDS, *bindings).get()
            if any(getattr(self, field) != original[field] for field in self.QUOTE_FIELDS):
                raise ValidationError(_("A commercial quote cannot be rewritten; request a fresh quote."))
            selected = set(kwargs["update_fields"]) if kwargs.get("update_fields") is not None else None
            if selected is not None and self.confirmed_at is not None and original["confirmed_at"] is None:
                selected.add("confirmed_at")
                kwargs["update_fields"] = selected
            if any(
                original[field] is not None
                and getattr(self, field) != original[field]
                and (selected is None or field in selected or field.removesuffix("_id") in selected)
                for field in bindings
            ):
                raise ValidationError(_("Accepted commercial document and authority bindings cannot be replaced."))
        fields = kwargs.get("update_fields")
        if self._state.adding or fields is None or "status" in fields:
            active = self.status in {"applying_limits", "limits_attention"}
            if active and self.next_reconcile_at is None:
                self.next_reconcile_at = timezone.now()
            elif not active:
                self.next_reconcile_at = None
            if fields is not None:
                kwargs["update_fields"] = {*fields, "next_reconcile_at"}
        kwargs["using"] = using
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Commercial plan-change evidence cannot be deleted."))

    def refresh_from_db(self, using: str | None = None, fields: Any = None, from_queryset: Any = None) -> None:
        saved = self.__dict__.pop("status", None) if fields is None or "status" in fields else None
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            if saved is not None:
                self.__dict__["status"] = saved
            raise

    @transition(field=status, source="quoted", target="awaiting_payment")
    def confirm(self) -> None:
        """Bind the exact quote before an on-session payment can be reserved."""
        self.confirmed_at = timezone.now()

    @transition(field=status, source="awaiting_payment", target="payment_in_flight")
    def begin_payment(self) -> None:
        """The durable attempt, not the browser, owns ambiguous payment recovery."""

    @transition(field=status, source="quoted", target="scheduled")
    def schedule(self) -> None:
        """Accept a downgrade at its recorded first uncommitted boundary."""
        self.confirmed_at = timezone.now()

    @transition(field=status, source=["awaiting_payment", "payment_in_flight", "scheduled"], target="applying_limits")
    def commit_limits(self) -> None:
        """Financial acceptance and the durable allowance intent commit together."""

    @transition(field=status, source=["applying_limits", "limits_attention"], target="completed")
    def complete(self) -> None:
        """Native verification, rather than a metadata write, completes fulfilment."""

    @transition(field=status, source=["applying_limits", "limits_attention", "scheduled"], target="limits_attention")
    def limits_failed(self) -> None:
        """Retain accepted money/terms while resources require attention."""

    @transition(field=status, source="*", target="paid_review")
    def require_review(self) -> None:
        """Late or invalidated financial evidence never silently switches resources."""

    @transition(field=status, source=["quoted", "awaiting_payment", "scheduled"], target="cancelled")
    def cancel(self) -> None:
        """The service must first prove that no provider attempt remains uncertain."""

    @transition(field=status, source=["quoted", "awaiting_payment"], target="expired")
    def expire(self) -> None:
        """An issued/unknown provider attempt cannot be expired by elapsed time."""

    @transition(field=status, source="payment_in_flight", target="cancelled")
    def cancel_payment(self) -> None:
        """Release only the persisted, proven terminal provider attempt."""
        self._require_terminal_payment()

    @transition(field=status, source="payment_in_flight", target="expired")
    def expire_payment(self) -> None:
        """Elapsed time alone never proves that an issued charge cannot settle."""
        self._require_terminal_payment()

    def _require_terminal_payment(self) -> None:
        from .plan_change_payment_models import PlanChangePaymentAttempt  # noqa: PLC0415 -- Model registration cycle.

        attempt = PlanChangePaymentAttempt.objects.select_related("payment").filter(change_id=self.pk).first()
        if attempt is None:
            raise ValidationError(_("The original payment attempt has no terminal cancellation proof."))
        payment = attempt.payment
        metadata = payment.meta or {}
        provider_cancelled = (
            attempt.provider_status == "canceled"
            and attempt.first_submitted_at is not None
            and attempt.submission_count > 0
            and bool(attempt.gateway_intent_id)
            and payment.gateway_txn_id == attempt.gateway_intent_id
            and metadata.get("plan_change_terminal_proof") == "provider_cancelled"
        )
        never_submitted = (
            attempt.provider_status == "not_submitted"
            and attempt.first_submitted_at is None
            and attempt.submission_count == 0
            and not attempt.gateway_intent_id
            and not payment.gateway_txn_id
            and metadata.get("plan_change_terminal_proof") == "never_submitted"
        )
        if (
            attempt.state != "cancelled"
            or payment.status != "failed"
            or payment.customer_id != self.customer_id
            or payment.proforma_id != self.proforma_id
            or payment.currency_id != self.currency_id
            or payment.amount_cents != self.total_cents
            or metadata.get("source") != "hosting_plan_change"
            or metadata.get("plan_change_id") != str(self.pk)
            or not (provider_cancelled or never_submitted)
        ):
            raise ValidationError(_("The original payment attempt has no terminal cancellation proof."))


class PlanChangeIntervalQuerySet(models.QuerySet["PlanChangeInterval"]):
    def update(self, **kwargs: Any) -> int:
        raise ValidationError(_("Commercial interval evidence is immutable."))

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Commercial interval evidence is immutable."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[PlanChangeInterval]:
        raise ValidationError(_("Commercial interval evidence must be audited individually."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Commercial interval evidence is immutable."))


class PlanChangeInterval(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    change = models.ForeignKey(PlanChange, on_delete=models.PROTECT, related_name="intervals")
    ordinal = models.PositiveSmallIntegerField()
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    slice_start = models.DateTimeField()
    base_net_cents = models.PositiveBigIntegerField()
    prior_supplement_cents = models.PositiveBigIntegerField()
    net_cents = models.PositiveBigIntegerField()
    current_slice = models.BooleanField()
    evidence = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    objects = PlanChangeIntervalQuerySet.as_manager()

    class Meta:
        db_table = "billing_plan_change_intervals"
        db_table_comment = "Frozen hosting plan supplement allocations for each covered billing interval."
        ordering = ("ordinal",)
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(fields=["change", "ordinal"], name="plan_change_interval_order_unique"),
            models.CheckConstraint(
                condition=models.Q(period_end__gt=models.F("period_start"))
                & models.Q(slice_start__gte=models.F("period_start"))
                & models.Q(slice_start__lt=models.F("period_end")),
                name="plan_change_interval_span_valid",
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ValidationError(_("Commercial interval evidence is immutable."))
        kwargs["force_insert"] = True
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Commercial interval evidence is immutable."))
