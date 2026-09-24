"""Locked, audited mutations for staff-managed billing policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils.translation import gettext_lazy as _

from .invoice_models import InvoiceSequence
from .payment_models import PaymentRetryPolicy

if TYPE_CHECKING:
    import uuid

    from apps.users.models import User


# Prefixes owned by non-default numbering scopes. The subscription sequence uses
# "SUB" and may not have a row yet, so the existing-rows reuse check cannot catch
# it — reserving the name prevents the invoice series from colliding with it later.
_RESERVED_SEQUENCE_PREFIXES = frozenset({"SUB"})

_RETRY_POLICY_FIELDS = (
    "name",
    "description",
    "retry_intervals_days",
    "max_attempts",
    "send_dunning_emails",
    "is_default",
    "is_active",
)


@dataclass(frozen=True)
class BillingControlActor:
    """Attribution shared by every billing-control mutation."""

    user: User
    reason: str
    ip_address: str | None


def _policy_values(policy: PaymentRetryPolicy) -> dict[str, Any]:
    return {field_name: getattr(policy, field_name) for field_name in _RETRY_POLICY_FIELDS}


def _require_audit_reason(actor: BillingControlActor) -> None:
    if not actor.reason.strip():
        raise ValidationError({"reason": _("A non-blank audit reason is required.")})


def _audit_configuration_change(
    *,
    content_object: Any,
    actor: BillingControlActor,
    old_values: dict[str, Any],
    new_values: dict[str, Any],
) -> None:
    from apps.audit.services import AuditService  # noqa: PLC0415  # ADR-0007 composition boundary

    AuditService.log_simple_event(
        event_type="configuration_changed",
        user=actor.user,
        content_object=content_object,
        description=f"Billing configuration changed: {content_object}",
        old_values=old_values,
        new_values=new_values,
        metadata={"source_app": "billing", "reason": actor.reason},
        ip_address=actor.ip_address,
    )


@transaction.atomic
def update_retry_policy(
    *,
    policy_id: Any,
    values: dict[str, Any],
    baseline: str,
    actor: BillingControlActor,
) -> PaymentRetryPolicy:
    """Apply one retry-policy edit without lost updates or default-policy gaps."""
    _require_audit_reason(actor)
    locked_policies = list(PaymentRetryPolicy.objects.select_for_update().order_by("id"))
    policy = next((candidate for candidate in locked_policies if candidate.pk == policy_id), None)
    if policy is None:
        raise PaymentRetryPolicy.DoesNotExist
    if policy.updated_at.isoformat() != baseline:
        raise ValidationError({"baseline": _("This policy changed while you were editing it. Reload and try again.")})
    if any(candidate.pk != policy.pk and candidate.name == values["name"] for candidate in locked_policies):
        raise ValidationError({"name": _("A retry policy with this name already exists.")})

    old_values = _policy_values(policy)
    making_default = bool(values["is_active"] and values["is_default"])
    if not making_default and policy.is_active and policy.is_default:
        replacement_exists = any(
            candidate.pk != policy.pk and candidate.is_active and candidate.is_default for candidate in locked_policies
        )
        if not replacement_exists:
            raise ValidationError({"is_default": _("Configure another active default policy first.")})

    if making_default:
        previous_defaults = [
            candidate
            for candidate in locked_policies
            if candidate.pk != policy.pk and candidate.is_active and candidate.is_default
        ]
        for previous in previous_defaults:
            previous_old_values = _policy_values(previous)
            previous.is_default = False
            previous.save(update_fields=["is_default", "updated_at"])
            _audit_configuration_change(
                content_object=previous,
                actor=actor,
                old_values=previous_old_values,
                new_values=_policy_values(previous),
            )

    for field_name in _RETRY_POLICY_FIELDS:
        setattr(policy, field_name, values[field_name])
    policy.clean()
    policy.save()
    _audit_configuration_change(
        content_object=policy,
        actor=actor,
        old_values=old_values,
        new_values=_policy_values(policy),
    )
    return policy


@transaction.atomic
def rotate_invoice_series(
    *,
    prefix: str,
    baseline: str,
    actor: BillingControlActor,
) -> InvoiceSequence:
    """Archive the active series and reset its stable, locked control row."""
    _require_audit_reason(actor)
    prefix = prefix.strip().upper()
    if re.fullmatch(r"[A-Z0-9][A-Z0-9-]{0,29}", prefix) is None:
        raise ValidationError({"prefix": _("Use uppercase letters, digits, and hyphens only.")})
    if prefix in _RESERVED_SEQUENCE_PREFIXES:
        raise ValidationError({"prefix": _("This prefix is reserved for another numbering scope.")})

    current = InvoiceSequence.objects.select_for_update().filter(scope="default").first()
    if current is None:
        if baseline != "missing":
            raise ValidationError({"baseline": _("The active series changed. Reload and try again.")})
        old_values: dict[str, Any] = {}
    else:
        current_baseline = f"{current.prefix}:{current.last_value}"
        if current_baseline != baseline:
            raise ValidationError({"baseline": _("The active series changed while you were editing. Reload.")})
        old_values = {"prefix": current.prefix, "last_value": current.last_value, "scope": current.scope}

    used_prefixes = InvoiceSequence.objects.filter(prefix=prefix)
    if current is not None:
        used_prefixes = used_prefixes.exclude(pk=current.pk)
    if used_prefixes.exists():
        raise ValidationError({"prefix": _("An invoice series with this prefix already exists.")})
    if current is not None and current.prefix == prefix:
        raise ValidationError({"prefix": _("The new prefix must differ from the active series.")})

    if current is None:
        try:
            with transaction.atomic():
                replacement = InvoiceSequence.objects.create(scope="default", prefix=prefix, last_value=0)
        except IntegrityError as exc:
            raise ValidationError({"baseline": _("The active series changed. Reload and try again.")}) from exc
    else:
        InvoiceSequence.objects.create(
            scope=f"archived:{current.prefix}",
            prefix=current.prefix,
            last_value=current.last_value,
        )
        current.prefix = prefix
        current.last_value = 0
        current.save(update_fields=["prefix", "last_value"])
        replacement = current
    _audit_configuration_change(
        content_object=replacement,
        actor=actor,
        old_values=old_values,
        new_values={"prefix": replacement.prefix, "last_value": 0, "scope": replacement.scope},
    )
    return replacement


def adopt_provider_document(
    *,
    issuance_id: uuid.UUID,
    series: str,
    number: str,
    actor: BillingControlActor,
) -> str:
    """Record that an operator found a document at the provider, and adopt its number.

    `outcome_unknown` means a POST may have created a fiscal document that PRAHO has
    no way to look up: the provider exposes no search by our reference, so identifying
    it is a human judgement. This is the only way out towards a numbered invoice, and
    it stays manual for that reason.

    Deliberately NOT `@transaction.atomic`, unlike its neighbours in this module.
    `reconcile_confirmed_issued` refuses to run inside a transaction and opens its own,
    so wrapping it here would break it. It also answers with a `Result` rather than
    raising, so the error is translated into the `ValidationError` the view layer and
    every other control in this module already speak.

    The audit event lives here rather than in the issuer service because attribution
    needs an actor, and the issuer service is reached from workers that have none. It
    assigns a legal fiscal number on a human's word, which under ADR-0016 is exactly
    the kind of act that must leave a trace naming who decided it.
    """
    from apps.billing.issuers.models import ProviderIssuance  # noqa: PLC0415  # ADR-0007
    from apps.billing.issuers.service import reconcile_confirmed_issued  # noqa: PLC0415  # ADR-0007
    from apps.common.types import Err  # noqa: PLC0415

    _require_audit_reason(actor)

    issuance = ProviderIssuance.objects.select_related("invoice").filter(pk=issuance_id).first()
    if issuance is None:
        raise ValidationError({"__all__": _("That reconciliation no longer exists.")})
    before = {
        "state": issuance.state,
        "provider_series": issuance.provider_series,
        "provider_number": issuance.provider_number,
        "invoice_number": issuance.invoice.number,
    }

    outcome = reconcile_confirmed_issued(
        issuance_id,
        series=series,
        number=number,
        operator_note=actor.reason,
    )
    if isinstance(outcome, Err):
        raise ValidationError({"__all__": outcome.error})
    legal_number = outcome.unwrap()

    # Re-fetched rather than refreshed: `state` is a protected FSMField, and
    # `refresh_from_db` re-enters its setter, which refuses direct assignment.
    issuance = ProviderIssuance.objects.select_related("invoice").get(pk=issuance_id)
    _audit_configuration_change(
        content_object=issuance.invoice,
        actor=actor,
        old_values=before,
        new_values={
            "state": issuance.state,
            "provider_series": issuance.provider_series,
            "provider_number": issuance.provider_number,
            "invoice_number": legal_number,
        },
    )
    return legal_number
