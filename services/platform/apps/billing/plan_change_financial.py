"""Read-only coverage checks shared by scheduled and native application gates."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.customers.models import Customer
from apps.provisioning.hosting_limit_models import HostingLimitApplication
from apps.provisioning.hosting_limit_policy import effective_disk_limit
from apps.provisioning.hosting_parent_limits import held_parent_cap_repair_issued
from apps.provisioning.virtualmin_migration_models import VirtualminMigration

from .invoice_models import Invoice
from .plan_change_coverage import invoice_has_paid_coverage
from .plan_change_historical_coverage import original_plan_coverage
from .plan_change_models import PlanChange
from .subscription_models import Subscription

COMMERCIAL_LIMIT_AUTHORITIES = frozenset({"paid_plan_change", "zero_due_plan_change", "scheduled_plan_change"})


def validate_preserved_plan_coverage(change: PlanChange) -> None:
    """No locks: already-visible disputed/refunded facts defeat a delayed review worker."""
    original = change.quote_snapshot.get("coverage")
    coverage = original_plan_coverage(change)
    # New lower renewal documents are allowed after a scheduled acceptance.
    # Every obligation that authorized that acceptance must still match.
    if not isinstance(original, dict):
        raise ValidationError(_("Original billing coverage changed and requires financial review."))
    own_allocations: dict[str, int] = {}
    if change.committed_at is not None:
        for part in change.intervals.all():
            key = str(part.evidence.get("cycle_id", ""))
            own_allocations[key] = own_allocations.get(key, 0) + part.net_cents
    for key, value in original.items():
        actual = coverage.get(key)
        if not isinstance(value, dict) or not isinstance(actual, dict):
            raise ValidationError(_("Original billing coverage changed and requires financial review."))
        expected, current = dict(value), dict(actual)
        prior = expected.get("prior_supplement_cents")
        if type(prior) is not int or prior < 0:
            raise ValidationError(_("Original supplement allocations require financial review."))
        expected["prior_supplement_cents"] = prior + own_allocations.get(key, 0)
        expected.pop("fingerprint", None)
        current.pop("fingerprint", None)
        if current != expected:
            raise ValidationError(_("Original billing coverage changed and requires financial review."))
    if change.invoice_id is not None and not invoice_has_paid_coverage(Invoice.objects.get(pk=change.invoice_id)):
        raise ValidationError(_("The plan-change payment no longer provides undisputed paid coverage."))


def _issued_frozen_migration_repair(application: HostingLimitApplication, parent: Mapping[str, Any]) -> bool:
    """Only a token-bound, issued parent may finish its already-approved cap repair."""
    try:
        identifier = UUID(str(parent.get("migration_id", "")))
    except (ValueError, TypeError):
        return False
    migration = VirtualminMigration.objects.filter(pk=identifier, account__service_id=application.service_id).first()
    if (
        migration is None
        or not migration.restore_issued
        or migration.status not in {"restoring", "verifying", "activating"}
        or str(migration.lease_token) != parent.get("token")
        or migration.worker_lease_expires_at is None
        or migration.worker_lease_expires_at <= timezone.now()
        or str(migration.target_server_id) != parent.get("native_server_id")
    ):
        return False
    frozen = migration.pre_migration_snapshot.get("hosting_limits")
    if (
        not isinstance(frozen, dict)
        or frozen.get("application_id") != str(application.pk)
        or parent.get("approved_application_id") != str(application.pk)
        or parent.get("frozen_application_id") != str(application.pk)
        or frozen.get("base_revision") != application.revision
        or frozen.get("overlay_revision") != 0
        or str(frozen.get("owner_id")) != application.authority.get("customer_id")
    ):
        return False
    cap = effective_disk_limit(application.disk_allowance_mib)
    ceiling, bandwidth = frozen.get("disk_cap_mib"), frozen.get("bandwidth_mib")
    target_bandwidth = application.bandwidth_allowance_mib
    return bool(
        type(ceiling) is int
        and ceiling >= 0
        and type(bandwidth) is int
        and bandwidth >= 0
        and cap is not None
        and (ceiling == 0 or 0 < cap <= ceiling)
        and target_bandwidth is not None
        and (bandwidth == 0 or 0 < target_bandwidth <= bandwidth)
    )


def commercial_source_refusal(application: HostingLimitApplication) -> str | None:
    """A validated original commercial application; no issued/overlay exception is granted here.

    Composed native applications resolve their original application from actual
    persisted bindings before calling this function. They separately prove any
    mandatory issued repair or preauthorized decreasing expiry at the native boundary.
    """
    authority = application.authority
    reason = _("Financial coverage requires review before dispatching this plan's native limits.")
    if authority.get("kind") not in COMMERCIAL_LIMIT_AUTHORITIES:
        return reason
    try:
        change = PlanChange.objects.get(pk=UUID(str(authority.get("plan_change_id", ""))))
        if (
            change.limit_application_id != application.pk
            or change.service_id != application.service_id
            or change.committed_at is None
            or change.status not in {"applying_limits", "limits_attention", "completed"}
            or str(change.customer_id) != authority.get("customer_id")
        ):
            return reason
        customer = Customer.all_objects.get(pk=change.customer_id)
        if customer.status != "active" or customer.anonymized_at is not None or customer.deleted_at is not None:
            return reason
        validate_preserved_plan_coverage(change)
    except (
        ValidationError,
        PlanChange.DoesNotExist,
        Subscription.DoesNotExist,
        Invoice.DoesNotExist,
        Customer.DoesNotExist,
        ValueError,
        TypeError,
        AttributeError,
    ):
        return reason
    return None


def plan_change_native_refusal(
    application: HostingLimitApplication, *, parent: Mapping[str, Any] | None = None
) -> str | None:
    """New commercial dispatches need coverage; an exact already-issued parent retains repair authority."""
    if application.authority.get("kind") not in COMMERCIAL_LIMIT_AUTHORITIES:
        return None
    reason = commercial_source_refusal(application)
    if (
        reason
        and parent
        and (
            held_parent_cap_repair_issued(application, dict(parent))
            or _issued_frozen_migration_repair(application, parent)
        )
    ):
        return None
    return reason
