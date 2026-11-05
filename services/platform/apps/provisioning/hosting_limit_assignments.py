"""Database-only allowance assignments; native work consumes the Service-owned outbox."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from django.core.exceptions import ValidationError
from django.db import router, transaction
from django.utils.translation import gettext_lazy as _

from .hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from .hosting_limit_policy import POLICY_VERSION, HostingAssignmentTerms, resolve_allowance

if TYPE_CHECKING:
    from .service_models import Service, ServicePlan

_ASSIGNMENT_WRITE = ContextVar("hosting_assignment_write", default=False)
_LOADED_PLAN = "_hosting_loaded_plan_id"
_LOADED_PRICE = "_hosting_loaded_price"
_PLAN_FIELDS = frozenset({"service_plan", "service_plan_id"})


def assignment_write_allowed() -> bool:
    return _ASSIGNMENT_WRITE.get()


def remember_plan(instance: Service) -> None:
    if "service_plan_id" in instance.__dict__:
        instance.__dict__[_LOADED_PLAN] = instance.service_plan_id


def remember_price(instance: Service) -> None:
    if "price" in instance.__dict__:
        instance.__dict__[_LOADED_PRICE] = instance.price


def _defaults() -> tuple[object, object]:
    from apps.settings.services import SettingsService  # noqa: PLC0415 -- Cross-app settings boundary.

    return (
        SettingsService.get_stored_setting("virtualmin.domain_quota_default_mb"),
        SettingsService.get_stored_setting("virtualmin.bandwidth_quota_default_mb"),
    )


def assignment_terms_for_plan(
    plan: ServicePlan,
    *,
    stored_defaults: tuple[object, object] | None = None,
) -> HostingAssignmentTerms:
    """Resolve a quote's target once; commercial callers freeze the returned terms."""
    defaults = stored_defaults if stored_defaults is not None else _defaults()
    disk = resolve_allowance(plan.disk_space_gb, defaults[0])
    bandwidth = resolve_allowance(plan.bandwidth_gb, defaults[1])
    if disk.mib is None or bandwidth.mib is None:
        raise ValueError("A newly accepted allowance cannot be unknown")
    return HostingAssignmentTerms(plan.pk, disk.mib, bandwidth.mib, disk.source, bandwidth.source)


def assignment_terms_for_plans(plans: Iterable[ServicePlan]) -> dict[int, HostingAssignmentTerms]:
    """Resolve a catalog batch using one shared default-settings snapshot."""
    defaults = _defaults()
    return {plan.pk: assignment_terms_for_plan(plan, stored_defaults=defaults) for plan in plans}


def _terms_snapshot(service: Service, terms: HostingAssignmentTerms) -> ServiceHostingLimits:
    return ServiceHostingLimits(
        service_id=service.pk,
        assigned_plan_id=terms.plan_id,
        disk_allowance_mib=terms.disk_allowance_mib,
        bandwidth_allowance_mib=terms.bandwidth_allowance_mib,
        disk_source=terms.disk_source,
        bandwidth_source=terms.bandwidth_source,
        policy_version=terms.policy_version,
        operational_revision=1,
        operational_disk_allowance_mib=terms.disk_allowance_mib,
        operational_bandwidth_allowance_mib=terms.bandwidth_allowance_mib,
    )


def _snapshot(service: Service, plan: ServicePlan, defaults: tuple[object, object]) -> ServiceHostingLimits:
    return _terms_snapshot(service, assignment_terms_for_plan(plan, stored_defaults=defaults))


def capture_initial_limits(services: Iterable[Service], *, using: str) -> None:
    """Called inside the insert transaction, including the supported bulk-create path."""
    from .service_models import ServicePlan  # noqa: PLC0415 -- Service imports its save boundary.

    records = tuple(services)
    if not records:
        return
    if not transaction.get_connection(using).in_atomic_block:
        raise RuntimeError("Initial hosting allowances must be captured atomically with their Service")
    # Pin one statement-visible committed catalog snapshot. The new Service and
    # allowance still commit atomically; later catalog edits cannot rewrite it.
    # Taking NO KEY UPDATE here serializes unrelated Service insertions with
    # provisioning's configuration read lock, beyond the FK's KEY SHARE check.
    plans = {
        plan.pk: plan
        for plan in ServicePlan.objects.using(using)
        .filter(pk__in={service.service_plan_id for service in records})
        .order_by("pk")
    }
    defaults = _defaults()
    snapshots = ServiceHostingLimits.objects.using(using).bulk_create(
        [_snapshot(service, plans[service.service_plan_id], defaults) for service in records]
    )
    from .hosting_limit_signals import audit_initial_limits  # noqa: PLC0415 -- Bulk inserts have no Django signals.

    audit_initial_limits(snapshots)
    for service in records:
        remember_plan(service)
        remember_price(service)


def _preserve_unedited_price(instance: Service, fields: set[str] | None, options: dict[str, Any]) -> None:
    if fields is not None or _LOADED_PRICE not in instance.__dict__:
        return
    if instance.__dict__.get("price") != instance.__dict__[_LOADED_PRICE]:
        return
    selected = options.get("update_fields")
    if selected is None:
        selected = {
            field.name
            for field in instance._meta.concrete_fields
            if not field.primary_key and field.attname not in instance.get_deferred_fields()
        }
    options["update_fields"] = set(selected) - {"price"}


def save_service_with_limits(
    instance: Service, save: Callable[..., None], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> None:
    """Preserve the ownership fence and prevent incidental/stale saves reverting a plan."""
    from .hosted_zone_ownership import save_with_ownership  # noqa: PLC0415 -- Avoid model import cycle.

    options = dict(kwargs)
    positional = ("force_insert", "force_update", "using", "update_fields")
    if len(args) > len(positional):
        raise TypeError("Model.save() accepts at most four positional arguments")
    for name, value in zip(positional, args, strict=False):
        if name in options:
            raise TypeError(f"save() received {name} twice")
        options[name] = value
    using = options.get("using") or router.db_for_write(type(instance), instance=instance)
    if instance._state.adding:
        with transaction.atomic(using=using):
            # An explicitly supplied existing PK must not turn an insert into a bypassing update.
            if instance.pk is not None and type(instance).objects.using(using).filter(pk=instance.pk).exists():
                raise ValidationError(_("A saved service must be loaded before it can be changed."))
            save_with_ownership(instance, "service", save, (), options)
            capture_initial_limits((instance,), using=using)
        return
    fields = options.get("update_fields")
    if fields is not None:
        fields = set(fields)
        options["update_fields"] = fields
    original_intent = fields
    if not assignment_write_allowed() and (fields is None or _PLAN_FIELDS.intersection(fields)):
        desired = instance.__dict__.get("service_plan_id")
        if desired is not None:
            loaded = instance.__dict__.get(_LOADED_PLAN)
            if loaded is None:
                loaded = (
                    type(instance)
                    .objects.using(using)
                    .filter(pk=instance.pk)
                    .values_list("service_plan_id", flat=True)
                    .get()
                )
            if desired != loaded:
                raise ValidationError(_("Use an explicit hosting plan assignment to change this service's plan."))
        selected = (
            set(fields)
            if fields is not None
            else {
                field.name
                for field in instance._meta.concrete_fields
                if not field.primary_key and field.attname not in instance.get_deferred_fields()
            }
        )
        options["update_fields"] = selected - _PLAN_FIELDS
    _preserve_unedited_price(instance, fields, options)
    save_with_ownership(instance, "service", save, (), options, caller_intent=original_intent)
    remember_plan(instance)
    remember_price(instance)


def plan_change_refusal(service: Service) -> str | None:
    """Database-only prerequisite. Commercial authority and native readiness are caller-specific."""
    if service.status not in {"pending", "active", "suspended"}:
        return str(_("This service cannot receive a new resource assignment in its current state."))
    if not ServiceHostingLimits.objects.using(service._state.db).filter(service_id=service.pk).exists():
        return str(_("Import and review the service's assigned allowance first."))
    return None


def request_service_plan_change(  # noqa: PLR0913 -- Explicit revision and idempotency authority.
    *,
    service: Service,
    target_plan_id: int,
    expected_revision: int,
    submission_id: UUID,
    reason: str,
    authority: dict[str, str],
    accepted_terms: HostingAssignmentTerms | None = None,
) -> HostingLimitApplication:
    """Accept one assignment and durable application intent without locking any native row.

    Caller holds Customer/Subscription locks where needed. The only locks acquired here
    are Service, pinned allowances and the configuration plan. No network/queue I/O occurs.
    """
    from .service_models import Service, ServicePlan  # noqa: PLC0415 -- Database ownership boundary.

    using = router.db_for_write(Service, instance=service)
    if not transaction.get_connection(using).in_atomic_block:
        raise RuntimeError("Plan assignments require an existing transaction")
    if not reason.strip() or not authority:
        raise ValidationError(_("An explicit reason and authority are required for a resource assignment."))
    if accepted_terms is not None and accepted_terms.plan_id != target_plan_id:
        raise ValueError("The accepted hosting terms belong to another target plan")
    expected_customer = service.__dict__.get("customer_id")
    if type(expected_customer) is not int:
        raise ValidationError(_("Load and authorize the service's current owner before assigning resources."))
    locked = Service.objects.using(using).select_for_update(of=("self",), no_key=True).get(pk=service.pk)
    if locked.customer_id != expected_customer:
        raise ValidationError(_("The service's owner changed. Reload and authorize the current owner."))
    recorded_authority = {**authority, "customer_id": str(expected_customer)}
    if accepted_terms is not None:
        recorded_authority["accepted_terms_hash"] = hashlib.sha256(
            json.dumps(accepted_terms.as_snapshot(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
    previous = HostingLimitApplication.objects.using(using).filter(service=locked, submission_id=submission_id).first()
    if previous is not None:
        if (
            previous.target_plan_id != target_plan_id
            or previous.reason != reason
            or previous.authority != recorded_authority
            or previous.revision != expected_revision + 1
            or (
                accepted_terms is not None
                and (
                    previous.disk_allowance_mib != accepted_terms.disk_allowance_mib
                    or previous.bandwidth_allowance_mib != accepted_terms.bandwidth_allowance_mib
                    or previous.policy_version != accepted_terms.policy_version
                )
            )
        ):
            raise ValidationError(_("This submission identity was already used for different assignment terms."))
        return previous
    refusal = plan_change_refusal(locked)
    if refusal:
        raise ValidationError(refusal)
    limits = ServiceHostingLimits.objects.using(using).select_for_update(of=("self",)).get(service=locked)
    if limits.revision != expected_revision:
        raise ValidationError(_("The assigned allowance changed. Reload before submitting again."))
    plan = ServicePlan.objects.using(using).select_for_update(of=("self",), no_key=True).get(pk=target_plan_id)
    if not plan.is_active:
        raise ValidationError(_("The target hosting plan is inactive."))
    target = (
        _terms_snapshot(locked, accepted_terms) if accepted_terms is not None else _snapshot(locked, plan, _defaults())
    )
    from .hosting_raise_service import compose_assignment_raise  # noqa: PLC0415 -- Service-only composed authority.

    overlay = compose_assignment_raise(locked, target.disk_allowance_mib)
    application = HostingLimitApplication.objects.using(using).create(
        service=locked,
        revision=limits.revision + 1,
        submission_id=submission_id,
        expected_plan_id=locked.service_plan_id,
        target_plan_id=plan.pk,
        disk_allowance_mib=target.disk_allowance_mib,
        bandwidth_allowance_mib=target.bandwidth_allowance_mib,
        policy_version=POLICY_VERSION,
        reason=reason,
        authority=recorded_authority,
        **overlay.application_fields(),
    )
    token = _ASSIGNMENT_WRITE.set(True)
    try:
        locked.service_plan = plan
        locked.save(using=using, update_fields=["service_plan", "updated_at"])
    finally:
        _ASSIGNMENT_WRITE.reset(token)
    limits.revision = application.revision
    limits.assigned_plan_id = plan.pk
    limits.disk_allowance_mib = target.disk_allowance_mib
    limits.bandwidth_allowance_mib = target.bandwidth_allowance_mib
    limits.disk_source = target.disk_source
    limits.bandwidth_source = target.bandwidth_source
    limits.policy_version = POLICY_VERSION
    limits.save(
        using=using,
        update_fields=[
            "revision",
            "assigned_plan_id",
            "disk_allowance_mib",
            "bandwidth_allowance_mib",
            "disk_source",
            "bandwidth_source",
            "policy_version",
            "updated_at",
        ],
    )
    return application


def reassign_hosting_limit_owner(service_id: int, customer_id: int, *, using: str) -> None:
    """Ownership fences hold Account/Name/Service already. Invalidate old assignment authority too."""
    if not transaction.get_connection(using).in_atomic_block:
        raise RuntimeError("Hosting ownership changes require their existing ownership transaction")
    limits = (
        ServiceHostingLimits.objects.using(using).select_for_update(of=("self",)).filter(service_id=service_id).first()
    )
    if limits is None:
        return
    limits.revision += 1
    limits.save(using=using, update_fields=["revision", "updated_at"])
    from .hosting_raise_service import compose_assignment_raise  # noqa: PLC0415
    from .service_models import Service  # noqa: PLC0415

    service = Service.objects.using(using).get(pk=service_id)
    overlay = compose_assignment_raise(service, limits.disk_allowance_mib)
    HostingLimitApplication.objects.using(using).create(
        service_id=service_id,
        revision=limits.revision,
        submission_id=uuid4(),
        expected_plan_id=limits.assigned_plan_id,
        target_plan_id=limits.assigned_plan_id,
        disk_allowance_mib=limits.disk_allowance_mib,
        bandwidth_allowance_mib=limits.bandwidth_allowance_mib,
        policy_version=limits.policy_version,
        reason="Hosting ownership changed",
        authority={"kind": "ownership_transfer", "customer_id": str(customer_id)},
        **overlay.application_fields(),
    )
