"""Preauthorized R removal is bound to a recorded operational base, never a desire."""

from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .hosting_limit_execution_models import HostingLimitExecution
from .hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from .hosting_limit_policy import effective_disk_limit
from .hosting_raise_models import ServiceHostingRaise
from .service_models import Service
from .virtualmin_models import VirtualminAccount


def _same_operational_base(application: HostingLimitApplication, limits: ServiceHostingLimits) -> bool:
    return bool(
        application.revision == limits.operational_revision == limits.applied_revision
        and application.disk_allowance_mib == limits.operational_disk_allowance_mib
        and application.bandwidth_allowance_mib == limits.operational_bandwidth_allowance_mib
    )


def _same_source_scope(source: HostingLimitExecution, service: Service, account: VirtualminAccount) -> bool:
    """Historical proof selects a base; the new execution must qualify current boot/epoch."""
    from .hosting_node_policy import current_quota_identity  # noqa: PLC0415 -- DB-only node identity.

    try:
        native = current_quota_identity(account.server)
        return bool(
            source.phase == "completed"
            and source.owner_id == service.customer_id
            and source.job.account_id == account.pk
            and source.job.server_id == account.server_id
            and source.identity.get("domain") == account.domain
            and all(source.identity.get(key) == native.get(key) for key in ("installation", "filesystem_uuid"))
            and source.receipt.get("identity") == source.identity
            and source.receipt.get("generation") == source.account_epoch
            and source.receipt.get("token") == str(source.job.execution_token)
        )
    except (ValidationError, ValueError, OSError, TypeError):
        return False


def _expiry_consent(service: Service, row: ServiceHostingRaise) -> HostingLimitApplication | None:
    return (
        HostingLimitApplication.objects.filter(
            service=service,
            authority__kind__in=("temporary_raise_grant", "temporary_raise_extension"),
            authority__customer_id=str(service.customer_id),
            authority__preauthorized_expiry="acknowledged",
            authority__first_granted_at=row.first_granted_at.isoformat(),
            overlay_expires_at=row.expires_at,
            overlay_extra_mib__gte=row.extra_mib,
            overlay_revision__lt=row.revision,
        )
        .order_by("-overlay_revision")
        .first()
    )


def has_expiry_consent(service: Service, row: ServiceHostingRaise) -> bool:
    return _expiry_consent(service, row) is not None


def create_expiry_cleanup(
    service: Service, limits: ServiceHostingLimits, row: ServiceHostingRaise
) -> HostingLimitApplication:
    """Caller holds Service and has atomically advanced the accepted expired R revision."""
    account = VirtualminAccount.objects.select_related("server").filter(service=service, quota_managed=True).first()
    if account is None or limits.operational_revision is None:
        raise ValidationError(_("Temporary resource expiry requires this owner's recorded operational native base."))
    source = (
        HostingLimitExecution.objects.select_related("job__hosting_limit_application")
        .filter(
            job__account=account,
            job__server_id=account.server_id,
            phase="completed",
            service_revision=limits.operational_revision,
            overlay_revision=limits.applied_overlay_revision,
            receipt=limits.verified_receipt,
        )
        .order_by("-created_at")
        .first()
    )
    consent = _expiry_consent(service, row)
    original = source.job.hosting_limit_application if source else None
    if (
        account is None
        or source is None
        or original is None
        or consent is None
        or not _same_operational_base(original, limits)
        or not _same_source_scope(source, service, account)
    ):
        raise ValidationError(_("Temporary resource expiry requires this owner's recorded operational native base."))
    existing = HostingLimitApplication.objects.filter(
        service=service, revision=original.revision, overlay_revision=row.revision
    ).first()
    if existing is not None:
        if not operational_expiry_authorized(existing, service):
            raise ValidationError(_("The existing expiry application has different operational authority."))
        return existing
    return HostingLimitApplication.objects.create(
        service=service,
        revision=original.revision,
        overlay_revision=row.revision,
        overlay_extra_mib=0,
        overlay_expires_at=row.expires_at,
        expected_plan_id=original.expected_plan_id,
        target_plan_id=original.target_plan_id,
        disk_allowance_mib=original.disk_allowance_mib,
        bandwidth_allowance_mib=original.bandwidth_allowance_mib,
        policy_version=original.policy_version,
        submission_id=uuid5(NAMESPACE_URL, f"praho:raise-expiry:{service.pk}:{original.pk}:{row.revision}"),
        reason="Remove only the preauthorized temporary allowance from the recorded operational base",
        authority={
            "kind": "temporary_raise_expiry",
            "customer_id": str(service.customer_id),
            "preauthorized_expiry": "acknowledged",
            "operational_application_id": str(original.pk),
            "operational_execution_id": str(source.pk),
            "expiry_consent_application_id": str(consent.pk),
        },
    )


def operational_expiry_authorized(application: HostingLimitApplication, service: Service) -> bool:
    """DB-only permission to remove R; this is never a fresh cap or usage observation."""
    authority = application.authority
    if authority.get("kind") != "temporary_raise_expiry" or authority.get("preauthorized_expiry") != "acknowledged":
        return False
    row = ServiceHostingRaise.objects.filter(service=service).first()
    limits = ServiceHostingLimits.objects.filter(service=service).first()
    if (
        row is None
        or limits is None
        or row.owner_id != service.customer_id
        or row.status != "expired"
        or row.expires_at > timezone.now()
        or application.overlay_revision != row.revision
        or application.overlay_extra_mib != 0
        or application.overlay_expires_at != row.expires_at
        or str(service.customer_id) != authority.get("customer_id")
        or not _same_operational_base(application, limits)
    ):
        return False
    try:
        source = HostingLimitExecution.objects.select_related("job__hosting_limit_application").get(
            pk=authority.get("operational_execution_id")
        )
        original = source.job.hosting_limit_application
        consent = _expiry_consent(service, row)
        account = VirtualminAccount.objects.select_related("server").get(service=service, quota_managed=True)
    except (HostingLimitExecution.DoesNotExist, VirtualminAccount.DoesNotExist, ValueError, ValidationError, TypeError):
        return False
    return bool(
        original is not None
        and consent is not None
        and str(original.pk) == authority.get("operational_application_id")
        and str(consent.pk) == authority.get("expiry_consent_application_id")
        and _same_operational_base(original, limits)
        and application.service_id == original.service_id
        and application.expected_plan_id == original.expected_plan_id
        and application.target_plan_id == original.target_plan_id
        and application.policy_version == original.policy_version
        and _same_source_scope(source, service, account)
    )


def pending_expiry_cleanup(service_id: int) -> HostingLimitApplication | None:
    service = Service.objects.get(pk=service_id)
    row = ServiceHostingRaise.objects.filter(service=service, status="expired").first()
    if row is None:
        return None
    limits = ServiceHostingLimits.objects.get(service=service)
    if limits.operational_revision is None:
        return None
    if limits.applied_overlay_revision == row.revision and limits.verified_at is not None:
        return None
    candidate = HostingLimitApplication.objects.filter(
        service=service,
        revision=limits.operational_revision,
        overlay_revision=row.revision,
        authority__kind="temporary_raise_expiry",
    ).first()
    return candidate if candidate and operational_expiry_authorized(candidate, service) else None


def cleanup_probe_refusal(application: HostingLimitApplication, probe: dict[str, object]) -> str | None:
    """A stand-alone expiry may never increase either current native hard cap."""
    from .hosting_limit_native import quantity  # noqa: PLC0415 -- Shared strict native integer parser.

    target = effective_disk_limit(application.disk_allowance_mib)
    if target is None or target == 0:
        return str(_("Expiry requires its recorded finite operational base."))
    try:
        if all(quantity(probe.get(key)) >= target * 1024 for key in ("uid_hard_kib", "gid_hard_kib")):
            return None
    except ValueError:
        pass
    return str(_("Expiry cannot increase either independently observed native hard cap."))
