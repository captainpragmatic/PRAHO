"""Durable quota lane: Account→Server→Service, then native I/O with no DB locks.

Money transactions publish only immutable Service-owned applications. This module
never locks a Customer, Subscription or financial document. An issued native token
retains account ownership and capacity until terminal receipt or permanent fence.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.types import Err, Ok, Result
from apps.infrastructure.node_maintenance_gate import maintenance_refusal, native_account_observation_refusal

from .hosting_limit_execution_models import HostingLimitExecution
from .hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from .hosting_limit_native import (
    canonical_observation,
    quantity,
    validate_identity,
    verify_quota_probe,
    verify_quota_receipt,
)
from .hosting_limit_policy import BYTES_PER_MIB, OVERLAY_QUOTA_PROTOCOL, effective_disk_limit
from .service_models import Service
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from .virtualmin_security import connection_identity

if TYPE_CHECKING:
    from .virtualmin_usage_models import UsageReading

logger = logging.getLogger(__name__)
OPERATION = "apply_hosting_limits"
ACTIVE_PHASES = ("prepared", "issued", "attention")
EXECUTION_BUDGET = timedelta(minutes=15)


def _application(job: VirtualminProvisioningJob) -> HostingLimitApplication:
    application = job.hosting_limit_application
    if application is None:
        raise ValidationError(_("The native quota job has no immutable hosting application."))
    return application


def _adoption_authorized(application: HostingLimitApplication, owner_id: int) -> bool:
    """An explicit account handover needs the real named staff exception authority."""
    from apps.tickets.models import Ticket  # noqa: PLC0415 -- Read-only human authority recheck; no financial locks.
    from apps.users.models import User  # noqa: PLC0415

    authority = application.authority
    if (
        authority.get("kind") != "staff_resource_override"
        or authority.get("adopt_existing_native_limits") != "acknowledged"
        or authority.get("billing_unchanged") != "acknowledged"
        or not application.reason.strip()
    ):
        return False
    try:
        actor = User.objects.filter(pk=authority.get("staff_user_id"), is_active=True).first()
        return bool(
            actor is not None
            and (actor.is_superuser or actor.staff_role in {"admin", "manager"})
            and Ticket.objects.filter(pk=authority.get("ticket_id"), customer_id=owner_id).exists()
        )
    except (ValueError, ValidationError, TypeError):
        return False


def _managed_or_admitted_parent(
    account: VirtualminAccount,
    application: HostingLimitApplication,
    owner_id: int,
    parent: dict[str, Any],
) -> bool:
    if parent.get("job_id"):
        from .hosting_parent_limits import held_parent_application_matches  # noqa: PLC0415

        if not held_parent_application_matches(application, parent):
            return False
    if account.quota_managed:
        return True
    # A new domain or explicitly reviewed move is a first-install authority,
    # unlike discovery/import or an ordinary restore of an unmanaged account.
    if parent.get("migration_id"):
        return True
    if (
        parent.get("job_id")
        and VirtualminProvisioningJob.objects.filter(
            pk=parent["job_id"],
            account_id=account.pk,
            operation="create_domain",
        ).exists()
    ):
        return True
    return _adoption_authorized(application, owner_id)


def quota_transport_refusal(  # noqa: PLR0911 -- Each refused authority retains native exclusion.
    server: VirtualminServer,
    variables: dict[str, Any] | None,
) -> str | None:
    """The shared SSH runner accepts only an exact committed native execution."""
    values = variables or {}
    action, request = values.get("quota_action"), values.get("quota_request")
    if action not in {"probe", "apply", "fence"} or not isinstance(request, dict):
        return "An exact admitted quota action is required."
    try:
        token = UUID(request["token"])
        generation = quantity(request["generation"])
    except (KeyError, ValueError, TypeError, AttributeError):
        return "The quota execution token or epoch is invalid."
    execution = HostingLimitExecution.objects.filter(
        job__execution_token=token,
        job__server_id=server.pk,
        account_epoch=generation,
    ).first()
    if execution is None:
        from .hosting_safety_observation import (  # noqa: PLC0415 -- Separate durable read-only job contract.
            observation_transport_allowed,
        )

        return (
            None
            if observation_transport_allowed(server, values)
            else "The quota execution or original node connection is no longer current."
        )
    if connection_identity(server) != execution.connection_identity:
        return "The quota execution or original node connection is no longer current."
    account = execution.job.account
    if account is None:
        return "The quota execution has no account identity."
    if action in {"apply", "fence"}:
        required = "issued" if action == "apply" else "attention"
        if execution.phase != required or execution.request != request:
            return "The native quota request differs from its durable execution."
    elif (
        execution.phase != "prepared"
        or not isinstance(request.get("identity"), dict)
        or set(request) != {"identity", "token", "generation", "disk_limit_kib", "bandwidth_limit_bytes"}
        or set(request["identity"]) != (set(execution.identity) - {"boot_id"}) | {"domain_id", "domain"}
        or any(request["identity"].get(key) != value for key, value in execution.identity.items() if key != "boot_id")
        or request["identity"].get("domain") != account.domain
        or not isinstance(request["identity"].get("domain_id"), str)
        or not request["identity"]["domain_id"].isdigit()
        or request.get("disk_limit_kib") != 0
        or request.get("bandwidth_limit_bytes") != 0
    ):
        return "The read-only quota probe differs from its prepared account identity."
    return None


def _account_busy(
    account: VirtualminAccount,
    *,
    ignore_job_id: UUID | None = None,
    parent: dict[str, Any] | None = None,
    transfer_job_id: UUID | None = None,
) -> bool:
    from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415

    parent = parent or {}
    migrations = VirtualminMigration.objects.filter(account_id=account.pk).exclude(
        status__in=("completed", "failed", "rolled_back")
    )
    if parent.get("migration_id"):
        migrations = migrations.exclude(pk=parent["migration_id"])
    if migrations.exists():
        return True
    ignored = [value for value in (ignore_job_id, parent.get("job_id"), transfer_job_id) if value]
    if (
        VirtualminProvisioningJob.objects.filter(
            account_id=account.pk,
            operation__in=("backup_domain", "restore_domain", "delete_domain", OPERATION),
            status__in=("pending", "running", "attention"),
        )
        .exclude(pk__in=ignored)
        .exists()
    ):
        return True
    # These ordinary lifecycle operations historically use a narrower admission
    # predicate. A quota writer must still yield to their committed native claims.
    jobs = VirtualminProvisioningJob.objects.filter(
        account_id=account.pk,
        operation__in=("create_domain", "suspend_domain", "unsuspend_domain"),
        status__in=("pending", "running", "attention"),
    )
    return jobs.exclude(pk__in=ignored).exists()


def _parent_refusal(account: VirtualminAccount, parent: dict[str, Any]) -> str | None:  # noqa: PLR0911 -- Independent current-claim, target, lease and immutable-review refusals.
    """An archive writer may repair quota as an explicitly bound child of its own lane."""
    if parent.get("job_id"):
        job = VirtualminProvisioningJob.objects.filter(pk=parent["job_id"], account_id=account.pk).first()
        if (
            job is None
            or job.status not in {"running", "completed"}
            or job.operation not in {"create_domain", "restore_domain"}
        ):
            return "The parent create/restore no longer owns its native account claim."
        if str(job.execution_token or "") != parent.get("token"):
            return "The parent native execution token changed."
        if str(job.server_id) != parent.get("native_server_id"):
            return "The parent native target changed."
    if parent.get("migration_id"):
        from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415

        migration = VirtualminMigration.objects.filter(pk=parent["migration_id"], account_id=account.pk).first()
        if (
            migration is None
            or str(migration.lease_token or "") != parent.get("token")
            or migration.status not in {"activating", "verifying", "restoring"}
            or migration.worker_lease_expires_at is None
            or migration.worker_lease_expires_at <= timezone.now()
            or str(migration.target_server_id) != parent.get("native_server_id")
            or account.server_id not in {migration.source_server_id, migration.target_server_id}
        ):
            return "The parent migration no longer owns this canonical target and live native lease."
        frozen = migration.pre_migration_snapshot.get("hosting_limits")
        if not isinstance(frozen, dict) or parent.get("approved_application_id") != frozen.get("application_id"):
            return "The migration quota application has no immutable reviewed ceiling."
        from .hosting_limit_review import (  # noqa: PLC0415 -- Reviewed derivative depends on the native execution model.
            reviewed_application_matches,
        )

        frozen_id = parent.get("frozen_application_id")
        application = (
            HostingLimitApplication.objects.filter(pk=frozen_id).first() if isinstance(frozen_id, str) else None
        )
        if application is None or not reviewed_application_matches(migration, application):
            return "The migration quota application exceeds or differs from its immutable reviewed ceiling."
    return None


def freeze_migration_limits(account: VirtualminAccount) -> dict[str, Any]:
    """Freeze reviewed application/ceiling; future assignments never rewrite this record."""
    from .hosting_limit_tasks import current_application  # noqa: PLC0415

    application = current_application(account.service_id)
    return {
        "schema": 2,
        "application_id": str(application.pk),
        "base_revision": application.revision,
        "overlay_revision": application.overlay_revision,
        "overlay_extra_mib": application.overlay_extra_mib,
        "overlay_expires_at": application.overlay_expires_at.isoformat() if application.overlay_expires_at else None,
        "owner_id": str(application.authority.get("customer_id")),
        "disk_cap_mib": effective_disk_limit(application.disk_allowance_mib, extra_mib=application.overlay_extra_mib),
        "bandwidth_mib": application.bandwidth_allowance_mib,
    }


def _frozen_parent_application(application: HostingLimitApplication, parent: dict[str, Any]) -> bool:
    if parent.get("job_id"):
        from .hosting_parent_limits import held_parent_application_matches  # noqa: PLC0415

        return held_parent_application_matches(application, parent)
    if not parent.get("migration_id") or parent.get("frozen_application_id") != str(application.pk):
        return False
    from .hosting_limit_review import reviewed_application_matches  # noqa: PLC0415
    from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415

    migration = VirtualminMigration.objects.filter(pk=parent["migration_id"]).first()
    return bool(
        migration is not None
        and parent.get("approved_application_id")
        == migration.pre_migration_snapshot.get("hosting_limits", {}).get("application_id")
        and reviewed_application_matches(migration, application)
    )


def _operational_cleanup(application: HostingLimitApplication, service: Service) -> bool:
    from .hosting_raise_expiry import (  # noqa: PLC0415 -- DB-only cycle boundary.
        operational_expiry_authorized,
    )

    return operational_expiry_authorized(application, service)


def quota_operation_refusal(server_id: UUID) -> str | None:
    """Node-wide policy changes use this while holding the Server row."""
    if VirtualminProvisioningJob.objects.filter(
        operation=OPERATION, server_id=server_id, status__in=("pending", "running", "attention")
    ).exists():
        return "A hosting quota operation owns this server; verify or fence it first."
    return None


def account_has_active_quota(account: VirtualminAccount) -> bool:
    return (
        VirtualminProvisioningJob.objects.using(account._state.db)
        .filter(
            account_id=account.pk,
            operation=OPERATION,
            status__in=("pending", "running", "attention"),
        )
        .exists()
    )


def _node_policy(server: VirtualminServer) -> Any:
    from .hosting_node_policy import managed_quota_refusal  # noqa: PLC0415 -- Optional capability owner.
    from .hosting_node_policy_models import NodeHostingPolicy  # noqa: PLC0415

    if refusal := managed_quota_refusal(server):
        raise ValidationError(refusal)
    return NodeHostingPolicy.objects.get(server_id=server.pk)


def _lock_context(execution: HostingLimitExecution) -> tuple[VirtualminAccount, VirtualminServer, Service]:
    """Caller owns an atomic block; execution itself is only an unlocked hint."""
    hint = VirtualminProvisioningJob.objects.get(pk=execution.job_id)
    if hint.account_id is None:
        raise ValidationError(_("The native quota execution has no account."))
    account = VirtualminAccount.objects.select_for_update(of=("self",), no_key=True).get(pk=hint.account_id)
    servers = list(
        VirtualminServer.objects.select_for_update(of=("self",))
        .filter(
            pk__in=(account.server_id, hint.server_id),
        )
        .order_by("pk")
    )
    server = next(node for node in servers if node.pk == hint.server_id)
    service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=account.service_id)
    return account, server, service


def _commercial_refusal(application: HostingLimitApplication, parent: dict[str, Any]) -> str | None:
    from .hosting_limit_commercial import quota_dispatch_refusal  # noqa: PLC0415 -- DB-only composed base provenance.

    return quota_dispatch_refusal(application, parent)


def _authority_refusal(  # noqa: C901, PLR0911, PLR0912 -- Independent owner, base/overlay, native-lane, provider and adopted-policy refusals.
    execution: HostingLimitExecution, account: VirtualminAccount, server: VirtualminServer, service: Service
) -> str | None:
    job = VirtualminProvisioningJob.objects.get(pk=execution.job_id)
    parent = job.parameters.get("quota_parent", {})
    if not _managed_or_admitted_parent(account, _application(job), service.customer_id, parent):
        return "This existing account has not been explicitly adopted for managed quotas."
    if (
        job.account_id != account.pk
        or job.server_id != server.pk
        or account.quota_generation != execution.account_epoch
        or service.customer_id != execution.owner_id
        or service.pk != _application(job).service_id
    ):
        return "The quota owner or canonical node changed; reconcile the current application."
    if account.server_id != server.pk and not parent:
        return "The canonical node changed; reconcile the current application."
    if parent and str(account.server_id) not in {parent.get("account_server_id"), parent.get("native_server_id")}:
        return "The parent quota operation no longer owns this account's source/target binding."
    limits = ServiceHostingLimits.objects.get(service_id=service.pk)
    if (
        limits.revision != execution.service_revision
        and not _frozen_parent_application(_application(job), parent)
        and not _operational_cleanup(_application(job), service)
    ):
        return "A newer hosting allowance supersedes this native application."
    if _application(job).authority.get("kind") == "temporary_raise_expiry" and not _operational_cleanup(
        _application(job), service
    ):
        return "The expiry cleanup no longer owns its recorded operational base."
    from .hosting_raise_service import application_raise_refusal  # noqa: PLC0415 -- Exact base/overlay composition.

    if refusal := application_raise_refusal(_application(job), service):
        return refusal
    if service.status not in {"active", "suspended", "provisioning", "pending"} or account.status == "terminated":
        return "The hosting service no longer permits a quota application."
    if refusal := _parent_refusal(account, parent):
        return refusal
    if account.restore_hold or _account_busy(account, ignore_job_id=job.pk, parent=parent):
        return "Another native operation owns the account."
    if refusal := maintenance_refusal(server.pk):
        return refusal
    try:
        policy = _node_policy(server)
    except ValidationError as error:
        return str(error)
    if (
        policy.revision != execution.node_policy_revision
        or connection_identity(server) != execution.connection_identity
    ):
        return "The adopted node policy or connection identity changed."
    from .hosting_limit_provider_recovery import (  # noqa: PLC0415
        provider_binding,
    )

    if job.parameters.get("quota_provider") and job.parameters["quota_provider"] != provider_binding(server):
        return "The original provider deployment or resource authority changed."
    # A financial change cannot discard the terminal receipt of an issued
    # command or prove that an uncertain command stopped.
    return _commercial_refusal(_application(job), parent) if execution.phase == "prepared" else None


def _parent_requalification_transfer(  # noqa: PLR0911 -- Closed original review, never-issued journal and native identity guards.
    application: HostingLimitApplication,
    account: VirtualminAccount,
    server: VirtualminServer,
    service: Service,
    parent: dict[str, Any],
) -> HostingLimitExecution | None:
    """Carry a never-issued parent claim after explicit same-node reboot qualification.

    The caller holds Account→sortedServers→Service. A prepared request is never
    authorized to mutate through the SSH gate; only an issued, complete request
    can dispatch. A smaller reviewed overlay may replace a still-probing child;
    the old complete request never existed. The same transaction retires that
    attempt and carries its full capacity into the successor.
    """
    if not parent or _parent_refusal(account, parent):
        return None
    try:
        policy = _node_policy(server)
    except ValidationError:
        return None
    ownership = {"job__hosting_limit_application_id": application.pk}
    if parent.get("migration_id") and parent.get("approved_application_id"):
        ownership = {
            "job__parameters__quota_parent__migration_id": parent["migration_id"],
            "job__parameters__quota_parent__approved_application_id": parent["approved_application_id"],
        }
    elif parent.get("job_id") and parent.get("approved_application_id"):
        ownership = {
            "job__parameters__quota_parent__job_id": parent["job_id"],
            "job__parameters__quota_parent__approved_application_id": parent["approved_application_id"],
        }
    candidates = list(
        HostingLimitExecution.objects.select_for_update(of=("self",))
        .filter(
            job__account_id=account.pk,
            job__server_id=server.pk,
            phase__in=ACTIVE_PHASES,
            **ownership,
        )
        .order_by("pk")[:2]
    )
    if len(candidates) != 1:
        return None
    old = candidates[0]
    old_parent = old.job.parameters.get("quota_parent", {})
    original = old.job.hosting_limit_application
    if original is None:
        return None
    derived = original.pk != application.pk
    if derived:
        from .hosting_limit_review import (  # noqa: PLC0415
            reviewed_application_history_matches,
            reviewed_job_application_matches,
        )
        from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415

        if parent.get("migration_id"):
            migration = VirtualminMigration.objects.filter(pk=parent["migration_id"]).first()
            reviewed = migration is not None and reviewed_application_history_matches(migration, original)
        else:
            job_id = parent.get("job_id")
            parent_job = (
                VirtualminProvisioningJob.objects.filter(pk=job_id).first() if isinstance(job_id, str) else None
            )
            reviewed = parent_job is not None and reviewed_job_application_matches(
                parent_job, original, historical=True
            )
        if (
            not reviewed
            or application.overlay_revision <= original.overlay_revision
            or application.overlay_extra_mib > original.overlay_extra_mib
            or original.overlay_expires_at is None
            or application.overlay_expires_at is None
            or application.overlay_expires_at > original.overlay_expires_at
        ):
            return None
    from .hosting_limit_provider_recovery import (  # noqa: PLC0415 -- Database-only original provider binding.
        provider_binding,
    )

    owned_phase = (old.phase, old.job.status) == ("attention", "attention") or (
        derived and (old.phase, old.job.status) == ("prepared", "running")
    )
    if (
        not owned_phase
        or old.issued_at is not None
        or old.request
        or old.receipt
        or old.job.execution_token is None
        or not old.reserved_bytes
        or old.reservation_released_at is not None
        or old.account_epoch != account.quota_generation
        or old.service_revision != application.revision
        or old.owner_id != service.customer_id
        or old.overlay_revision != original.overlay_revision
        or old.job.parameters.get("overlay_revision") != original.overlay_revision
        or old.job.parameters.get("overlay_extra_mib", 0) != original.overlay_extra_mib
        or old.job.parameters.get("overlay_expires_at")
        != (original.overlay_expires_at.isoformat() if original.overlay_expires_at else None)
        or not isinstance(old_parent, dict)
        or {key: value for key, value in old_parent.items() if key not in {"token", "frozen_application_id"}}
        != {key: value for key, value in parent.items() if key not in {"token", "frozen_application_id"}}
        or not (old_parent.get("migration_id") or old_parent.get("job_id"))
        or old.node_policy_revision > policy.revision
        or old.connection_identity != connection_identity(server)
        or old.job.parameters.get("quota_provider") != provider_binding(server)
        or set(old.identity) != {"installation", "filesystem_uuid", "boot_id"}
        or any(old.identity.get(key) != policy.quota_evidence.get(key) for key in ("installation", "filesystem_uuid"))
        or (not derived and old.identity["boot_id"] == policy.quota_evidence.get("boot_id"))
        or (
            old.identity["boot_id"] != policy.quota_evidence.get("boot_id")
            and old.node_policy_revision >= policy.revision
        )
    ):
        return None
    return old


def admit_application(  # noqa: C901, PLR0911, PLR0912 -- Explicit stale, duplicate, adoption, retry-budget, atomic reservation transfer and held admission refusals.
    application_id: UUID | str,
    *,
    parent: dict[str, Any] | None = None,
    native_server_id: UUID | None = None,
) -> HostingLimitExecution | None:
    """Idempotent outbox consumer. Unsupported/held nodes remain pending, with no I/O."""
    application = HostingLimitApplication.objects.get(pk=application_id)
    account_hint = (
        VirtualminAccount.objects.filter(service_id=application.service_id).values_list("pk", flat=True).first()
    )
    if account_hint is None:
        return None
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update(of=("self",), no_key=True).get(pk=account_hint)
        nodes = list(
            VirtualminServer.objects.select_for_update(of=("self",))
            .filter(
                pk__in=(account.server_id, native_server_id or account.server_id),
            )
            .order_by("pk")
        )
        server = next(node for node in nodes if node.pk == (native_server_id or account.server_id))
        service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=account.service_id)
        limits = ServiceHostingLimits.objects.get(service_id=service.pk)
        if application.service_id != service.pk or (
            limits.revision != application.revision
            and not _frozen_parent_application(application, parent or {})
            and not _operational_cleanup(application, service)
        ):
            return None
        if application.authority.get("kind") == "temporary_raise_expiry" and not _operational_cleanup(
            application, service
        ):
            return None
        if str(application.authority.get("customer_id")) != str(service.customer_id):
            return None
        if not _managed_or_admitted_parent(account, application, service.customer_id, parent or {}):
            return None
        transfer = _parent_requalification_transfer(application, account, server, service, parent or {})
        candidates = HostingLimitExecution.objects.filter(
            job__hosting_limit_application_id=application.pk,
            job__server_id=server.pk,
            phase__in=(*ACTIVE_PHASES, "completed"),
        )
        if (
            limits.verified_at is None
            or limits.applied_revision != application.revision
            or limits.applied_overlay_revision != application.overlay_revision
        ):
            candidates = candidates.exclude(phase="completed")
        if parent:
            candidates = candidates.filter(job__parameters__quota_parent=parent)
        if transfer is not None:
            candidates = candidates.exclude(pk=transfer.pk)
        existing = candidates.order_by("-created_at").first()
        if existing is not None:
            if not parent and existing.job.parameters.get("quota_parent") and existing.phase != "completed":
                return None
            if existing.phase == "prepared" and (refusal := _commercial_refusal(application, parent or {})):
                _fail_unissued(existing.pk, refusal)
                existing.refresh_from_db()
            return existing
        failed = (
            HostingLimitExecution.objects.filter(
                job__hosting_limit_application_id=application.pk,
                job__server_id=server.pk,
                job__status="failed",
                phase="superseded",
                job__parameters__quota_parent=parent or {},
            )
            .order_by("-created_at")
            .first()
        )
        retry_count = 0
        if failed is not None:
            previous = failed.job
            if previous.next_retry_at is not None and previous.next_retry_at > timezone.now():
                return None
            retry_count = previous.retry_count + 1
        if _parent_refusal(account, parent or {}):
            return None
        if (
            account.restore_hold
            or _account_busy(account, parent=parent, transfer_job_id=transfer.job_id if transfer else None)
            or native_account_observation_refusal(account.pk)
            or maintenance_refusal(server.pk)
        ):
            return None
        policy = _node_policy(server)
        if service.status not in {"active", "suspended", "provisioning", "pending"} or account.status == "terminated":
            return None
        if application.disk_allowance_mib is None or application.bandwidth_allowance_mib is None:
            return None
        if refusal := _commercial_refusal(application, parent or {}):
            raise ValidationError(refusal)
        account.quota_generation += 1
        account.save(update_fields=["quota_generation", "updated_at"])
        now, token = timezone.now(), uuid4()
        from .hosting_limit_provider_recovery import (  # noqa: PLC0415
            provider_binding,
        )

        job = VirtualminProvisioningJob.objects.create(
            operation=OPERATION,
            account=account,
            server=server,
            hosting_limit_application=application,
            correlation_id="hosting-limits-" + str(application.pk),
            status="running",
            claimed_at=now,
            started_at=now,
            execution_token=token,
            execution_deadline=now + EXECUTION_BUDGET,
            retry_count=retry_count,
            parameters={
                "revision": application.revision,
                "overlay_revision": application.overlay_revision,
                "overlay_extra_mib": application.overlay_extra_mib,
                "overlay_expires_at": application.overlay_expires_at.isoformat()
                if application.overlay_expires_at
                else None,
                "quota_parent": parent or {},
                "quota_provider": provider_binding(server),
                **({"quota_reservation_from": str(transfer.pk)} if transfer is not None else {}),
            },
        )
        from .hosting_node_policy import current_quota_identity  # noqa: PLC0415

        execution = HostingLimitExecution.objects.create(
            job=job,
            service_revision=application.revision,
            overlay_revision=application.overlay_revision,
            owner_id=service.customer_id,
            account_epoch=account.quota_generation,
            node_policy_revision=policy.revision,
            connection_identity=connection_identity(server),
            identity=current_quota_identity(server),
            reserved_bytes=transfer.reserved_bytes if transfer is not None else 0,
        )
        if transfer is not None:
            _release(
                transfer,
                phase="superseded",
                status="cancelled",
                message="Never-issued reservation transferred after explicit node requalification to "
                + str(execution.pk),
            )
        return execution


def _release(execution: HostingLimitExecution, *, phase: str, status: str, message: str) -> None:
    now = timezone.now()
    previous_phase = execution.phase
    execution.phase, execution.finished_at = phase, now
    execution.reservation_released_at = execution.reservation_released_at or now
    execution.save(update_fields=["phase", "finished_at", "reservation_released_at", "updated_at"])
    # fsm-bypass: CharField job; locked execution's terminal proof releases its native claim.
    VirtualminProvisioningJob.objects.filter(pk=execution.job_id).update(
        status=status,
        status_message=message,
        completed_at=now,
        next_retry_at=None,
        updated_at=now,
    )
    if phase not in {previous_phase, "fenced"}:
        _audit_status(execution.job_id)


def _audit_status(job_id: UUID) -> None:
    from .virtualmin_signals import (  # noqa: PLC0415
        audit_job_status_transition,
    )

    job = VirtualminProvisioningJob.objects.select_related("account", "server").get(pk=job_id)
    audit_job_status_transition(job)


def _fail_unissued(execution_id: UUID, message: str) -> None:
    hint = HostingLimitExecution.objects.get(pk=execution_id)
    with transaction.atomic():
        _lock_context(hint)
        execution = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution_id)
        if execution.phase == "prepared" and execution.issued_at is None:
            if execution.reserved_bytes and _parent_still_active(execution):
                execution.phase = "attention"
                execution.save(update_fields=["phase", "updated_at"])
                # fsm-bypass: CharField job; locked parent operation retains capacity and attention ownership.
                VirtualminProvisioningJob.objects.filter(pk=execution.job_id).update(
                    status="attention",
                    status_message=message + " Resolve the parent native operation before releasing capacity.",
                    next_retry_at=None,
                    updated_at=timezone.now(),
                )
                _audit_status(execution.job_id)
                return
            _release(execution, phase="superseded", status="failed", message=message)
            job = VirtualminProvisioningJob.objects.get(pk=execution.job_id)
            if job.retry_count + 1 >= job.max_retries:
                execution.phase = "attention"
                execution.save(update_fields=["phase", "updated_at"])
                # fsm-bypass: CharField job; locked unissued execution exhausted its bounded read-only budget.
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
                    status="attention",
                    next_retry_at=None,
                    status_message="Read-only quota admission exhausted its retry budget: " + message,
                )
                _audit_status(job.pk)
            else:
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
                    next_retry_at=timezone.now() + timedelta(minutes=5)
                )


def _parent_still_active(execution: HostingLimitExecution) -> bool:
    parent = execution.job.parameters.get("quota_parent", {})
    if parent.get("job_id"):
        return VirtualminProvisioningJob.objects.filter(
            pk=parent["job_id"],
            status__in=("pending", "running", "attention"),
        ).exists()
    if parent.get("migration_id"):
        from .virtualmin_migration_models import VirtualminMigration  # noqa: PLC0415

        return (
            VirtualminMigration.objects.filter(pk=parent["migration_id"])
            .exclude(
                status__in=("completed", "failed", "rolled_back"),
            )
            .exists()
        )
    return False


def _attention(execution_id: UUID, message: str) -> None:
    hint = HostingLimitExecution.objects.get(pk=execution_id)
    with transaction.atomic():
        _lock_context(hint)
        execution = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution_id)
        if execution.phase not in {"issued", "attention"}:
            return
        already_attention = execution.phase == "attention"
        execution.phase = "attention"
        execution.save(update_fields=["phase", "updated_at"])
        # fsm-bypass: CharField job; locked issued execution retains its uncertain native claim.
        VirtualminProvisioningJob.objects.filter(pk=execution.job_id).update(
            status="attention",
            status_message=message,
            next_retry_at=None,
            updated_at=timezone.now(),
        )
        if not already_attention:
            _audit_status(execution.job_id)


def _safety_used(account: VirtualminAccount, probe: dict[str, Any], *, owner_id: int) -> int:
    """Only what the kernel cap governs has to fit: databases are measured but outside it (ADR-0075)."""
    return max(
        quantity(probe["uid_used_bytes"]),
        quantity(probe["gid_used_bytes"]),
        _canonical_files_bytes(account, probe, owner_id=owner_id),
    )


def canonical_safety_used_bytes(account: VirtualminAccount, probe: dict[str, Any], *, owner_id: int) -> int:
    """Shared exact-owner canonical evidence; kernel accounting is never a fallback."""
    if "observation" in probe:
        # The closed probe verifier already bound its timestamp and complete
        # native identity to this current owner and canonical/held target.
        return canonical_observation(probe["observation"])
    total = _fresh_disk_reading(account, probe, owner_id=owner_id).disk_total_bytes
    if total is None:
        raise ValidationError(_("Fresh canonical disk evidence for this exact owner and native scope is required."))
    return total


def _canonical_files_bytes(account: VirtualminAccount, probe: dict[str, Any], *, owner_id: int) -> int:
    if "observation" in probe:
        canonical_observation(probe["observation"])
        return quantity(probe["observation"]["files_bytes"])
    files = _fresh_disk_reading(account, probe, owner_id=owner_id).disk_files_bytes
    if files is None:
        raise ValidationError(_("Fresh canonical disk evidence for this exact owner and native scope is required."))
    return files


def _fresh_disk_reading(account: VirtualminAccount, probe: dict[str, Any], *, owner_id: int) -> UsageReading:
    from .virtualmin_usage_models import AccountUsageState, UsageReading  # noqa: PLC0415

    state = AccountUsageState.objects.filter(account_id=account.pk).first()
    if (
        state is not None
        and state.disk_reading_id is not None
        and state.service_id_snapshot == account.service_id
        and state.customer_id_snapshot == owner_id
        and state.server_id_snapshot == account.server_id
        and state.chain_epoch_snapshot == account.chain_epoch
        and state.domain_id == probe["identity"]["domain_id"]
        and str(state.installation) == probe["identity"]["installation"]
    ):
        reading = UsageReading.objects.filter(
            pk=state.disk_reading_id,
            account_id=account.pk,
            owner_scope=state.owner_scope,
            server_id_snapshot=account.server_id,
            chain_epoch=account.chain_epoch,
            taken_at__gte=timezone.now() - timedelta(hours=2),
            taken_at__lte=timezone.now() + timedelta(seconds=5),
            scan_started_at__gte=max(state.gauge_not_before, state.owner_started_at),
        ).first()
        if reading is not None:
            return reading
    raise ValidationError(_("Fresh canonical disk evidence for this exact owner and native scope is required."))


def _refuse_prepared(execution: HostingLimitExecution, refusal: str) -> None:
    if execution.reserved_bytes and _parent_still_active(execution):
        raise ValidationError(refusal)
    _release(execution, phase="superseded", status="cancelled", message=refusal)


def _verify_cleanup_reduction(
    execution: HostingLimitExecution, application: HostingLimitApplication, service: Service, probe: dict[str, Any]
) -> None:
    if not _operational_cleanup(application, service):
        return
    from .hosting_limit_review import (  # noqa: PLC0415 -- Issued immutable parent boundary.
        issued_reviewed_parent,
    )
    from .hosting_raise_expiry import cleanup_probe_refusal  # noqa: PLC0415

    if not issued_reviewed_parent(application, execution.job.parameters.get("quota_parent", {})) and (
        refusal := cleanup_probe_refusal(application, probe)
    ):
        raise ValidationError(refusal)


def _application_policy(
    execution: HostingLimitExecution, application: HostingLimitApplication, service: Service
) -> dict[str, Any]:
    from .hosting_limit_review import (  # noqa: PLC0415 -- Native issued review boundary.
        issued_reviewed_parent,
    )
    from .hosting_raise_service import is_preauthorized_raise_expiry  # noqa: PLC0415

    if application.overlay_expires_at is None:
        raise ValidationError(_("The temporary resource application has no exact expiry."))
    expiry_reduction = is_preauthorized_raise_expiry(application, service)
    return {
        "schema": OVERLAY_QUOTA_PROTOCOL,
        "base_revision": application.revision,
        "overlay_revision": application.overlay_revision,
        "extra_mib": application.overlay_extra_mib,
        "expires_at": application.overlay_expires_at.isoformat(),
        "expiry_reduction": expiry_reduction,
        "monotonic_reduction": expiry_reduction
        and not issued_reviewed_parent(application, execution.job.parameters.get("quota_parent", {})),
    }


def _prepare_dispatch(execution_id: UUID, probe: dict[str, Any]) -> dict[str, Any] | None:
    hint = HostingLimitExecution.objects.get(pk=execution_id)
    # Commit a verified same-node reboot observation before the dispatch's
    # refusal transaction. Raising inside that transaction would roll back the
    # revocation and leave historical enforcement displayed as current.
    identity = validate_identity(probe.get("identity"))
    if identity.get("boot_id") != hint.identity.get("boot_id"):
        verify_quota_probe(probe, identity=identity, now=timezone.now())
        from .hosting_node_execution import invalidate_observed_quota_identity  # noqa: PLC0415

        with transaction.atomic():
            _account, observed_server, _service = _lock_context(hint)
            invalidated = invalidate_observed_quota_identity(observed_server, identity)
        if invalidated:
            raise ValidationError(_("The node rebooted; requalify it before dispatching managed quotas."))
    with transaction.atomic():
        account, server, service = _lock_context(hint)
        execution = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution_id)
        if execution.phase != "prepared":
            return None
        if refusal := _authority_refusal(execution, account, server, service):
            _refuse_prepared(execution, refusal)
            return None
        application = _application(execution.job)
        cap = effective_disk_limit(application.disk_allowance_mib, extra_mib=application.overlay_extra_mib)
        if cap is None:
            raise ValidationError(_("The assigned disk allowance is unknown."))
        identity = validate_identity(probe.get("identity"))
        if (
            any(identity.get(key) != value for key, value in execution.identity.items())
            or identity["domain"] != account.domain
        ):
            raise ValidationError(_("The native owner or adopted node identity differs from the prepared application."))
        observed = verify_quota_probe(probe, identity=identity, now=timezone.now())
        _verify_cleanup_reduction(execution, application, service, probe)
        if application.overlay_revision and probe.get("quota_protocol") != OVERLAY_QUOTA_PROTOCOL:
            raise ValidationError(_("Prepare the current quota helper protocol before applying temporary resources."))
        current = observed.capacity_baseline_kib
        from .hosting_raise_service import is_preauthorized_raise_expiry  # noqa: PLC0415

        if (
            cap
            and not is_preauthorized_raise_expiry(application, service)
            and _safety_used(account, probe, owner_id=execution.owner_id) > cap * BYTES_PER_MIB
        ):
            raise ValidationError(_("Current usage exceeds the requested cap; limits remain pending for review."))
        if cap == 0 and current is not None:
            raise ValidationError(_("An unbounded increase needs an explicit node capacity review."))
        increase = 0 if current is None else max(0, cap * BYTES_PER_MIB - current * 1024)
        delta = max(execution.reserved_bytes, increase)
        additional_claim = delta - execution.reserved_bytes
        reserved = (
            HostingLimitExecution.objects.filter(
                job__server_id=server.pk,
                reservation_released_at__isnull=True,
            )
            .exclude(pk=execution.pk)
            .aggregate(total=Sum("reserved_bytes"))["total"]
            or 0
        )
        # Keep the node's configured free-space reserve in addition to unresolved claims.
        from apps.settings.services import SettingsService  # noqa: PLC0415

        reserve_mib = SettingsService.get_integer_setting("virtualmin.disk_free_reserve_mb", 1024)
        if reserve_mib < 0 or (
            additional_claim
            and quantity(probe.get("available_bytes")) < additional_claim + reserved + reserve_mib * BYTES_PER_MIB
        ):
            raise ValidationError(_("Insufficient verified unreserved node capacity for this increase."))
        request = {
            "identity": identity,
            "token": str(execution.job.execution_token),
            "generation": execution.account_epoch,
            "disk_limit_kib": cap * 1024,
            "bandwidth_limit_bytes": quantity(application.bandwidth_allowance_mib) * BYTES_PER_MIB,
        }
        if application.overlay_revision:
            request["policy"] = _application_policy(execution, application, service)
        execution.identity, execution.request, execution.reserved_bytes = identity, request, delta
        ServiceHostingLimits.objects.filter(service_id=service.pk).update(verified_at=None)
        execution.phase, execution.issued_at = "issued", timezone.now()
        execution.save(update_fields=["identity", "request", "reserved_bytes", "phase", "issued_at", "updated_at"])
        return request


def _complete(execution_id: UUID, receipt: dict[str, Any], *, publish_completed: bool = False) -> bool:
    hint = HostingLimitExecution.objects.get(pk=execution_id)
    with transaction.atomic():
        account, server, service = _lock_context(hint)
        execution = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution_id)
        if execution.phase != "issued" and not (publish_completed and execution.phase == "completed"):
            return False
        application = _application(execution.job)
        if application.overlay_revision and receipt.get("quota_protocol") != OVERLAY_QUOTA_PROTOCOL:
            raise ValidationError(_("The native helper did not verify the temporary resource protocol."))
        verify_quota_receipt(
            receipt,
            identity=execution.identity,
            token=execution.request["token"],
            generation=execution.account_epoch,
            disk_limit_mib=execution.request["disk_limit_kib"] // 1024,
            bandwidth_limit_mib=quantity(application.bandwidth_allowance_mib),
            now=timezone.now(),
            require_bandwidth_actions_safe=True,
        )
        if refusal := _authority_refusal(execution, account, server, service):
            if refusal != "A newer hosting allowance supersedes this native application.":
                raise ValidationError(refusal)
            # The exact terminal receipt proves this issued command ended. Retain
            # its history and release admission, while leaving operational state
            # unchanged for the newer durable assignment's worker.
            execution.receipt = receipt
            execution.save(update_fields=["receipt", "updated_at"])
            _release(execution, phase="completed", status="completed", message=refusal)
            return False
        if account.server_id != server.pk:
            execution.receipt = receipt
            execution.save(update_fields=["receipt", "updated_at"])
            _release(
                execution,
                phase="completed",
                status="completed",
                message="Held target limits verified before canonical ownership commit.",
            )
            return True
        limits = ServiceHostingLimits.objects.select_for_update(of=("self",)).get(service_id=service.pk)
        if (
            publish_completed
            and account.quota_managed
            and limits.verified_at is not None
            and limits.applied_revision == execution.service_revision
            and limits.verified_receipt == receipt
        ):
            return True
        limits.applied_revision = limits.operational_revision = execution.service_revision
        limits.applied_overlay_revision = execution.overlay_revision
        limits.applied_disk_allowance_mib = limits.operational_disk_allowance_mib = application.disk_allowance_mib
        limits.applied_bandwidth_allowance_mib = limits.operational_bandwidth_allowance_mib = (
            application.bandwidth_allowance_mib
        )
        limits.verified_receipt, limits.verified_at = receipt, timezone.now()
        limits.save(
            update_fields=[
                "applied_revision",
                "applied_overlay_revision",
                "operational_revision",
                "applied_disk_allowance_mib",
                "operational_disk_allowance_mib",
                "applied_bandwidth_allowance_mib",
                "operational_bandwidth_allowance_mib",
                "verified_receipt",
                "verified_at",
                "updated_at",
            ]
        )
        account.disk_quota_mb = application.disk_allowance_mib
        account.effective_disk_quota_mb = execution.request["disk_limit_kib"] // 1024
        account.bandwidth_quota_mb = application.bandwidth_allowance_mib
        account.__dict__["_hosting_quota_old_managed"] = account.quota_managed
        account.__dict__["_hosting_quota_authority"] = {
            "application_id": str(application.pk),
            "revision": application.revision,
            "authority": application.authority,
            "native_parent": execution.job.parameters.get("quota_parent", {}),
            "native_token": execution.request["token"],
            "native_epoch": execution.account_epoch,
        }
        account.quota_managed = True
        try:
            account.save(
                update_fields=[
                    "disk_quota_mb",
                    "effective_disk_quota_mb",
                    "bandwidth_quota_mb",
                    "quota_managed",
                    "updated_at",
                ]
            )
        finally:
            account.__dict__.pop("_hosting_quota_authority", None)
            account.__dict__.pop("_hosting_quota_old_managed", None)
        execution.receipt = receipt
        execution.save(update_fields=["receipt", "updated_at"])
        _release(
            execution, phase="completed", status="completed", message="Both kernel quotas and native metadata verified."
        )
    return True


def publish_managed_limits(account: VirtualminAccount) -> None:
    """Publish a held target receipt at the canonical ownership commit, without I/O."""
    from .hosting_node_policy_models import NodeHostingPolicy  # noqa: PLC0415

    if not NodeHostingPolicy.objects.filter(server_id=account.server_id, quota_adopted=True).exists():
        return
    execution = (
        HostingLimitExecution.objects.filter(
            job__account_id=account.pk,
            job__server_id=account.server_id,
            phase="completed",
            account_epoch=account.quota_generation,
        )
        .order_by("-created_at")
        .first()
    )
    if execution is None or not _complete(execution.pk, execution.receipt, publish_completed=True):
        raise ValidationError(_("The canonical target has no current verified managed quota receipt."))


def ensure_managed_limits(  # noqa: C901, PLR0911, PLR0912 -- Preserve independent legacy, parent, canonical and frozen-review refusals.
    account: VirtualminAccount,
    *,
    parent_job: VirtualminProvisioningJob | None = None,
    migration: Any = None,
    native_server: VirtualminServer | None = None,
) -> Result[bool, str]:
    """Shared completion barrier after create/archive restoration, before activation.

    Legacy nodes remain observational until explicit adoption. Once adopted, any
    policy/ownership/capacity uncertainty refuses completion. The caller's durable
    native lane is rechecked as parent authority, never bypassed or released here.
    """
    from .hosting_limit_tasks import current_application  # noqa: PLC0415
    from .hosting_node_policy_models import NodeHostingPolicy  # noqa: PLC0415
    from .hosting_notification_completion import verify_lifecycle_notification_policy  # noqa: PLC0415

    staged_server = native_server
    account.refresh_from_db()
    target = staged_server or account.server
    policy = NodeHostingPolicy.objects.filter(server_id=target.pk).first()
    if policy is None or not policy.quota_adopted:
        if staged_server is not None:
            account.server = staged_server
        if account.quota_managed:
            return Err("This managed account requires a currently qualified target node before native completion.")
        mail = verify_lifecycle_notification_policy(
            account, native_server=target, parent_job=parent_job, migration=migration
        )
        return Err(mail.unwrap_err()) if mail.is_err() else Ok(False)
    if not account.quota_managed and parent_job is not None and parent_job.operation == "restore_domain":
        # Restoring an imported account is not implicit quota-policy adoption.
        mail = verify_lifecycle_notification_policy(
            account, native_server=target, parent_job=parent_job, migration=migration
        )
        return Err(mail.unwrap_err()) if mail.is_err() else Ok(False)
    parent: dict[str, Any] = {}
    if parent_job is not None:
        parent = {"job_id": str(parent_job.pk), "token": str(parent_job.execution_token or "")}
    if migration is not None:
        parent = {"migration_id": str(migration.pk), "token": str(migration.lease_token or "")}
    if parent:
        parent.update(account_server_id=str(account.server_id), native_server_id=str(target.pk))
        if migration is not None:
            parent["account_server_id"] = str(migration.source_server_id)
    # A restored archive may have overwritten caps even for the same revision.
    # Keep the prior receipt as history, but never display it as current proof.
    if parent:
        ServiceHostingLimits.objects.filter(service_id=account.service_id).update(verified_at=None)
    if migration is not None:
        frozen = migration.pre_migration_snapshot.get("hosting_limits")
        if not isinstance(frozen, dict) or frozen.get("disk_cap_mib") is None or frozen.get("bandwidth_mib") is None:
            return Err("The reviewed migration cap is unknown.")
        from .hosting_limit_review import (  # noqa: PLC0415 -- Shared bounded immutable parent review.
            reviewed_parent_application,
        )

        try:
            application = reviewed_parent_application(migration)
        except (ValidationError, HostingLimitApplication.DoesNotExist, ValueError, KeyError, TypeError) as error:
            return Err(str(error))
        parent["approved_application_id"] = frozen["application_id"]
        parent["frozen_application_id"] = str(application.pk)
    elif parent_job is not None:
        from .hosting_limit_review import reviewed_job_application  # noqa: PLC0415

        try:
            recorded = VirtualminProvisioningJob.objects.get(pk=parent_job.pk)
            application = reviewed_job_application(recorded)
            parent["approved_application_id"] = str(recorded.hosting_limit_application_id)
            parent["frozen_application_id"] = str(application.pk)
        except (ValidationError, HostingLimitApplication.DoesNotExist, VirtualminAccount.DoesNotExist) as error:
            return Err(str(error))
    else:
        application = current_application(account.service_id)
    outcome = apply_hosting_limits(application.pk, parent=parent, native_server_id=target.pk)
    if staged_server is not None:
        account.server = staged_server
    if outcome != "completed":
        return Err("Current managed quotas could not be verified; preserve the native hold (" + outcome + ").")
    mail = verify_lifecycle_notification_policy(
        account, native_server=target, parent_job=parent_job, migration=migration
    )
    return Err(mail.unwrap_err()) if mail.is_err() else Ok(True)


def reserve_managed_creation(  # noqa: PLR0911 -- Explicit pre-dispatch refusal contracts retain the native account lane.
    account: VirtualminAccount,
    job: VirtualminProvisioningJob,
    available_bytes: int | None,
) -> Result[bool, str]:
    """Reserve the full new target cap BEFORE create-domain can publish it."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    from .hosting_node_policy_models import NodeHostingPolicy  # noqa: PLC0415

    target = account.server
    if not NodeHostingPolicy.objects.filter(server_id=target.pk, quota_adopted=True).exists():
        if account.quota_managed:
            return Err("A managed account cannot be recreated on an unqualified quota target.")
        return Ok(False)
    if available_bytes is None:
        return Err("Managed positive-cap creation requires fresh known native free space.")
    actual = VirtualminAccount.objects.get(pk=account.pk)
    parent = {
        "job_id": str(job.pk),
        "token": str(job.execution_token or ""),
        "account_server_id": str(actual.server_id),
        "native_server_id": str(target.pk),
    }
    try:
        from .hosting_limit_review import reviewed_job_application  # noqa: PLC0415

        recorded = VirtualminProvisioningJob.objects.get(pk=job.pk)
        application = reviewed_job_application(recorded)
        parent["approved_application_id"] = str(recorded.hosting_limit_application_id)
        parent["frozen_application_id"] = str(application.pk)
        execution = admit_application(application.pk, parent=parent, native_server_id=target.pk)
        if execution is None:
            return Err("The managed creation no longer owns its quota capacity admission.")
        with transaction.atomic():
            locked, server, service = _lock_context(execution)
            current = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution.pk)
            if current.phase != "prepared":
                return Err("The creation's quota capacity claim is no longer prepared.")
            if refusal := _authority_refusal(current, locked, server, service):
                return Err(refusal)
            cap = effective_disk_limit(application.disk_allowance_mib, extra_mib=application.overlay_extra_mib)
            if cap is None:
                return Err("The managed creation allowance is unknown.")
            total = (
                HostingLimitExecution.objects.filter(
                    job__server_id=server.pk,
                    reservation_released_at__isnull=True,
                )
                .exclude(pk=current.pk)
                .aggregate(total=Sum("reserved_bytes"))["total"]
                or 0
            )
            reserve = SettingsService.get_integer_setting("virtualmin.disk_free_reserve_mb", 1024) * BYTES_PER_MIB
            if reserve < 0 or quantity(available_bytes) < cap * BYTES_PER_MIB + total + reserve:
                _release(
                    current,
                    phase="superseded",
                    status="failed",
                    message="Insufficient unreserved creation capacity before dispatch.",
                )
                return Err("Insufficient unreserved native capacity for the full new hosting cap.")
            current.reserved_bytes = cap * BYTES_PER_MIB
            current.save(update_fields=["reserved_bytes", "updated_at"])
    except (ValidationError, ValueError) as error:
        return Err(str(error))
    return Ok(True)


def reserve_managed_migration(migration: Any) -> Result[bool, str]:  # noqa: C901, PLR0911 -- Every missing proof refuses before native mutation.
    """The held destination reserves its complete reviewed cap before creating/restoring data."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    from .hosting_node_policy_models import NodeHostingPolicy  # noqa: PLC0415
    from .virtualmin_gateway import VirtualminConfig, VirtualminGateway  # noqa: PLC0415
    from .virtualmin_service import VirtualminProvisioningService  # noqa: PLC0415

    target = migration.target_server
    if not NodeHostingPolicy.objects.filter(server_id=target.pk, quota_adopted=True).exists():
        if migration.account.quota_managed:
            return Err("A managed account requires a qualified quota destination before migration restore.")
        return Ok(False)
    frozen = migration.pre_migration_snapshot.get("hosting_limits")
    if not isinstance(frozen, dict) or frozen.get("disk_cap_mib") is None:
        return Err("The migration has no reviewed finite/explicit-unlimited composed cap.")
    from .hosting_limit_review import reviewed_parent_application  # noqa: PLC0415

    try:
        application = reviewed_parent_application(migration)
        composed_cap = effective_disk_limit(application.disk_allowance_mib, extra_mib=application.overlay_extra_mib)
    except (ValidationError, HostingLimitApplication.DoesNotExist, ValueError, KeyError, TypeError) as error:
        return Err(str(error))
    if composed_cap is None:
        return Err("The migration's current reviewed composed cap is unknown.")
    health = VirtualminGateway(VirtualminConfig(server=target)).test_connection()
    if health.is_err() or health.unwrap().get("healthy") is not True:
        return Err("The migration destination has no fresh affirmative capacity evidence.")
    info = health.unwrap()
    available_mib = VirtualminProvisioningService._available_disk_mb(info.get("data", info))
    if available_mib is None:
        return Err("The migration destination free space is unknown.")
    parent = {
        "migration_id": str(migration.pk),
        "token": str(migration.lease_token or ""),
        "account_server_id": str(migration.source_server_id),
        "native_server_id": str(target.pk),
        "approved_application_id": frozen["application_id"],
        "frozen_application_id": str(application.pk),
    }
    execution = admit_application(application.pk, parent=parent, native_server_id=target.pk)
    if execution is None:
        return Err("The migration no longer owns its reviewed destination capacity.")
    with transaction.atomic():
        account, server, service = _lock_context(execution)
        current = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution.pk)
        if current.phase != "prepared":
            return Err("The migration's quota capacity claim needs native recovery.")
        if refusal := _authority_refusal(current, account, server, service):
            return Err(refusal)
        cap = composed_cap * BYTES_PER_MIB
        if current.reserved_bytes < cap:
            others = (
                HostingLimitExecution.objects.filter(
                    job__server_id=server.pk,
                    reservation_released_at__isnull=True,
                )
                .exclude(pk=current.pk)
                .aggregate(total=Sum("reserved_bytes"))["total"]
                or 0
            )
            reserve = SettingsService.get_integer_setting("virtualmin.disk_free_reserve_mb", 1024) * BYTES_PER_MIB
            if reserve < 0 or available_mib * BYTES_PER_MIB < cap + others + reserve:
                _release(
                    current,
                    phase="superseded",
                    status="failed",
                    message="Insufficient reviewed destination capacity before dispatch.",
                )
                return Err("Insufficient unreserved capacity for the complete reviewed destination cap.")
            current.reserved_bytes = cap
            current.save(update_fields=["reserved_bytes", "updated_at"])
    return Ok(True)


def apply_hosting_limits(  # noqa: PLR0911 -- Distinguish pending, terminal, superseded and uncertain outcomes.
    application_id: UUID | str,
    *,
    parent: dict[str, Any] | None = None,
    native_server_id: UUID | None = None,
) -> str:
    """Queue duplicates are harmless; issued or uncertain work is NEVER blindly retried."""
    from .hosting_limit_transport import probe_account_quota, run_quota_operation  # noqa: PLC0415

    try:
        execution = admit_application(application_id, parent=parent, native_server_id=native_server_id)
    except ValidationError:
        return "pending"
    if execution is None:
        return "pending"
    if execution.phase != "prepared":
        return execution.phase
    try:
        probe = probe_account_quota(execution)
        request = _prepare_dispatch(execution.pk, probe)
    except (ValidationError, ValueError, RuntimeError, OSError) as error:
        _fail_unissued(execution.pk, str(error))
        return "pending"
    if request is None:
        return "superseded"
    try:
        receipt = run_quota_operation(execution.job.server, "apply", request)
        return "completed" if _complete(execution.pk, receipt) else "superseded"
    except (ValidationError, ValueError, RuntimeError, OSError) as error:
        _attention(execution.pk, "Native quota outcome requires permanent fencing: " + str(error))
        return "attention"


def resolve_quota_job(  # noqa: PLR0911 -- Each failed proof retains the hold before the one terminal release.
    job: VirtualminProvisioningJob,
    *,
    resolved_by: str,
    note: str,
) -> Result[bool, str]:
    """Fence under the ORIGINAL native lock before releasing capacity/account ownership."""
    from .hosting_limit_transport import run_quota_operation  # noqa: PLC0415

    if job.operation != OPERATION or job.status != "attention" or not note.strip():
        return Err("Only a quota job awaiting attention can be resolved, with a reason.")
    execution = HostingLimitExecution.objects.filter(job_id=job.pk).first()
    if execution is None:
        return Err("The quota execution evidence is missing; retain account ownership.")
    if execution.issued_at is None and execution.reserved_bytes and _parent_still_active(execution):
        return Err("The parent native create/restore/migration still owns this capacity; resolve that operation first.")
    if execution.issued_at is not None:
        # Use the frozen endpoint/identity; changed credentials/trust require explicit
        # administrative recovery, never fencing an unrelated replacement node.
        if connection_identity(job.server) != execution.connection_identity:
            return Err(
                "The original native connection changed; recover that exact node before releasing its quota hold."
            )
        try:
            receipt = run_quota_operation(job.server, "fence", execution.request)
        except (ValueError, RuntimeError, OSError) as error:
            return Err("Could not permanently fence the native quota token: " + str(error))
        if receipt != {"outcome": "fenced", "token": execution.request["token"], "generation": execution.account_epoch}:
            return Err("Native fencing evidence is incomplete; the account stays held.")
    with transaction.atomic():
        _lock_context(execution)
        current = HostingLimitExecution.objects.select_for_update(of=("self",)).get(pk=execution.pk)
        if current.phase != "attention" or VirtualminProvisioningJob.objects.get(pk=job.pk).status != "attention":
            return Err("This quota job no longer owns the attention hold.")
        _release(current, phase="fenced", status="failed", message=f"Permanently fenced by {resolved_by}: {note}")
    return Ok(True)


def recover_quota_executions() -> int:
    """A lease is an execution budget, never evidence of native termination."""
    now, recovered = timezone.now(), 0
    candidates = HostingLimitExecution.objects.filter(
        phase__in=("prepared", "issued"),
        job__execution_deadline__lte=now,
    )
    for execution in candidates.iterator():
        if execution.issued_at is None:
            if execution.reserved_bytes and _parent_still_active(execution):
                # The parent can legitimately restore for longer than this child
                # quota dispatch budget. Its own lease/recovery preserves the lane.
                continue
            _fail_unissued(execution.pk, "Quota dispatch budget expired before native issuance.")
        else:
            _attention(execution.pk, "Quota execution budget expired; permanently fence its token before retrying.")
        recovered += 1
    return recovered
