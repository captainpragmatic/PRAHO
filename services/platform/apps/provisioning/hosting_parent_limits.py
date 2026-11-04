"""Immutable create/restore resource authority, independent of later assignments."""

from __future__ import annotations

from collections.abc import Mapping
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from .hosting_limit_models import HostingLimitApplication
    from .virtualmin_models import VirtualminProvisioningJob

PARENT_OPERATIONS = ("create_domain", "restore_domain")
SNAPSHOT_KEY = "hosting_limits"
BINDING_KEY = "hosting_limits_binding"
ISSUED_KEY = "hosting_limits_issued"
PARENT_PROTECTED_FIELDS = frozenset(
    {
        "id",
        "pk",
        "operation",
        "account",
        "account_id",
        "server",
        "server_id",
        "hosting_limit_application",
        "hosting_limit_application_id",
        "parameters",
    }
)
_ISSUE_WRITE = ContextVar("hosting_parent_issue_write", default=False)


def prepare_new_parent(job: VirtualminProvisioningJob) -> None:
    """Called atomically with first parent publication; no Account/Server locks or I/O."""
    if job.operation not in PARENT_OPERATIONS or job.account_id is None:
        return
    from .hosting_limit_execution import freeze_migration_limits  # noqa: PLC0415 -- Shared immutable snapshot shape.
    from .hosting_node_policy_models import NodeHostingPolicy  # noqa: PLC0415
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415
    from .virtualmin_security import connection_identity  # noqa: PLC0415

    account = VirtualminAccount.objects.get(pk=job.account_id)
    policy = NodeHostingPolicy.objects.filter(server_id=job.server_id, quota_adopted=True).first()
    if policy is None or (job.operation == "restore_domain" and not account.quota_managed):
        return
    if (
        any(key in job.parameters for key in (SNAPSHOT_KEY, BINDING_KEY, ISSUED_KEY))
        or job.hosting_limit_application_id
    ):
        raise ValidationError(_("Native parent resource authority is captured by admission, not supplied by callers."))
    snapshot = freeze_migration_limits(account)
    job.hosting_limit_application_id = UUID(snapshot["application_id"])
    job.parameters = {
        **job.parameters,
        SNAPSHOT_KEY: snapshot,
        BINDING_KEY: {
            "job_id": str(job.pk),
            "operation": job.operation,
            "account_id": str(account.pk),
            "service_id": account.service_id,
            "owner_id": snapshot["owner_id"],
            "domain": account.domain,
            "username": account.virtualmin_username,
            "account_server_id": str(account.server_id),
            "native_server_id": str(job.server_id),
            "connection_identity": connection_identity(job.server),
            "node_identity": {
                key: policy.quota_evidence.get(key) for key in ("installation", "filesystem_uuid", "boot_id")
            },
        },
    }


def guard_parent_write(previous: Mapping[str, Any], changes: dict[str, Any]) -> None:
    if previous["operation"] not in PARENT_OPERATIONS:
        return
    old = previous["parameters"]
    bound = previous["hosting_limit_application_id"] is not None and SNAPSHOT_KEY in old
    if not bound:
        if changes.get("hosting_limit_application_id") or (
            isinstance(changes.get("parameters"), dict)
            and any(key in changes["parameters"] for key in (SNAPSHOT_KEY, BINDING_KEY, ISSUED_KEY))
        ):
            raise ValidationError(_("Existing native parents cannot invent resource admission authority."))
        return
    for key in ("id", "operation", "account_id", "server_id", "hosting_limit_application_id"):
        if key in changes and changes[key] != previous[key]:
            raise ValidationError(_("Accepted native parent resource bindings cannot change."))
    if "parameters" in changes:
        new = changes["parameters"]
        if not isinstance(new, dict) or any(new.get(key) != old.get(key) for key in (SNAPSHOT_KEY, BINDING_KEY)):
            raise ValidationError(_("Accepted native parent resource snapshots cannot change."))
        if new.get(ISSUED_KEY) != old.get(ISSUED_KEY):
            before, after = old.get(ISSUED_KEY, []), new.get(ISSUED_KEY)
            append = (
                _ISSUE_WRITE.get()
                and isinstance(before, list)
                and isinstance(after, list)
                and len(after) == len(before) + 1
                and after[:-1] == before
            )
            if not append:
                raise ValidationError(_("Native parent dispatch evidence can only append an admitted claim."))


def _dispatch_claim(job: VirtualminProvisioningJob) -> dict[str, Any]:
    return {
        "token": str(job.execution_token or ""),
        "claimed_at": job.claimed_at.isoformat() if job.claimed_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
    }


def _current_dispatch_witness(job: VirtualminProvisioningJob, issued: Any) -> bool:
    fields = {"job_id", "application_id", "token", "claimed_at", "started_at", "issued_at", "binding"}
    if not isinstance(issued, dict) or set(issued) != fields:
        return False
    observed = parse_datetime(issued["issued_at"]) if isinstance(issued["issued_at"], str) else None
    return bool(
        observed is not None
        and timezone.is_aware(observed)
        and observed <= timezone.now()
        and job.started_at is not None
        and all(issued.get(key) == value for key, value in _dispatch_claim(job).items())
        and issued.get("job_id") == str(job.pk)
        and issued.get("application_id") == str(job.hosting_limit_application_id)
        and issued.get("binding") == job.parameters.get(BINDING_KEY)
    )


def frozen_parent_application(job: VirtualminProvisioningJob) -> HostingLimitApplication:
    from .hosting_limit_models import HostingLimitApplication  # noqa: PLC0415
    from .hosting_limit_policy import effective_disk_limit  # noqa: PLC0415
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415
    from .virtualmin_security import connection_identity  # noqa: PLC0415

    if job.account_id is None or job.hosting_limit_application_id is None:
        raise ValidationError(_("This native parent has no admitted managed resource snapshot."))
    account = VirtualminAccount.objects.get(pk=job.account_id)
    application = HostingLimitApplication.objects.get(pk=job.hosting_limit_application_id)
    snapshot, binding = job.parameters.get(SNAPSHOT_KEY), job.parameters.get(BINDING_KEY)
    expected = {
        "application_id": str(application.pk),
        "base_revision": application.revision,
        "overlay_revision": 0,
        "overlay_expires_at": None,
        "owner_id": str(application.authority.get("customer_id")),
        "disk_cap_mib": effective_disk_limit(application.disk_allowance_mib),
        "bandwidth_mib": application.bandwidth_allowance_mib,
    }
    if (
        snapshot != expected
        or not isinstance(binding, dict)
        or binding.get("job_id") != str(job.pk)
        or binding.get("operation") != job.operation
        or binding.get("account_id") != str(account.pk)
        or binding.get("service_id") != account.service_id
        or application.service_id != account.service_id
        or binding.get("owner_id") != str(account.service.customer_id)
        or binding.get("domain") != account.domain
        or binding.get("username") != account.virtualmin_username
        or binding.get("native_server_id") != str(job.server_id)
        or str(account.server_id) not in {binding.get("account_server_id"), binding.get("native_server_id")}
        or binding.get("connection_identity") != connection_identity(job.server)
    ):
        raise ValidationError(
            _("The native parent's immutable resource admission no longer matches its owner or target.")
        )
    return application


def mark_parent_limits_issued(job: VirtualminProvisioningJob) -> bool:  # noqa: PLR0911 -- Explicit scope, nonce, lease and installed-node refusals.
    """Commit exact resource dispatch authority immediately before native mutation."""
    from .hosting_node_policy import current_quota_identity  # noqa: PLC0415
    from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer  # noqa: PLC0415

    if job.account_id is None:
        return False
    if job.hosting_limit_application_id is None:
        recorded = VirtualminProvisioningJob.objects.filter(pk=job.pk).first()
        return recorded is not None and recorded.hosting_limit_application_id is None
    with transaction.atomic():
        account = VirtualminAccount.objects.select_for_update(of=("self",)).get(pk=job.account_id)
        list(
            VirtualminServer.objects.select_for_update(of=("self",))
            .filter(pk__in=(account.server_id, job.server_id))
            .order_by("pk")
        )
        current = VirtualminProvisioningJob.objects.select_for_update(of=("self",)).get(pk=job.pk)
        frozen_parent_application(current)
        if (
            current.status != "running"
            or current.started_at is None
            or current.execution_token != job.execution_token
            or (current.operation == "create_domain" and _dispatch_claim(current) != _dispatch_claim(job))
        ):
            return False
        if current.operation == "restore_domain" and (
            current.execution_deadline is None or current.execution_deadline <= timezone.now()
        ):
            return False
        native = current_quota_identity(current.server)
        original = current.parameters[BINDING_KEY]["node_identity"]
        if any(original.get(key) != native.get(key) for key in ("installation", "filesystem_uuid")):
            return False
        history = current.parameters.get(ISSUED_KEY, [])
        if not isinstance(history, list):
            return False
        if (
            history
            and current.operation == "restore_domain"
            and history[-1].get("token") != str(current.execution_token or "")
        ):
            return False
        if not history and original.get("boot_id") != native.get("boot_id"):
            return False
        if not history or not _current_dispatch_witness(current, history[-1]):
            token = _ISSUE_WRITE.set(True)
            try:
                current.parameters = {
                    **current.parameters,
                    ISSUED_KEY: [
                        *history,
                        {
                            "job_id": str(current.pk),
                            "application_id": str(current.hosting_limit_application_id),
                            **_dispatch_claim(current),
                            "issued_at": timezone.now().isoformat(),
                            "binding": current.parameters[BINDING_KEY],
                        },
                    ],
                }
                current.save(update_fields=["parameters", "updated_at"])
            finally:
                _ISSUE_WRITE.reset(token)
        job.parameters = current.parameters
        return True


def held_parent_application_matches(application: HostingLimitApplication, parent: dict[str, Any]) -> bool:  # noqa: PLR0911 -- Explicit UUID, claim, lease, owner and original-node refusals.
    """Frozen planning authority; this alone does not prove native work was issued."""
    from .hosting_node_policy import current_quota_identity  # noqa: PLC0415
    from .virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415

    try:
        identifier = UUID(parent.get("job_id", ""))
    except (ValueError, TypeError, AttributeError):
        return False
    job = VirtualminProvisioningJob.objects.filter(
        pk=identifier,
        hosting_limit_application=application,
        operation__in=PARENT_OPERATIONS,
        status="running",
    ).first()
    if job is None or str(job.execution_token or "") != parent.get("token"):
        return False
    if str(job.server_id) != parent.get("native_server_id"):
        return False
    if job.operation == "restore_domain" and (
        job.execution_deadline is None or job.execution_deadline <= timezone.now()
    ):
        return False
    try:
        frozen_parent_application(job)
        native = current_quota_identity(job.server)
        original = job.parameters[BINDING_KEY]["node_identity"]
        if any(original.get(key) != native.get(key) for key in ("installation", "filesystem_uuid")):
            return False
    except (ValidationError, ValueError, TypeError, AttributeError):
        return False
    binding = job.parameters[BINDING_KEY]
    return bool(parent.get("account_server_id") == binding["account_server_id"])


def held_parent_cap_repair_issued(application: HostingLimitApplication, parent: dict[str, Any]) -> bool:
    """DB-only witness for an already-issued exact parent's original bounded repair."""
    from .virtualmin_models import VirtualminProvisioningJob  # noqa: PLC0415

    if not held_parent_application_matches(application, parent):
        return False
    job = VirtualminProvisioningJob.objects.get(pk=parent["job_id"])
    history = job.parameters.get(ISSUED_KEY)
    return bool(isinstance(history, list) and history and _current_dispatch_witness(job, history[-1]))
