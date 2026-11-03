"""Durable owner-bound reads; no capacity, quota epoch or account activation writes."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID, uuid4

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.utils import timezone
from django.utils.translation import gettext as _
from django_q.tasks import async_task

from apps.infrastructure.node_maintenance_gate import maintenance_refusal

from .hosting_limit_execution import _account_busy, canonical_safety_used_bytes
from .hosting_limit_native import quantity, validate_identity, verify_quota_probe
from .hosting_limit_transport import probe_registered_account_quota
from .hosting_node_execution import invalidate_observed_quota_identity
from .hosting_safety_scope import SAFETY_BUDGET, SAFETY_PROBE_MAX_AGE, current_safety_scope
from .service_models import Service
from .virtualmin_models import (
    SAFETY_OBSERVATION_OPERATION,
    VirtualminAccount,
    VirtualminProvisioningJob,
    VirtualminServer,
)

logger = logging.getLogger(__name__)


def _autocommit() -> None:
    if connection.in_atomic_block:
        raise RuntimeError("Safety refresh requires a separate request outside all database transactions.")


def _actor_allowed(actor_id: int, customer_id: int) -> bool:
    from apps.users.models import CustomerMembership, User  # noqa: PLC0415 -- Current authority; no financial locks.

    actor = User.objects.filter(pk=actor_id, is_active=True).first()
    return bool(
        actor is not None
        and (
            actor.is_staff_user
            or CustomerMembership.objects.filter(
                user=actor, customer_id=customer_id, is_active=True, role__in=("owner", "billing")
            ).exists()
        )
    )


def _lock_context(account_id: UUID, server_id: UUID) -> tuple[VirtualminAccount, VirtualminServer, Service]:
    account = VirtualminAccount.objects.select_for_update(of=("self",), no_key=True).get(pk=account_id)
    servers = list(
        VirtualminServer.objects.select_for_update(of=("self",))
        .filter(pk__in=(account.server_id, server_id))
        .order_by("pk")
    )
    server = next(row for row in servers if row.pk == server_id)
    service = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=account.service_id)
    return account, server, service


def _enqueue(job_id: UUID, token: UUID) -> None:
    try:
        identifier = async_task(
            "apps.provisioning.hosting_safety_observation.run_hosting_safety_observation",
            str(job_id),
            str(token),
            q_options={"sync": False, "timeout": 270},
        )
        VirtualminProvisioningJob.objects.filter(pk=job_id, status="pending", execution_token=token).update(
            task_id=str(identifier)
        )
    except Exception:
        # The committed pending row is the outbox; the periodic dispatcher retries delivery.
        logger.warning("Safety observation queue delivery pending for job %s", job_id)


def request_safety_refresh(service_id: int, customer_id: int, actor_id: int) -> VirtualminProvisioningJob:
    _autocommit()
    if any(type(value) is not int or value <= 0 for value in (service_id, customer_id, actor_id)):
        raise ValidationError(_("Safety refresh requires exact current service and requester identities."))
    hint = VirtualminAccount.objects.filter(service_id=service_id).values("pk", "server_id").first()
    if hint is None:
        raise ValidationError(_("This service has no registered native account."))
    with transaction.atomic():
        account, server, service = _lock_context(hint["pk"], hint["server_id"])
        scope = current_safety_scope(service.pk)
        if (
            scope is None
            or service.pk != service_id
            or service.customer_id != customer_id
            or not _actor_allowed(actor_id, customer_id)
            or _account_busy(account)
            or maintenance_refusal(server.pk)
        ):
            raise ValidationError(_("The current service does not permit a native safety refresh."))
        existing = VirtualminProvisioningJob.objects.filter(
            operation=SAFETY_OBSERVATION_OPERATION,
            account=account,
            status__in=("pending", "running"),
            execution_deadline__gt=timezone.now(),
            parameters__scope=scope,
        ).first()
        if existing is not None:
            if _actor_allowed(existing.parameters.get("requested_by"), customer_id):
                return existing
            _fail_locked(existing, str(_("Original safety refresh authority expired.")))
        now, token = timezone.now(), uuid4()
        job = VirtualminProvisioningJob.objects.create(
            operation=SAFETY_OBSERVATION_OPERATION,
            server=server,
            account=account,
            status="pending",
            max_retries=0,
            execution_token=token,
            claimed_at=now,
            execution_deadline=now + SAFETY_BUDGET,
            correlation_id="safety-" + str(token),
            parameters={"schema": 1, "scope": scope, "requested_by": actor_id, "task_budget_seconds": 240},
        )
        transaction.on_commit(lambda: _enqueue(job.pk, token))
        return job


def _fail_locked(job: VirtualminProvisioningJob, message: str) -> None:
    job.status, job.status_message, job.completed_at = "failed", message, timezone.now()
    job.save(update_fields=["status", "status_message", "completed_at", "updated_at"])


def _claim(job_id: UUID, token: UUID) -> tuple[VirtualminProvisioningJob | None, str]:
    hint = VirtualminProvisioningJob.objects.filter(pk=job_id, operation=SAFETY_OBSERVATION_OPERATION).first()
    if hint is None or hint.account_id is None:
        return None, "missing"
    with transaction.atomic():
        account, server, service = _lock_context(hint.account_id, hint.server_id)
        job = VirtualminProvisioningJob.objects.select_for_update(of=("self",)).get(pk=job_id)
        if job.execution_token != token:
            return None, "superseded"
        if job.status != "pending":
            return None, job.status
        now = timezone.now()
        if (
            job.execution_deadline is None
            or job.execution_deadline <= now
            or job.parameters.get("scope") != current_safety_scope(service.pk)
            or not _actor_allowed(job.parameters.get("requested_by"), service.customer_id)
            or _account_busy(account)
            or maintenance_refusal(server.pk)
        ):
            _fail_locked(job, str(_("Safety observation scope or execution authority changed.")))
            return None, "failed"
        job.status, job.started_at = "running", now
        job.save(update_fields=["status", "started_at", "updated_at"])
        return job, "running"


def observation_transport_allowed(server: VirtualminServer, values: dict[str, Any]) -> bool:
    """Only an exact running observer may invoke a zero-cap read, never apply/fence."""
    request = values.get("quota_request")
    if values.get("quota_action") != "probe" or not isinstance(request, dict):
        return False
    try:
        token = request.get("token")
        if not isinstance(token, str) or str(UUID(token)) != token:
            return False
    except ValueError:
        return False
    job = VirtualminProvisioningJob.objects.filter(
        operation=SAFETY_OBSERVATION_OPERATION,
        server_id=server.pk,
        status="running",
        execution_token=request.get("token"),
        execution_deadline__gt=timezone.now(),
    ).first()
    if job is None:
        return False
    scope, identity = job.parameters.get("scope"), request.get("identity")
    service_id = scope.get("service_id") if isinstance(scope, dict) else None
    if type(service_id) is not int:
        return False
    return bool(
        isinstance(scope, dict)
        and isinstance(identity, dict)
        and scope == current_safety_scope(service_id)
        and set(request) == {"identity", "token", "generation", "disk_limit_kib", "bandwidth_limit_bytes"}
        and set(identity) == {"installation", "filesystem_uuid", "domain_id", "domain"}
        and all(identity.get(key) == scope["native_identity"][key] for key in ("installation", "filesystem_uuid"))
        and identity.get("domain") == scope["domain"]
        and isinstance(identity.get("domain_id"), str)
        and identity["domain_id"].isascii()
        and identity["domain_id"].isdigit()
        and type(request.get("generation")) is int
        and request["generation"] == max(1, scope["quota_generation"])
        and type(request.get("disk_limit_kib")) is int
        and request["disk_limit_kib"] == 0
        and type(request.get("bandwidth_limit_bytes")) is int
        and request["bandwidth_limit_bytes"] == 0
    )


def _publish(job_id: UUID, token: UUID, probe: dict[str, Any]) -> str:
    hint = VirtualminProvisioningJob.objects.get(pk=job_id)
    if hint.account_id is None:
        return "missing"
    with transaction.atomic():
        account, server, service = _lock_context(hint.account_id, hint.server_id)
        job = VirtualminProvisioningJob.objects.select_for_update(of=("self",)).get(pk=job_id)
        if job.status != "running" or job.execution_token != token:
            return "superseded"
        now = timezone.now()
        identity = validate_identity(probe.get("identity"))
        verified = verify_quota_probe(probe, identity=identity, now=now)
        if invalidate_observed_quota_identity(server, identity):
            _fail_locked(job, str(_("Requalify this node after reboot before refreshing current safety.")))
            return "failed"
        scope = current_safety_scope(service.pk)
        if (
            scope is None
            or scope != job.parameters.get("scope")
            or job.execution_deadline is None
            or job.execution_deadline <= now
            or not now - SAFETY_PROBE_MAX_AGE <= verified.observed_at <= now
            or not _actor_allowed(job.parameters.get("requested_by"), service.customer_id)
            or _account_busy(account)
            or maintenance_refusal(server.pk)
            or identity["domain"] != scope["domain"]
            or any(identity.get(key) != value for key, value in scope["native_identity"].items())
        ):
            _fail_locked(job, str(_("Fresh native safety no longer matches this service scope.")))
            return "failed"
        parts = {
            "uid_bytes": quantity(probe["uid_used_bytes"]),
            "gid_bytes": quantity(probe["gid_used_bytes"]),
            "canonical_bytes": canonical_safety_used_bytes(account, probe, owner_id=service.customer_id),
        }
        job.result = {
            "schema": 1,
            "scope": scope,
            "identity": identity,
            "observed_at": verified.observed_at.isoformat(),
            "components": parts,
            "used_bytes": max(parts.values()),
        }
        job.status, job.completed_at = "completed", now
        job.save(update_fields=["result", "status", "completed_at", "updated_at"])
        return "completed"


def run_hosting_safety_observation(job_id: str, nonce: str) -> str:  # noqa: PLR0911 -- Missing, replayed, expired and failed reads never share a mutation/retry path.
    _autocommit()
    identifier, token = UUID(job_id), UUID(nonce)
    try:
        job, outcome = _claim(identifier, token)
    except (
        VirtualminAccount.DoesNotExist,
        VirtualminServer.DoesNotExist,
        Service.DoesNotExist,
        VirtualminProvisioningJob.DoesNotExist,
    ):
        return "missing"
    if job is None:
        return outcome
    if job.account_id is None:
        return "missing"
    try:
        account = VirtualminAccount.objects.get(pk=job.account_id)
        scope = job.parameters["scope"]
        probe = probe_registered_account_quota(
            account, job.server, scope["native_identity"], token=nonce, generation=max(1, scope["quota_generation"])
        )
        return _publish(identifier, token, probe)
    except (
        VirtualminAccount.DoesNotExist,
        VirtualminServer.DoesNotExist,
        Service.DoesNotExist,
        VirtualminProvisioningJob.DoesNotExist,
    ):
        return "missing"
    except (ValidationError, ValueError, RuntimeError, OSError):
        with transaction.atomic():
            hint = VirtualminProvisioningJob.objects.get(pk=identifier)
            if hint.account_id is None:
                return "missing"
            _lock_context(hint.account_id, hint.server_id)
            current = VirtualminProvisioningJob.objects.select_for_update(of=("self",)).get(pk=identifier)
            if current.status == "running" and current.execution_token == token:
                _fail_locked(current, str(_("Read-only native safety observation did not complete.")))
        return "failed"


def dispatch_hosting_safety_observations() -> int:
    now, dispatched = timezone.now(), 0
    for job in VirtualminProvisioningJob.objects.filter(
        operation=SAFETY_OBSERVATION_OPERATION, status__in=("pending", "running")
    ).order_by("created_at")[:100]:
        if job.execution_deadline is None or job.execution_deadline <= now:
            VirtualminProvisioningJob.objects.filter(
                pk=job.pk, status=job.status, execution_token=job.execution_token
            ).update(
                status="failed",
                completed_at=now,
                status_message=str(_("Read-only observation execution budget expired.")),
                updated_at=now,
            )
        elif job.status == "pending" and job.execution_token is not None:
            _enqueue(job.pk, job.execution_token)
            dispatched += 1
    return dispatched
