"""Explicit node-wide ownership and supported maintenance execution adapters."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps
from inspect import signature
from typing import TYPE_CHECKING
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.types import Err, Ok, Result
from apps.infrastructure.node_maintenance_delivery import publish_window_notices
from apps.infrastructure.node_maintenance_gate import (
    ACTIVE_EXECUTIONS,
    competing_operation_refusal,
    locked_deployment_gate,
)
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.infrastructure.node_maintenance_service import (
    audit_window,
    capture_audience,
    manual_target_snapshot,
    require_maintenance_operator,
)

if TYPE_CHECKING:
    from apps.infrastructure.models import DriftRemediationRequest, NodeDeployment
    from apps.users.models import User


def create_emergency_window(
    node_id: UUID, *, reason: str, timezone_name: str, duration_minutes: int = 30, actor: User | None = None
) -> NodeMaintenanceWindow:
    return _create_emergency_window(
        node_id, reason=reason, timezone_name=timezone_name, duration_minutes=duration_minutes, actor=actor
    )


@dataclass(frozen=True)
class _DriftOwner:
    deployment: NodeDeployment
    request_id: int
    started_at: datetime
    action: str


def _create_emergency_window(  # noqa: PLR0913  # Public impact choices plus the private exact drift owner are independent.
    node_id: UUID,
    *,
    reason: str,
    timezone_name: str,
    duration_minutes: int = 30,
    actor: User | None = None,
    drift_owner: _DriftOwner | None = None,
) -> NodeMaintenanceWindow:
    """Publish an immediate emergency independently of the ordinary permitted calendar."""
    if actor is not None:
        require_maintenance_operator(actor)
    if not reason.strip() or not 1 <= duration_minutes <= 24 * 60:
        raise ValidationError(_("Give an emergency reason and a bounded duration of 1 to 1440 minutes."))
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValidationError(_("Choose a valid operator timezone for this emergency.")) from exc
    with transaction.atomic():
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # Node owner boundary

        node = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=node_id)
        from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Registered deployment binding

        list(NodeDeployment.objects.select_for_update(of=("self",)).filter(virtualmin_server=node).order_by("pk"))
        if refusal := competing_operation_refusal(
            node.pk, owned_drift_request_id=drift_owner.request_id if drift_owner else None
        ):
            raise ValidationError(refusal)
        now, emergency_id = timezone.now(), uuid4()
        prior = (
            NodeMaintenanceWindow.objects.select_for_update(of=("self",))
            .filter(node=node, status__in=("scheduled", "running", "overran"))
            .first()
        )
        if prior is not None:
            if (
                prior.status != "scheduled"
                or prior.current_execution_id is not None
                or prior.kind == "emergency"
                or prior.starts_at <= now
            ):
                raise ValidationError(_("An emergency cannot preempt already claimed or current maintenance."))
            prior.cancel()
            prior.revision += 1
            prior.internal_outcome = {"code": "emergency_supersession", "superseded_by": str(emergency_id)}
            prior.save()
            audit_window(prior, None, "cancel", "Unclaimed future window superseded by an emergency")
            publish_window_notices(prior, "correction")
        policy = NodeMaintenancePolicy.objects.filter(node=node).first()
        window = NodeMaintenanceWindow(
            id=emergency_id,
            node=node,
            node_uuid=node.pk,
            kind="emergency",
            execution_mode="drift" if drift_owner else "manual",
            policy=policy,
            policy_revision=policy.revision if policy else 0,
            policy_timezone=timezone_name,
            starts_at=now,
            ends_at=now + timedelta(minutes=duration_minutes),
            start_by=now,
            customer_note=_(
                "Emergency maintenance is needed on the server your site runs on. We are checking its recovery."
            ),
            internal_outcome={"code": "emergency", "reason": reason.strip()[:1000]},
            origin="system",
            created_by=actor,
            expects_downtime=True,
        )
        window.full_clean(exclude=["status"])
        window.save()
        binding = (
            _drift_binding(drift_owner)
            if drift_owner
            else {"internal_result": {"manual_target": manual_target_snapshot(node)}}
        )
        execution = NodeMaintenanceExecution.objects.create(
            node=node,
            node_uuid=node.pk,
            window=window,
            window_revision=window.revision,
            action=drift_owner.action if drift_owner else "emergency",
            adapter="drift" if drift_owner else "manual",
            **binding,
        )
        if drift_owner is None:
            execution.issue()
            execution.save()
        window.current_execution = execution
        capture_audience(window, "execution")
        window.begin()
        window.save()
        audit_window(window, actor, "created", "Emergency window: " + reason.strip())
        audit_window(window, actor, "start", "Emergency execution ownership published")
        publish_window_notices(window, "scheduled")
        return window


class MaintenanceOwnershipLostError(ValidationError):
    """The exact node/resource/revision no longer belongs to this invocation."""


@dataclass(frozen=True)
class NodeExecutionLease:
    execution_id: UUID
    token: UUID
    deployment_id: int
    correlation_id: UUID
    provider_resource_id: str
    node_id: UUID | None
    window_id: UUID | None
    window_revision: int
    action: str
    ipv4_address: str
    ssh_port: int


@dataclass
class _Invocation:
    lease: NodeExecutionLease
    issued_here: bool = False
    recovery_verified: bool = False


_invocation: ContextVar[_Invocation | None] = ContextVar("node_maintenance_invocation", default=None)


def execute_window_claim(window_id: UUID, revision: int, execution_token: UUID) -> Result[bool, str]:
    """Consume a single queued claim; no transaction spans the actual native method."""
    hint = NodeMaintenanceExecution.objects.filter(
        window_id=window_id, window_revision=revision, token=execution_token
    ).first()
    if hint is None or hint.deployment_id is None:
        return Err("No exact managed execution owns this queued window")
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415

    deployment = NodeDeployment.objects.get(pk=hint.deployment_id)
    # Build from recorded identities, never silently adopt a changed live resource.
    lease = _lease(hint, deployment)
    frame = _Invocation(lease)
    invocation_token = _invocation.set(frame)
    succeeded = False
    try:
        with _locked_invocation(frame) as (current, _window):
            if current.phase != "claimed":
                return Err("This queued execution was already issued or settled; do not replay")
        from apps.infrastructure.deployment_service import get_deployment_service  # noqa: PLC0415

        service = get_deployment_service()
        if hint.action == "reboot":
            from apps.infrastructure.provider_config import get_provider_token  # noqa: PLC0415

            credentials = get_provider_token(deployment.provider)
            if credentials.is_err():
                return Err(credentials.unwrap_err())
            reboot_result = service.reboot_node(deployment, {"api_token": credentials.unwrap()})
            error = reboot_result.unwrap_err() if reboot_result.is_err() else None
        else:
            return Err("This window has no supported automatic execution adapter")
        succeeded = error is None
        return Ok(True) if error is None else Err(error)
    except MaintenanceOwnershipLostError as exc:
        return Err(str(exc))
    finally:
        try:
            # The native decorator settles its own result; preflight failures still
            # close only this exact unissued claim, never a later owner.
            _settle_invocation(frame, succeeded)
        finally:
            _invocation.reset(invocation_token)


def _lease(execution: NodeMaintenanceExecution, deployment: NodeDeployment) -> NodeExecutionLease:
    if execution.deployment_correlation_id is None:
        raise MaintenanceOwnershipLostError("No exact deployment correlation is recorded")
    return NodeExecutionLease(
        execution.pk,
        execution.token,
        deployment.pk,
        execution.deployment_correlation_id,
        execution.provider_resource_id,
        execution.node_id,
        execution.window_id,
        execution.window_revision,
        execution.action,
        str(execution.internal_result.get("ipv4_address", "")),
        int(execution.internal_result.get("ssh_port", 0)),
    )


def prepare_native_queue(deployment_id: int, action: str) -> UUID:
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415

    result = claim_direct_operation(NodeDeployment.objects.get(pk=deployment_id), action)
    if result.is_err():
        raise ValidationError(result.unwrap_err())
    return result.unwrap().token


def bind_native_queue(token: UUID, task_id: str) -> None:
    NodeMaintenanceExecution.objects.filter(token=token, phase="claimed").update(q_task_id=task_id)


class QueuedNodeOperationGuard:
    """Consume the exact queue reservation, including failures before the native service is called."""

    def __init__(self, action: str) -> None:
        self.action = action

    def __call__[**P](self, method: Callable[P, dict[str, object]]) -> Callable[P, dict[str, object]]:
        call_signature = signature(method)

        @wraps(method)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> dict[str, object]:
            bound = call_signature.bind(*args, **kwargs).arguments
            raw_token = bound.get("maintenance_token")
            if raw_token is None:
                return method(*args, **kwargs)  # Legacy payloads still use the native entrypoint's current gate.
            if not isinstance(raw_token, str):
                return {"success": False, "error": "Invalid native reservation token"}
            execution = NodeMaintenanceExecution.objects.filter(
                token=raw_token, deployment_id=bound.get("deployment_id"), action=self.action, phase="claimed"
            ).first()
            if execution is None or execution.deployment is None:
                return {"success": False, "error": "This native queue claim was already issued, settled, or replaced"}
            frame = _Invocation(_lease(execution, execution.deployment))
            context_token = _invocation.set(frame)
            succeeded = False
            try:
                with _locked_invocation(frame):
                    pass
                result = method(*args, **kwargs)
                succeeded = result.get("success") is True
                return result
            except MaintenanceOwnershipLostError as exc:
                return {"success": False, "error": str(exc)}
            finally:
                try:
                    _settle_invocation(frame, succeeded)
                finally:
                    _invocation.reset(context_token)

        return wrapped


def _drift_binding(owner: _DriftOwner) -> dict[str, object]:
    deployment = owner.deployment
    return {
        "deployment": deployment,
        "deployment_correlation_id": deployment.correlation_id,
        "provider_resource_id": str(deployment.external_node_id or ""),
        "existing_job_type": "drift",
        "existing_job_id": str(owner.request_id),
        "lease_until": timezone.now() + timedelta(minutes=15),
        "internal_result": {
            "ipv4_address": str(deployment.ipv4_address or ""),
            "ssh_port": deployment.ssh_port,
            "drift_started_at": owner.started_at.isoformat(),
        },
    }


def prepare_drift_execution(request: DriftRemediationRequest, deployment: NodeDeployment, started_at: datetime) -> None:
    """Called under Server→Deployment before Request CAS; caller rolls back publication on lost CAS."""
    if NodeMaintenanceExecution.objects.filter(deployment=deployment, phase__in=ACTIVE_EXECUTIONS).exists():
        raise MaintenanceOwnershipLostError("Maintenance already owns this deployment")
    if deployment.operation_reserved_at is not None or deployment.needs_reconciliation:
        raise MaintenanceOwnershipLostError("A deployment operation is reserved or requires reconciliation")
    details = request.action_details or {}
    power_recovery = (
        details.get("field_name") == "server_status"
        and details.get("expected_value") == "running"
        and details.get("actual_value") in {"off", "stopped"}
    )
    owner = _DriftOwner(deployment, request.pk, started_at, "drift_power_on" if power_recovery else "drift_resize")
    if power_recovery and deployment.virtualmin_server_id:
        policy = NodeMaintenancePolicy.objects.filter(node_id=deployment.virtualmin_server_id).first()
        _create_emergency_window(
            deployment.virtualmin_server_id,
            reason="Approved recovery of an observed powered-off server",
            timezone_name=policy.timezone if policy else "UTC",
            drift_owner=owner,
        )
        return
    if deployment.virtualmin_server_id and (
        refusal := competing_operation_refusal(deployment.virtualmin_server_id, owned_drift_request_id=request.pk)
    ):
        raise MaintenanceOwnershipLostError(refusal)
    NodeMaintenanceExecution.objects.create(
        node_id=deployment.virtualmin_server_id,
        node_uuid=deployment.virtualmin_server_id,
        action=owner.action,
        adapter="drift",
        **_drift_binding(owner),
    )


def run_drift_execution(
    request: DriftRemediationRequest, callback: Callable[[], Result[bool, str]]
) -> Result[bool, str]:
    if request.started_at is None:
        return Err("The source drift claim has no start identity")
    execution = NodeMaintenanceExecution.objects.get(
        existing_job_type="drift",
        existing_job_id=str(request.pk),
        internal_result__drift_started_at=request.started_at.isoformat(),
    )
    frame = _Invocation(_lease(execution, request.deployment))
    context_token = _invocation.set(frame)
    succeeded = False
    try:
        result = callback()
        succeeded = result.is_ok()
        return result
    except MaintenanceOwnershipLostError as exc:
        return Err(str(exc))
    finally:
        try:
            _settle_invocation(frame, succeeded)
        finally:
            _invocation.reset(context_token)


def drift_recovery_verified(deployment: NodeDeployment) -> None:
    frame = _invocation.get()
    if frame is not None and frame.lease.deployment_id == deployment.pk:
        frame.recovery_verified = bool(deployment.ipv4_address)


def mark_drift_rollback_issued(deployment: NodeDeployment) -> None:
    frame = _invocation.get()
    if frame is None or frame.lease.action not in {"drift_power_on", "drift_resize"}:
        raise MaintenanceOwnershipLostError("No exact drift invocation owns this rollback")
    mark_node_operation_issued(deployment, frame.lease.action)


def reconcile_execution_source(execution: NodeMaintenanceExecution, reason: str) -> None:
    """Fence the existing source job with the operator's exact execution closure."""
    if execution.adapter == "manual":
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        if execution.node_id is None:
            raise MaintenanceOwnershipLostError(
                "The recorded manual target was removed; retain its hold for manual review"
            )
        node = VirtualminServer.objects.filter(pk=execution.node_id).first()
        if node is None or execution.internal_result.get("manual_target") != manual_target_snapshot(node):
            raise MaintenanceOwnershipLostError("The recorded manual target changed; retain its hold for manual review")
        return
    from apps.infrastructure.models import DriftRemediationRequest, NodeDeployment  # noqa: PLC0415

    if execution.deployment_id is None:
        raise MaintenanceOwnershipLostError("The recorded deployment was removed; retain its hold for manual review")
    deployment = NodeDeployment.objects.filter(pk=execution.deployment_id).first()
    if (
        deployment is None
        or execution.deployment_correlation_id != deployment.correlation_id
        or execution.provider_resource_id != str(deployment.external_node_id or "")
        or execution.node_id != deployment.virtualmin_server_id
        or execution.node_uuid != deployment.virtualmin_server_id
        or execution.internal_result.get("ipv4_address") != str(deployment.ipv4_address or "")
        or execution.internal_result.get("ssh_port") != deployment.ssh_port
    ):
        raise MaintenanceOwnershipLostError("The recorded native resource changed; retain its hold for manual review")
    if execution.existing_job_type != "drift":
        return
    source = DriftRemediationRequest.objects.select_for_update(of=("self",)).get(pk=execution.existing_job_id)
    if (
        source.deployment_id != deployment.pk
        or source.started_at is None
        or source.started_at.isoformat() != execution.internal_result.get("drift_started_at")
    ):
        raise MaintenanceOwnershipLostError("The source drift claim changed; retain its hold for manual review")
    if source.status == "in_progress":
        DriftRemediationRequest.objects.filter(pk=source.pk, status="in_progress", started_at=source.started_at).update(
            status="failed",
            completed_at=timezone.now(),
            error_message=("Exact execution closed by an operator: " + reason)[:1000],
        )


def recover_unissued_executions(window_ids: list[str] | None = None) -> int:
    """Expire only proved-unissued claims; an issued/unknown command never expires."""
    candidates = NodeMaintenanceExecution.objects.filter(
        phase="claimed", issued_at__isnull=True, lease_until__lte=timezone.now(), deployment__isnull=False
    )
    if window_ids is not None:
        candidates = candidates.filter(window_id__in=window_ids)
    failed_windows = 0
    for execution in candidates.select_related("deployment"):
        if execution.deployment is None:
            continue
        frame = _Invocation(_lease(execution, execution.deployment))
        try:
            with _locked_invocation(frame, settling=True) as (current, window):
                if (
                    current.phase != "claimed"
                    or current.issued_at is not None
                    or current.lease_until is None
                    or current.lease_until > timezone.now()
                ):
                    continue
                if current.existing_job_type == "drift":
                    from apps.infrastructure.models import DriftRemediationRequest  # noqa: PLC0415

                    source = DriftRemediationRequest.objects.get(pk=current.existing_job_id)
                    if source.status in {"approved", "in_progress"}:
                        continue  # The existing source job/reaper remains authoritative.
                _settle_invocation(frame, False)
                failed_windows += int(window is not None)
        except MaintenanceOwnershipLostError:
            continue  # Changed identity is an operator review hold, never an expiry permission.
    return failed_windows


def claim_direct_operation(deployment: NodeDeployment, action: str) -> Result[NodeExecutionLease, str]:
    """Publish one otherwise-untracked native owner; all provider I/O occurs after commit."""
    with locked_deployment_gate(deployment.pk) as current:
        if current is None:
            return Err("The deployment no longer exists")
        if (
            current.virtualmin_server_id != deployment.virtualmin_server_id
            or current.correlation_id != deployment.correlation_id
            or current.external_node_id != deployment.external_node_id
            or current.ipv4_address != deployment.ipv4_address
            or current.ssh_port != deployment.ssh_port
        ):
            return Err("The deployment resource binding changed; reload before operating it")
        if current.operation_reserved_at is not None or current.needs_reconciliation:
            return Err("A deployment operation is reserved or requires reconciliation")
        if NodeMaintenanceExecution.objects.filter(deployment=current, phase__in=ACTIVE_EXECUTIONS).exists():
            return Err("Maintenance currently owns this deployment; verify its existing operation first")
        if current.virtualmin_server_id and (refusal := competing_operation_refusal(current.virtualmin_server_id)):
            return Err(refusal)
        execution = NodeMaintenanceExecution.objects.create(
            node_id=current.virtualmin_server_id,
            node_uuid=current.virtualmin_server_id,
            deployment=current,
            deployment_correlation_id=current.correlation_id,
            provider_resource_id=str(current.external_node_id or ""),
            action=action,
            adapter="security" if action == "security" else "provider",
            lease_until=timezone.now() + timedelta(minutes=15),
            internal_result={"ipv4_address": str(current.ipv4_address or ""), "ssh_port": current.ssh_port},
        )
        return Ok(_lease(execution, current))


@contextmanager
def _locked_invocation(
    frame: _Invocation, *, settling: bool = False
) -> Iterator[tuple[NodeMaintenanceExecution, NodeMaintenanceWindow | None]]:
    lease = frame.lease
    with locked_deployment_gate(lease.deployment_id) as deployment:
        if (
            deployment is None
            or deployment.correlation_id != lease.correlation_id
            or str(deployment.external_node_id or "") != lease.provider_resource_id
            or deployment.virtualmin_server_id != lease.node_id
            or str(deployment.ipv4_address or "") != lease.ipv4_address
            or deployment.ssh_port != lease.ssh_port
        ):
            raise MaintenanceOwnershipLostError("The native resource binding changed")
        window = None
        if lease.window_id is not None:
            window = NodeMaintenanceWindow.objects.select_for_update(of=("self",)).get(pk=lease.window_id)
            if (
                window.current_execution_id != lease.execution_id
                or window.revision != lease.window_revision
                or window.status not in {"running", "overran"}
                or window.node_id != lease.node_id
            ):
                raise MaintenanceOwnershipLostError("The window no longer owns this execution")
        execution = NodeMaintenanceExecution.objects.select_for_update(of=("self",)).get(pk=lease.execution_id)
        if (
            execution.token != lease.token
            or execution.phase not in ACTIVE_EXECUTIONS
            or execution.deployment_id != lease.deployment_id
            or execution.deployment_correlation_id != lease.correlation_id
            or execution.provider_resource_id != lease.provider_resource_id
            or execution.node_id != lease.node_id
            or execution.node_uuid != lease.node_id
            or execution.action != lease.action
            or execution.window_id != lease.window_id
            or execution.window_revision != lease.window_revision
        ):
            raise MaintenanceOwnershipLostError("The native execution claim is no longer current")
        if execution.existing_job_type == "drift":
            from apps.infrastructure.models import DriftRemediationRequest  # noqa: PLC0415

            source = DriftRemediationRequest.objects.select_for_update(of=("self",)).get(pk=execution.existing_job_id)
            if source.started_at is None or source.started_at.isoformat() != execution.internal_result.get(
                "drift_started_at"
            ):
                raise MaintenanceOwnershipLostError("The source drift claim changed")
            if not settling and source.status != "in_progress":
                raise MaintenanceOwnershipLostError("The source drift request no longer owns execution")
        yield execution, window


def mark_node_operation_issued(deployment: NodeDeployment, action: str) -> None:
    """The exact invocation publishes intent before the first mutating external command."""
    frame = _invocation.get()
    if frame is None or frame.lease.deployment_id != deployment.pk or frame.lease.action != action:
        raise MaintenanceOwnershipLostError("No matching native operation claim")
    with _locked_invocation(frame) as (execution, window):
        if frame.issued_here:
            if execution.phase != "issued":
                raise MaintenanceOwnershipLostError("The issued invocation no longer owns its command")
            return
        if execution.phase != "claimed" or (execution.lease_until and execution.lease_until <= timezone.now()):
            raise MaintenanceOwnershipLostError("This claim was already issued or expired; do not replay it")
        if window is not None and window.kind != "emergency" and timezone.now() > window.start_by:
            raise MaintenanceOwnershipLostError("The permitted latest start passed before command dispatch")
        if action != "security" and not execution.provider_resource_id:
            raise MaintenanceOwnershipLostError("No exact provider resource is recorded for this operation")
        execution.issue()
        execution.save()
        frame.issued_here = True


@contextmanager
def native_write_guard(deployment: NodeDeployment) -> Iterator[None]:
    """Fence late local lifecycle writes without holding any lock across provider I/O."""
    frame = _invocation.get()
    if frame is None or frame.lease.deployment_id != deployment.pk or not frame.issued_here:
        raise MaintenanceOwnershipLostError("No current issued native invocation")
    with _locked_invocation(frame) as (execution, _window):
        if execution.phase != "issued":
            raise MaintenanceOwnershipLostError("The native invocation was reconciled before this result arrived")
        yield


@contextmanager
def current_native_server_write_guard(node_id: UUID) -> Iterator[None]:
    """Fence a native caller's late server write; ordinary activation retains its existing CAS."""
    frame = _invocation.get()
    if frame is None:
        yield
        return
    if frame.lease.node_id != node_id or not frame.issued_here:
        raise MaintenanceOwnershipLostError("No current issued native invocation owns this server")
    with _locked_invocation(frame) as (execution, _window):
        if execution.phase != "issued":
            raise MaintenanceOwnershipLostError("The native invocation was reconciled before this activation result")
        yield


def current_stop_token(deployment: NodeDeployment) -> UUID | None:
    frame = _invocation.get()
    if frame is None or frame.lease.action != "stop" or frame.lease.deployment_id != deployment.pk:
        return None
    with _locked_invocation(frame):
        return frame.lease.token


def _settle_invocation(frame: _Invocation, succeeded: bool) -> None:
    try:
        with _locked_invocation(frame, settling=True) as (execution, window):
            if execution.phase == "claimed":
                execution.fail()
                execution.internal_result = {**execution.internal_result, "code": "not_run"}
                if window is not None:
                    window.fail()
                    window.completion_source = "job"
                    window.public_outcome = _("The planned work did not run. An operator will review the next steps.")
            elif execution.phase == "issued":
                if not frame.issued_here:
                    return  # A duplicate payload did not issue this other invocation's command.
                if succeeded and (frame.lease.action == "security" or frame.recovery_verified):
                    execution.verify()
                    if window is not None:
                        window.complete()
                        window.completion_source = "job"
                        window.public_outcome = (
                            _("The provider reports the server running and its management connection responds.")
                            if frame.recovery_verified
                            else _("The approved maintenance tasks finished successfully.")
                        )
                elif succeeded:
                    execution.await_recovery()
                else:
                    execution.mark_uncertain()
            execution.save()
            if window is not None:
                window.save()
                if window.status in {"completed", "failed"}:
                    audit_window(window, None, "finish", "Exact execution result settled the window")
                    publish_window_notices(window, "completed")
    except MaintenanceOwnershipLostError:
        return  # A stale result never paints a newer owner or releases its hold.


class NodeOperationGuard:
    """Apply the same ownership protocol to each existing direct native entrypoint."""

    def __init__(self, action: str) -> None:
        self.action = action

    def __call__[V, **P](self, method: Callable[P, Result[V, str]]) -> Callable[P, Result[V, str]]:
        call_signature = signature(method)

        @wraps(method)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> Result[V, str]:
            from apps.infrastructure.models import (  # noqa: PLC0415  # Source claim follows Execution in lock order.
                NodeDeployment,  # Preserve the complete public signature
            )

            deployment = call_signature.bind(*args, **kwargs).arguments.get("deployment")
            if not isinstance(deployment, NodeDeployment):
                return Err("A persisted deployment identity is required for native operations")
            frame = _invocation.get()
            if frame is None:
                claim = claim_direct_operation(deployment, self.action)
                if claim.is_err():
                    return Err(claim.unwrap_err())
                frame = _Invocation(claim.unwrap())
            elif frame.lease.deployment_id != deployment.pk or frame.lease.action != self.action:
                return Err("A different native operation owns this invocation")
            token = _invocation.set(frame)
            succeeded = False
            try:
                result = method(*args, **kwargs)
                succeeded = result.is_ok()
                return result
            finally:
                try:
                    _settle_invocation(frame, succeeded)
                finally:
                    _invocation.reset(token)

        return wrapped


def reconcile_direct_execution(  # noqa: PLR0913  # Phase, outcome and both independent operator attestations are explicit.
    execution_id: UUID,
    *,
    actor: User,
    expected_phase: str,
    outcome: str,
    reason: str,
    commands_stopped: bool,
    resource_confirmed: bool,
) -> NodeMaintenanceExecution:
    """An authorized operator attests the exact recorded, unwindowed operation's final state."""
    require_maintenance_operator(actor)
    if not reason.strip() or not commands_stopped or not resource_confirmed or outcome not in {"verified", "failed"}:
        raise ValidationError(
            _("Confirm the recorded target identity and that all commands stopped, then record the outcome.")
        )
    hint = NodeMaintenanceExecution.objects.only("deployment_id", "window_id").get(pk=execution_id)
    if hint.window_id is not None or hint.deployment_id is None:
        raise ValidationError(_("Use the linked maintenance window's outcome controls for this execution."))
    with locked_deployment_gate(hint.deployment_id) as deployment:
        if deployment is None:
            raise ValidationError(_("The recorded deployment no longer exists. Manual resource review is required."))
        execution = NodeMaintenanceExecution.objects.select_for_update(of=("self",)).get(pk=execution_id)
        if (
            execution.phase != expected_phase
            or execution.phase not in ACTIVE_EXECUTIONS
            or execution.window_id is not None
        ):
            raise ValidationError(_("This execution changed. Reload and review its current phase."))
        if execution.phase == "claimed" and outcome != "failed":
            raise ValidationError(_("An unissued claim can only be closed as not run."))
        if (
            execution.deployment_id != deployment.pk
            or execution.deployment_correlation_id != deployment.correlation_id
            or execution.provider_resource_id != str(deployment.external_node_id or "")
            or execution.node_id != deployment.virtualmin_server_id
            or execution.node_uuid != deployment.virtualmin_server_id
            or execution.internal_result.get("ipv4_address") != str(deployment.ipv4_address or "")
            or execution.internal_result.get("ssh_port") != deployment.ssh_port
        ):
            raise ValidationError(
                _("The recorded resource binding changed. Do not release this hold without manual review.")
            )
        execution.verify() if outcome == "verified" else execution.fail()
        reconcile_execution_source(execution, reason)
        execution.internal_result = {
            **execution.internal_result,
            "operator_note": reason.strip()[:1000],
            "reconciled_by": str(actor.pk),
            "reconciled_at": timezone.now().isoformat(),
        }
        execution.save()
        from apps.audit.services import (  # noqa: PLC0415  # Operator audit boundary
            AuditContext,
            AuditEventData,
            AuditService,
        )

        AuditService.log_event(
            AuditEventData(
                event_type="node_operation_reconciled",
                content_object=execution,
                new_values={"phase": execution.phase, "action": execution.action},
                description=reason.strip(),
            ),
            AuditContext(user=actor),
        )
        return execution
