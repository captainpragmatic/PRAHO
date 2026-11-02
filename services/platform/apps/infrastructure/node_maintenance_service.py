"""Audited operator decisions and revision-fenced maintenance lifecycle."""

from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha256
from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.infrastructure.node_maintenance_delivery import publish_window_notices
from apps.infrastructure.node_maintenance_gate import competing_operation_refusal
from apps.infrastructure.node_maintenance_models import (
    NodeMaintenanceAudience,
    NodeMaintenanceExecution,
    NodeMaintenancePolicy,
    NodeMaintenanceWindow,
)
from apps.infrastructure.node_maintenance_policy import validate_policy_interval

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_models import VirtualminServer
    from apps.users.models import User


def require_maintenance_operator(actor: User) -> None:
    if not actor.is_active or not (actor.is_superuser or actor.staff_role in {"admin", "manager"}):
        raise PermissionDenied(_("An active administrator or manager must approve maintenance changes."))


def audit_window(window: NodeMaintenanceWindow, actor: User | None, action: str, reason: str) -> None:
    AuditService.log_event(
        AuditEventData(
            event_type=f"node_window_{action}",
            content_object=window,
            new_values={"revision": window.revision, "status": window.status},
            description=reason,
        ),
        AuditContext(user=actor, actor_type="user" if actor else "system"),
    )


def capture_audience(window: NodeMaintenanceWindow, provenance: str) -> None:
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415

    for service_id in VirtualminAccount.objects.filter(server_id=window.node_id).values_list("service_id", flat=True):
        record, created = NodeMaintenanceAudience.objects.get_or_create(
            window=window,
            service_id_snapshot=service_id,
            defaults={"service_id": service_id, "provenance": provenance},
        )
        if not created and provenance == "execution":
            record.provenance = provenance
            record.captured_at = timezone.now()
            record.save(update_fields=["provenance", "captured_at", "updated_at"])


def manual_target_snapshot(node: VirtualminServer) -> dict[str, object]:
    """Freeze recorded endpoints without inspecting or pretending to verify a physical host."""
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415

    result: dict[str, object] = {
        "node_id": str(node.pk),
        "hostname": node.hostname,
        "ipv4_address": str(node.ipv4_address or ""),
        "ipv6_address": str(node.ipv6_address or ""),
        "api_port": node.api_port,
        "api_username": node.api_username,
        "ssh_port": node.ssh_port,
        "use_ssl": node.use_ssl,
        "ssl_verify": node.ssl_verify,
        "ssl_cert_fingerprint": node.ssl_cert_fingerprint,
        "credential_fingerprint": sha256(bytes(node.encrypted_api_password or b"")).hexdigest(),
        "effective_address": str(node.ipv4_address or node.hostname),
        "effective_ssh_port": node.ssh_port,
    }
    deployment = NodeDeployment.objects.filter(virtualmin_server=node).first()
    if deployment is not None:
        result["effective_address"] = str(deployment.ipv4_address or node.ipv4_address or node.hostname)
        result["effective_ssh_port"] = deployment.ssh_port
        result["managed_deployment"] = {
            "id": deployment.pk,
            "correlation_id": str(deployment.correlation_id),
            "provider_resource_id": str(deployment.external_node_id or ""),
            "ipv4_address": str(deployment.ipv4_address or ""),
            "ssh_port": deployment.ssh_port,
        }
    return result


def create_window(  # noqa: PLR0913  # Explicit scheduling and expected impact are independent operator decisions.
    node_id: UUID,
    *,
    actor: User,
    kind: str,
    execution_mode: str,
    starts_at: datetime,
    ends_at: datetime,
    expects_downtime: bool,
    expected_downtime_minutes: int | None,
    customer_note: str,
) -> NodeMaintenanceWindow:
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

    require_maintenance_operator(actor)
    with transaction.atomic():
        node = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=node_id)
        policy = NodeMaintenancePolicy.objects.get(node=node)
        validate_policy_interval(policy, starts_at, ends_at)
        permitted_modes = {"reboot": {"manual", "reboot"}, "panel_update": {"manual"}}
        if execution_mode == "security":
            raise ValidationError(
                _(
                    "Automatic hardening is not supported by maintenance windows. Use the separate reviewed hardening workflow; panel updates remain manual."
                )
            )
        if execution_mode not in permitted_modes.get(kind, set()):
            raise ValidationError(_("Choose a supported ordinary window and execution mode."))
        if execution_mode == "reboot" and not expects_downtime:
            raise ValidationError(_("An automated restart must declare its expected interruption."))
        if execution_mode != "manual" and policy.max_defer_minutes < 1:
            raise ValidationError(
                _("Automatic work needs at least one minute of explicitly approved latest-start deferral.")
            )
        if not customer_note.strip():
            raise ValidationError(_("Describe the expected customer impact."))
        if refusal := competing_operation_refusal(node.pk):
            raise ValidationError(refusal)
        window = NodeMaintenanceWindow(
            node=node,
            node_uuid=node.pk,
            policy=policy,
            policy_revision=policy.revision,
            policy_timezone=policy.timezone,
            kind=kind,
            execution_mode=execution_mode,
            starts_at=starts_at,
            ends_at=ends_at,
            start_by=min(ends_at, starts_at + timedelta(minutes=policy.max_defer_minutes)),
            expects_downtime=expects_downtime,
            expected_downtime_minutes=expected_downtime_minutes,
            customer_note=customer_note.strip(),
            created_by=actor,
        )
        # The protected FSM field is initialized by the model, never copied back by clean_fields.
        window.full_clean(exclude=["status"])
        window.save()
        capture_audience(window, "scheduled")
        audit_window(window, actor, "created", "Operator scheduled maintenance")
        publish_window_notices(window, "scheduled")
        return window


def locked_window(window_id: UUID) -> NodeMaintenanceWindow:
    """Lock routing identity first, then recheck after the self-only window lock."""
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

    node_id = NodeMaintenanceWindow.objects.values_list("node_id", flat=True).get(pk=window_id)
    if node_id is None:
        raise ValidationError(_("The original server is no longer registered."))
    VirtualminServer.objects.select_for_update(of=("self",)).get(pk=node_id)
    from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Server→Deployment→Window order

    list(NodeDeployment.objects.select_for_update(of=("self",)).filter(virtualmin_server_id=node_id).order_by("pk"))
    window = NodeMaintenanceWindow.objects.select_for_update(of=("self",)).get(pk=window_id)
    if window.node_id != node_id or window.node_uuid != node_id:
        raise ValidationError(_("The maintenance server binding changed. Reload before continuing."))
    return window


def _finish_operator_window(
    window: NodeMaintenanceWindow, *, outcome: str, public_outcome: str, attestation: bool
) -> None:
    if window.status not in {"running", "overran"} or not attestation or outcome not in {"completed", "failed"}:
        raise ValidationError(_("Confirm commands have stopped and record the actual maintenance outcome."))
    if not public_outcome.strip():
        raise ValidationError(_("Describe the actual outcome for affected customers."))
    if window.current_execution_id is None:
        raise ValidationError(_("The maintenance execution is missing. Reconcile it before recording an outcome."))
    execution = NodeMaintenanceExecution.objects.select_for_update(of=("self",)).get(pk=window.current_execution_id)
    if (
        execution.window_id != window.pk
        or execution.window_revision != window.revision
        or execution.node_uuid != window.node_uuid
        or execution.node_id != window.node_id
    ):
        raise ValidationError(_("The current execution no longer matches this window revision."))
    from apps.infrastructure.node_maintenance_execution import reconcile_execution_source  # noqa: PLC0415

    reconcile_execution_source(execution, public_outcome.strip())
    execution.verify() if outcome == "completed" else execution.fail()
    execution.save()
    window.completion_source = "operator"
    window.public_outcome = public_outcome.strip()
    window.was_overrun = window.was_overrun or timezone.now() > window.ends_at
    window.complete() if outcome == "completed" else window.fail()


def _begin_operator_window(window: NodeMaintenanceWindow) -> None:
    if window.execution_mode not in {"manual", "reboot"}:
        raise ValidationError(
            _("This automatic operation is unsupported. Choose a supported restart or a manual panel-update window.")
        )
    if window.status != "scheduled" or not window.starts_at <= timezone.now() <= window.start_by:
        raise ValidationError(_("Start only an unclaimed window within its permitted latest-start time."))
    if refusal := competing_operation_refusal(window.node_uuid):
        raise ValidationError(refusal)
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

    binding: dict[str, object] = {
        "internal_result": {"manual_target": manual_target_snapshot(VirtualminServer.objects.get(pk=window.node_uuid))}
    }
    if window.execution_mode != "manual":
        from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415  # Already locked before Window

        deployment = NodeDeployment.objects.filter(virtualmin_server_id=window.node_id).first()
        if deployment is None or deployment.status != "completed":
            raise ValidationError(_("Automatic maintenance requires a completed managed deployment."))
        binding = {
            "deployment": deployment,
            "deployment_correlation_id": deployment.correlation_id,
            "provider_resource_id": str(deployment.external_node_id or ""),
            "lease_until": min(window.start_by, timezone.now() + timedelta(minutes=15)),
            "internal_result": {"ipv4_address": str(deployment.ipv4_address or ""), "ssh_port": deployment.ssh_port},
        }
    execution = NodeMaintenanceExecution.objects.create(
        node_id=window.node_id,
        node_uuid=window.node_uuid,
        window=window,
        window_revision=window.revision,
        action=window.kind if window.execution_mode == "manual" else window.execution_mode,
        adapter=window.execution_mode,
        **binding,
    )
    window.current_execution = execution
    capture_audience(window, "execution")
    window.begin()


def queue_window_execution(window: NodeMaintenanceWindow) -> None:
    """Publish the ORM leaf in the same transaction as the exact claimed owner."""
    if window.execution_mode == "manual":
        return
    from django_q.tasks import async_task  # noqa: PLC0415  # No synchronous fallback at this boundary

    if window.current_execution_id is None:
        raise ValidationError(_("No claimed execution owns this window."))
    execution = NodeMaintenanceExecution.objects.get(pk=window.current_execution_id)
    execution.q_task_id = async_task(
        "apps.infrastructure.node_maintenance_tasks.execute_window",
        str(window.pk),
        window.revision,
        str(execution.token),
        q_options={"sync": False, "ack_failure": True, "timeout": 40 * 60},
    )
    execution.save(update_fields=["q_task_id", "updated_at"])


def change_window(  # noqa: PLR0912, PLR0913  # Explicit action dispatch keeps operator decisions in one revision transaction.
    window_id: UUID,
    *,
    actor: User,
    revision: int,
    action: str,
    reason: str,
    outcome: str = "",
    public_outcome: str = "",
    attestation: bool = False,
    starts_at: datetime | None = None,
    ends_at: datetime | None = None,
    customer_note: str = "",
) -> NodeMaintenanceWindow:
    require_maintenance_operator(actor)
    if not reason.strip():
        raise ValidationError(_("Record why this maintenance change is necessary."))
    with transaction.atomic():
        window = locked_window(window_id)
        if window.revision != revision:
            raise ValidationError(_("This window changed. Reload and review the current revision."))
        if action == "start":
            _begin_operator_window(window)
        elif action == "finish":
            _finish_operator_window(window, outcome=outcome, public_outcome=public_outcome, attestation=attestation)
        elif action in {"cancel", "move"}:
            if window.status != "scheduled" or window.current_execution_id:
                raise ValidationError(_("Only an unclaimed scheduled window can be moved or cancelled."))
            if action == "cancel":
                window.cancel()
            else:
                if starts_at is None or ends_at is None or window.policy_id is None:
                    raise ValidationError(_("Provide the complete replacement interval and configured policy."))
                policy = NodeMaintenancePolicy.objects.get(pk=window.policy_id)
                validate_policy_interval(policy, starts_at, ends_at)
                window.starts_at, window.ends_at = starts_at, ends_at
                window.start_by = min(ends_at, starts_at + timedelta(minutes=policy.max_defer_minutes))
                window.policy_revision, window.policy_timezone = policy.revision, policy.timezone
                if customer_note.strip():
                    window.customer_note = customer_note.strip()
            window.revision += 1
        else:
            raise ValidationError(_("Choose a supported maintenance action."))
        window.save()
        if action == "start":
            queue_window_execution(window)
        audit_window(window, actor, action, reason.strip())
        notice_event = {"cancel": "correction", "move": "correction", "finish": "completed"}.get(action)
        if notice_event:
            publish_window_notices(window, notice_event)
        return window
