"""Sequential node evacuation and health-sweep coordination."""

from __future__ import annotations

import logging
from datetime import timedelta
from time import monotonic
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from django.conf import settings
from django.db import IntegrityError, models, transaction
from django.utils import timezone
from django_q.tasks import async_task

from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.common.types import Err, Ok, Result
from apps.settings.services import SettingsService

from .virtualmin_migration_models import _TERMINAL_STATUSES, NodeDrain, VirtualminMigration
from .virtualmin_migration_service import VirtualminMigrationService, migration_task_timeout
from .virtualmin_models import HEALTH_AUTO_FAIL_THRESHOLD, VirtualminAccount, VirtualminServer

if TYPE_CHECKING:
    from apps.users.models import User

logger = logging.getLogger(__name__)


def _audit(obj: models.Model, action: str, user: User | None = None, detail: str = "") -> None:
    review = action.endswith(("paused", "health_alert", "autofail_deferred"))
    AuditService.log_event(
        AuditEventData(event_type=action, content_object=obj, description=detail or action),
        AuditContext(
            user=user,
            actor_type="user" if user else "system",
            metadata={
                "source_app": "provisioning",
                "severity": "high" if review else "low",
                "requires_review": review,
                "detail": detail,
            },
        ),
    )


def server_has_active_migration(server: VirtualminServer) -> bool:
    return (
        VirtualminMigration.objects.filter(models.Q(source_server=server) | models.Q(target_server=server))
        .exclude(status__in=_TERMINAL_STATUSES)
        .exists()
    )


class NodeDrainService:
    @staticmethod
    def _timeout() -> int:
        timeout = migration_task_timeout() + 300
        if timeout + 60 >= int(str(settings.Q_CLUSTER.get("retry", 0))):
            raise ValueError("Drain task budget must fit below the broker visibility timeout")
        return timeout

    @classmethod
    def start_drain(
        cls, server: VirtualminServer, *, initiated_by: User | None, reason: str = "manual"
    ) -> Result[NodeDrain, str]:
        try:
            if not SettingsService.get_boolean_setting("provisioning.migration_enabled", False):
                raise ValueError("Virtualmin migration is disabled")
            if not SettingsService.get_boolean_setting("infrastructure.drain_enabled", False):
                raise ValueError("Node drain is disabled")
            cls._timeout()
            with transaction.atomic():
                server = VirtualminServer.objects.select_for_update().get(pk=server.pk)
                if server.status != "active" or server.is_draining:
                    raise ValueError("Server must be active and not already draining")
                if reason not in NodeDrain.Reason.values:
                    raise ValueError("Invalid drain reason")
                if not getattr(server, "node_deployment", None):
                    raise ValueError("Server has no managed node_deployment")
                if server.drains.exclude(status__in=NodeDrain.TERMINAL).exists():
                    raise ValueError("Server already has an active drain")
                if server.migrations_in.exclude(status__in=_TERMINAL_STATUSES).exists():
                    raise ValueError("Server has an incoming migration")
                drain = NodeDrain.objects.create(
                    server=server,
                    initiated_by=initiated_by,
                    reason=reason,
                    accounts_total=server.accounts.filter(status__in=("active", "suspended")).count(),
                )
                server.is_draining = True
                server.save(update_fields=["is_draining", "updated_at"])
                _audit(drain, "node_drain_started", initiated_by)
                transaction.on_commit(lambda: cls._enqueue(drain.pk, drain.task_token))
            return Ok(drain)
        except (ValueError, IntegrityError) as error:
            return Err(str(error))

    @staticmethod
    def _close(drain: NodeDrain, status: str, detail: str = "") -> None:
        drain.status = status  # fsm-bypass: NodeDrain has a CharField; callers hold its row lock.
        drain.error_detail = detail
        drain.accounts_skipped = max(0, drain.accounts_total - drain.accounts_migrated)
        drain.finished_at = timezone.now() if status in NodeDrain.TERMINAL else None
        drain.save()
        if status == "cancelled":
            VirtualminServer.objects.filter(pk=drain.server_id).update(is_draining=False, updated_at=timezone.now())
        action = "paused" if status == "paused_needs_review" else status
        _audit(drain, f"node_drain_{action}", drain.initiated_by, detail)
        logger.info("✅ [NodeDrain] drain=%s status=%s", drain.pk, status)

    @classmethod
    def _enqueue(cls, drain_id: UUID, token: UUID) -> None:
        try:
            async_task(
                "apps.provisioning.virtualmin_tasks.run_node_drain",
                str(drain_id),
                str(token),
                timeout=cls._timeout(),
            )
        except Exception as error:
            logger.exception("🔥 [NodeDrain] Enqueue failed: %s", drain_id)
            with transaction.atomic():
                drain = NodeDrain.objects.select_for_update().get(pk=drain_id)
                if drain.status == "pending" and drain.task_token == token:
                    cls._close(drain, "paused_needs_review", f"Enqueue failed: {error}")

    @classmethod
    def cancel_drain(cls, drain: NodeDrain) -> Result[NodeDrain, str]:
        with transaction.atomic():
            drain = NodeDrain.objects.select_for_update().get(pk=drain.pk)
            if drain.status in NodeDrain.TERMINAL:
                return Err("Only a non-terminal drain can be cancelled")
            drain.cancel_requested = True
            drain.save(update_fields=["cancel_requested", "updated_at"])
            if drain.status != "running":
                cls._close(drain, "cancelled")
        return Ok(drain)

    @classmethod
    def finalize_drain(cls, drain: NodeDrain, *, confirmed_by: User) -> Result[NodeDrain, str]:
        with transaction.atomic():
            drain = NodeDrain.objects.select_for_update().get(pk=drain.pk)
            server = VirtualminServer.objects.select_for_update().get(pk=drain.server_id)
            if drain.status != "completed":
                return Err("Only a completed drain can be finalized")
            if drain.routing_confirmed:
                return Ok(drain)
            if not server.is_draining or server.accounts.filter(status__in=("active", "suspended")).exists():
                return Err("Server is not fully drained")
            if server_has_active_migration(server):
                return Err("Server still has an active migration")
            drain.routing_confirmed = True
            drain.save(update_fields=["routing_confirmed", "updated_at"])
            # fsm-bypass: VirtualminServer status is a CharField; locked operator finalization.
            server.status, server.is_draining = "disabled", False
            server.save(update_fields=["status", "is_draining", "updated_at"])
            _audit(drain, "node_drain_finalized", confirmed_by)
        return Ok(drain)

    @classmethod
    def _next(cls, drain: NodeDrain, deadline: float) -> VirtualminAccount | None:
        if drain.cancel_requested:
            cls._close(drain, "cancelled")
            return None
        account = (
            VirtualminAccount.objects.filter(server_id=drain.server_id, status__in=("active", "suspended"))
            .order_by("pk")
            .first()
        )
        if account is None:
            cls._close(drain, "completed")
            return None
        drain.server.refresh_from_db()
        if not drain.server.is_healthy:
            cls._close(drain, "paused_needs_review", "Source is unhealthy or unreachable")
            return None
        if deadline - monotonic() < migration_task_timeout() + 60:
            # fsm-bypass: persist a between-account checkpoint; token fences old deliveries.
            drain.status, drain.task_token = "pending", uuid4()
            drain.save(update_fields=["status", "task_token", "updated_at"])
            transaction.on_commit(lambda: cls._enqueue(drain.pk, drain.task_token))
            return None
        return account

    @classmethod
    def _migrate(cls, drain: NodeDrain, account: VirtualminAccount) -> str:
        service = VirtualminMigrationService()
        targets = sorted(service.eligible_targets(account), key=lambda server: (server.current_domains, str(server.pk)))
        if not targets:
            return "No eligible migration target"
        result = service.start_migration(
            account, targets[0], initiated_by=drain.initiated_by, reason="drain", enqueue=False
        )
        if result.is_err():
            return result.unwrap_err()
        migration = result.unwrap()
        NodeDrain.objects.filter(pk=drain.pk, task_token=drain.task_token, status="running").update(
            current_migration=migration, updated_at=timezone.now()
        )
        execution = service.run(migration.pk)
        migration.refresh_from_db()
        if execution.is_err():
            return execution.unwrap_err()
        return "" if migration.status == "completed" else f"Migration {migration.pk}: {migration.status}"

    @classmethod
    def run(cls, drain_id: UUID, task_token: UUID | None = None) -> Result[NodeDrain, str]:
        timeout = cls._timeout()
        deadline = monotonic() + timeout
        with transaction.atomic():
            drain = NodeDrain.objects.select_for_update().get(pk=drain_id)
            token = task_token or drain.task_token
            if token != drain.task_token:
                return Ok(drain)
            if (
                drain.status == "running"
                and drain.worker_started_at
                and drain.worker_started_at < timezone.now() - timedelta(seconds=timeout + 60)
            ):
                cls._close(drain, "paused_needs_review", "Worker interrupted; inspect the current migration")
            if drain.status != "pending":
                return Ok(drain)
            # fsm-bypass: conditional claim under the drain row lock.
            drain.status, drain.worker_started_at = "running", timezone.now()
            drain.save(update_fields=["status", "worker_started_at", "updated_at"])
        while True:
            with transaction.atomic():
                drain = NodeDrain.objects.select_for_update().get(pk=drain_id)
                if drain.status != "running" or drain.task_token != token:
                    return Ok(drain)
                account = cls._next(drain, deadline)
                if account is None:
                    return Ok(drain)
            try:
                error = cls._migrate(drain, account)
            except Exception as exc:
                logger.exception("🔥 [NodeDrain] Migration interrupted: %s", drain.pk)
                error = str(exc)
            with transaction.atomic():
                drain = NodeDrain.objects.select_for_update().get(pk=drain_id)
                if drain.status != "running" or drain.task_token != token:
                    return Ok(drain)
                if error:
                    cls._close(drain, "paused_needs_review", error)
                    return Ok(drain)
                drain.accounts_migrated += 1
                drain.save(update_fields=["accounts_migrated", "updated_at"])


def coordinate_health_failure(server: VirtualminServer) -> None:
    """Serialize auto-fail with drain admission and migration server locks."""
    with transaction.atomic():
        server = VirtualminServer.objects.select_for_update().get(pk=server.pk)
        threshold = min(
            HEALTH_AUTO_FAIL_THRESHOLD - 1,
            max(1, SettingsService.get_integer_setting("infrastructure.auto_drain_failure_threshold", 3)),
        )
        if server.consecutive_health_failures == threshold:
            _audit(server, "virtualmin_server_health_alert", detail=server.health_check_error)
            auto = SettingsService.get_boolean_setting("infrastructure.auto_drain_enabled", False)
            enabled = SettingsService.get_boolean_setting("infrastructure.drain_enabled", False)
            if auto and enabled and not server.is_draining:
                try:
                    result = NodeDrainService.start_drain(server, initiated_by=None, reason="auto_health")
                    if result.is_err():
                        raise ValueError(result.unwrap_err())
                except Exception as error:
                    logger.exception("🔥 [NodeDrain] Auto-drain could not start: %s", server.pk)
                    _audit(server, "virtualmin_server_health_alert", detail=f"Auto-drain failed: {error}")
                server.refresh_from_db()
        if server.status == "active" and server.consecutive_health_failures >= HEALTH_AUTO_FAIL_THRESHOLD:
            if server.is_draining or server_has_active_migration(server):
                _audit(server, "virtualmin_server_autofail_deferred", detail=server.health_check_error)
            else:
                # fsm-bypass: VirtualminServer CharField; health-owned failure under its row lock.
                VirtualminServer.objects.filter(
                    pk=server.pk,
                    status="active",
                    is_draining=False,
                    consecutive_health_failures__gte=HEALTH_AUTO_FAIL_THRESHOLD,
                ).update(  # fsm-bypass: VirtualminServer CharField; health-owned failure.
                    status="failed", failed_by_health_check=True, updated_at=timezone.now()
                )
                logger.error(
                    "🔥 [ServerManagement] Auto-failed %s after %s checks",
                    server.hostname,
                    server.consecutive_health_failures,
                )
