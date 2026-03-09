"""
Django app configuration for Infrastructure app
"""

import logging

from django.apps import AppConfig
from django.db import utils as db_utils

logger = logging.getLogger(__name__)

_CLEANUP_FAILED_INTERVAL_MINUTES = 360  # 6 hours
_RECOVER_STUCK_INTERVAL_MINUTES = 30


class InfrastructureConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.infrastructure"
    verbose_name = "Infrastructure Management"

    def ready(self) -> None:
        """Connect signals when app is ready"""
        # Import signals to register them
        from django.db.models.signals import post_migrate

        # Import provider modules so register_cloud_gateway() fires at startup
        # Import provider_sync so register_sync_fn() calls fire at startup
        from . import (  # noqa: F401  # Circular: app registry
            aws_service,
            digitalocean_service,
            hcloud_service,
            provider_sync,  # Circular: app registry
            signals,  # Circular: app registry
            vultr_service,
        )

        post_migrate.connect(self._sync_providers_on_first_boot, sender=self)
        post_migrate.connect(self._schedule_infrastructure_tasks, sender=self)

    @staticmethod
    def _schedule_infrastructure_tasks(sender: type, **kwargs: object) -> None:
        """Register infrastructure scheduled tasks with Django-Q2."""
        try:
            from django_q.models import Schedule
        except ImportError:
            return

        schedules = [
            ("drift_scan", "apps.infrastructure.tasks.run_drift_scan_task", 15, Schedule.MINUTES),
            (
                "scheduled_remediations",
                "apps.infrastructure.tasks.apply_scheduled_remediations_task",
                5,
                Schedule.MINUTES,
            ),
            ("remediation_health", "apps.infrastructure.tasks.check_remediation_health_task", 5, Schedule.MINUTES),
            ("cleanup_snapshots", "apps.infrastructure.tasks.cleanup_old_snapshots_task", 1, Schedule.DAILY),
            (
                "cleanup_failed_deployments",
                "apps.infrastructure.tasks.cleanup_failed_deployments_task",
                _CLEANUP_FAILED_INTERVAL_MINUTES,
                Schedule.MINUTES,
            ),
            ("bulk_validate_nodes", "apps.infrastructure.tasks.bulk_validate_nodes_task", 1, Schedule.DAILY),
            ("calculate_daily_costs", "apps.infrastructure.tasks.calculate_daily_costs_task", 1, Schedule.DAILY),
            ("sync_providers", "apps.infrastructure.tasks.sync_providers_task", 7, Schedule.WEEKLY),
            (
                "recover_stuck_deployments",
                "apps.infrastructure.tasks.recover_stuck_deployments_task",
                _RECOVER_STUCK_INTERVAL_MINUTES,
                Schedule.MINUTES,
            ),
        ]

        for name, func, interval, schedule_type in schedules:
            try:
                Schedule.objects.update_or_create(
                    name=f"infra_{name}",
                    defaults={
                        "func": func,
                        "schedule_type": schedule_type,
                        "minutes": interval if schedule_type == Schedule.MINUTES else None,
                        "repeats": -1,
                    },
                )
            except Exception:
                logger.error("Failed to register schedule: infra_%s", name, exc_info=True)

    @staticmethod
    def _sync_providers_on_first_boot(sender: type, **kwargs: object) -> None:
        """Sync provider catalog on first boot if no providers exist."""
        from .models import CloudProvider

        if CloudProvider.objects.exists():
            return

        from .tasks import queue_sync_providers

        try:
            queue_sync_providers()
        except db_utils.DatabaseError:
            logger.debug("Skipping provider sync — django_q tables not yet migrated")
