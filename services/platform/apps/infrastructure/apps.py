"""
Django app configuration for Infrastructure app
"""

import contextlib

from django.apps import AppConfig


class InfrastructureConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.infrastructure"
    verbose_name = "Infrastructure Management"

    def ready(self) -> None:
        """Connect signals when app is ready"""
        # Import signals to register them
        from . import signals  # noqa: F401

        from django.db.models.signals import post_migrate

        post_migrate.connect(self._sync_providers_on_first_boot, sender=self)

    @staticmethod
    def _sync_providers_on_first_boot(sender: type, **kwargs: object) -> None:
        """Sync provider catalog on first boot if no providers exist."""
        from .models import CloudProvider

        if CloudProvider.objects.exists():
            return

        from .tasks import queue_sync_providers

        with contextlib.suppress(Exception):  # Q cluster may not be running during migrations
            queue_sync_providers()
