import contextlib

from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.audit'
    verbose_name = 'Audit & Compliance'

    def ready(self) -> None:
        """Import signal handlers when app is ready."""
        with contextlib.suppress(ImportError):
            import apps.audit.signals  # noqa: PLC0415, F401 # Django app signals pattern requires import in ready()
