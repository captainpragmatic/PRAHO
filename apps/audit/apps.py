
from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.audit'
    verbose_name = 'Audit & Compliance'

    def ready(self) -> None:
        """Import signal handlers when app is ready."""
        try:
            from . import signals  # noqa: F401
            signals.register_audit_signals()
        except ImportError:
            pass
