from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.audit"
    verbose_name = "Audit & Compliance"

    def ready(self) -> None:
        """Import signal handlers when app is ready."""
        from . import signals  # noqa: PLC0415

        signals.register_audit_signals()
