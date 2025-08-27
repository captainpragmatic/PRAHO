
from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.audit'
    verbose_name = 'Audit & Compliance'

    def ready(self) -> None:
        """Import signal handlers when app is ready."""
        # No signals defined yet for audit app
