from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.audit'
    verbose_name = 'Audit & Compliance'

    def ready(self):
        """Import signal handlers when app is ready."""
        try:
            import apps.audit.signals  # noqa F401
        except ImportError:
            pass
