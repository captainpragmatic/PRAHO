from django.apps import AppConfig


class NotificationsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.notifications"
    verbose_name = "Notifications & Email Templates"

    def ready(self) -> None:
        """Initialize notification signals when app is ready."""
        # Import signals to register them
        from . import signals  # noqa: F401

        # Set up Anymail signal handlers for email tracking
        signals.setup_anymail_signals()
