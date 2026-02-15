"""Django app configuration for Domains app."""

from django.apps import AppConfig


class DomainsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.domains"
    verbose_name = "Domains"

    def ready(self) -> None:
        """Import signals when Django starts."""
        from . import signals  # noqa: F401
