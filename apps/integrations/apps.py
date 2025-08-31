import contextlib

from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class IntegrationsConfig(AppConfig):
    """
    🔌 External service integrations and webhook management

    Handles:
    - Webhook deduplication for all external services
    - Stripe payment webhooks
    - Virtualmin/cPanel server management webhooks
    - Domain registrar webhooks
    - Third-party service integrations
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.integrations"
    verbose_name = _("🔌 Integrations")

    def ready(self) -> None:
        """Import signal handlers when the app is ready"""
        with contextlib.suppress(ImportError):
            from . import (  # noqa: PLC0415  # Django pattern: import signals in ready() to avoid circular imports
                signals,  # noqa: F401
            )
