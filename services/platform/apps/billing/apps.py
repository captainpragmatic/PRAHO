"""
Django app configuration for Billing app
"""

import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class BillingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.billing"
    verbose_name = "Billing"

    def ready(self) -> None:
        """Import signals and schedule e-Factura tasks when Django starts."""
        from django.conf import settings

        from . import checks, signals  # noqa: F401  # System-check + signal registration
        from .issuers import builtin  # noqa: F401  # Registers the built-in invoice issuer
        from .issuers.smartbill import issuer  # noqa: F401  # Registers the SmartBill issuer

        # Schedule e-Factura recurring tasks if enabled
        if getattr(settings, "EFACTURA_ENABLED", False):
            try:
                from apps.billing.efactura.tasks import schedule_efactura_tasks

                schedule_efactura_tasks()
            except Exception:
                logger.warning("⚠️ [Billing] Failed to schedule e-Factura tasks during startup")
