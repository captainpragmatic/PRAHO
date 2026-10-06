"""
Django app configuration for Billing app
"""

from django.apps import AppConfig


class BillingConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.billing"
    verbose_name = "Billing"

    def ready(self) -> None:
        """Register checks, signals and issuers; schedules belong to explicit setup."""
        from . import checks, signals  # noqa: F401  # System-check + signal registration
        from .issuers import builtin  # noqa: F401  # Registers the built-in invoice issuer
        from .issuers.smartbill import issuer  # noqa: F401  # Registers the SmartBill issuer
