# ===============================================================================
# PRAHO API APP CONFIGURATION 🛠️
# ===============================================================================

from django.apps import AppConfig


class ApiConfig(AppConfig):
    """
    Configuration for PRAHO's centralized API app.
    
    This app provides REST API endpoints for all PRAHO domains:
    - Customer management
    - Billing & invoicing (Romanian VAT compliance)
    - Support tickets & SLA tracking
    - Domain management
    - Provisioning services
    
    Architecture follows successful patterns from Sentry, Stripe, and DRF.
    """
    
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.api"
    label = "platform_api"  # Unique label to avoid conflicts
    verbose_name = "PRAHO Platform API"
    
    def ready(self) -> None:
        """Initialize API app - register signals, etc."""
        # Future: API-specific signals, middleware registration, etc.
        pass
