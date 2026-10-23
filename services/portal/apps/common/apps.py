"""
Common app configuration for PRAHO Portal Service
"""

from django.apps import AppConfig


class CommonConfig(AppConfig):
    """Configuration for portal common utilities"""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.common"
    verbose_name = "Portal Common"

    def ready(self) -> None:
        from django.conf import settings  # noqa: PLC0415

        import apps.common.checks  # noqa: F401, PLC0415
        from apps.common.signing import resolve_signing_secret, validate_portal_id  # noqa: PLC0415

        if getattr(settings, "PORTAL_HMAC_REQUIRE_ISOLATION", False):
            validate_portal_id()
            resolve_signing_secret()
