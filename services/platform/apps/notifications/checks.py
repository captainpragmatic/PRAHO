"""
System checks for notifications app.

Validates deprecated settings to prevent silent misconfiguration.
"""

from typing import Any

from django.conf import settings
from django.core.checks import Tags, register
from django.core.checks import Warning as DjangoWarning


@register(Tags.security)
def check_deprecated_encryption_fallback_setting(app_configs: Any, **kwargs: Any) -> list[Any]:
    """Warn if removed ALLOW_UNENCRYPTED_EMAIL_LOG_FALLBACK is still defined."""
    errors: list[Any] = []

    if hasattr(settings, "ALLOW_UNENCRYPTED_EMAIL_LOG_FALLBACK"):
        errors.append(
            DjangoWarning(
                "ALLOW_UNENCRYPTED_EMAIL_LOG_FALLBACK is deprecated and has no effect.",
                hint=(
                    "Remove this setting. EmailLog now always saves with "
                    "body_encrypted=False on encryption failure and emits a CRITICAL alert. "
                    "Use `manage.py reencrypt_email_logs` to re-encrypt after resolving."
                ),
                id="notifications.W001",
            )
        )

    return errors
