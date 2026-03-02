"""
Production settings for PRAHO Portal Service
"""

import os
from urllib.parse import urlsplit

from .base import *  # noqa: F403

# Security
DEBUG = False

# 🔒 SECURITY: Strict secret validation for production
from apps.common.security_validation import validate_all_secrets  # noqa: E402

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "SECURITY ERROR: SECRET_KEY environment variable must be set in production.\n"
        'Generate one with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"'
    )

# Allowed hosts from environment
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "portal.pragmatichost.com").split(",")

# Platform API configuration
PLATFORM_API_BASE_URL = os.environ.get("PLATFORM_API_BASE_URL", "https://platform:8700/api")
PLATFORM_API_SECRET = os.environ.get("PLATFORM_API_SECRET")
# Escape hatch for controlled environments; keep secure-by-default behavior.
PLATFORM_API_ALLOW_INSECURE_HTTP = os.environ.get("PLATFORM_API_ALLOW_INSECURE_HTTP", "False").lower() in {
    "1",
    "true",
    "yes",
}
if not PLATFORM_API_ALLOW_INSECURE_HTTP and urlsplit(PLATFORM_API_BASE_URL).scheme.lower() != "https":
    raise ValueError(
        "SECURITY ERROR: PLATFORM_API_BASE_URL must use HTTPS in production. "
        "Set PLATFORM_API_ALLOW_INSECURE_HTTP=true only for controlled internal environments."
    )
if not PLATFORM_API_SECRET:
    raise ValueError(
        "SECURITY ERROR: PLATFORM_API_SECRET must be set in production.\n"
        'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )
PLATFORM_API_TIMEOUT = int(os.environ.get("PLATFORM_API_TIMEOUT", "30"))

# 🔒 SECURITY: Validate all secrets meet production security requirements
# This will raise ValueError with detailed instructions if any secret is too weak
try:
    validate_all_secrets()
except ImportError as e:
    # Handle case where security_validation module isn't available yet
    import logging

    logging.getLogger(__name__).warning(f"⚠️ [Security] Could not import security validation: {e}")

# Security settings
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"

# HSTS settings
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Static files - served by nginx/Apache in production
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"

# Cache configuration for production
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "portal-prod-cache",
        "OPTIONS": {
            "MAX_ENTRIES": 10000,
        },
    }
}

# Production logging — structured JSON with request ID tracing
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "apps.common.logging.PortalJSONFormatter",
        },
        "verbose": {
            "format": "[{asctime}] {levelname} [{name}:{funcName}:{lineno}] {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "filters": {
        "add_request_id": {
            "()": "apps.common.middleware.RequestIDFilter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["add_request_id"],
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/portal/app.log",
            "maxBytes": 52428800,  # 50MB
            "backupCount": 10,
            "formatter": "json",
            "filters": ["add_request_id"],
        },
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/portal/error.log",
            "maxBytes": 52428800,  # 50MB
            "backupCount": 30,
            "formatter": "json",
            "filters": ["add_request_id"],
            "level": "ERROR",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.security": {
            "handlers": ["console", "file", "error_file"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console", "file", "error_file"],
            "level": "ERROR",
            "propagate": False,
        },
        "apps": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
