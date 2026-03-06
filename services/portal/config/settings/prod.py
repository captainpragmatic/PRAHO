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

# Allowed hosts — required in production, no fallback
_allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS", "").strip()
if not _allowed_hosts_raw:
    raise ValueError(
        "SECURITY ERROR: ALLOWED_HOSTS must be set in production. "
        "Set it to your portal FQDN, e.g.: portal.pragmatichost.com,localhost,127.0.0.1"
    )

ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_raw.split(",") if h.strip()]

if "*" in ALLOWED_HOSTS:
    raise ValueError(
        "SECURITY ERROR: ALLOWED_HOSTS contains '*' — this disables host validation "
        "and enables host header injection attacks. Use specific FQDNs."
    )

CSRF_TRUSTED_ORIGINS = [f"https://{host}" for host in ALLOWED_HOSTS if host not in {"localhost", "127.0.0.1"}]

# Explicit domain setting for safe absolute URL construction
PORTAL_DOMAIN = os.environ.get("PORTAL_DOMAIN", "")
if not PORTAL_DOMAIN:
    raise ValueError(
        "SECURITY ERROR: PORTAL_DOMAIN must be set in production. "
        "This is used for absolute URL construction in emails and links. "
        "Example: PORTAL_DOMAIN=portal.pragmatichost.com"
    )

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
if PLATFORM_API_ALLOW_INSECURE_HTTP:
    import logging as _logging

    _logging.getLogger(__name__).warning(
        "SECURITY WARNING: PLATFORM_API_ALLOW_INSECURE_HTTP is ACTIVE. "
        "Ensure PLATFORM_API_BASE_URL=%s is on an internal/private network only. "
        "This MUST NOT be enabled for external-facing deployments.",
        PLATFORM_API_BASE_URL,
    )
if not PLATFORM_API_SECRET:
    raise ValueError(
        "SECURITY ERROR: PLATFORM_API_SECRET must be set in production.\n"
        'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )
PLATFORM_API_TIMEOUT = int(os.environ.get("PLATFORM_API_TIMEOUT", "30"))
PLATFORM_TO_PORTAL_WEBHOOK_SECRET = os.environ.get("PLATFORM_TO_PORTAL_WEBHOOK_SECRET", "")
if not PLATFORM_TO_PORTAL_WEBHOOK_SECRET:
    raise ValueError(
        "SECURITY ERROR: PLATFORM_TO_PORTAL_WEBHOOK_SECRET must be set in production.\n"
        'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )

# 🔒 SECURITY: Validate all secrets meet production security requirements
# This will raise ValueError with detailed instructions if any secret is too weak
try:
    validate_all_secrets()
except ImportError as e:
    # Handle case where security_validation module isn't available yet
    import logging

    logging.getLogger(__name__).warning(f"⚠️ [Security] Could not import security validation: {e}")

# Security settings
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")  # TLS terminated by reverse proxy
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_REDIRECT_EXEMPT = [r"^status/$"]  # Allow health checks over HTTP from localhost
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"

# HSTS settings
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Static files - served by reverse proxy in production
STATIC_ROOT = Path(os.environ.get("STATIC_ROOT", str(BASE_DIR / "staticfiles")))
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

# Stateless portal: use cache-backed sessions (no database migration needed)
SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

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
