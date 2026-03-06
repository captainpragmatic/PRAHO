"""
Staging settings for PRAHO Portal Service.

Why this exists separately from prod.py:
─────────────────────────────────────────
Same Ansible playbook for staging and prod (-e praho_env=staging|prod).
The Django settings file is the only difference. Key staging overrides:

  1. HSTS: 1 hour (not 1 year) — allows rolling back to HTTP if needed
  2. App log level: DEBUG (not INFO) — more verbose for debugging
  3. Log file retention: smaller sizes — staging doesn't need prod-scale logs
  4. Cache location: "portal-staging-cache" — prevents collision if dev is testing locally

If none of these matter, use prod.py for everything.
"""

import os

from .base import *  # noqa: F403

# Security - similar to production but with debug info
DEBUG = False
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "SECURITY ERROR: SECRET_KEY environment variable must be set in staging.\n"
        'Generate one with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"'
    )

# Allowed hosts — env-driven, no hardcoded fallback
_allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS", "").strip()
if not _allowed_hosts_raw:
    raise ValueError(
        "SECURITY ERROR: ALLOWED_HOSTS must be set in staging. "
        "Set it to your portal FQDN, e.g.: portal-staging.pragmatichost.com,localhost,127.0.0.1"
    )
ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_raw.split(",") if h.strip()]
if "*" in ALLOWED_HOSTS:
    raise ValueError("SECURITY ERROR: ALLOWED_HOSTS contains '*' — use specific FQDNs.")
CSRF_TRUSTED_ORIGINS = [f"https://{host}" for host in ALLOWED_HOSTS if host not in {"localhost", "127.0.0.1"}]

# Explicit domain setting
PORTAL_DOMAIN = os.environ.get("PORTAL_DOMAIN", "")
if not PORTAL_DOMAIN:
    raise ValueError(
        "SECURITY ERROR: PORTAL_DOMAIN must be set in staging. Example: PORTAL_DOMAIN=portal-staging.pragmatichost.com"
    )

# Platform API configuration for staging
PLATFORM_API_BASE_URL = os.environ.get("PLATFORM_API_BASE_URL", "http://platform-staging:8700/api")
PLATFORM_API_SECRET = (os.environ.get("PLATFORM_API_SECRET") or "").strip()
if not PLATFORM_API_SECRET:
    raise ValueError(
        "SECURITY ERROR: PLATFORM_API_SECRET must be set in staging.\n"
        'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )
PLATFORM_API_TIMEOUT = int(os.environ.get("PLATFORM_API_TIMEOUT", "20"))

# PRAHO-internal webhook secret: Platform → Portal notification after a payment succeeds.
# This is NOT the Stripe webhook secret — it signs platform-to-portal HTTP calls only.
# Required only when testing the payment confirmation flow end-to-end in staging.
# If unset, payment webhooks are silently rejected (401) without breaking other features.
PLATFORM_TO_PORTAL_WEBHOOK_SECRET = os.environ.get("PLATFORM_TO_PORTAL_WEBHOOK_SECRET", "")
if not PLATFORM_TO_PORTAL_WEBHOOK_SECRET:
    import logging as _logging

    _logging.getLogger(__name__).warning(
        "PLATFORM_TO_PORTAL_WEBHOOK_SECRET is not set in staging. "
        "Payment webhook notifications from Platform will be rejected (401). "
        "Set it only if testing the payment confirmation flow end-to-end. "
        'Generate: python -c "import secrets; print(secrets.token_urlsafe(32))"'
    )

# Allow HTTP for internal Platform communication (native deploys use localhost)
PLATFORM_API_ALLOW_INSECURE_HTTP = os.environ.get("PLATFORM_API_ALLOW_INSECURE_HTTP", "False").lower() in {
    "1",
    "true",
    "yes",
}
if PLATFORM_API_ALLOW_INSECURE_HTTP:
    import logging as _logging

    _logging.getLogger(__name__).warning(
        "SECURITY WARNING: PLATFORM_API_ALLOW_INSECURE_HTTP is ACTIVE in staging. "
        "Ensure PLATFORM_API_BASE_URL=%s is on an internal/private network only.",
        PLATFORM_API_BASE_URL,
    )

# Security settings (less strict than production for testing)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")  # Caddy terminates TLS
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_REDIRECT_EXEMPT = [r"^status/$"]  # Allow health checks over HTTP from localhost
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"

# HSTS settings (shorter duration for staging)
SECURE_HSTS_SECONDS = 3600  # 1 hour for staging
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# Static files — env-driven for deployment flexibility
STATIC_ROOT = Path(os.environ.get("STATIC_ROOT", str(BASE_DIR / "staticfiles")))
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"

# Cache configuration for staging
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "portal-staging-cache",
        "OPTIONS": {
            "MAX_ENTRIES": 5000,
        },
    }
}

# Staging logging — structured JSON with request ID tracing (smaller retention than prod)
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
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "formatter": "json",
            "filters": ["add_request_id"],
        },
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/portal/error.log",
            "maxBytes": 10485760,  # 10MB
            "backupCount": 10,
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
            "level": "DEBUG",
            "propagate": False,
        },
    },
}
