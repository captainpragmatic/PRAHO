"""
Staging settings for PRAHO Platform.

Why this exists separately from prod.py:
─────────────────────────────────────────
Staging and production share the same Ansible playbook and inventory
(-e praho_env=staging|prod). The Django settings file is the ONLY thing
that differs. These differences prevent real-world side effects during testing:

  1. Email backend: console (prints to log) — prevents sending real emails
  2. e-Factura: test mode — prevents submitting invoices to ANAF
  3. HSTS: 1 hour (not 1 year) — allows rolling back to HTTP if needed
  4. Session: 2 hours, no browser-close — more lenient for testing
  5. DB sslmode: "prefer" (not "require") — staging DB may lack SSL certs
  6. Data retention: 30 days (not 7 years) — don't keep years of test data
  7. App log level: DEBUG (not INFO) — more verbose for debugging
  8. STAGING_FEATURES dict — toggles test-only features

If none of these matter for your use case, use prod.py for everything.
"""

import os as _os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured as _ImproperlyConfigured

from .base import *  # noqa: F403  # Django settings pattern

# ===============================================================================
# STAGING SECURITY VALIDATION
# ===============================================================================

validate_production_secret_key()  # Rejects django-insecure-* prefix

_db_password = _os.environ.get("DB_PASSWORD", "")
if not _db_password or _db_password in {"changeme", "development_password", "password", "postgres"}:
    raise _ImproperlyConfigured(
        "DB_PASSWORD must be set to a strong value in staging. Current value is missing or a known default."
    )

# ===============================================================================
# STAGING ENVIRONMENT CONFIGURATION
# ===============================================================================

# Staging flags - limited debugging for testing
DEBUG = False  # Set to True only if needed for staging debugging
TEMPLATE_DEBUG = False

_allowed_hosts_raw = _os.environ.get("ALLOWED_HOSTS", "").strip()
if not _allowed_hosts_raw:
    raise _ImproperlyConfigured(
        "ALLOWED_HOSTS must be set in staging. "
        "Set it to your portal and platform FQDNs, e.g.: "
        "portal-staging.pragmatichost.com,platform-staging.pragmatichost.com,localhost,127.0.0.1"
    )
ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_raw.split(",") if h.strip()]
if "*" in ALLOWED_HOSTS:
    raise _ImproperlyConfigured("ALLOWED_HOSTS contains '*' — use specific FQDNs.")
CSRF_TRUSTED_ORIGINS = [f"https://{host}" for host in ALLOWED_HOSTS if host not in {"localhost", "127.0.0.1"}]

# Explicit domain settings
PORTAL_DOMAIN = _os.environ.get("PORTAL_DOMAIN", "")
PLATFORM_DOMAIN = _os.environ.get("PLATFORM_DOMAIN", "")
if not PORTAL_DOMAIN or not PLATFORM_DOMAIN:
    raise _ImproperlyConfigured(
        f"PORTAL_DOMAIN and PLATFORM_DOMAIN must both be set in staging. "
        f"Got PORTAL_DOMAIN={PORTAL_DOMAIN!r}, PLATFORM_DOMAIN={PLATFORM_DOMAIN!r}."
    )

# ===============================================================================
# HTTPS SECURITY HARDENING - STAGING 🔒
# ===============================================================================

# Ensure SecurityMiddleware is FIRST in middleware stack
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",  # MUST be first
    "apps.common.middleware.RequestIDMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.common.middleware.SecurityHeadersMiddleware",
    "apps.common.middleware.AuditMiddleware",
    "apps.common.middleware.SessionSecurityMiddleware",
    "apps.common.middleware.GDPRComplianceMiddleware",
]

# ===============================================================================
# HTTPS ENFORCEMENT & SSL SETTINGS (Staging)
# ===============================================================================

# SSL/TLS Configuration - Only if staging has HTTPS
# Set SECURE_SSL_REDIRECT = False if staging uses HTTP
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True  # Set to False if staging is HTTP-only
SECURE_REDIRECT_EXEMPT = [r"health/", r"^api/"]  # Allow health checks and internal API over HTTP from localhost

# Cookie Security - Match production if staging has HTTPS
SESSION_COOKIE_SECURE = True  # Set to False if staging is HTTP-only
CSRF_COOKIE_SECURE = True  # Set to False if staging is HTTP-only
SESSION_COOKIE_SAMESITE = "Lax"

# ===============================================================================
# HTTP STRICT TRANSPORT SECURITY (HSTS) - Staging
# ===============================================================================

# HSTS - Use shorter duration for staging to allow rollback
SECURE_HSTS_SECONDS = 3600  # 1 hour (shorter than production)
SECURE_HSTS_INCLUDE_SUBDOMAINS = False  # Keep False for staging flexibility
SECURE_HSTS_PRELOAD = False  # Never enable for staging

# ===============================================================================
# ADDITIONAL SECURITY HEADERS (Staging)
# ===============================================================================

# Content security and XSS protection
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"
SECURE_BROWSER_XSS_FILTER = True

# ===============================================================================
# SESSION SECURITY CONFIGURATION (Staging)
# ===============================================================================

# Relaxed session settings for staging testing
SESSION_COOKIE_AGE = 7200  # 2 hours for staging (longer for testing)
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Allow persistent sessions in staging
SESSION_COOKIE_NAME = "pragmatichost_staging_sessionid"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_PATH = "/"
SESSION_SAVE_EVERY_REQUEST = True

# ===============================================================================
# SECURE IP DETECTION - STAGING CONFIGURATION 🔒
# ===============================================================================

# Staging: Configure for your staging load balancer/proxy setup
IPWARE_TRUSTED_PROXY_LIST = [
    # Staging proxy/LB IP ranges
    # Add your staging load balancer IP ranges here
    # Example: "10.0.0.0/24", "172.16.0.0/16"
]

# ===============================================================================
# DATABASE STAGING SETTINGS
# ===============================================================================

DATABASES["default"].update(
    {
        "CONN_MAX_AGE": 300,  # Shorter than production
        "OPTIONS": {
            "application_name": "pragmatichost_staging",
            "sslmode": "prefer",  # Less strict than production
        },
    }
)

# ===============================================================================
# LOGGING CONFIGURATION (Staging)
# ===============================================================================

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "apps.audit.logging_formatters.SIEMJSONFormatter",
        },
        "verbose": {
            "format": "[{asctime}] {levelname} [{name}:{funcName}:{lineno}] {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "audit": {
            "()": "apps.audit.logging_formatters.AuditLogFormatter",
        },
    },
    "filters": {
        "add_request_id": {
            "()": "apps.common.logging.RequestIDFilter",
        },
        "add_audit_context": {
            "()": "apps.audit.logging_formatters.AuditContextFilter",
        },
    },
    "handlers": {
        # Console handler for containerized deployments
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["add_request_id", "add_audit_context"],
        },
        # Main application log file (smaller retention than prod)
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/app.log",
            "maxBytes": 10485760,  # 10MB (prod: 50MB)
            "backupCount": 5,  # prod: 10
            "formatter": "json",
            "filters": ["add_request_id", "add_audit_context"],
        },
        # Security-specific log file
        "security_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/security.log",
            "maxBytes": 10485760,  # 10MB (prod: 50MB)
            "backupCount": 10,  # prod: 30
            "formatter": "json",
            "filters": ["add_request_id", "add_audit_context"],
        },
        # Audit log file (immutable audit trail)
        "audit_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/audit.log",
            "maxBytes": 20971520,  # 20MB (prod: 100MB)
            "backupCount": 30,  # prod: 90
            "formatter": "audit",
            "filters": ["add_request_id", "add_audit_context"],
        },
        # Error log for critical issues
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/error.log",
            "maxBytes": 10485760,  # 10MB (prod: 50MB)
            "backupCount": 10,  # prod: 30
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
        # Django framework logging
        "django": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.security": {
            "handlers": ["console", "security_file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console", "file", "error_file"],
            "level": "INFO",
            "propagate": False,
        },
        # Application logging (DEBUG for staging verbosity)
        "apps": {
            "handlers": ["console", "file"],
            "level": "DEBUG",
            "propagate": False,
        },
        # Audit-specific logging (for SIEM integration)
        "apps.audit": {
            "handlers": ["console", "audit_file", "security_file"],
            "level": "INFO",
            "propagate": False,
        },
        # Security events (authentication, authorization)
        "apps.users": {
            "handlers": ["console", "file", "security_file"],
            "level": "INFO",
            "propagate": False,
        },
        # Common middleware (request/response logging)
        "apps.common.middleware": {
            "handlers": ["console", "audit_file"],
            "level": "INFO",
            "propagate": False,
        },
        # SIEM integration logging
        "apps.audit.siem": {
            "handlers": ["console", "security_file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# ===============================================================================
# EMAIL CONFIGURATION (Staging - Use test backend)
# ===============================================================================

# Use console backend for staging - displays emails in console
# Alternative: django.core.mail.backends.filebased.EmailBackend with EMAIL_FILE_PATH setting
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

DEFAULT_FROM_EMAIL = "staging-noreply@pragmatichost.com"
SERVER_EMAIL = DEFAULT_FROM_EMAIL

# ===============================================================================
# CACHE CONFIGURATION (Staging - Database cache)
# ===============================================================================

CACHES["default"].update(
    {
        "OPTIONS": {
            "MAX_ENTRIES": 25000,  # Medium limit for staging
            "CULL_FREQUENCY": 3,
        },
        "TIMEOUT": 1800,  # 30 minutes timeout for staging
    }
)

# ===============================================================================
# RATE LIMITING (Staging - Relaxed)
# ===============================================================================

RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = "default"

# ===============================================================================
# ROMANIAN COMPLIANCE (Staging)
# ===============================================================================

# e-Factura staging settings
EFACTURA_ENABLED = True
EFACTURA_TEST_MODE = True  # Keep in test mode for staging

# GDPR compliance
GDPR_ENABLED = True
DATA_RETENTION_DAYS = 30  # Shorter retention for staging

# ===============================================================================
# MONITORING & HEALTH CHECKS (Staging)
# ===============================================================================

HEALTH_CHECK_ENABLED = True
HEALTH_CHECK_URL = "/health/"

MONITORING = {
    "enabled": True,
    "check_database": True,
    "check_cache": True,
    "check_queue": False,  # Simplified monitoring for staging
}

# ===============================================================================
# STATIC FILES (Staging - Simple file serving)
# ===============================================================================

# Use local static file serving for staging
STATIC_URL = "/static/"
STATIC_ROOT = Path(_os.environ.get("STATIC_ROOT", "/opt/praho/static"))

# ===============================================================================
# DEVELOPMENT HELPERS (Staging specific)
# ===============================================================================

# Enable Django Debug Toolbar for staging debugging (if needed)
if DEBUG:
    INTERNAL_IPS = ["127.0.0.1", "10.0.0.0/8"]

# Staging-specific feature flags
STAGING_FEATURES = {
    "enable_test_data": True,
    "allow_staff_impersonation": True,
    "show_debug_info": False,
}
