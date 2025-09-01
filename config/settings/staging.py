"""
Staging settings for PRAHO Platform
Staging environment configuration for pre-production testing.
"""

from pathlib import Path

from .base import *  # noqa: F403

# ===============================================================================
# STAGING ENVIRONMENT CONFIGURATION
# ===============================================================================

# Staging flags - limited debugging for testing
DEBUG = False  # Set to True only if needed for staging debugging
TEMPLATE_DEBUG = False

# Staging hosts
ALLOWED_HOSTS = ["staging.pragmatichost.com", "staging-app.pragmatichost.com"]
CSRF_TRUSTED_ORIGINS = ["https://staging.pragmatichost.com", "https://staging-app.pragmatichost.com"]

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
    "debug_toolbar.middleware.DebugToolbarMiddleware",
]

# ===============================================================================
# HTTPS ENFORCEMENT & SSL SETTINGS (Staging)
# ===============================================================================

# SSL/TLS Configuration - Only if staging has HTTPS
# Set SECURE_SSL_REDIRECT = False if staging uses HTTP
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True  # Set to False if staging is HTTP-only

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
        "detailed": {
            "format": "[{asctime}] {levelname} {name} {process:d} {thread:d} {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "detailed",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/pragmatichost/staging.log",
            "maxBytes": 5242880,  # 5MB
            "backupCount": 3,
            "formatter": "detailed",
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
        "apps": {
            "handlers": ["console", "file"],
            "level": "DEBUG",  # More verbose logging for staging
            "propagate": False,
        },
        "django.security": {
            "handlers": ["console", "file"],
            "level": "WARNING",
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
# CACHE CONFIGURATION (Staging - Redis)
# ===============================================================================

CACHES["default"].update(
    {
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "CONNECTION_POOL_KWARGS": {
                "max_connections": 10,  # Fewer connections than production
                "retry_on_timeout": True,
            },
        }
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
STATIC_ROOT = Path("/var/www/staging-static/")

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
