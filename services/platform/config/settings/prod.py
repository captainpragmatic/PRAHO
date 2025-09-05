"""
Production settings for PRAHO Platform
Security-first configuration for Romanian hosting provider.
"""

import logging
import os

# Optional Sentry integration
try:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration

    HAS_SENTRY = True
except ImportError:
    HAS_SENTRY = False

from .base import *  # noqa: F403

# ===============================================================================
# PRODUCTION SECURITY VALIDATION
# ===============================================================================

# Validate SECRET_KEY meets production security requirements
validate_production_secret_key()

# ===============================================================================
# PRODUCTION FLAGS
# ===============================================================================

DEBUG = False
TEMPLATE_DEBUG = False

# Note: ALLOWED_HOSTS configured in HTTPS security section below

# ===============================================================================
# HTTPS SECURITY HARDENING - PRODUCTION 🔒
# ===============================================================================

# Production security - app.pragmatichost.com
DEBUG = False
ALLOWED_HOSTS = ["app.pragmatichost.com"]
CSRF_TRUSTED_ORIGINS = ["https://app.pragmatichost.com"]

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
# HTTPS ENFORCEMENT & SSL SETTINGS
# ===============================================================================

# SSL/TLS Configuration - Behind TLS-terminating load balancer
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True

# Cookie Security - Require HTTPS for all cookies
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection + usability

# ===============================================================================
# HTTP STRICT TRANSPORT SECURITY (HSTS)
# ===============================================================================

# HSTS - Enable only after confirming HTTPS end-to-end works
SECURE_HSTS_SECONDS = 31536000  # 1 year (31,536,000 seconds)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = False  # Keep False unless you control the apex domain

# ===============================================================================
# ADDITIONAL SECURITY HEADERS
# ===============================================================================

# Content security and XSS protection
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"

# Legacy browser XSS protection (deprecated but still useful)
SECURE_BROWSER_XSS_FILTER = True

# ===============================================================================
# SESSION SECURITY CONFIGURATION
# ===============================================================================

# Enhanced session security for production
SESSION_COOKIE_AGE = 3600  # 1 hour for production security
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_NAME = "pragmatichost_sessionid"
SESSION_COOKIE_HTTPONLY = True  # Prevent XSS access to session cookie
SESSION_COOKIE_PATH = "/"
SESSION_SAVE_EVERY_REQUEST = True  # Update session on every request

# ===============================================================================
# DATABASE PRODUCTION SETTINGS
# ===============================================================================

DATABASES["default"].update(
    {
        "CONN_MAX_AGE": 600,
        "OPTIONS": {
            "application_name": "pragmatichost_crm_prod",
            "sslmode": "require",
        },
    }
)

# ===============================================================================
# SENTRY CONFIGURATION (Error Monitoring)
# ===============================================================================

SENTRY_DSN = os.environ.get("SENTRY_DSN")
if SENTRY_DSN and HAS_SENTRY:
    sentry_logging = LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(),
            sentry_logging,
        ],
        traces_sample_rate=0.1,
        send_default_pii=False,
        environment="production",
        release=os.environ.get("APP_VERSION", "unknown"),
    )

# ===============================================================================
# LOGGING CONFIGURATION (Production)
# ===============================================================================

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "format": '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s", "request_id": "%(request_id)s"}',
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "filters": {
        "add_request_id": {
            "()": "apps.common.logging.RequestIDFilter",
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
            "filename": "/var/log/pragmatichost/app.log",
            "maxBytes": 10485760,  # 10MB
            "backupCount": 5,
            "formatter": "json",
            "filters": ["add_request_id"],
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
            "level": "INFO",
            "propagate": False,
        },
        "django.security": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# ===============================================================================
# EMAIL CONFIGURATION (Production SMTP)
# ===============================================================================

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.environ.get("EMAIL_HOST")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
# Default from email for production
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "noreply@pragmatichost.com")
SERVER_EMAIL = DEFAULT_FROM_EMAIL

# ===============================================================================
# CACHE CONFIGURATION (Database Production - optimized settings)
# ===============================================================================

CACHES["default"].update(
    {
        "OPTIONS": {
            "MAX_ENTRIES": 50000,  # Higher limit for production
            "CULL_FREQUENCY": 4,   # More aggressive culling
        },
        "TIMEOUT": 3600,  # 1 hour timeout for production
    }
)


# ===============================================================================
# STATIC FILES (Production with CDN)
# ===============================================================================

# AWS S3 settings (if using S3 for static files)
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_STORAGE_BUCKET_NAME = os.environ.get("AWS_STORAGE_BUCKET_NAME")
AWS_S3_REGION_NAME = os.environ.get("AWS_S3_REGION_NAME", "eu-central-1")

if AWS_STORAGE_BUCKET_NAME:
    AWS_S3_CUSTOM_DOMAIN = f"{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com"
    STATICFILES_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"
    STATIC_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/static/"

# ===============================================================================
# CUSTOM STAFF INTERFACE (Admin Removed)
# ===============================================================================

# Django admin has been removed - all staff operations use custom interface
# Staff interface available at /app/ with role-based access control

# ===============================================================================
# RATE LIMITING (Production)
# ===============================================================================

RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = "default"

# ===============================================================================
# SECURE IP DETECTION - PRODUCTION CONFIGURATION 🔒
# ===============================================================================

# Production: Configure trusted proxy CIDRs for your load balancer/reverse proxy
# These should be the EXACT IP ranges of your production load balancer
# Example: If using AWS ALB, use ALB subnets
# Example: If using Cloudflare, use CF edge ranges
# Replace empty list with actual production proxy/LB CIDR blocks
IPWARE_TRUSTED_PROXY_LIST = [
    # Production proxy/LB IP ranges will be configured here
    # Common patterns:
    # - AWS ALB: Private subnet ranges (10.0.0.0/8, 172.16.0.0/12)
    # - Cloudflare: CF edge IP ranges
    # - Internal LB: Private network ranges (192.168.0.0/16)
]


# ===============================================================================
# MONITORING & HEALTH CHECKS
# ===============================================================================

# Health check endpoint settings
HEALTH_CHECK_ENABLED = True
HEALTH_CHECK_URL = "/health/"

# Monitoring settings
MONITORING = {
    "enabled": True,
    "check_database": True,
    "check_cache": True,
    "check_queue": True,
}

# ===============================================================================
# ROMANIAN COMPLIANCE (Production)
# ===============================================================================

# e-Factura production settings
EFACTURA_ENABLED = True
EFACTURA_TEST_MODE = False

# GDPR compliance
GDPR_ENABLED = True
DATA_RETENTION_DAYS = 2555  # 7 years (Romanian requirement)

# ===============================================================================
# BACKUP CONFIGURATION
# ===============================================================================

BACKUP_ENABLED = True
BACKUP_S3_BUCKET = os.environ.get("BACKUP_S3_BUCKET")
BACKUP_ENCRYPTION_KEY = os.environ.get("BACKUP_ENCRYPTION_KEY")

# ===============================================================================
# PERFORMANCE SETTINGS
# ===============================================================================

# Database connection pooling
DATABASES["default"]["OPTIONS"]["MAX_CONNS"] = 20

# Template caching
TEMPLATE_LOADERS = [
    (
        "django.template.loaders.cached.Loader",
        [
            "django.template.loaders.filesystem.Loader",
            "django.template.loaders.app_directories.Loader",
        ],
    ),
]
