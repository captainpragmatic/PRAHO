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
# EMAIL CONFIGURATION (Production - Multi-Provider via Anymail)
# ===============================================================================

# Dynamic email backend selection based on EMAIL_PROVIDER env var
_email_backends = {
    "amazon_ses": "anymail.backends.amazon_ses.EmailBackend",
    "sendgrid": "anymail.backends.sendgrid.EmailBackend",
    "mailgun": "anymail.backends.mailgun.EmailBackend",
    "smtp": "django.core.mail.backends.smtp.EmailBackend",
}

EMAIL_BACKEND = _email_backends.get(
    os.environ.get("EMAIL_PROVIDER", "smtp"), "django.core.mail.backends.smtp.EmailBackend"
)

# SMTP fallback configuration (also used by some ESPs)
EMAIL_USE_TLS = True

# Default from email for production
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "PRAHO Platform <noreply@pragmatichost.com>")
SERVER_EMAIL = os.environ.get("SERVER_EMAIL", DEFAULT_FROM_EMAIL)

# ===============================================================================
# CACHE CONFIGURATION (Redis for Production - with fallback to Database)
# ===============================================================================

# Use Redis for production caching if available
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
                "SOCKET_CONNECT_TIMEOUT": 5,
                "SOCKET_TIMEOUT": 5,
                "CONNECTION_POOL_KWARGS": {
                    "max_connections": 50,
                    "retry_on_timeout": True,
                },
                "COMPRESSOR": "django_redis.compressors.zlib.ZlibCompressor",
            },
            "KEY_PREFIX": "praho",
            "VERSION": CACHE_VERSION,
            "TIMEOUT": 3600,  # 1 hour default
        },
        # Separate cache for sessions (more persistent)
        "sessions": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
                "db": 1,  # Separate Redis DB for sessions
            },
            "KEY_PREFIX": "praho_session",
            "TIMEOUT": 86400,  # 24 hours for sessions
        },
        # Rate limiting cache (very short TTL)
        "ratelimit": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
                "db": 2,  # Separate Redis DB for rate limiting
            },
            "KEY_PREFIX": "praho_rate",
            "TIMEOUT": 60,
        },
    }
    # Use Redis for sessions
    SESSION_CACHE_ALIAS = "sessions"
else:
    # Fallback to database cache
    CACHES["default"].update(
        {
            "OPTIONS": {
                "MAX_ENTRIES": 50000,  # Higher limit for production
                "CULL_FREQUENCY": 4,  # More aggressive culling
            },
            "TIMEOUT": 3600,  # 1 hour timeout for production
        }
    )

# Rate limiting cache alias
RATELIMIT_USE_CACHE = "ratelimit" if REDIS_URL else "default"


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

# ===============================================================================
# SIEM INTEGRATION CONFIGURATION 🔐
# ===============================================================================

# SIEM (Security Information and Event Management) configuration
# Supports: Splunk, IBM QRadar, Elastic SIEM, Graylog, Microsoft Sentinel
SIEM_CONFIG = {
    # Enable/disable SIEM integration
    "ENABLED": os.environ.get("SIEM_ENABLED", "false").lower() == "true",
    # Log format: cef, leef, json, syslog, ocsf
    # CEF = ArcSight/Splunk, LEEF = IBM QRadar, JSON = Elastic/Graylog
    "FORMAT": os.environ.get("SIEM_FORMAT", "json"),
    # Transport: tcp, udp, https, file
    "PROTOCOL": os.environ.get("SIEM_PROTOCOL", "tcp"),
    "HOST": os.environ.get("SIEM_HOST", "localhost"),
    "PORT": int(os.environ.get("SIEM_PORT", "514")),
    "USE_TLS": os.environ.get("SIEM_USE_TLS", "true").lower() == "true",
    # Authentication for HTTPS endpoints (e.g., Splunk HEC)
    "API_KEY": os.environ.get("SIEM_API_KEY", ""),
    "CERTIFICATE_PATH": os.environ.get("SIEM_CERTIFICATE_PATH", ""),
    # Buffering configuration
    "BUFFER_SIZE": int(os.environ.get("SIEM_BUFFER_SIZE", "1000")),
    "BATCH_SIZE": int(os.environ.get("SIEM_BATCH_SIZE", "100")),
    "FLUSH_INTERVAL": int(os.environ.get("SIEM_FLUSH_INTERVAL", "5")),
    # Retry configuration
    "MAX_RETRIES": int(os.environ.get("SIEM_MAX_RETRIES", "3")),
    "RETRY_DELAY": int(os.environ.get("SIEM_RETRY_DELAY", "1")),
    # Filtering - minimum severity to forward
    # Options: low, medium, high, critical
    "MIN_SEVERITY": os.environ.get("SIEM_MIN_SEVERITY", "low"),
    # Category filtering (comma-separated)
    "INCLUDE_CATEGORIES": [c.strip() for c in os.environ.get("SIEM_INCLUDE_CATEGORIES", "").split(",") if c.strip()],
    "EXCLUDE_CATEGORIES": [c.strip() for c in os.environ.get("SIEM_EXCLUDE_CATEGORIES", "").split(",") if c.strip()],
    # Tamper-proof hash chain
    "ENABLE_HASH_CHAIN": os.environ.get("SIEM_ENABLE_HASH_CHAIN", "true").lower() == "true",
    "HASH_ALGORITHM": os.environ.get("SIEM_HASH_ALGORITHM", "sha256"),
    # Vendor information for CEF/LEEF formats
    "VENDOR": os.environ.get("SIEM_VENDOR", "PRAHO"),
    "PRODUCT": os.environ.get("SIEM_PRODUCT", "PlatformAudit"),
    "VERSION": os.environ.get("SIEM_VERSION", "1.0"),
}

# Log directory for file-based SIEM integration
SIEM_LOG_DIR = os.environ.get("SIEM_LOG_DIR", "/var/log/praho/siem")

# ===============================================================================
# ENHANCED AUDIT LOGGING CONFIGURATION 📋
# ===============================================================================

# Enhanced logging with SIEM-compatible JSON format
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
        # Main application log file
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/app.log",
            "maxBytes": 52428800,  # 50MB
            "backupCount": 10,
            "formatter": "json",
            "filters": ["add_request_id", "add_audit_context"],
        },
        # Security-specific log file (high severity events)
        "security_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/security.log",
            "maxBytes": 52428800,  # 50MB
            "backupCount": 30,  # Keep more security logs
            "formatter": "json",
            "filters": ["add_request_id", "add_audit_context"],
        },
        # Audit log file (immutable audit trail)
        "audit_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/audit.log",
            "maxBytes": 104857600,  # 100MB
            "backupCount": 90,  # 90 days for compliance
            "formatter": "audit",
            "filters": ["add_request_id", "add_audit_context"],
        },
        # Error log for critical issues
        "error_file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/praho/error.log",
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
        # Application logging
        "apps": {
            "handlers": ["console", "file"],
            "level": "INFO",
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
# AUDIT LOG RETENTION CONFIGURATION 📅
# ===============================================================================

# Retention periods for different log categories (in days)
AUDIT_LOG_RETENTION = {
    # Authentication events - required for security analysis
    "authentication": {
        "retention_days": 2555,  # 7 years (Romanian requirement)
        "action": "archive",
        "legal_basis": "Romanian Law 677/2001, GDPR Art. 17",
    },
    # Authorization/access control events
    "authorization": {
        "retention_days": 2555,
        "action": "archive",
        "legal_basis": "ISO 27001, SOC 2",
    },
    # Security incidents - keep indefinitely
    "security_event": {
        "retention_days": 3650,  # 10 years
        "action": "archive",
        "legal_basis": "Romanian Penal Code, Cybersecurity Directive",
    },
    # Business operations (billing, orders)
    "business_operation": {
        "retention_days": 3650,  # 10 years (tax requirement)
        "action": "archive",
        "legal_basis": "Romanian Fiscal Code Art. 25",
    },
    # Data protection/GDPR events
    "data_protection": {
        "retention_days": 2555,
        "action": "archive",
        "legal_basis": "GDPR Art. 30",
    },
    # Privacy events
    "privacy": {
        "retention_days": 2555,
        "action": "archive",
        "legal_basis": "GDPR Art. 7",
    },
    # System administration
    "system_admin": {
        "retention_days": 1825,  # 5 years
        "action": "archive",
        "legal_basis": "ISO 27001 A.12",
    },
    # Integration events (webhooks, APIs)
    "integration": {
        "retention_days": 365,  # 1 year
        "action": "delete",
        "legal_basis": "Operational requirement",
    },
    # Account management
    "account_management": {
        "retention_days": 2555,
        "action": "archive",
        "legal_basis": "GDPR Art. 17, Romanian Law 677/2001",
    },
    # Compliance events
    "compliance": {
        "retention_days": 3650,  # 10 years
        "action": "archive",
        "legal_basis": "Romanian Fiscal Code, e-Factura Regulation",
    },
}

# ===============================================================================
# COMPLIANCE REPORTING CONFIGURATION 📊
# ===============================================================================

COMPLIANCE_REPORTING = {
    # Enable automated compliance report generation
    "ENABLED": True,
    # Report storage location
    "REPORT_DIR": os.environ.get("COMPLIANCE_REPORT_DIR", "/var/log/praho/compliance"),
    # Report formats: pdf, csv, json
    "FORMATS": ["pdf", "csv", "json"],
    # Report scheduling (cron expressions)
    "SCHEDULES": {
        "daily_security": "0 6 * * *",  # 6 AM daily
        "weekly_access": "0 6 * * 1",  # Monday 6 AM
        "monthly_compliance": "0 6 1 * *",  # 1st of month 6 AM
        "quarterly_audit": "0 6 1 1,4,7,10 *",  # Quarterly
    },
    # Report types to generate
    "REPORT_TYPES": [
        "security_summary",
        "access_review",
        "authentication_audit",
        "data_access_audit",
        "compliance_violations",
        "gdpr_compliance",
        "romanian_fiscal_compliance",
    ],
    # Email notifications for reports
    "EMAIL_RECIPIENTS": [c.strip() for c in os.environ.get("COMPLIANCE_REPORT_RECIPIENTS", "").split(",") if c.strip()],
    # Compliance frameworks to check
    "FRAMEWORKS": [
        "ISO27001",
        "SOC2",
        "GDPR",
        "ROMANIAN_FISCAL",
        "E_FACTURA",
    ],
}
