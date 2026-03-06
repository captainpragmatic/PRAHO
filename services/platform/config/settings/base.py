"""
Django settings for PRAHO Platform - Base Configuration with security-first approach.
"""

import os
from pathlib import Path
from typing import Any

from django.core.exceptions import ImproperlyConfigured

# ===============================================================================
# CORE DJANGO SETTINGS
# ===============================================================================

# 🚨 FIX: Update BASE_DIR after move to services/platform/
BASE_DIR = Path(__file__).resolve().parent.parent.parent  # Up 3 levels to services/platform/

# Application definition
DJANGO_APPS: list[str] = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
]

THIRD_PARTY_APPS: list[str] = [
    "rest_framework",
    "rest_framework.authtoken",  # 🔐 Token authentication for API access
    "ipware",
    "django_q",  # Async task processing
]

LOCAL_APPS: list[str] = [
    "apps.common",
    "apps.users",
    "apps.customers",
    "apps.billing",
    "apps.tickets",
    "apps.provisioning",
    "apps.infrastructure",  # 🖥️ Cloud infrastructure & node deployment
    "apps.products",
    "apps.orders",
    "apps.domains",  # 🌐 Domain management & TLD configuration
    "apps.notifications",
    "apps.integrations",  # 🔌 External service webhooks & deduplication
    "apps.audit",
    "apps.ui",
    "apps.promotions",  # 🎁 Coupons, discounts, loyalty programs
    "apps.settings",  # ⚙️ System configuration management
    "apps.api",  # 🚀 Centralized API endpoints (Sentry/Stripe pattern)
]

INSTALLED_APPS: list[str] = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE: list[str] = [
    "apps.common.middleware.RequestIDMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "apps.common.middleware.SecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "apps.common.middleware.StaffOnlyPlatformMiddleware",  # Block customer access to platform (after AuthenticationMiddleware and MessageMiddleware)
    "apps.common.middleware.PortalServiceHMACMiddleware",  # HMAC auth for portal API requests (after AuthenticationMiddleware)
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            BASE_DIR / "templates",
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.common.context_processors.current_customer",
                "apps.common.context_processors.romanian_business_context",
                "apps.common.context_processors.navigation_dropdowns",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# ===============================================================================
# DATABASE CONFIGURATION
# ===============================================================================

DATABASES: dict[str, dict[str, Any]] = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "pragmatichost"),
        "USER": os.environ.get("DB_USER", "pragmatichost"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "development_password"),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
        "CONN_MAX_AGE": 60,  # Database connection pooling
        "OPTIONS": {
            "application_name": "pragmatichost_crm",
        },
    }
}

# ===============================================================================
# AUTHENTICATION & AUTHORIZATION
# ===============================================================================

AUTH_USER_MODEL = "users.User"

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 12,  # Strong passwords for hosting provider
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Use Argon2 for password hashing (security best practice)
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

# Authentication URLs
LOGIN_URL = "/auth/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/"

# Password reset settings
PASSWORD_RESET_TIMEOUT = 7200  # 2 hours in seconds

# Account lockout threshold: number of failed attempts before progressive lockout kicks in.
# Default 1 means lockout starts on the first failed attempt (most secure).
# Increase to allow N free attempts before lockout delays apply.
ACCOUNT_LOCKOUT_THRESHOLD = 1

# ===============================================================================
# INTERNATIONALIZATION & LOCALIZATION
# ===============================================================================

LANGUAGE_CODE = "en"  # English default, with Romanian support
TIME_ZONE = "Europe/Bucharest"
USE_I18N = True
USE_TZ = True

LANGUAGES = [
    ("en", "English"),
    ("ro", "Română"),
]

# Romanian locale formatting
LOCALE_PATHS = [
    BASE_DIR / "locale",
]

# ===============================================================================
# STATIC FILES & MEDIA
# ===============================================================================

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [
    BASE_DIR / "static",
]

STATICFILES_STORAGE = "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# ===============================================================================
# CACHE CONFIGURATION (Database-backed cache - no Redis needed) 💾
# ===============================================================================

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "django_cache_table",
        "KEY_PREFIX": "pragmatichost",
        "OPTIONS": {
            "MAX_ENTRIES": 10000,
            "CULL_FREQUENCY": 3,  # Delete 1/3 of cache when MAX_ENTRIES reached
        },
        "TIMEOUT": 300,  # 5 minutes default timeout
        "VERSION": 1,
    }
}

# ===============================================================================
# SESSION & COOKIE SETTINGS
# ===============================================================================

# Use DB-backed sessions across environments (simple and persistent)
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_SAVE_EVERY_REQUEST = True
# Note: SESSION_COOKIE_SECURE = True set in prod.py

# CSRF settings
CSRF_COOKIE_HTTPONLY = True
CSRF_TRUSTED_ORIGINS: list[str] = []
# Note: CSRF_COOKIE_SECURE = True set in prod.py

# ===============================================================================
# ADDITIONAL SECURITY SETTINGS
# ===============================================================================

# Security headers (enhanced in production)
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# File upload security
FILE_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
FILE_UPLOAD_PERMISSIONS = 0o644

# ===============================================================================
# EMAIL CONFIGURATION 📧
# ===============================================================================

# Email security settings
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False  # Use TLS instead of SSL

# Default email addresses
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL", "PRAHO Platform <noreply@pragmatichost.com>")
SERVER_EMAIL = os.environ.get("SERVER_EMAIL", "server@pragmatichost.com")

# Email provider configuration
# Supported: 'smtp', 'amazon_ses', 'sendgrid', 'mailgun', 'console', 'locmem'
EMAIL_PROVIDER = os.environ.get("EMAIL_PROVIDER", "smtp")

# SMTP Configuration (fallback/default)
EMAIL_HOST = os.environ.get("EMAIL_HOST", "localhost")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", "587"))
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
EMAIL_TIMEOUT = int(os.environ.get("EMAIL_TIMEOUT", "30"))

# ===============================================================================
# ANYMAIL CONFIGURATION (Multi-Provider Email Backend)
# ===============================================================================

ANYMAIL = {
    # Amazon SES configuration
    "AMAZON_SES_CLIENT_PARAMS": {
        "region_name": os.environ.get("AWS_SES_REGION", "eu-west-1"),
    },
    "AMAZON_SES_SESSION_PARAMS": {
        "aws_access_key_id": os.environ.get("AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY"),
    },
    "AMAZON_SES_CONFIGURATION_SET": os.environ.get("AWS_SES_CONFIGURATION_SET"),
    # SendGrid configuration
    "SENDGRID_API_KEY": os.environ.get("SENDGRID_API_KEY"),
    # Mailgun configuration
    "MAILGUN_API_KEY": os.environ.get("MAILGUN_API_KEY"),
    "MAILGUN_SENDER_DOMAIN": os.environ.get("MAILGUN_SENDER_DOMAIN"),
    "MAILGUN_API_URL": os.environ.get("MAILGUN_API_URL", "https://api.eu.mailgun.net/v3"),
    # Webhook configuration
    "WEBHOOK_SECRET": os.environ.get("EMAIL_WEBHOOK_SECRET"),
    # Tracking settings
    "TRACK_OPENS": True,
    "TRACK_CLICKS": True,
    # Ignore unsupported features rather than raising errors
    "IGNORE_UNSUPPORTED_FEATURES": True,
}

# Email rate limiting and throttling
EMAIL_RATE_LIMIT = {
    "MAX_PER_MINUTE": int(os.environ.get("EMAIL_MAX_PER_MINUTE", "50")),
    "MAX_PER_HOUR": int(os.environ.get("EMAIL_MAX_PER_HOUR", "1000")),
    "MAX_PER_DAY": int(os.environ.get("EMAIL_MAX_PER_DAY", "10000")),
    "BURST_SIZE": int(os.environ.get("EMAIL_BURST_SIZE", "100")),
}

# Email retry configuration
EMAIL_RETRY = {
    "MAX_RETRIES": int(os.environ.get("EMAIL_MAX_RETRIES", "3")),
    "RETRY_DELAY_SECONDS": int(os.environ.get("EMAIL_RETRY_DELAY", "60")),
    "EXPONENTIAL_BACKOFF": True,
}

# Email template configuration
EMAIL_TEMPLATES = {
    "CACHE_TIMEOUT": int(os.environ.get("EMAIL_TEMPLATE_CACHE_TIMEOUT", "3600")),  # 1 hour
    "STRICT_MODE": os.environ.get("EMAIL_TEMPLATE_STRICT_MODE", "false").lower() == "true",
}

# Email deliverability settings
EMAIL_DELIVERABILITY = {
    "REQUIRE_SPF": True,
    "REQUIRE_DKIM": True,
    "REQUIRE_DMARC": True,
    "SOFT_BOUNCE_THRESHOLD": int(os.environ.get("EMAIL_SOFT_BOUNCE_THRESHOLD", "3")),
    "HARD_BOUNCE_ACTION": "suppress",  # 'suppress' or 'warn'
    "COMPLAINT_ACTION": "suppress",  # 'suppress' or 'warn'
}

# ===============================================================================
# DJANGO REST FRAMEWORK
# ===============================================================================

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        # Session auth for web UI (HTMX calls from platform)
        "rest_framework.authentication.SessionAuthentication",
        # Token auth for portal service and external clients
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 20,  # Updated to match our API pagination
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
    ],
    "EXCEPTION_HANDLER": "apps.api.exception_handlers.platform_exception_handler",
    # Set explicitly later from THROTTLE_RATES + canonical throttle classes.
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {},
}

# ===============================================================================
# ROMANIAN BUSINESS CONFIGURATION
# ===============================================================================

# NOTE: VAT rates removed — use TaxService.get_vat_rate('RO'). See ADR-0005, ADR-0015.

# Romanian company information
ROMANIAN_BUSINESS_CONTEXT = {
    "company_name": os.environ.get("COMPANY_NAME", "PragmaticHost SRL"),
    "company_cui": os.environ.get("COMPANY_CUI", "RO12345678"),
    "email": os.environ.get("COMPANY_EMAIL", "contact@pragmatichost.com"),
    "phone": os.environ.get("COMPANY_PHONE", "+40.21.123.4567"),
    "address": os.environ.get("COMPANY_ADDRESS", "Str. Exemplu Nr. 1, Bucuresti, Romania"),
    "currency": "RON",
}

# Currency settings
DEFAULT_CURRENCY = "RON"
SUPPORTED_CURRENCIES = ["RON", "EUR", "USD"]

# ===============================================================================
# EXTERNAL INTEGRATIONS
# ===============================================================================

# Stripe settings
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")

# ✅ Virtualmin settings migrated to Settings UI!
# Visit: /app/settings/dashboard/ → Provisioning & Infrastructure
# Credentials are stored in the encrypted credential vault.

# e-Factura API settings
EFACTURA_API_URL = os.environ.get("EFACTURA_API_URL")
EFACTURA_API_KEY = os.environ.get("EFACTURA_API_KEY")

# ===============================================================================
# DEFAULT AUTO FIELD
# ===============================================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ===============================================================================
# SECURITY SETTINGS (Base - override in prod.py)
# ===============================================================================

# SECRET_KEY validation for production security
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")
if not SECRET_KEY:
    # Development fallback - never use this in production
    import warnings

    warnings.warn(
        "🚨 SECURITY WARNING: Using default SECRET_KEY. Set DJANGO_SECRET_KEY environment variable for production!",
        UserWarning,
        stacklevel=2,
    )
    SECRET_KEY = "django-insecure-dev-key-only-change-in-production-or-tests"  # Not a real secret: fallback for development only  # noqa: S105  # Not a real secret: config key name


# Validate SECRET_KEY security in production (checked in prod.py and staging.py)
MIN_SECRET_KEY_LENGTH = 50


def validate_production_secret_key(secret_key: str) -> None:
    """Validate that SECRET_KEY is safe for production use."""
    secret_key = secret_key.strip() if secret_key else ""

    if not secret_key:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY environment variable is required")

    if len(secret_key) < MIN_SECRET_KEY_LENGTH:
        raise ImproperlyConfigured(
            f"DJANGO_SECRET_KEY is too short ({len(secret_key)} chars). "
            "Use at least 50 characters: openssl rand -base64 50"
        )

    insecure_prefixes = [
        "django-insecure-",
        "dev-secret-key-",
        "dev-portal-key-",
        "test-secret-key-",
    ]
    insecure_values = ["changeme", "secret", "password"]

    key_lower = secret_key.lower()
    for prefix in insecure_prefixes:
        if key_lower.startswith(prefix):
            raise ImproperlyConfigured(
                f"DJANGO_SECRET_KEY starts with insecure prefix '{prefix}'. "
                "Generate a secure key: openssl rand -base64 50"
            )

    if key_lower in insecure_values:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY is a well-known insecure value. Generate a secure key: openssl rand -base64 50"
        )


# ===============================================================================
# COMPANY INFORMATION FOR INVOICES & LEGAL DOCUMENTS 🏢
# ===============================================================================

# Company information - override these in environment or local settings
COMPANY_NAME = os.environ.get("COMPANY_NAME", "PRAHO Platform")
COMPANY_ADDRESS = os.environ.get("COMPANY_ADDRESS", "Str. Exemplu Nr. 1")
COMPANY_CITY = os.environ.get("COMPANY_CITY", "București")
COMPANY_COUNTRY = os.environ.get("COMPANY_COUNTRY", "România")
COMPANY_CUI = os.environ.get("COMPANY_CUI", "RO12345678")  # Romanian tax ID
COMPANY_EMAIL = os.environ.get("COMPANY_EMAIL", "contact@praho.ro")
COMPANY_PHONE = os.environ.get("COMPANY_PHONE", "+40 21 000 0000")
COMPANY_WEBSITE = os.environ.get("COMPANY_WEBSITE", "https://praho.ro")

# VAT settings for Romanian compliance
# NOTE: VAT_RATE removed — use TaxService.get_vat_rate('RO'). See ADR-0005, ADR-0015.
VAT_ENABLED = True

# ===============================================================================
# SECURE IP DETECTION CONFIGURATION 🔒
# ===============================================================================

# Configure trusted proxy handling for secure IP detection
# This prevents IP spoofing attacks against rate limiting and audit logging
# Default: trust no proxy headers (safe for development)
IPWARE_TRUSTED_PROXY_LIST: list[str] = []

# Always configure proxy SSL header (used by load balancers)
# Only meaningful when behind a load balancer/reverse proxy
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ===============================================================================
# ✅ VIRTUALMIN AUTHENTICATION - MIGRATED TO SETTINGS UI! 🎉
# ===============================================================================

# All Virtualmin settings have been migrated to the Settings UI:
# 🌐 Visit: /app/settings/dashboard/ → "Provisioning & Infrastructure"
# 🔐 Credentials are stored securely in the encrypted credential vault
# � Use: python manage.py setup_credential_vault to manage credentials
#
# Benefits:
# ✅ Runtime configuration changes (no restart needed)
# ✅ Encrypted credential storage
# ✅ Audit trail for all changes
# ✅ Type validation and defaults
# ✅ Centralized management interface

# ===============================================================================
# CREDENTIAL VAULT CONFIGURATION 🔐
# ===============================================================================

# Master encryption key for credential vault (AES-256-GCM)
# Generate with: python -c 'import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())'
CREDENTIAL_VAULT_MASTER_KEY = os.environ.get("CREDENTIAL_VAULT_MASTER_KEY")

# Vault configuration
CREDENTIAL_VAULT_ENABLED = os.environ.get("CREDENTIAL_VAULT_ENABLED", "true").lower() == "true"
CREDENTIAL_VAULT_DEFAULT_EXPIRY_DAYS = int(os.environ.get("CREDENTIAL_VAULT_DEFAULT_EXPIRY_DAYS", "30"))
CREDENTIAL_VAULT_MAX_AGE_DAYS = int(os.environ.get("CREDENTIAL_VAULT_MAX_AGE_DAYS", "90"))

# ===============================================================================
# VIRTUALMIN TIMEOUT CONFIGURATIONS ⏱️
# ===============================================================================

# Externalized timeout configurations for production optimization
# These values can be overridden by environment variables (VIRTUALMIN_*_TIMEOUT)
VIRTUALMIN_TIMEOUTS = {
    # API request timeouts (seconds)
    "API_REQUEST_TIMEOUT": int(os.environ.get("VIRTUALMIN_API_REQUEST_TIMEOUT", "30")),
    "API_HEALTH_CHECK_TIMEOUT": int(os.environ.get("VIRTUALMIN_API_HEALTH_CHECK_TIMEOUT", "10")),
    "API_BACKUP_TIMEOUT": int(os.environ.get("VIRTUALMIN_API_BACKUP_TIMEOUT", "300")),
    "API_BULK_TIMEOUT": int(os.environ.get("VIRTUALMIN_API_BULK_TIMEOUT", "600")),
    # Connection timeouts (seconds)
    "CONNECTION_TIMEOUT": int(os.environ.get("VIRTUALMIN_CONNECTION_TIMEOUT", "15")),
    "READ_TIMEOUT": int(os.environ.get("VIRTUALMIN_READ_TIMEOUT", "30")),
    "WRITE_TIMEOUT": int(os.environ.get("VIRTUALMIN_WRITE_TIMEOUT", "30")),
    # Task-specific timeouts (seconds)
    "PROVISIONING_TIMEOUT": int(os.environ.get("VIRTUALMIN_PROVISIONING_TIMEOUT", "180")),
    "DOMAIN_SYNC_TIMEOUT": int(os.environ.get("VIRTUALMIN_DOMAIN_SYNC_TIMEOUT", "120")),
    "USAGE_SYNC_TIMEOUT": int(os.environ.get("VIRTUALMIN_USAGE_SYNC_TIMEOUT", "60")),
    # Retry and rate limiting
    "RETRY_DELAY": int(os.environ.get("VIRTUALMIN_RETRY_DELAY", "5")),
    "MAX_RETRIES": int(os.environ.get("VIRTUALMIN_MAX_RETRIES", "3")),
    "RATE_LIMIT_WINDOW": int(os.environ.get("VIRTUALMIN_RATE_LIMIT_WINDOW", "3600")),
    "RATE_LIMIT_MAX_CALLS": int(os.environ.get("VIRTUALMIN_RATE_LIMIT_MAX_CALLS", "100")),
    "CONNECTION_POOL_SIZE": int(os.environ.get("VIRTUALMIN_CONNECTION_POOL_SIZE", "10")),
}

# ===============================================================================
# RATE LIMITING CONFIGURATION 🔒
# ===============================================================================

# Rate limiting key function for intelligent user/IP-based limiting
RATELIMIT_KEY = "apps.users.ratelimit_keys.user_or_ip"

# Cache backend for rate limiting (uses database cache)
RATELIMIT_USE_CACHE = "default"

# Enable rate limiting (can be disabled in development)
# RATELIMIT_ENABLE: used by django-ratelimit library decorators
# RATELIMIT_ENABLED: used by our custom middleware (PortalServiceHMACMiddleware, etc.)
# Both must stay in sync — custom code should read RATELIMIT_ENABLED.
RATELIMIT_ENABLE = True
RATELIMIT_ENABLED = True

# ===============================================================================
# DJANGO-Q2 ASYNC TASK PROCESSING 🚀
# ===============================================================================

# Base queue cluster configuration
Q_CLUSTER_BASE = {
    "name": "praho-cluster",
    "timeout": 300,  # 5 minutes
    "retry": 600,  # 10 minutes retry delay
    "save_limit": 1000,  # Keep last 1000 task results
    "catch_up": False,  # Don't run missed scheduled tasks
    "orm": "default",  # Use PostgreSQL database backend
    "bulk": 10,  # Process 10 jobs at once
    "queue_limit": 100,  # Max 100 jobs in queue
}

# Default production configuration (overridden in environment-specific settings)
Q_CLUSTER = {
    **Q_CLUSTER_BASE,
    "workers": 2,  # 2 worker processes
    "recycle": 500,  # Restart workers after 500 tasks
    "sync": False,  # Async execution
}

# ===============================================================================
# 🚀 PERFORMANCE & SCALABILITY CONFIGURATION
# ===============================================================================

# Cache version for invalidation (increment to invalidate all caches)
CACHE_VERSION = int(os.environ.get("CACHE_VERSION", "1"))

# ===============================================================================
# REDIS CACHE CONFIGURATION (Production) 🔄
# ===============================================================================

# Redis URL for caching (if available, otherwise falls back to database cache)
REDIS_URL = os.environ.get("REDIS_URL")

# Redis cache configuration (used when REDIS_URL is set)
REDIS_CACHE_CONFIG = {
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
}

# ===============================================================================
# DRF THROTTLING CONFIGURATION 🚦
# ===============================================================================

# Rate limiting rates for different scopes
THROTTLE_RATES = {
    # Global DRF defaults (apps.common.performance.rate_limiting)
    "portal_hmac": os.environ.get("THROTTLE_RATE_PORTAL_HMAC", "100/minute"),
    "portal_hmac_burst": "50/10s",
    "customer": os.environ.get("THROTTLE_RATE_CUSTOMER", "100/minute"),
    "burst": "30/10s",
    # Per-view API throttles (apps.api.core.throttling)
    "auth": "5/minute",
    "sustained": "1000/hour",
    "api_burst": "60/min",
    # Built-in DRF classes used directly by decorators
    "anon": "20/minute",
    # Order API scoped throttles (apps.api.orders.views)
    "order_create": "10/min",
    "order_calculate": "30/min",
    "order_list": "100/min",
    "product_catalog": "200/min",
}

# Add throttling classes to REST_FRAMEWORK
REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"] = [
    "apps.common.performance.rate_limiting.PortalHMACRateThrottle",
    "apps.common.performance.rate_limiting.PortalHMACBurstThrottle",
    "apps.common.performance.rate_limiting.CustomerRateThrottle",
    "apps.common.performance.rate_limiting.BurstRateThrottle",
]
REST_FRAMEWORK["DEFAULT_THROTTLE_RATES"] = THROTTLE_RATES

# ===============================================================================
# CONNECTION POOLING CONFIGURATION 🔌
# ===============================================================================

# HTTP connection pool settings for external services
HTTP_CONNECTION_POOL = {
    "pool_connections": int(os.environ.get("HTTP_POOL_CONNECTIONS", "10")),
    "pool_maxsize": int(os.environ.get("HTTP_POOL_MAXSIZE", "20")),
    "max_retries": int(os.environ.get("HTTP_MAX_RETRIES", "3")),
    "backoff_factor": float(os.environ.get("HTTP_BACKOFF_FACTOR", "0.5")),
    "timeout_connect": float(os.environ.get("HTTP_TIMEOUT_CONNECT", "10.0")),
    "timeout_read": float(os.environ.get("HTTP_TIMEOUT_READ", "30.0")),
}

# Service-specific connection pool overrides
CONNECTION_POOL_OVERRIDES = {
    "virtualmin": {
        "pool_connections": 5,
        "pool_maxsize": 10,
        "timeout_connect": 15.0,
        "timeout_read": 60.0,
    },
    "stripe": {
        "pool_connections": 10,
        "pool_maxsize": 20,
        "timeout_connect": 10.0,
        "timeout_read": 30.0,
    },
    "efactura": {
        "pool_connections": 3,
        "pool_maxsize": 5,
        "timeout_read": 60.0,
    },
}

# ===============================================================================
# RESOURCE QUOTAS CONFIGURATION 📊
# ===============================================================================

# Enable/disable quota enforcement
QUOTA_ENFORCEMENT_ENABLED = os.environ.get("QUOTA_ENFORCEMENT_ENABLED", "true").lower() == "true"

# Default quotas by customer tier
CUSTOMER_QUOTA_TIERS = {
    "basic": {
        "api_requests": 10000,  # per month
        "storage_mb": 5120,  # 5 GB
        "bandwidth_mb": 102400,  # 100 GB
        "services": 3,
        "domains": 5,
        "email_accounts": 10,
        "databases": 3,
        "users": 2,
    },
    "professional": {
        "api_requests": 100000,
        "storage_mb": 51200,  # 50 GB
        "bandwidth_mb": 512000,  # 500 GB
        "services": 10,
        "domains": 25,
        "email_accounts": 100,
        "databases": 25,
        "users": 10,
    },
    "enterprise": {
        "api_requests": 1000000,
        "storage_mb": 512000,  # 500 GB
        "bandwidth_mb": 5120000,  # 5 TB
        "services": 100,
        "domains": 500,
        "email_accounts": 1000,
        "databases": 250,
        "users": 100,
    },
}

# ===============================================================================
# ASYNC TASK PROCESSING CONFIGURATION ⚡
# ===============================================================================

# Task priority queue configuration
TASK_PRIORITIES = {
    "critical": {"timeout": 60, "retry": 120, "max_retries": 5},
    "high": {"timeout": 180, "retry": 300, "max_retries": 3},
    "normal": {"timeout": 300, "retry": 600, "max_retries": 3},
    "low": {"timeout": 600, "retry": 1800, "max_retries": 2},
    "background": {"timeout": 1800, "retry": 3600, "max_retries": 1},
}

# Bulk operation settings
BULK_OPERATION_BATCH_SIZE = int(os.environ.get("BULK_BATCH_SIZE", "100"))
BULK_OPERATION_USE_TRANSACTION = True

# ===============================================================================
# QUERY OPTIMIZATION CONFIGURATION 🔍
# ===============================================================================

# Enable query profiling in development/staging
QUERY_PROFILING_ENABLED = os.environ.get("QUERY_PROFILING_ENABLED", "false").lower() == "true"
QUERY_PROFILING_THRESHOLD = int(os.environ.get("QUERY_PROFILING_THRESHOLD", "5"))

# N+1 query detection warning threshold
N_PLUS_ONE_THRESHOLD = int(os.environ.get("N_PLUS_ONE_THRESHOLD", "10"))

# ===============================================================================
# DISTRIBUTED LOCKING CONFIGURATION 🔐
# ===============================================================================

# Lock timeout defaults (seconds)
DISTRIBUTED_LOCK_TIMEOUT = int(os.environ.get("DISTRIBUTED_LOCK_TIMEOUT", "300"))
DISTRIBUTED_LOCK_BLOCKING_TIMEOUT = int(os.environ.get("DISTRIBUTED_LOCK_BLOCKING_TIMEOUT", "30"))

# ===============================================================================
# API CLIENT TIMEOUT CONFIGURATIONS ⏱️
# ===============================================================================

# Externalized timeout configurations for API clients (Domain, Server Gateway, Portal)
# These values can be overridden by environment variables (API_*_TIMEOUT)
API_TIMEOUTS = {
    # General API request timeouts (seconds)
    "REQUEST_TIMEOUT": int(os.environ.get("API_REQUEST_TIMEOUT", "30")),
    "HEALTH_CHECK_TIMEOUT": int(os.environ.get("API_HEALTH_CHECK_TIMEOUT", "10")),
    # Retry configuration
    "MAX_RETRIES": int(os.environ.get("API_MAX_RETRIES", "3")),
    "RETRY_DELAY": int(os.environ.get("API_RETRY_DELAY", "2")),
    # Rate limiting
    "RATE_LIMIT_WINDOW": int(os.environ.get("API_RATE_LIMIT_WINDOW", "3600")),  # 1 hour
    "RATE_LIMIT_MAX_CALLS": int(os.environ.get("API_RATE_LIMIT_MAX_CALLS", "50")),
}

# Portal service specific timeout (can be overridden)
PORTAL_API_TIMEOUT = int(os.environ.get("PORTAL_API_TIMEOUT", "30"))

# Portal payment webhook URL (platform → portal notification after Stripe payment)
PORTAL_PAYMENT_WEBHOOK_URL: str = os.environ.get("PORTAL_PAYMENT_WEBHOOK_URL", "")

# Dedicated HMAC secret for platform→portal webhook signing (separate from HMAC_SECRET)
# Must match PLATFORM_TO_PORTAL_WEBHOOK_SECRET on the portal side.
PLATFORM_TO_PORTAL_WEBHOOK_SECRET: str = os.environ.get("PLATFORM_TO_PORTAL_WEBHOOK_SECRET", "")

# Outbound HTTP: allowed domains for INTERNAL_SERVICE policy (empty = unrestricted)
INTERNAL_SERVICE_ALLOWED_DOMAINS: list[str] = ["localhost"]
