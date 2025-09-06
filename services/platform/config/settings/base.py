"""
Django settings for PRAHO Platform - Base Configuration with security-first approach.
"""

import os
from pathlib import Path
from typing import Any

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
    "django_extensions",
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
    "apps.products",
    "apps.orders",
    "apps.domains",  # 🌐 Domain management & TLD configuration
    "apps.notifications",
    "apps.integrations",  # 🔌 External service webhooks & deduplication
    "apps.audit",
    "apps.ui",
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
    "apps.common.middleware.PortalServiceHMACMiddleware",  # HMAC auth for portal API requests
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
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
LOGIN_URL = "/users/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/"

# Password reset settings
PASSWORD_RESET_TIMEOUT = 7200  # 2 hours in seconds

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

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"
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

# Email security
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False  # Use TLS instead of SSL

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
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle", 
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/hour",     # Anonymous users (very limited)
        "user": "1000/hour",    # Authenticated users (generous for portal)
        "burst": "60/min",      # Search/autocomplete endpoints
    },
}

# ===============================================================================
# ROMANIAN BUSINESS CONFIGURATION
# ===============================================================================

# Romanian VAT rate (19% standard)
ROMANIA_VAT_RATE = "0.19"

# Romanian company information
ROMANIAN_BUSINESS_CONTEXT = {
    "company_name": os.environ.get("COMPANY_NAME", "PragmaticHost SRL"),
    "company_cui": os.environ.get("COMPANY_CUI", "RO12345678"),
    "email": os.environ.get("COMPANY_EMAIL", "contact@pragmatichost.com"),
    "phone": os.environ.get("COMPANY_PHONE", "+40.21.123.4567"),
    "address": os.environ.get("COMPANY_ADDRESS", "Str. Exemplu Nr. 1, Bucuresti, Romania"),
    "vat_rate": 0.19,
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
    SECRET_KEY = "django-insecure-dev-key-only-change-in-production-or-tests"  # noqa: S105


# Validate SECRET_KEY security in production (checked in prod.py)
def validate_production_secret_key() -> None:
    """Validate SECRET_KEY meets production security requirements"""
    if SECRET_KEY and SECRET_KEY.startswith("django-insecure-"):
        raise ValueError(
            "🔥 CRITICAL SECURITY ERROR: Cannot use insecure SECRET_KEY in production! "
            "Generate a secure key: python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'"
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
VAT_RATE = 0.19  # 19% Romanian VAT rate
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

# Master encryption key for credential vault
# Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
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
    'API_REQUEST_TIMEOUT': int(os.environ.get('VIRTUALMIN_API_REQUEST_TIMEOUT', '30')),
    'API_HEALTH_CHECK_TIMEOUT': int(os.environ.get('VIRTUALMIN_API_HEALTH_CHECK_TIMEOUT', '10')),
    'API_BACKUP_TIMEOUT': int(os.environ.get('VIRTUALMIN_API_BACKUP_TIMEOUT', '300')),
    'API_BULK_TIMEOUT': int(os.environ.get('VIRTUALMIN_API_BULK_TIMEOUT', '600')),
    
    # Connection timeouts (seconds)
    'CONNECTION_TIMEOUT': int(os.environ.get('VIRTUALMIN_CONNECTION_TIMEOUT', '15')),
    'READ_TIMEOUT': int(os.environ.get('VIRTUALMIN_READ_TIMEOUT', '30')),
    'WRITE_TIMEOUT': int(os.environ.get('VIRTUALMIN_WRITE_TIMEOUT', '30')),
    
    # Task-specific timeouts (seconds)
    'PROVISIONING_TIMEOUT': int(os.environ.get('VIRTUALMIN_PROVISIONING_TIMEOUT', '180')),
    'DOMAIN_SYNC_TIMEOUT': int(os.environ.get('VIRTUALMIN_DOMAIN_SYNC_TIMEOUT', '120')),
    'USAGE_SYNC_TIMEOUT': int(os.environ.get('VIRTUALMIN_USAGE_SYNC_TIMEOUT', '60')),
    
    # Retry and rate limiting
    'RETRY_DELAY': int(os.environ.get('VIRTUALMIN_RETRY_DELAY', '5')),
    'MAX_RETRIES': int(os.environ.get('VIRTUALMIN_MAX_RETRIES', '3')),
    'RATE_LIMIT_WINDOW': int(os.environ.get('VIRTUALMIN_RATE_LIMIT_WINDOW', '3600')),
    'RATE_LIMIT_MAX_CALLS': int(os.environ.get('VIRTUALMIN_RATE_LIMIT_MAX_CALLS', '100')),
    'CONNECTION_POOL_SIZE': int(os.environ.get('VIRTUALMIN_CONNECTION_POOL_SIZE', '10')),
}

# ===============================================================================
# RATE LIMITING CONFIGURATION 🔒
# ===============================================================================

# Rate limiting key function for intelligent user/IP-based limiting
RATELIMIT_KEY = "apps.users.ratelimit_keys.user_or_ip"

# Cache backend for rate limiting (uses database cache)
RATELIMIT_USE_CACHE = "default"

# Enable rate limiting (can be disabled in development)
RATELIMIT_ENABLE = True

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
