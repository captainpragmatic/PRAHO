"""
Django settings for PRAHO Portal Service - Customer-facing app configuration.
"""

import os
from pathlib import Path
from typing import Any

# ===============================================================================
# CORE DJANGO SETTINGS
# ===============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Application definition - Portal service apps only
DJANGO_APPS: list[str] = [
    "django.contrib.sessions",  # Session framework (cache-only)
    "django.contrib.messages",  # Message framework for user feedback
    "django.contrib.staticfiles",  # Static file serving
    "django.contrib.humanize",  # Template humanization
]

THIRD_PARTY_APPS: list[str] = [
    "django_extensions",
    "ipware",
]

LOCAL_APPS: list[str] = [
    "apps.common",  # Shared utilities, validators (duplicated from platform)
    "apps.users",  # Portal user authentication (validates via Platform API)
    "apps.dashboard",  # Customer dashboard (API-only)
    "apps.billing",  # Customer billing views (API client)
    "apps.tickets",  # Customer support tickets (API client)
    "apps.services",  # Customer service management (API client)
    "apps.ui",  # Template tags and components
    "apps.api_client",  # Platform API integration service
]

INSTALLED_APPS: list[str] = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE: list[str] = [
    "django.middleware.security.SecurityMiddleware",
    # 🔒 SECURITY: Rate limiting before sessions to prevent DoS
    "apps.common.rate_limiting.AuthenticationRateLimitMiddleware",  # Auth rate limiting
    "apps.common.rate_limiting.APIRateLimitMiddleware",  # API rate limiting
    "django.contrib.sessions.middleware.SessionMiddleware",  # Cache-only sessions
    "django.middleware.locale.LocaleMiddleware",  # After sessions
    "apps.users.middleware.SessionLanguageMiddleware",  # Activate session language
    "django.middleware.common.CommonMiddleware",  # After locale
    "django.middleware.csrf.CsrfViewMiddleware",  # CSRF protection
    "django.contrib.messages.middleware.MessageMiddleware",  # Messages support
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # 🔒 SECURITY: Session security after authentication
    "apps.common.middleware.SessionSecurityMiddleware",  # Session protection
    # Custom middleware last
    "apps.common.middleware.RequestIDMiddleware",
    "apps.common.middleware.SecurityHeadersMiddleware",
    "apps.users.middleware.PortalAuthenticationMiddleware",  # Portal validation
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
                "django.template.context_processors.i18n",
                "django.contrib.messages.context_processors.messages",  # Messages in templates
                "apps.common.context_processors.portal_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ===============================================================================
# DATABASE - POSTGRESQL FOR PRODUCTION, SQLITE FOR DEV
# ===============================================================================

# DUMMY DATABASE - DJANGO REQUIREMENT (NEVER USED IN STATELESS PORTAL)
# Portal uses cache-only sessions and Platform API for all data
DATABASES: dict[str, dict[str, Any]] = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        # Use a file-backed SQLite DB so sessions persist across reloads
        "NAME": str(BASE_DIR / "portal.sqlite3"),
        "OPTIONS": {
            "timeout": 20,
        },
    }
}

# SESSION STORAGE
# Use DB-backed sessions in both dev and prod (simple, persistent across reloads)
SESSION_ENGINE = "django.contrib.sessions.backends.db"

# Keep a local cache for general portal caching (not sessions)
if os.environ.get("DEBUG", "True").lower() == "true":
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "portal-dev-cache",
        }
    }
else:
    # In production we can still use LocMem or point to Redis later
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "portal-prod-cache",
        }
    }


# ===============================================================================
# PLATFORM API CONFIGURATION
# ===============================================================================

# Platform service API connection
PLATFORM_API_BASE_URL = os.environ.get("PLATFORM_API_BASE_URL", "http://localhost:8700/api")
# 🔒 SECURITY: No fallback secrets in base config - must be set in environment
PLATFORM_API_SECRET = os.environ.get("PLATFORM_API_SECRET")
PLATFORM_API_TIMEOUT = int(os.environ.get("PLATFORM_API_TIMEOUT", "30"))


# ===============================================================================
# INTERNATIONALIZATION
# ===============================================================================

LANGUAGE_CODE = "en"
TIME_ZONE = "Europe/Bucharest"  # Romanian timezone
USE_I18N = True
USE_TZ = True

LANGUAGES = [
    ("en", "English"),
    ("ro", "Română"),
]

LOCALE_PATHS = [
    BASE_DIR / "locale",
]

# ===============================================================================
# STATIC FILES
# ===============================================================================

STATIC_URL = "/static/"
STATICFILES_DIRS = [
    BASE_DIR / "static",  # Changed from "assets" to "static"
]
STATIC_ROOT = BASE_DIR / "staticfiles"

# ===============================================================================
# SECURITY SETTINGS
# ===============================================================================

# 🔒 SECURITY: No fallback secrets in base config - must be set in environment
# Production settings will enforce this with proper error messages
SECRET_KEY = os.environ.get("SECRET_KEY")

DEBUG = os.environ.get("DEBUG", "True").lower() == "true"

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "portal.pragmatichost.com"]

# ===============================================================================
# SESSION CONFIGURATION 🔐
# ===============================================================================

# Session duration settings
SESSION_COOKIE_AGE_DEFAULT = 24 * 60 * 60  # 24 hours (86400 seconds)
SESSION_COOKIE_AGE_REMEMBER_ME = 30 * 24 * 60 * 60  # 30 days (2592000 seconds)

# Session behavior
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Use custom age settings
SESSION_SAVE_EVERY_REQUEST = False  # Only save when modified
SESSION_COOKIE_NAME = "portal_session"  # Custom session name

# Cookie security settings
SESSION_COOKIE_SECURE = not DEBUG  # HTTPS in production
SESSION_COOKIE_HTTPONLY = True  # Prevent XSS access
SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection
CSRF_COOKIE_SECURE = not DEBUG  # HTTPS for CSRF cookies
CSRF_COOKIE_HTTPONLY = False  # ✅ Allow JS access for AJAX
CSRF_COOKIE_SAMESITE = "Lax"  # CSRF protection

# CSRF trusted origins (must include scheme + host)
CSRF_TRUSTED_ORIGINS = [
    "https://portal.pragmatichost.com",
    "https://www.pragmatichost.com",
]

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"  # ✅ Added
X_FRAME_OPTIONS = "DENY"

# HTTPS redirect in production
SECURE_SSL_REDIRECT = not DEBUG

# ===============================================================================
# LOGGING
# ===============================================================================
# PLATFORM API INTEGRATION SETTINGS
# ===============================================================================

# Portal service identification for HMAC authentication
PORTAL_ID = os.environ.get("PORTAL_ID", "portal-001")

# Platform API connection settings
PLATFORM_API_BASE_URL = os.environ.get(
    "PLATFORM_API_BASE_URL",
    "http://localhost:8700/api",  # Default to local development
)
PLATFORM_API_SECRET = os.environ.get("PLATFORM_API_SECRET")
PLATFORM_API_TIMEOUT = int(os.environ.get("PLATFORM_API_TIMEOUT", "30"))

# ===============================================================================
# LOGGING CONFIGURATION
# ===============================================================================

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO"),
            "propagate": False,
        },
        "apps": {
            "handlers": ["console"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
    },
}

# ===============================================================================
# DEFAULT PRIMARY KEY FIELD TYPE
# ===============================================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
