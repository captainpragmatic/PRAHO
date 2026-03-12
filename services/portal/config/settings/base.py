"""
Django settings for PRAHO Portal Service - Customer-facing app configuration.
"""

import logging
import os
from pathlib import Path
from typing import Any

from django.utils.translation import gettext_lazy as _

# ===============================================================================
# CORE DJANGO SETTINGS
# ===============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Application definition - Portal service apps only
DJANGO_APPS: list[str] = [
    "django.contrib.sessions",  # Session framework (DB-backed, see ADR-0017)
    "django.contrib.messages",  # Message framework for user feedback
    "django.contrib.staticfiles",  # Static file serving
    "django.contrib.humanize",  # Template humanization
]

THIRD_PARTY_APPS: list[str] = [
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
    # 🔒 SECURITY: Auth rate limiting before sessions (IP-only, no session needed)
    "apps.common.rate_limiting.AuthenticationRateLimitMiddleware",  # Auth rate limiting
    "django.contrib.sessions.middleware.SessionMiddleware",  # DB-backed sessions
    # 🔒 SECURITY: API rate limiting after sessions (cart limits need session key)
    "apps.common.rate_limiting.APIRateLimitMiddleware",  # API + cart session rate limiting
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
    "apps.common.middleware.CSPNonceMiddleware",
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
                "apps.common.context_processors.csp_nonce",
                "apps.common.context_processors.portal_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ===============================================================================
# DATABASE - SQLITE FOR SESSION STORAGE ONLY (ALL ENVIRONMENTS)
# ===============================================================================

# SESSION DATABASE — used for Django session storage only, no business data.
# Portal fetches all domain data from Platform via HMAC-signed API calls.
# Losing portal.sqlite3 forces re-login but loses no business data.
DATABASES: dict[str, dict[str, Any]] = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("SESSION_DB_PATH", str(BASE_DIR / "portal.sqlite3")),
        "OPTIONS": {
            # timeout: seconds to wait for a write lock (maps to sqlite3.connect timeout).
            "timeout": 20,
            # WAL mode: concurrent readers + single writer without blocking.
            # Django 5.1+ supports init_command for SQLite (executed on every connection).
            "init_command": "PRAGMA journal_mode=WAL;",
        },
    }
}

# SESSION STORAGE
# Server-side DB sessions: session_key works, cookie stays ~32 bytes,
# SecurityMiddleware can fingerprint/expire sessions, and server-side
# revocation is possible. See ADR-0017 addendum for rationale.
SESSION_ENGINE = "django.contrib.sessions.backends.db"

# Portal uses LocMemCache (per-process, in-memory).
# Limitation: rate limit counters are NOT shared across gunicorn workers.
# In multi-worker deployments, effective rate limits are multiplied by worker count.
# This is an accepted tradeoff for the portal's stateless architecture (no database).
# cache.add()/cache.incr() are still atomic within each worker process.
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

# Company bank details for bank transfer payment instructions
COMPANY_BANK_IBAN = os.environ.get("COMPANY_BANK_IBAN", "")
COMPANY_BANK_NAME = os.environ.get("COMPANY_BANK_NAME", "")
COMPANY_BANK_BENEFICIARY = os.environ.get("COMPANY_BANK_BENEFICIARY", "PragmaticHost SRL")


# ===============================================================================
# INTERNATIONALIZATION
# ===============================================================================

LANGUAGE_CODE = "en"
TIME_ZONE = "Europe/Bucharest"  # Romanian timezone
USE_I18N = True
USE_TZ = True

LANGUAGES = [
    ("en", _("English")),
    ("ro", _("Română")),
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
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")

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
# PORTAL SERVICE IDENTIFICATION
# ===============================================================================

# Portal service identification for HMAC authentication
PORTAL_ID = os.environ.get("PORTAL_ID", "portal-001")

# ===============================================================================
# LOGGING CONFIGURATION
# ===============================================================================


class _ServiceNameFilter(logging.Filter):
    """Inject a fixed service tag into every log record."""

    def __init__(self, service_name: str = "PORT") -> None:
        super().__init__()
        self.service_name = service_name

    def filter(self, record: logging.LogRecord) -> bool:
        setattr(record, "service_name", self.service_name)  # noqa: B010
        return True


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "unified": {
            "()": "colorlog.ColoredFormatter",
            "format": "{asctime} {log_color}{levelname:<8}{reset} {service_name} {name:<40} {message} [{request_id}]",
            "datefmt": "%Y-%m-%d %H:%M:%S",
            "style": "{",
            "log_colors": {
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        },
    },
    "filters": {
        "add_request_id": {
            "()": "apps.common.middleware.RequestIDFilter",
        },
        "add_service_name": {
            "()": _ServiceNameFilter,
            "service_name": "PORT",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "unified",
            "filters": ["add_request_id", "add_service_name"],
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
        "django.server": {
            "handlers": ["console"],
            "level": "INFO",
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

# ===============================================================================
# TRUSTED PROXY CONFIGURATION
# ===============================================================================

# Aligned with platform setting name — both services use IPWARE_TRUSTED_PROXY_LIST
# Trusted proxy CIDR list for get_safe_client_ip().
# Set to your load balancer / CDN CIDR(s) in production.
# Leave empty to use REMOTE_ADDR only (safe default for direct connections).
IPWARE_TRUSTED_PROXY_LIST: list[str] = []
