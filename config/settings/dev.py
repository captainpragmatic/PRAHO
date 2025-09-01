"""
Development settings for PRAHO Platform
Fast iteration with debugging tools enabled.
"""

import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from .base import *  # noqa: F403

# ===============================================================================
# DEVELOPMENT FLAGS
# ===============================================================================

DEBUG = True
TEMPLATE_DEBUG = True

# Disable account lockout for development and E2E testing
DISABLE_ACCOUNT_LOCKOUT = True

# Note: ALLOWED_HOSTS configured in HTTPS security section below

# ===============================================================================
# DEVELOPMENT MIDDLEWARE
# ===============================================================================

# Insert debug toolbar middleware into existing MIDDLEWARE list
MIDDLEWARE.insert(1, "debug_toolbar.middleware.DebugToolbarMiddleware")

# ===============================================================================
# DEVELOPMENT APPS
# ===============================================================================

# Add debug toolbar to existing INSTALLED_APPS list
INSTALLED_APPS += [
    "debug_toolbar",
]

# ===============================================================================
# DATABASE FOR DEVELOPMENT (SQLite for speed)
# ===============================================================================

if os.environ.get("USE_POSTGRES") != "true":
    # Override DATABASES for development with SQLite
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": str(BASE_DIR / "db.sqlite3"),
        }
    }

# ===============================================================================
# DEBUG TOOLBAR CONFIGURATION
# ===============================================================================

INTERNAL_IPS = [
    "127.0.0.1",
    "localhost",
]

DEBUG_TOOLBAR_CONFIG = {
    "SHOW_TOOLBAR_CALLBACK": lambda request: DEBUG,
    "SHOW_COLLAPSED": True,
    "IS_RUNNING_TESTS": False,  # Fix for debug toolbar test issue
}

# Disable debug toolbar during tests
if "test" in sys.argv:
    INSTALLED_APPS = [app for app in INSTALLED_APPS if app != "debug_toolbar"]
    MIDDLEWARE = [mw for mw in MIDDLEWARE if "debug_toolbar" not in mw]

# ===============================================================================
# EMAIL BACKEND (Console for development)
# ===============================================================================

EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
# Email configuration for development
DEFAULT_FROM_EMAIL = "dev@pragmatichost.com"

# ===============================================================================
# CACHE (Dummy cache for development)
# ===============================================================================

if os.environ.get("USE_REDIS") != "true":
    # Override CACHES for development with in-memory cache
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "praho-cache",
        }
    }
    # Use database sessions when Redis is disabled
    SESSION_ENGINE = "django.contrib.sessions.backends.db"

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
            "level": "INFO",
            "propagate": False,
        },
        "apps": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}

# ===============================================================================
# HTTPS SECURITY SETTINGS - DEVELOPMENT/LOCAL 🔒
# ===============================================================================

# Development security - HTTP only (localhost + Tailscale)
ALLOWED_HOSTS = ["*"]  # Allow all hosts in development for Tailscale compatibility
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8001",
    "http://127.0.0.1:8001",
    "http://100.73.13.8:8001",  # Tailscale IP
]

# ===============================================================================
# SSL/HTTPS SETTINGS - Disabled for local development
# ===============================================================================

# HTTPS enforcement - DISABLED for local development
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0

# Cookie security - DISABLED for HTTP development
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SAMESITE = "Lax"

# ===============================================================================
# SESSION SECURITY CONFIGURATION - Development
# ===============================================================================

# Relaxed session settings for development
SESSION_COOKIE_AGE = 86400  # 24 hours for development convenience
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Allow persistent sessions
SESSION_COOKIE_NAME = "pragmatichost_dev_sessionid"
SESSION_COOKIE_HTTPONLY = True  # Still prevent XSS in development
SESSION_COOKIE_PATH = "/"
SESSION_SAVE_EVERY_REQUEST = False  # Less overhead in development

# ===============================================================================
# ADDITIONAL SECURITY HEADERS - Development
# ===============================================================================

# Content security - Still useful in development
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "SAMEORIGIN"  # Relaxed for development tools
SECURE_BROWSER_XSS_FILTER = True

# ===============================================================================
# DEVELOPMENT SECURITY (Relaxed for local development)
# ===============================================================================

SECRET_KEY = "django-insecure-dev-key-change-for-production"

# Relaxed CORS for development
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# ===============================================================================
# STATICFILES FOR DEVELOPMENT
# ===============================================================================

# Disable manifest storage for dev (faster)
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"

# ===============================================================================
# ROMANIAN DEVELOPMENT DEFAULTS
# ===============================================================================

# Test company info for development
# Update Romanian business context for development
ROMANIAN_BUSINESS_CONTEXT.update(
    {
        "company_name": "PragmaticHost Dev SRL",
        "company_cui": "RO99999999",
        "email": "dev@pragmatichost.com",
    }
)

# ===============================================================================
# SECURE IP DETECTION - DEVELOPMENT CONFIGURATION 🔒
# ===============================================================================

# Development: Don't trust any proxy headers - use REMOTE_ADDR only
# This prevents IP spoofing during local development
IPWARE_TRUSTED_PROXY_LIST = []

# Note: CSRF_TRUSTED_ORIGINS configured in HTTPS security section above
