"""
Development settings for PRAHO Platform
Fast iteration with debugging tools enabled.
"""

import logging
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

# Disable CSRF middleware for API development (allows Portal login)
MIDDLEWARE = [mw for mw in MIDDLEWARE if "CsrfViewMiddleware" not in mw]

# ===============================================================================
# DEVELOPMENT APPS
# ===============================================================================

# Add debug toolbar to existing INSTALLED_APPS list
INSTALLED_APPS += [
    "debug_toolbar",
]

# Django Silk configuration is below after is_testing is defined

# ===============================================================================
# DATABASE FOR DEVELOPMENT (SQLite for speed)
# ===============================================================================

if os.environ.get("USE_POSTGRES") != "true":
    # Override DATABASES for development with SQLite.
    # OS-scoped DB name prevents corruption when macOS host and Docker container
    # both access the same bind-mounted directory — VirtioFS cannot reliably
    # coordinate SQLite file locks across the macOS/Linux boundary.
    import sys as _sys

    _db_suffix = "darwin" if _sys.platform == "darwin" else "linux"
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": str(BASE_DIR / f"db-{_db_suffix}.sqlite3"),
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
# Check for both Django's test runner and pytest - comprehensive detection to avoid race conditions
is_testing = (
    "test" in sys.argv
    or "pytest" in sys.modules
    or os.environ.get("PYTEST_CURRENT_TEST")
    or os.environ.get("DJANGO_SETTINGS_MODULE", "").endswith(".test")
    or "unittest" in sys.modules
    or hasattr(sys, "_called_from_test")  # Django sets this during test runs
    or "TESTING" in os.environ  # Explicit override
)

if is_testing:
    # Remove debug toolbar from apps and middleware during testing
    INSTALLED_APPS = [app for app in INSTALLED_APPS if app != "debug_toolbar"]
    MIDDLEWARE = [mw for mw in MIDDLEWARE if "debug_toolbar" not in mw]

    # Also update debug toolbar config to prevent any rendering attempts
    DEBUG_TOOLBAR_CONFIG = {
        "SHOW_TOOLBAR_CALLBACK": lambda request: False,  # Never show during tests
        "IS_RUNNING_TESTS": True,  # Explicit test flag
    }

    # Disable rate limiting during tests to prevent 403 errors from race conditions
    RATELIMIT_ENABLE = False
    # Disable DRF throttling in tests to prevent 429s from rapid API calls
    REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"] = []
else:
    # Ensure rate limiting is enabled in development (but allow override)
    RATELIMIT_ENABLE = os.environ.get("RATELIMIT_ENABLE", "true").lower() == "true"

# When rate limiting is explicitly disabled (e.g. RATELIMIT_ENABLE=false make dev),
# also disable DRF throttling so E2E tests don't hit 429s.
if not RATELIMIT_ENABLE:
    REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"] = []

# ===============================================================================
# DJANGO SILK PROFILER CONFIGURATION 📊
# ===============================================================================

# Enable Silk profiler for SQL and request profiling in development
ENABLE_SILK_PROFILER = os.environ.get("ENABLE_SILK_PROFILER", "false").lower() == "true"

if ENABLE_SILK_PROFILER and not is_testing:
    INSTALLED_APPS += ["silk"]
    # Insert Silk middleware after RequestIDMiddleware for proper correlation
    MIDDLEWARE.insert(2, "silk.middleware.SilkyMiddleware")

    # Silk configuration for performance profiling
    SILKY_PYTHON_PROFILER = True  # Enable Python profiler
    SILKY_PYTHON_PROFILER_BINARY = True  # Use binary profiler (faster)
    SILKY_PYTHON_PROFILER_RESULT_PATH = str(BASE_DIR / "silk_profiles")
    SILKY_MAX_REQUEST_BODY_SIZE = 1024  # Limit request body logging (1KB)
    SILKY_MAX_RESPONSE_BODY_SIZE = 1024  # Limit response body logging (1KB)
    SILKY_INTERCEPT_PERCENT = 100  # Profile all requests
    SILKY_MAX_RECORDED_REQUESTS = 10000  # Keep last 10K requests
    SILKY_META = True  # Enable meta profiling (profile the profiler)
    SILKY_AUTHENTICATION = True  # Require authentication to view Silk
    SILKY_AUTHORISATION = True  # Require staff status to view Silk
    SILKY_ANALYZE_QUERIES = True  # Analyze SQL queries for optimization hints
    SILKY_EXPLAIN_FLAGS = {  # PostgreSQL EXPLAIN flags
        "format": "JSON",
        "costs": True,
        "verbose": True,
        "buffers": True,
    }

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
# LOGGING CONFIGURATION - Enhanced with Request ID Tracing
# ===============================================================================


class _ServiceNameFilter(logging.Filter):
    """Inject a fixed service tag into every log record (dev-only)."""

    def __init__(self, service_name: str = "PLAT") -> None:
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
            "()": "apps.common.logging.RequestIDFilter",
        },
        "add_service_name": {
            "()": _ServiceNameFilter,
            "service_name": "PLAT",
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
            "level": "INFO",
            "propagate": False,
        },
        "django.server": {
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
    "http://localhost:8700",
    "http://127.0.0.1:8700",
    "http://localhost:8701",
    "http://127.0.0.1:8701",
    "http://100.73.13.8:8700",  # Tailscale IP - Platform
    "http://100.73.13.8:8701",  # Tailscale IP - Portal
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
# INTER-SERVICE COMMUNICATION
# ===============================================================================

# Shared secret for portal service authentication
PLATFORM_API_SECRET = "dev-shared-secret-change-in-production"

# ===============================================================================
# SECURE IP DETECTION - DEVELOPMENT CONFIGURATION 🔒
# ===============================================================================

# Development: Don't trust any proxy headers - use REMOTE_ADDR only
# This prevents IP spoofing during local development
IPWARE_TRUSTED_PROXY_LIST = []

# Note: CSRF_TRUSTED_ORIGINS configured in HTTPS security section above
