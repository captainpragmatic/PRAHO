"""
Development settings for PRAHO Portal Service
"""

import os
import sys

from .base import *  # noqa: F403

# Debug mode
DEBUG = True

# 🔒 SECURITY: Development-safe secret fallback
if not SECRET_KEY:
    # Only in development - provide a working default
    SECRET_KEY = "dev-portal-key-for-local-development-only-not-for-production"
    import logging
    logging.getLogger(__name__).info("🔍 [Dev] Using development SECRET_KEY fallback")

# Allow all hosts in development
ALLOWED_HOSTS = ["*"]

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
# DEBUG TOOLBAR CONFIGURATION
# ===============================================================================

INTERNAL_IPS = [
    "127.0.0.1",
    "localhost",
]

DEBUG_TOOLBAR_CONFIG = {
    "SHOW_TOOLBAR_CALLBACK": lambda request: DEBUG,
    "SHOW_COLLAPSED": True,
    "IS_RUNNING_TESTS": False,
}

# Disable debug toolbar during tests
is_testing = (
    "test" in sys.argv
    or "pytest" in sys.modules
    or os.environ.get("PYTEST_CURRENT_TEST")
    or os.environ.get("DJANGO_SETTINGS_MODULE", "").endswith(".test")
    or "unittest" in sys.modules
    or hasattr(sys, "_called_from_test")
    or "TESTING" in os.environ
)

if is_testing:
    # Remove debug toolbar from apps and middleware during testing
    INSTALLED_APPS = [app for app in INSTALLED_APPS if app != "debug_toolbar"]
    MIDDLEWARE = [mw for mw in MIDDLEWARE if "debug_toolbar" not in mw]

    DEBUG_TOOLBAR_CONFIG = {
        "SHOW_TOOLBAR_CALLBACK": lambda request: False,
        "IS_RUNNING_TESTS": True,
    }

    # Keep DB-backed sessions in tests so cache.clear() in security tests
    # does not wipe authentication session state.
    SESSION_ENGINE = "django.contrib.sessions.backends.db"

    # Disable rate limiting during tests
    RATELIMIT_ENABLE = False

    # Reduce log noise and timing jitter in security/performance tests.
    LOGGING['root']['level'] = 'ERROR'
    LOGGING['loggers']['apps']['level'] = 'ERROR'
    if 'django' in LOGGING.get('loggers', {}):
        LOGGING['loggers']['django']['level'] = 'ERROR'
    if 'urllib3' in LOGGING.get('loggers', {}):
        LOGGING['loggers']['urllib3']['level'] = 'WARNING'
else:
    # Allow E2E tests to disable rate limiting via environment variable
    RATELIMIT_ENABLE = os.environ.get("RATELIMIT_ENABLE", "true").lower() == "true"

# Development platform API URL
PLATFORM_API_BASE_URL = "http://localhost:8700/api"
PLATFORM_API_SECRET = "dev-shared-secret-change-in-production"
PLATFORM_API_TIMEOUT = 10  # seconds

# 🔒 SECURITY: Development warnings for weak secrets (non-blocking)
try:
    from apps.common.security_validation import validate_all_secrets
    # Run validation but don't fail in development - just warn
    validate_all_secrets()
except ImportError:
    # Security validation module not available yet - skip silently
    pass
except ValueError as e:
    # In development, security validation errors become warnings
    import logging
    logging.getLogger(__name__).warning(f"⚠️ [Dev Security] {e}")
except Exception as e:
    import logging
    logging.getLogger(__name__).debug(f"🔍 [Dev Security] Validation check: {e}")

# No authentication backends - portal is stateless

# No session configuration - portal is stateless
CSRF_COOKIE_SECURE = False

# CSRF trusted origins for development
CSRF_TRUSTED_ORIGINS += [
    "http://localhost:8701",
    "http://127.0.0.1:8701", 
    "http://claudius-imac:8701",
    "http://100.73.13.8:8700",  # Tailscale IP - Platform
    "http://100.73.13.8:8701",  # Tailscale IP - Portal
]

# Cache (use local memory cache for development)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'portal-cache',
    }
}

# Development logging
if not is_testing:
    LOGGING['root']['level'] = 'DEBUG'
    LOGGING['loggers']['apps']['level'] = 'DEBUG'
