"""
Development settings for PRAHO Portal Service
"""

import os
import sys

from .base import *

# Debug mode
DEBUG = True

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

# Development platform API URL
PLATFORM_API_BASE_URL = "http://localhost:8700/api"
PLATFORM_API_SECRET = "dev-shared-secret-change-in-production"
PLATFORM_API_TIMEOUT = 10  # seconds

# No authentication backends - portal is stateless

# No session configuration - portal is stateless
CSRF_COOKIE_SECURE = False

# Cache (use local memory cache for development)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'portal-cache',
    }
}

# Development logging
LOGGING['root']['level'] = 'DEBUG'
LOGGING['loggers']['apps']['level'] = 'DEBUG'
