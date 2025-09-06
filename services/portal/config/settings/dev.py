"""
Development settings for PRAHO Portal Service
"""

from .base import *

# Debug mode
DEBUG = True

# Allow all hosts in development
ALLOWED_HOSTS = ["*"]

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