"""
Staging settings for PRAHO Portal Service
"""

import os

from .base import *  # noqa: F403

# Security - similar to production but with debug info
DEBUG = False
SECRET_KEY = os.environ.get("SECRET_KEY", "staging-key-change-before-prod")

# Allowed hosts for staging
ALLOWED_HOSTS = os.environ.get(
    "ALLOWED_HOSTS", "staging-portal.pragmatichost.com,portal-staging.pragmatichost.com"
).split(",")

# Platform API configuration for staging
PLATFORM_API_BASE_URL = os.environ.get("PLATFORM_API_BASE_URL", "http://platform-staging:8700/api")
PLATFORM_API_SECRET = os.environ.get("PLATFORM_API_SECRET", "staging-shared-secret")
PLATFORM_API_TIMEOUT = int(os.environ.get("PLATFORM_API_TIMEOUT", "20"))

# Security settings (less strict than production for testing)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
X_FRAME_OPTIONS = "DENY"

# HSTS settings (shorter duration for staging)
SECURE_HSTS_SECONDS = 3600  # 1 hour for staging
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False

# Static files
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "django.contrib.staticfiles.storage.ManifestStaticFilesStorage"

# Cache configuration for staging
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "portal-staging-cache",
        "OPTIONS": {
            "MAX_ENTRIES": 5000,
        },
    }
}

# Staging logging (more verbose than production)
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": "/var/log/portal/portal-staging.log",
            "maxBytes": 1024 * 1024 * 15,  # 15MB
            "backupCount": 5,
            "formatter": "verbose",
        },
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["file", "console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["file", "console"],
            "level": "INFO",
            "propagate": False,
        },
        "apps": {
            "handlers": ["file", "console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}
