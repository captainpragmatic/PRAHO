"""
Development settings for PRAHO Platform
Fast iteration with debugging tools enabled.
"""

import os
import sys

from .base import *  # noqa: F403

# ===============================================================================
# DEVELOPMENT FLAGS
# ===============================================================================

DEBUG = True
TEMPLATE_DEBUG = True

# Get ALLOWED_HOSTS from environment variable, with sensible development defaults
allowed_hosts_env = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1,0.0.0.0')
ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_env.split(',') if host.strip()]

# ===============================================================================
# DEVELOPMENT MIDDLEWARE
# ===============================================================================

MIDDLEWARE.insert(1, 'debug_toolbar.middleware.DebugToolbarMiddleware')  # noqa: F405

# ===============================================================================
# DEVELOPMENT APPS
# ===============================================================================

INSTALLED_APPS += [  # noqa: F405
    'debug_toolbar',
]

# ===============================================================================
# DATABASE FOR DEVELOPMENT (SQLite for speed)
# ===============================================================================

if os.environ.get('USE_POSTGRES') != 'true':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': str(BASE_DIR / 'db.sqlite3'),  # noqa: F405
        }
    }

# ===============================================================================
# DEBUG TOOLBAR CONFIGURATION
# ===============================================================================

INTERNAL_IPS = [
    '127.0.0.1',
    'localhost',
]

DEBUG_TOOLBAR_CONFIG = {
    'SHOW_TOOLBAR_CALLBACK': lambda request: DEBUG,
    'SHOW_COLLAPSED': True,
    'IS_RUNNING_TESTS': False,  # Fix for debug toolbar test issue
}

# Disable debug toolbar during tests
if 'test' in sys.argv:
    INSTALLED_APPS = [app for app in INSTALLED_APPS if app != 'debug_toolbar']
    MIDDLEWARE = [mw for mw in MIDDLEWARE if 'debug_toolbar' not in mw]  # noqa: F405

# ===============================================================================
# EMAIL BACKEND (Console for development)
# ===============================================================================

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
# Email configuration for development
DEFAULT_FROM_EMAIL = 'dev@pragmatichost.com'

# ===============================================================================
# CACHE (Dummy cache for development)
# ===============================================================================

if os.environ.get('USE_REDIS') != 'true':
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'praho-cache',
        }
    }
    # Use database sessions when Redis is disabled
    SESSION_ENGINE = 'django.contrib.sessions.backends.db'

# ===============================================================================
# LOGGING CONFIGURATION
# ===============================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}

# ===============================================================================
# DEVELOPMENT SECURITY (Relaxed for local development)
# ===============================================================================

SECRET_KEY = 'django-insecure-dev-key-change-for-production'

# Relaxed CORS for development
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# ===============================================================================
# STATICFILES FOR DEVELOPMENT
# ===============================================================================

# Disable manifest storage for dev (faster)
STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# ===============================================================================
# ROMANIAN DEVELOPMENT DEFAULTS
# ===============================================================================

# Test company info for development
ROMANIAN_BUSINESS_CONTEXT.update({  # noqa: F405
    'company_name': 'PragmaticHost Dev SRL',
    'company_cui': 'RO99999999',
    'email': 'dev@pragmatichost.com',
})
