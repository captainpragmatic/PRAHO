"""
PRAHO Portal - Customer-Facing Service Settings
🚨 ARCHITECTURE: In-memory DB for Django internals only. NO business data stored.
Portal apps use NO models or ORM - pure API-only communication with platform.
"""
import os
from pathlib import Path

# ===============================================================================
# PORTAL SECURITY CONFIGURATION 🔒
# ===============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent

# 🚨 CRITICAL: In-memory DATABASES - Django internals only, NO business models
# Portal apps must NOT define models or use ORM - API-only communication with platform  
# In-memory DB used for: sessions cache, Django internals, migration tracking
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',  # In-memory database
        'OPTIONS': {
            'timeout': 20,
        },
    }
}

# Use cache-based sessions (in-memory, auto-cleanup, no files)
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_SECURE = False  # Set to True in production
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 86400  # 24 hours (default)
SESSION_COOKIE_SAMESITE = 'Lax'  # Prevent CSRF while allowing normal navigation
SESSION_SAVE_EVERY_REQUEST = False  # Only save when modified

# Custom session age settings for middleware
SESSION_COOKIE_AGE_DEFAULT = 24 * 60 * 60  # 24 hours 
SESSION_COOKIE_AGE_REMEMBER_ME = 30 * 24 * 60 * 60  # 30 days

# Cache configuration for sessions (in-memory)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'portal-sessions',
        'OPTIONS': {
            'MAX_ENTRIES': 10000,  # Max number of sessions
        }
    }
}

# ===============================================================================
# BASIC DJANGO CONFIGURATION
# ===============================================================================

# 🔒 SECURITY: No fallback secrets - must be set in environment
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')

DEBUG = os.environ.get('DJANGO_DEBUG', 'True').lower() == 'true'
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']

# ===============================================================================
# MINIMAL APPLICATIONS - NO ADMIN, NO BUSINESS MODELS
# ===============================================================================

INSTALLED_APPS = [
    # Core Django (minimal) - uses in-memory DB for internals only
    'django.contrib.contenttypes',
    'django.contrib.sessions', 
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party
    'rest_framework',
    
    # Portal apps - NO models.py files, NO ORM usage, API-only
    'apps.users',        # Session auth middleware only
    'apps.dashboard',    # View logic only  
    'apps.api_client',   # HMAC API client only
    'apps.billing',      # Dataclasses + serializers only (NO models)
    'apps.tickets',      # Customer tickets (API-only)
    'apps.services',     # Customer services (API-only)
    'apps.orders',       # Order flow and cart (session-based, NO models)
    'apps.common',       # Shared utilities only
    'apps.ui',          # Template tags only
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.template.context_processors.i18n',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# ===============================================================================
# PLATFORM API CONFIGURATION 🌐
# ===============================================================================

# Platform service API endpoint
PLATFORM_API_BASE_URL = os.environ.get(
    'PLATFORM_API_BASE_URL', 
    'http://127.0.0.1:8700'
)

# 🔒 SECURITY: API authentication - no fallback secrets
PLATFORM_API_TOKEN = os.environ.get('PLATFORM_API_TOKEN')  # Legacy token
PLATFORM_API_SECRET = os.environ.get('PLATFORM_API_SECRET')  # HMAC secret - REQUIRED
PLATFORM_API_TIMEOUT = int(os.environ.get('PLATFORM_API_TIMEOUT', '30'))  # 30 seconds

# ===============================================================================
# LOCALIZATION
# ===============================================================================

LANGUAGE_CODE = 'en'  # English default
TIME_ZONE = 'Europe/Bucharest'
USE_I18N = True
USE_TZ = True

# Where project-level translations live (services/portal/locale)
LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

# ===============================================================================
# STATIC FILES (NO MEDIA - API ONLY)
# ===============================================================================

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# ===============================================================================
# REST FRAMEWORK CONFIGURATION
# ===============================================================================

REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
}

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ===============================================================================
# LOGGING CONFIGURATION 📝
# ===============================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process} {thread} {message}',
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
        'portal': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
