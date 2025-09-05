"""
PRAHO Portal - Customer-Facing Service Settings
🚨 SECURITY: NO DATABASE ACCESS - API-only communication with platform
"""
import os
from pathlib import Path

# ===============================================================================
# PORTAL SECURITY CONFIGURATION 🔒
# ===============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent

# 🚨 CRITICAL: No database configuration - prevents direct DB access
# Portal communicates with platform service via API only
DATABASES = {}

# Use signed cookies for session management (no DB required)
SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
SESSION_COOKIE_SECURE = False  # Set to True in production
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 86400  # 24 hours

# ===============================================================================
# BASIC DJANGO CONFIGURATION
# ===============================================================================

SECRET_KEY = os.environ.get(
    'DJANGO_SECRET_KEY', 
    'django-insecure-%x&z&%0*hbpmsngz&y_avfpp0-h+z&+9toxb%i7+(ivw#-y7l4'
)

DEBUG = os.environ.get('DJANGO_DEBUG', 'True').lower() == 'true'
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']

# ===============================================================================
# MINIMAL APPLICATIONS - NO ADMIN, NO AUTH MODELS
# ===============================================================================

INSTALLED_APPS = [
    # Core Django (minimal)
    'django.contrib.contenttypes',
    'django.contrib.sessions', 
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party
    'rest_framework',
    
    # Portal app
    'portal',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
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
    'http://127.0.0.1:8700/api/'
)

# API authentication token (shared secret)
PLATFORM_API_TOKEN = os.environ.get('PLATFORM_API_TOKEN', 'dev-token-123')

# ===============================================================================
# LOCALIZATION
# ===============================================================================

LANGUAGE_CODE = 'ro'  # Romanian default
TIME_ZONE = 'Europe/Bucharest'
USE_I18N = True
USE_TZ = True

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
