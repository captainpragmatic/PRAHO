"""
Django settings for PRAHO Platform - Base Configuration
Romanian hosting provider with security-first approach.
"""

import os
from pathlib import Path
from typing import List

# ===============================================================================
# CORE DJANGO SETTINGS
# ===============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'django_extensions',
]

LOCAL_APPS = [
    'apps.common',
    'apps.users',
    'apps.customers',
    'apps.billing',
    'apps.tickets',
    'apps.provisioning',
    'apps.products',
    'apps.orders',
    'apps.domains',        # 🌐 Domain management & TLD configuration
    'apps.notifications',
    'apps.integrations',  # 🔌 External service webhooks & deduplication
    'apps.audit',
    'apps.ui',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'apps.common.middleware.RequestIDMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            BASE_DIR / 'templates',
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'apps.common.context_processors.current_customer',
                'apps.common.context_processors.romanian_business_context',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

# ===============================================================================
# DATABASE CONFIGURATION
# ===============================================================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'pragmatichost'),
        'USER': os.environ.get('DB_USER', 'pragmatichost'),
        'PASSWORD': os.environ.get('DB_PASSWORD', 'development_password'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
        'OPTIONS': {
            'application_name': 'pragmatichost_crm',
        },
    }
}

# Database connection pooling
DATABASES['default']['CONN_MAX_AGE'] = 60

# ===============================================================================
# AUTHENTICATION & AUTHORIZATION
# ===============================================================================

AUTH_USER_MODEL = 'users.User'

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,  # Strong passwords for hosting provider
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Use Argon2 for password hashing (security best practice)
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

# Authentication URLs
LOGIN_URL = '/auth/login/'
LOGIN_REDIRECT_URL = '/app/'
LOGOUT_REDIRECT_URL = '/'

# ===============================================================================
# INTERNATIONALIZATION & LOCALIZATION
# ===============================================================================

LANGUAGE_CODE = 'ro'  # Romanian primary for hosting provider
TIME_ZONE = 'Europe/Bucharest'
USE_I18N = True
USE_TZ = True

LANGUAGES = [
    ('ro', 'Română'),
    ('en', 'English'),
]

# Romanian locale formatting
LOCALE_PATHS = [
    BASE_DIR / 'locale',
]

# ===============================================================================
# STATIC FILES & MEDIA
# ===============================================================================

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.ManifestStaticFilesStorage'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ===============================================================================
# CACHE CONFIGURATION (Redis)
# ===============================================================================

REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': REDIS_URL,
        'KEY_PREFIX': 'pragmatichost',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# ===============================================================================
# SESSION & COOKIE SETTINGS
# ===============================================================================

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_SAVE_EVERY_REQUEST = True

# CSRF settings
CSRF_COOKIE_HTTPONLY = True
CSRF_TRUSTED_ORIGINS = []

# ===============================================================================
# DJANGO REST FRAMEWORK
# ===============================================================================

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 25,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
    ],
}

# ===============================================================================
# ROMANIAN BUSINESS CONFIGURATION
# ===============================================================================

# Romanian VAT rate (19% standard)
ROMANIA_VAT_RATE = '0.19'

# Romanian company information
ROMANIAN_BUSINESS_CONTEXT = {
    'company_name': os.environ.get('COMPANY_NAME', 'PragmaticHost SRL'),
    'company_cui': os.environ.get('COMPANY_CUI', 'RO12345678'),
    'email': os.environ.get('COMPANY_EMAIL', 'contact@pragmatichost.com'),
    'phone': os.environ.get('COMPANY_PHONE', '+40.21.123.4567'),
    'address': os.environ.get('COMPANY_ADDRESS', 'Str. Exemplu Nr. 1, Bucuresti, Romania'),
    'vat_rate': 0.19,
    'currency': 'RON'
}

# Currency settings
DEFAULT_CURRENCY = 'RON'
SUPPORTED_CURRENCIES = ['RON', 'EUR', 'USD']

# ===============================================================================
# EXTERNAL INTEGRATIONS
# ===============================================================================

# Stripe settings
STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')

# Virtualmin settings
VIRTUALMIN_URL = os.environ.get('VIRTUALMIN_URL')
VIRTUALMIN_USERNAME = os.environ.get('VIRTUALMIN_USERNAME')
VIRTUALMIN_PASSWORD = os.environ.get('VIRTUALMIN_PASSWORD')

# e-Factura API settings
EFACTURA_API_URL = os.environ.get('EFACTURA_API_URL')
EFACTURA_API_KEY = os.environ.get('EFACTURA_API_KEY')

# ===============================================================================
# DEFAULT AUTO FIELD
# ===============================================================================

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ===============================================================================
# SECURITY SETTINGS (Base - override in prod.py)
# ===============================================================================

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-change-in-production')
