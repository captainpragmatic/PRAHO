"""
Test settings for PRAHO Platform
Fast, isolated testing environment.
"""

from .base import *

# ===============================================================================
# TEST FLAGS
# ===============================================================================

DEBUG = False
TEMPLATE_DEBUG = False

# ===============================================================================
# DISABLE DEBUG TOOLBAR IN TESTS
# ===============================================================================

DEBUG_TOOLBAR_CONFIG = {
    'IS_RUNNING_TESTS': False
}

# Remove debug toolbar from installed apps in tests
INSTALLED_APPS = [app for app in INSTALLED_APPS if app != 'debug_toolbar']

# Remove debug toolbar middleware in tests
MIDDLEWARE = [mw for mw in MIDDLEWARE if 'debug_toolbar' not in mw]

# Ensure proper middleware order for tests - messages framework needs sessions and auth
# Remove custom middleware that might interfere in tests
test_middleware = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware', 
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

MIDDLEWARE = test_middleware

# ===============================================================================
# TEST DATABASE (In-memory for speed)
# ===============================================================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
        'OPTIONS': {
            'timeout': 20,
        }
    }
}

# ===============================================================================
# TEST CACHE (Dummy cache)
# ===============================================================================

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'test-cache',
    }
}

# ===============================================================================
# TEST EMAIL BACKEND
# ===============================================================================

EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# ===============================================================================
# DISABLE MIGRATIONS FOR FASTER TESTS
# ===============================================================================

class DisableMigrations:
    def __contains__(self, item: str) -> bool:
        return True

    def __getitem__(self, item: str) -> None:
        return None

# Uncomment to disable migrations in tests (faster but risky)
# MIGRATION_MODULES = DisableMigrations()

# ===============================================================================
# PASSWORD HASHER (Fast for tests)
# ===============================================================================

PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',  # Fast but insecure (test only)
]

# ===============================================================================
# LOGGING (Minimal for tests)
# ===============================================================================

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'null': {
            'class': 'logging.NullHandler',
        },
    },
    'root': {
        'handlers': ['null'],
        'level': 'CRITICAL',
    },
}

# ===============================================================================
# STATIC FILES (No collection needed in tests)
# ===============================================================================

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'

# ===============================================================================
# LOCALIZATION (English for tests)
# ===============================================================================

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Europe/Bucharest'  # Keep same timezone as production for consistency
USE_I18N = True
USE_L10N = True
USE_TZ = True  # Enable timezone support

# ===============================================================================
# SECURITY (Relaxed for tests)
# ===============================================================================

SECRET_KEY = 'django-test-key-not-secure'
ALLOWED_HOSTS = ['testserver', 'localhost', '127.0.0.1']

# Explicit test flag so views can soften behaviors (e.g., rate limits)
TESTING = True

# ===============================================================================
# ENCRYPTION (Test encryption key)
# ===============================================================================

ENCRYPTION_KEY = 'iuTrSBoKchmRt7RiySTHNuANNDmWe_xIqZWtMQaLMXs='

# ===============================================================================
# EXTERNAL SERVICES (Disabled in tests)
# ===============================================================================

# Disable external API calls
STRIPE_PUBLISHABLE_KEY = 'pk_test_fake_key'
STRIPE_SECRET_KEY = 'sk_test_fake_key'
EFACTURA_ENABLED = False

# ===============================================================================
# DJANGO MESSAGES FRAMEWORK (Test Configuration)
# ===============================================================================

MESSAGE_STORAGE = 'django.contrib.messages.storage.fallback.FallbackStorage'

# ===============================================================================
# TASK QUEUE (Synchronous for tests)
# ===============================================================================

RQ_QUEUES = {
    'default': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 15,  # Separate DB for tests
        'ASYNC': False,  # Run jobs synchronously in tests
    },
    'provisioning': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 15,
        'ASYNC': False,
    },
}

# ===============================================================================
# TEST-SPECIFIC FEATURES (Disable audit signals during testing)
# ===============================================================================

DISABLE_AUDIT_SIGNALS = True

# ===============================================================================
# SECURITY TESTING (Enable account lockout for proper testing)
# ===============================================================================

# Enable account lockout in tests to ensure security features work properly
DISABLE_ACCOUNT_LOCKOUT = False
