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
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
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
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
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
# SECURITY (Relaxed for tests)
# ===============================================================================

SECRET_KEY = 'django-test-key-not-secure'

# ===============================================================================
# EXTERNAL SERVICES (Disabled in tests)
# ===============================================================================

# Disable external API calls
STRIPE_PUBLISHABLE_KEY = 'pk_test_fake_key'
STRIPE_SECRET_KEY = 'sk_test_fake_key'
EFACTURA_ENABLED = False

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
