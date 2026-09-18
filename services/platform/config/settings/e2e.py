"""
End-to-end test settings for PRAHO Platform.

This module intentionally builds on development settings but ensures
pytest E2E runs do not emit default SECRET_KEY warnings.
"""

from __future__ import annotations

import os
import sys

# Must be set before importing dev->base to avoid base.py warning fallback.
os.environ.setdefault("DJANGO_SECRET_KEY", "django-insecure-e2e-key-change-for-production")
os.environ.setdefault("TESTING", "1")
os.environ["PRAHO_SKIP_DOTENV"] = "1"

from .dev import *  # noqa: F403  # Django settings pattern

# Explicit E2E defaults
SECRET_KEY = os.environ.get("E2E_DJANGO_SECRET_KEY", "django-insecure-e2e-key-change-for-production")
TESTING = True  # Required by force_status() in tests/helpers/fsm_helpers.py
E2E_FIXTURES_ENABLED = True
E2E_DATABASE_PATH = BASE_DIR / f"e2e-platform-{sys.platform}.sqlite3"
MEDIA_ROOT = BASE_DIR.parent.parent / "output" / "e2e-media"
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(E2E_DATABASE_PATH),
        "OPTIONS": {"timeout": 30},
        # pytest's ORM tests must never write the running browser server's database.
        "TEST": {"NAME": ":memory:"},
    }
}
PORTAL_HMAC_BYPASS = False
PLATFORM_API_SECRET = "local-e2e-shared-secret-do-not-use-in-production"  # noqa: S105 -- local public test key
PORTAL_HMAC_MODE = "legacy"
PORTAL_HMAC_CREDENTIALS = None
PLATFORM_TO_PORTAL_WEBHOOK_SECRET = "local-e2e-webhook-secret-do-not-use-in-production"  # noqa: S105 -- local public test key
PORTAL_PAYMENT_WEBHOOK_URL = "http://localhost:8701/billing/webhooks/payment-status/"
ENCRYPTION_KEYS = ["MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="]
EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
STRIPE_SECRET_KEY = ""
STRIPE_PUBLISHABLE_KEY = ""
STRIPE_WEBHOOK_SECRET = ""
COMPANY_NAME = "E2E Hosting SRL"
COMPANY_CUI = "RO14399847"
EFACTURA_COMPANY_CUI = "RO14399847"
COMPANY_REGISTRATION_NUMBER = "J40/1234/2020"
COMPANY_STREET = "Str. Victoriei nr. 10"
COMPANY_CITY = "București"
COMPANY_POSTAL_CODE = "010061"
COMPANY_COUNTRY_CODE = "RO"
COMPANY_COUNTRY_NAME = "Romania"
COMPANY_EMAIL = "supplier@e2e.test"
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]
if "django.middleware.csrf.CsrfViewMiddleware" not in MIDDLEWARE:
    MIDDLEWARE.insert(
        MIDDLEWARE.index("django.contrib.auth.middleware.AuthenticationMiddleware"),
        "django.middleware.csrf.CsrfViewMiddleware",
    )
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
configure_rate_limiting(globals(), enabled=False)
REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"] = []
