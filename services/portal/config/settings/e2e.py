"""End-to-end settings for the separately running portal service."""

from __future__ import annotations

import os
import sys

# Set before importing dev -> base so the E2E process is deterministic and
# dev.py disables debug-toolbar and rate-limiting test interference.
os.environ.setdefault(
    "DJANGO_SECRET_KEY",
    "django-insecure-portal-e2e-key-change-for-production",
)
os.environ.setdefault("TESTING", "1")
os.environ["PRAHO_SKIP_DOTENV"] = "1"

from .dev import *  # noqa: F403

DATABASES["default"]["NAME"] = str(BASE_DIR / f"e2e-portal-{sys.platform}.sqlite3")
PLATFORM_API_BASE_URL = "http://localhost:8700/api"
PLATFORM_API_SECRET = "local-e2e-shared-secret-do-not-use-in-production"  # noqa: S105 -- local public test key
PORTAL_HMAC_SECRET = None
PORTAL_ID = "portal-001"
PLATFORM_TO_PORTAL_WEBHOOK_SECRET = "local-e2e-webhook-secret-do-not-use-in-production"  # noqa: S105 -- local public test key
ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver"]

E2E_TEST_ROUTES_ENABLED = True
ROOT_URLCONF = "config.e2e_urls"

# Let the unauthenticated browser reach the CSP positive-control page without a
# login redirect. Scoped to E2E only — never set in dev/staging/prod.
# NOTE: keep external DB-driver names out of prose in config/settings* — the
# portal DB-isolation CI guard greps these files for them by substring.
PORTAL_EXTRA_PUBLIC_URLS = ["/__e2e__/"]

# Public test-only banking details; no real payment is initiated by the suite.
COMPANY_BANK_IBAN = "RO49AAAA1B31007593840000"
COMPANY_BANK_NAME = "E2E Test Bank"
COMPANY_BANK_BENEFICIARY = "E2E Hosting SRL"
