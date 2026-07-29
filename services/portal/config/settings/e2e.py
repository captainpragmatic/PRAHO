"""End-to-end settings for the separately running portal service."""

from __future__ import annotations

import os

# Set before importing dev -> base so the E2E process is deterministic and
# dev.py disables debug-toolbar and rate-limiting test interference.
os.environ.setdefault(
    "DJANGO_SECRET_KEY",
    "django-insecure-portal-e2e-key-change-for-production",
)
os.environ.setdefault("TESTING", "1")

from .dev import *  # noqa: E402, F403

E2E_TEST_ROUTES_ENABLED = True
ROOT_URLCONF = "config.e2e_urls"

# Let the unauthenticated browser oracle reach the CSP positive-control page
# without a login redirect. Scoped to E2E only — never set in dev/staging/prod.
PORTAL_EXTRA_PUBLIC_URLS = ["/__e2e__/"]
