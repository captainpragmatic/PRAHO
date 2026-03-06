"""
End-to-end test settings for PRAHO Platform.

This module intentionally builds on development settings but ensures
pytest E2E runs do not emit default SECRET_KEY warnings.
"""

from __future__ import annotations

import os

# Must be set before importing dev->base to avoid base.py warning fallback.
os.environ.setdefault("DJANGO_SECRET_KEY", "django-insecure-e2e-key-change-for-production")
os.environ.setdefault("TESTING", "1")

from .dev import *  # noqa: F403  # Django settings pattern

# Explicit E2E defaults
SECRET_KEY = os.environ.get("E2E_DJANGO_SECRET_KEY", "django-insecure-e2e-key-change-for-production")
# Both needed: RATELIMIT_ENABLE (django-ratelimit library), RATELIMIT_ENABLED (custom middleware)
RATELIMIT_ENABLE = False  # django-ratelimit library decorators (@ratelimit)
RATELIMIT_ENABLED = False
REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"] = []
