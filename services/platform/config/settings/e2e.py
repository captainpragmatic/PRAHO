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
TESTING = True  # Required by force_status() in tests/helpers/fsm_helpers.py
PORTAL_HMAC_BYPASS: bool = True  # Allows billing HMAC bypass in E2E (safe: TESTING=True above)
configure_rate_limiting(globals(), enabled=False)
REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"] = []
