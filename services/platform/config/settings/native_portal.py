"""Real native UI authentication on the existing manifest-bound native database."""

import json
import os
from copy import deepcopy
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from apps.infrastructure.native_portal import validate_ui

from .native import *  # noqa: F403 -- Preserve the native database and original vault/session identity.
from .native import _native

# isort: split
from . import base as _base

try:
    _ui = validate_ui(_native, Path(os.environ["PRAHO_NATIVE_UI_AUTHORITY"]))
except (KeyError, OSError, ValueError, TypeError) as error:
    raise ImproperlyConfigured("A current private VM-bound native UI authority is required") from error

NATIVE_UI_PORTAL_ID = "native-" + _ui["instance"]
MIDDLEWARE = list(_base.MIDDLEWARE)
PASSWORD_HASHERS = list(_base.PASSWORD_HASHERS)
CACHES = deepcopy(_base.CACHES)
REST_FRAMEWORK = deepcopy(_base.REST_FRAMEWORK)
SESSION_ENGINE = _base.SESSION_ENGINE
AUTHENTICATION_BACKENDS = list(_base.AUTHENTICATION_BACKENDS)
RATE_LIMITING_ENABLED = True
TESTING = False
PLATFORM_API_SECRET = None  # Enforced registry only; do not reuse its key as a legacy shared credential.
PORTAL_HMAC_MODE = "enforce"
PORTAL_HMAC_CREDENTIALS = json.dumps({NATIVE_UI_PORTAL_ID: _ui["secret"]})
PORTAL_HMAC_REQUIRE_ISOLATION = True
PORTAL_SESSION_REQUIRED = True
STRIPE_SECRET_KEY = None  # Configure actual Stripe TEST credentials in the isolated database, never CI's fake keys.
STRIPE_PUBLISHABLE_KEY = None
STRIPE_WEBHOOK_SECRET = None
ALLOWED_HOSTS = ["127.0.0.1"]
PORTAL_PUBLIC_ORIGIN = f"http://127.0.0.1:{_ui['portal_port']}"
CSRF_TRUSTED_ORIGINS = [f"http://127.0.0.1:{_ui['platform_port']}"]
SESSION_COOKIE_NAME = "native_platform_" + _ui["instance"].replace("-", "")
CSRF_COOKIE_NAME = SESSION_COOKIE_NAME + "_csrf"
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False
