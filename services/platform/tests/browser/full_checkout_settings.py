"""Loopback-only server settings for the explicit full checkout acceptance gate."""

import os
from copy import deepcopy
from pathlib import Path
from tempfile import gettempdir

from config.settings.ci import *  # noqa: F403 -- Test-only settings extension.
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET

DATABASES = deepcopy(DATABASES)
DATABASES["default"].update(
    NAME="test_hosting_browser",
    HOST="127.0.0.1",
    USER="praho_hosting_test",
    PASSWORD="praho_hosting_local_fixture",  # noqa: S106 -- Public owned-fixture credentials only.
)
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
MIDDLEWARE = HMAC_TEST_MIDDLEWARE
PLATFORM_API_SECRET = HMAC_TEST_SECRET
PORTAL_HMAC_MODE = "legacy"
PORTAL_HMAC_CREDENTIALS = None
PORTAL_SESSION_REQUIRED = True
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
Q_CLUSTER = {**Q_CLUSTER, "sync": False, "orm": "default"}
MEDIA_ROOT = Path(os.environ.get("HOSTING_CHECKOUT_DIRECTORY", gettempdir())) / "hosting-checkout-media"
