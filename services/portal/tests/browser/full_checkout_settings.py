"""Real Portal authentication and signing against the isolated checkout server."""

import os
from urllib.parse import urlsplit

from config.settings.dev import *  # noqa: F403 -- Test-only settings extension.

PLATFORM_API_BASE_URL = os.environ.get("HOSTING_CHECKOUT_PLATFORM_URL", "http://127.0.0.1:1") + "/api"
if urlsplit(PLATFORM_API_BASE_URL).hostname != "127.0.0.1":
    raise RuntimeError("Full checkout Portal may call only its local Platform")
PORTAL_SESSION_ID_REQUIRED = True
PORTAL_BROWSER_FINGERPRINT_REQUIRED = True
PORTAL_SESSION_DEADLINES_REQUIRED = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
MIDDLEWARE = ["tests.browser.full_checkout_static.BrowserStaticFilesMiddleware", *MIDDLEWARE]
