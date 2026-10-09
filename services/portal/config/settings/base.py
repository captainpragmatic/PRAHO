"""
Django settings for PRAHO Portal Service - Customer-facing app configuration.
"""

import logging
import math
import os
from pathlib import Path
from typing import Any

from django.utils.translation import gettext_lazy as _

# ===============================================================================
# CORE DJANGO SETTINGS
# ===============================================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = BASE_DIR.parent.parent  # Up to project root (PRAHO/)

# Application definition - Portal service apps only
DJANGO_APPS: list[str] = [
    "django.contrib.sessions",  # Session framework (DB-backed, see ADR-0017)
    "django.contrib.messages",  # Message framework for user feedback
    "django.contrib.staticfiles",  # Static file serving
    "django.contrib.humanize",  # Template humanization
]

THIRD_PARTY_APPS: list[str] = [
    "ipware",
]

LOCAL_APPS: list[str] = [
    "apps.common",  # Shared utilities, validators (duplicated from platform)
    "apps.users",  # Portal user authentication (validates via Platform API)
    "apps.dashboard",  # Customer dashboard (API-only)
    "apps.billing",  # Customer billing views (API client)
    "apps.tickets",  # Customer support tickets (API client)
    "apps.services",  # Customer service management (API client)
    "apps.customers",  # Customer team, tax profile, and address management
    "apps.ui",  # Template tags and components
    "apps.api_client",  # Platform API integration service
]

INSTALLED_APPS: list[str] = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE: list[str] = [
    "django.middleware.security.SecurityMiddleware",
    "apps.common.session_store.SessionMiddleware",  # DB-backed sessions; contended saves answer 503
    # 🔒 SECURITY: API rate limiting after sessions (cart limits need session key)
    "apps.common.rate_limiting.APIRateLimitMiddleware",  # API + cart session rate limiting
    "django.middleware.locale.LocaleMiddleware",  # After sessions
    "django.middleware.common.CommonMiddleware",  # After locale
    "django.middleware.csrf.CsrfViewMiddleware",  # CSRF protection
    "django.contrib.messages.middleware.MessageMiddleware",  # Messages support
    # 🔒 SECURITY: Run after messages so throttled browser POSTs can carry an error message.
    "apps.common.rate_limiting.AuthenticationRateLimitMiddleware",  # Auth rate limiting
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # 🔒 SECURITY: Session security after authentication
    "apps.common.middleware.SessionSecurityMiddleware",  # Session protection
    # Custom middleware last
    "apps.common.middleware.RequestIDMiddleware",
    "apps.common.middleware.CSPNonceMiddleware",
    "apps.common.middleware.SecurityHeadersMiddleware",
    "apps.users.middleware.PortalAuthenticationMiddleware",  # Portal validation
    "apps.common.localisation_middleware.LocalisationMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            BASE_DIR / "templates",  # Service-specific (highest priority, can override shared)
            REPO_ROOT / "shared" / "ui" / "templates",  # Shared design system components
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.template.context_processors.i18n",
                "django.contrib.messages.context_processors.messages",  # Messages in templates
                "apps.common.context_processors.csp_nonce",
                "apps.common.context_processors.portal_context",
                "apps.common.context_processors.company_identity",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ===============================================================================
# DATABASE - SQLITE FOR SESSION STORAGE ONLY (ALL ENVIRONMENTS)
# ===============================================================================

# SESSION DATABASE — used for Django session storage only, no business data.
# Portal fetches all domain data from Platform via HMAC-signed API calls.
# Losing portal.sqlite3 forces re-login but loses no business data.
DATABASES: dict[str, dict[str, Any]] = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("SESSION_DB_PATH", str(BASE_DIR / "portal.sqlite3")),
        "OPTIONS": {
            # timeout: seconds to wait for a write lock (maps to sqlite3.connect timeout).
            "timeout": 20,
            # WAL mode: concurrent readers + single writer without blocking.
            # Django 5.1+ supports init_command for SQLite (executed on every connection).
            "init_command": "PRAGMA journal_mode=WAL;",
        },
    }
}

# SESSION STORAGE
# Server-side DB sessions: session_key works, cookie stays ~32 bytes,
# SecurityMiddleware can fingerprint/expire sessions, and server-side
# revocation is possible. See ADR-0017 addendum for rationale.
SESSION_ENGINE = "apps.common.session_store"  # DB sessions that merge concurrent writes (ADR-0055)

# Portal uses LocMemCache for disposable cached data and per-worker coordination (ADR-0050).
# Rate limits and payment/checkout idempotency use apps.common.counters in the shared session database.
# Clearing LocMemCache does not reset those counters or claims.
# Protected memberships have a 300 s session TTL and are invalidated when validation changes membership_hash.
if os.environ.get("DEBUG", "True").lower() == "true":
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "portal-dev-cache",
        }
    }
else:
    # In production we can still use LocMem or point to Redis later
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "portal-prod-cache",
        }
    }


# ===============================================================================
# PLATFORM API CONFIGURATION
# ===============================================================================

# Platform service API connection
PLATFORM_API_BASE_URL = os.environ.get("PLATFORM_API_BASE_URL", "http://localhost:8700/api")
# 🔒 SECURITY: No fallback secrets in base config - must be set in environment
PLATFORM_API_SECRET = os.environ.get("PLATFORM_API_SECRET")


def seconds_setting(name: str, raw: str | None, default: float, *, minimum: float, maximum: float) -> float:
    """Parse a duration setting in seconds, refusing to start on a value outside [minimum, maximum].

    Unset or empty means the default. `nan`, `inf` and anything unparsable refuse too: a silently
    unbounded or zero wait is worse than a portal that will not start.
    """
    from django.core.exceptions import ImproperlyConfigured  # noqa: PLC0415  # settings import time

    if raw is None or not raw.strip():
        value = default
    else:
        try:
            value = float(raw)
        except ValueError as error:
            raise ImproperlyConfigured(f"{name} is not a number: {raw!r}") from error
    # The default is checked too: it can fall outside a range that depends on another setting.
    if not math.isfinite(value) or not minimum <= value <= maximum:
        raise ImproperlyConfigured(f"{name} must be between {minimum:g} and {maximum:g} seconds: {raw or value!r}")
    return value


# The most one Platform call may take, retries and backoff included. Under threaded workers a call
# that never ends holds a thread for good, and gunicorn's `timeout` does not end it (it only checks
# that the worker is alive). Keep it below the portal gunicorn's graceful_timeout, so a restart
# waits for calls in flight. Not a whole-page deadline: a page making several calls takes longer.
PLATFORM_API_TOTAL_BUDGET_SECONDS = seconds_setting(
    "PLATFORM_API_TOTAL_BUDGET_SECONDS",
    os.environ.get("PLATFORM_API_TOTAL_BUDGET_SECONDS"),
    45.0,
    minimum=5,
    maximum=45,
)
# Each phase of one attempt (connecting; then each wait for the next bytes) is bounded by this.
# The default never exceeds the budget; an explicit value outside 1..budget refuses to start.
PLATFORM_API_TIMEOUT = seconds_setting(
    "PLATFORM_API_TIMEOUT",
    os.environ.get("PLATFORM_API_TIMEOUT"),
    min(30.0, PLATFORM_API_TOTAL_BUDGET_SECONDS),
    minimum=1,
    maximum=PLATFORM_API_TOTAL_BUDGET_SECONDS,
)

# Login timing floor (seconds). Every portal login takes at least this long, so the time a
# failure takes gives no sign of whether the email belongs to an account (#640 follow-up).
# Measured worst case was 0.46 s locally (a BCrypt-hashed account, 5 concurrent logins); the
# production default leaves room for slower hosts and is also the lowest value accepted: an
# operator can raise the floor, never lower it into a no-op. Unset here, so tests and dev do not
# sleep; production and staging call `login_floor_seconds`.
LOGIN_FLOOR_MIN_SECONDS = 1.0
LOGIN_FLOOR_MAX_SECONDS = 10.0


def login_floor_seconds(raw: str | None, default: float) -> float:
    """Parse PLATFORM_API_AUTH_MIN_DURATION_SECONDS, refusing values that would disable the floor.

    Unset or empty means the default. Anything else must be a finite number in [1, 10]: a smaller
    value (0.001 as much as 0 or a negative) hides too little, `nan` would silently turn the
    protection off, and `inf` would hang every login.
    """
    from django.core.exceptions import ImproperlyConfigured  # noqa: PLC0415  # settings import time

    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as error:
        raise ImproperlyConfigured(f"PLATFORM_API_AUTH_MIN_DURATION_SECONDS is not a number: {raw!r}") from error
    if not math.isfinite(value) or not LOGIN_FLOOR_MIN_SECONDS <= value <= LOGIN_FLOOR_MAX_SECONDS:
        raise ImproperlyConfigured(
            "PLATFORM_API_AUTH_MIN_DURATION_SECONDS must be in "
            f"[{LOGIN_FLOOR_MIN_SECONDS:g}, {LOGIN_FLOOR_MAX_SECONDS:g}]: {raw!r}"
        )
    return value


# Cold-outage defaults mirror Platform's public company catalog entries.
COMPANY_IDENTITY_DEFAULTS: dict[str, str] = {
    "legal_name": "PragmaticHost SRL",
    "email_support": "support@pragmatichost.com",
    "email_privacy": "privacy@pragmatichost.com",
    "email_finance": "",
    "phone": "",
}

# Company bank details for bank transfer payment instructions
COMPANY_BANK_IBAN = os.environ.get("COMPANY_BANK_IBAN", "")
COMPANY_BANK_NAME = os.environ.get("COMPANY_BANK_NAME", "")
COMPANY_BANK_BENEFICIARY = os.environ.get("COMPANY_BANK_BENEFICIARY", "PragmaticHost SRL")


# ===============================================================================
# INTERNATIONALIZATION
# ===============================================================================

LANGUAGE_CODE = "en"
TIME_ZONE = "Europe/Bucharest"  # Romanian timezone
USE_I18N = True
USE_TZ = True

LANGUAGES = [
    ("en", _("English")),
    ("ro", _("Română")),
]

LOCALE_PATHS = [
    REPO_ROOT / "shared" / "ui" / "locale",
    BASE_DIR / "locale",
]

# ===============================================================================
# STATIC FILES
# ===============================================================================

STATIC_URL = "/static/"
STATICFILES_DIRS = [
    BASE_DIR / "static",  # Service-specific static files (highest priority)
    REPO_ROOT / "shared" / "ui" / "static",  # Shared JS components (modal.js, toast.js)
]
STATIC_ROOT = BASE_DIR / "staticfiles"

# ===============================================================================
# SECURITY SETTINGS
# ===============================================================================

# 🔒 SECURITY: No fallback secrets in base config - must be set in environment
# Production settings will enforce this with proper error messages
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")

DEBUG = os.environ.get("DEBUG", "True").lower() == "true"

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "portal.pragmatichost.com"]

# ===============================================================================
# SESSION CONFIGURATION 🔐
# ===============================================================================

# Session duration settings
SESSION_COOKIE_AGE_DEFAULT = 24 * 60 * 60  # 24 hours (86400 seconds)
SESSION_COOKIE_AGE_REMEMBER_ME = 30 * 24 * 60 * 60  # 30 days (2592000 seconds)

# Session behavior
SESSION_EXPIRE_AT_BROWSER_CLOSE = False  # Use custom age settings
SESSION_SAVE_EVERY_REQUEST = False  # Only save when modified
SESSION_COOKIE_NAME = "portal_session"  # Custom session name

# Cookie security settings
SESSION_COOKIE_SECURE = not DEBUG  # HTTPS in production
SESSION_COOKIE_HTTPONLY = True  # Prevent XSS access
SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection
CSRF_COOKIE_SECURE = not DEBUG  # HTTPS for CSRF cookies
CSRF_COOKIE_HTTPONLY = False  # ✅ Allow JS access for AJAX
CSRF_COOKIE_SAMESITE = "Lax"  # CSRF protection

# CSRF trusted origins (must include scheme + host)
CSRF_TRUSTED_ORIGINS = [
    "https://portal.pragmatichost.com",
    "https://www.pragmatichost.com",
]

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"  # ✅ Added
X_FRAME_OPTIONS = "DENY"

# Content Security Policy rollout (#104 [M7]). Server-selected only — never
# from a request header/param. Unknown/typo profile values are handled by
# SecurityHeadersMiddleware as "current" (byte-identical to the live policy).
# The shipped default is a NAMED CONSTANT (not an inline literal) so a guard test
# can pin it independently of whether CSP_PROFILE is exported in the environment
# — asserting the effective setting alone would be masked by a CI/shell override.
DEFAULT_CSP_PROFILE = "phase3-target"
CSP_PROFILE = os.environ.get("CSP_PROFILE", DEFAULT_CSP_PROFILE)
CSP_REPORT_ONLY = os.environ.get("CSP_REPORT_ONLY", "false").lower() in ("1", "true", "yes")

# Test-only URL surface (CSP violation positive-control). The E2E settings
# module is the sole enabler; base/dev/staging/prod keep this False so the
# route 404s even if config.e2e_urls is somehow loaded.
E2E_TEST_ROUTES_ENABLED = False

# HTTPS redirect in production
SECURE_SSL_REDIRECT = not DEBUG

# ===============================================================================
# LOGGING
# ===============================================================================
# PORTAL SERVICE IDENTIFICATION
# ===============================================================================

# Portal service identification for HMAC authentication
PORTAL_ID = os.environ.get("PORTAL_ID", "portal-001")

# Per-portal HMAC signing secret (#277). When set, this portal signs Platform requests with
# its own secret (matched against PORTAL_HMAC_CREDENTIALS[PORTAL_ID] on the platform) instead
# of the shared PLATFORM_API_SECRET. Absent → falls back to PLATFORM_API_SECRET (backward compat).
# `... or None`: under Docker/compose `${PORTAL_HMAC_SECRET:-}` interpolation, an unset var
# reaches the container as the empty string — indistinguishable from truly unset — so both mean
# "use the shared secret". The empty-is-a-provisioning-error guard in api_client.services still
# fires for a directly-assigned Python setting (e.g. override_settings in tests).
PORTAL_HMAC_SECRET = os.environ.get("PORTAL_HMAC_SECRET") or None

# ===============================================================================
# LOGGING CONFIGURATION
# ===============================================================================


class _ServiceNameFilter(logging.Filter):
    """Inject a fixed service tag into every log record."""

    def __init__(self, service_name: str = "PORT") -> None:
        super().__init__()
        self.service_name = service_name

    def filter(self, record: logging.LogRecord) -> bool:
        setattr(record, "service_name", self.service_name)  # noqa: B010
        return True


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "unified": {
            "()": "colorlog.ColoredFormatter",
            "format": "{asctime} {log_color}{levelname:<8}{reset} {service_name} {name:<40} {message} [{request_id}]",
            "datefmt": "%Y-%m-%d %H:%M:%S",
            "style": "{",
            "log_colors": {
                "DEBUG": "cyan",
                "INFO": "green",
                "WARNING": "yellow",
                "ERROR": "red",
                "CRITICAL": "bold_red",
            },
        },
    },
    "filters": {
        "add_request_id": {
            "()": "apps.common.middleware.RequestIDFilter",
        },
        "add_service_name": {
            "()": _ServiceNameFilter,
            "service_name": "PORT",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "unified",
            "filters": ["add_request_id", "add_service_name"],
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": os.environ.get("DJANGO_LOG_LEVEL", "INFO"),
            "propagate": False,
        },
        "django.server": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "apps": {
            "handlers": ["console"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
    },
}

# ===============================================================================
# DEFAULT PRIMARY KEY FIELD TYPE
# ===============================================================================

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ===============================================================================
# TRUSTED PROXY CONFIGURATION
# ===============================================================================

# Aligned with platform setting name — both services use IPWARE_TRUSTED_PROXY_LIST
# Trusted proxy CIDR list for get_safe_client_ip().
# Set to your load balancer / CDN CIDR(s) in production.
# Production and staging require explicit proxy CIDRs.
IPWARE_TRUSTED_PROXY_LIST: list[str] = [
    cidr.strip() for cidr in os.environ.get("PORTAL_TRUSTED_PROXY_CIDRS", "").split(",") if cidr.strip()
]
