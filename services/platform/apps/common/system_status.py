"""
System status checker for PRAHO Platform dashboard.

Checks configuration and connectivity for each subsystem.
Results are cached and displayed on the dashboard widget.
"""

from __future__ import annotations

import logging
import os
import smtplib
from dataclasses import dataclass
from enum import StrEnum

from django.conf import settings
from django.core.cache import cache
from django.db import connection

logger = logging.getLogger(__name__)

CACHE_KEY = "system_status_results"
CACHE_TIMEOUT = 86400 * 2  # 48 hours

# #103 (H3): the most recent BNR fetch outcome, kept independently of rate age so a
# failed ingestion stays visible even while last-good rates are still fresh. A successful
# fetch clears it; a failure persists for a week (until the next good fetch or manual fix).
_FX_FETCH_OUTCOME_KEY = "fx:last_fetch_outcome"
_FX_FETCH_OUTCOME_TTL = 86400 * 7


def record_fx_fetch_outcome(*, success: bool, detail: str) -> None:
    """Persist the last BNR fetch outcome for the freshness surface (#103, H3).

    Rate *age* alone cannot tell a failed daily fetch from a quiet weekend, so a failed
    ingestion whose last-good rates are still fresh would otherwise read GREEN (and, if the
    alert email also bounced, be entirely invisible). Recording the outcome here lets
    ``_check_fx_freshness`` escalate to AMBER — which the daily task then alerts on.
    """
    from django.utils import timezone  # noqa: PLC0415

    if success:
        cache.delete(_FX_FETCH_OUTCOME_KEY)
        return
    cache.set(
        _FX_FETCH_OUTCOME_KEY,
        {"detail": detail, "at": timezone.now().isoformat()},
        timeout=_FX_FETCH_OUTCOME_TTL,
    )


class StatusLevel(StrEnum):
    GREEN = "green"  # Configured and connected
    AMBER = "amber"  # Configured but degraded / warning
    RED = "red"  # Not configured (required) or failing
    GREY = "grey"  # Not required for this environment


@dataclass(frozen=True)
class SubsystemStatus:
    name: str
    level: StatusLevel
    message: str
    detail: str = ""


def _is_production() -> bool:
    """Detect if running in production environment."""
    settings_module = os.environ.get("DJANGO_SETTINGS_MODULE", "")
    return "prod" in settings_module


def _is_staging() -> bool:
    """Detect if running in staging environment."""
    settings_module = os.environ.get("DJANGO_SETTINGS_MODULE", "")
    return "staging" in settings_module


def _is_dev() -> bool:
    """Detect if running in development environment (neither prod nor staging)."""
    return not _is_production() and not _is_staging()


def _check_database() -> SubsystemStatus:
    """Check database connectivity."""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return SubsystemStatus(
            name="Database",
            level=StatusLevel.GREEN,
            message="Connected",
            detail=f"PostgreSQL on {settings.DATABASES['default'].get('HOST', 'localhost')}",
        )
    except Exception as exc:
        return SubsystemStatus(
            name="Database",
            level=StatusLevel.RED,
            message="Connection failed",
            detail=str(exc),
        )


def _check_email() -> SubsystemStatus:
    """Check email configuration and connectivity."""
    if _is_dev():
        return SubsystemStatus(
            name="Email",
            level=StatusLevel.GREY,
            message="Dev mode",
            detail="Development uses console backend — emails go to terminal",
        )
    if _is_staging():
        return SubsystemStatus(
            name="Email",
            level=StatusLevel.GREY,
            message="Not required",
            detail="Staging uses console backend — emails go to journalctl",
        )

    host = os.environ.get("EMAIL_HOST", "")
    user = os.environ.get("EMAIL_HOST_USER", "")

    if not host or not user:
        return SubsystemStatus(
            name="Email",
            level=StatusLevel.AMBER,
            message="Not configured",
            detail="Set EMAIL_HOST and EMAIL_HOST_USER in .env",
        )

    # Test SMTP connectivity
    try:
        port = int(os.environ.get("EMAIL_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=5) as smtp:
            smtp.ehlo()
        return SubsystemStatus(
            name="Email",
            level=StatusLevel.GREEN,
            message="SMTP connected",
            detail=f"{host}:{port}",
        )
    except (OSError, smtplib.SMTPException) as exc:
        return SubsystemStatus(
            name="Email",
            level=StatusLevel.AMBER,
            message="SMTP unreachable",
            detail=str(exc),
        )


def _check_stripe() -> SubsystemStatus:
    """Check Stripe configuration."""
    if _is_dev():
        return SubsystemStatus(
            name="Stripe",
            level=StatusLevel.GREY,
            message="Dev mode",
            detail="Payment processing not needed in development",
        )
    if _is_staging():
        return SubsystemStatus(
            name="Stripe",
            level=StatusLevel.GREY,
            message="Not required",
            detail="Staging can use test keys or skip entirely",
        )

    secret_key = getattr(settings, "STRIPE_SECRET_KEY", None)
    if not secret_key:
        return SubsystemStatus(
            name="Stripe",
            level=StatusLevel.AMBER,
            message="Not configured",
            detail="Set STRIPE_SECRET_KEY in .env for payment processing",
        )

    # Verify key format (don't make API call to avoid rate limits)
    if secret_key.startswith(("sk_live_", "sk_test_")):
        key_type = "live" if "sk_live_" in secret_key else "test"
        return SubsystemStatus(
            name="Stripe",
            level=StatusLevel.GREEN,
            message=f"Configured ({key_type})",
            detail="API key format valid",
        )

    return SubsystemStatus(
        name="Stripe",
        level=StatusLevel.AMBER,
        message="Invalid key format",
        detail="STRIPE_SECRET_KEY should start with sk_live_ or sk_test_",
    )


def _check_efactura() -> SubsystemStatus:
    """Check e-Factura (ANAF) configuration."""
    if _is_dev():
        return SubsystemStatus(
            name="e-Factura",
            level=StatusLevel.GREY,
            message="Dev mode",
            detail="e-Factura not needed in development",
        )
    if _is_staging():
        return SubsystemStatus(
            name="e-Factura",
            level=StatusLevel.GREY,
            message="Not required",
            detail="Staging uses test mode — no ANAF submissions",
        )

    api_url = getattr(settings, "EFACTURA_API_URL", None)
    api_key = getattr(settings, "EFACTURA_API_KEY", None)

    if not api_url or not api_key:
        return SubsystemStatus(
            name="e-Factura",
            level=StatusLevel.AMBER,
            message="Not configured",
            detail="Set EFACTURA_API_URL and EFACTURA_API_KEY in .env",
        )

    return SubsystemStatus(
        name="e-Factura",
        level=StatusLevel.GREEN,
        message="Configured",
        detail=f"API: {api_url}",
    )


def _check_encryption() -> SubsystemStatus:
    """Check encryption key configuration (AES-256-GCM)."""
    encryption_key = os.environ.get("DJANGO_ENCRYPTION_KEY", "")

    if not encryption_key:
        return SubsystemStatus(
            name="Encryption",
            level=StatusLevel.AMBER,
            message="Not configured",
            detail="Set DJANGO_ENCRYPTION_KEY — TOTP secrets stored unencrypted",
        )

    # Validate AES-256 key format (32 bytes, URL-safe base64)
    try:
        import base64  # noqa: PLC0415

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

        expected_key_length = 32
        key_bytes = base64.urlsafe_b64decode(encryption_key.encode())
        if len(key_bytes) != expected_key_length:
            raise ValueError(f"Key must be 32 bytes, got {len(key_bytes)}")
        AESGCM(key_bytes)
        return SubsystemStatus(
            name="Encryption",
            level=StatusLevel.GREEN,
            message="Active",
            detail="AES-256-GCM key valid",
        )
    except Exception:
        return SubsystemStatus(
            name="Encryption",
            level=StatusLevel.RED,
            message="Invalid key",
            detail="DJANGO_ENCRYPTION_KEY is not a valid AES-256 key (32 bytes, URL-safe base64)",
        )


def _check_credential_vault() -> SubsystemStatus:
    """Check credential vault configuration (AES-256-GCM)."""
    master_key = getattr(settings, "CREDENTIAL_VAULT_MASTER_KEY", None)
    enabled = getattr(settings, "CREDENTIAL_VAULT_ENABLED", False)

    if not enabled:
        return SubsystemStatus(
            name="Credential Vault",
            level=StatusLevel.GREY,
            message="Disabled",
            detail="CREDENTIAL_VAULT_ENABLED=false",
        )

    if not master_key:
        return SubsystemStatus(
            name="Credential Vault",
            level=StatusLevel.AMBER,
            message="No master key",
            detail="Set CREDENTIAL_VAULT_MASTER_KEY — credentials stored unencrypted",
        )

    # Validate AES-256 key format (32 bytes, URL-safe base64)
    try:
        import base64  # noqa: PLC0415

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: PLC0415

        expected_key_length = 32
        key_bytes = base64.urlsafe_b64decode(master_key.encode())
        if len(key_bytes) != expected_key_length:
            raise ValueError(f"Key must be 32 bytes, got {len(key_bytes)}")
        AESGCM(key_bytes)
        return SubsystemStatus(
            name="Credential Vault",
            level=StatusLevel.GREEN,
            message="Active",
            detail="AES-256-GCM master key valid",
        )
    except Exception:
        return SubsystemStatus(
            name="Credential Vault",
            level=StatusLevel.RED,
            message="Invalid master key",
            detail="CREDENTIAL_VAULT_MASTER_KEY is not a valid AES-256 key (32 bytes, URL-safe base64)",
        )


def _check_sentry() -> SubsystemStatus:
    """Check Sentry configuration."""
    dsn = os.environ.get("SENTRY_DSN", "")

    if not dsn:
        return SubsystemStatus(
            name="Sentry",
            level=StatusLevel.GREY,
            message="Not configured",
            detail="Optional — errors logged to files only",
        )

    return SubsystemStatus(
        name="Sentry",
        level=StatusLevel.GREEN,
        message="Active",
        detail="Error tracking enabled",
    )


def _check_hmac() -> SubsystemStatus:
    """Check HMAC secret for portal↔platform auth."""
    hmac_secret = os.environ.get("HMAC_SECRET", "")

    if not hmac_secret:
        return SubsystemStatus(
            name="Portal Auth",
            level=StatusLevel.RED,
            message="HMAC not configured",
            detail="Set HMAC_SECRET — Portal cannot authenticate to Platform",
        )

    return SubsystemStatus(
        name="Portal Auth",
        level=StatusLevel.GREEN,
        message="HMAC active",
        detail=f"Key length: {len(hmac_secret)} chars",
    )


def _check_backup() -> SubsystemStatus:
    """Check backup configuration (cron job existence)."""
    import subprocess  # noqa: PLC0415

    try:
        result = subprocess.run(
            ["crontab", "-l"],  # noqa: S607 — crontab location varies across distros
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if "backup" in result.stdout.lower():
            return SubsystemStatus(
                name="Backup",
                level=StatusLevel.GREEN,
                message="Cron active",
                detail="Daily backup job found in crontab",
            )
        return SubsystemStatus(
            name="Backup",
            level=StatusLevel.AMBER,
            message="No cron job",
            detail="No backup cron found — run Ansible to configure",
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # Running in dev or container — no crontab available
        return SubsystemStatus(
            name="Backup",
            level=StatusLevel.GREY,
            message="N/A",
            detail="Crontab not available (dev/container environment)",
        )


def _check_fx_freshness() -> SubsystemStatus:
    """FX-rate freshness for foreign-currency issuance (#103), guarded so an unexpected
    error cannot silently disable the daily FX pager.

    ``check_all_subsystems`` does not wrap its members, so an uncaught raise here (e.g. a
    transient ``OperationalError`` from the settings/FXRate queries below) would abort the
    whole daily status task before it caches results or runs ``_alert_on_fx_freshness`` —
    the very pager that surfaces a silently-failed fetch. On any such error we return RED,
    never GREY: ``_alert_on_fx_freshness`` treats GREY as recovery and clears the dedup key,
    so a GREY-on-error would convert "cannot verify FX" into "recovered".
    """
    try:
        return _compute_fx_freshness()
    except Exception as exc:  # a status check must degrade to RED, never take the task down
        logger.warning("🔴 [SystemStatus] FX freshness check errored: %s", exc)
        return SubsystemStatus(
            name="FX rates",
            level=StatusLevel.RED,
            message="Freshness check errored",
            detail=f"Could not verify FX freshness (treated as blocking): {exc}",
        )


def _compute_fx_freshness() -> SubsystemStatus:
    """Resolver-accurate, computed LIVE (never trusts a cached level for its
    date-sensitivity): for each configured foreign pair it attempts today's
    currency->RON resolution with the same semantics ``Invoice.issue()`` uses.
    RED  = a pair cannot resolve today (missing / unprovenanced) → foreign issuance
           for it is blocked;
    AMBER= resolves but the rate is older than the staleness window, or the last daily
           fetch failed while last-good rates still resolve;
    GREEN= every configured pair resolves and is fresh;
    GREY = no foreign pairs configured.
    """
    from datetime import timedelta  # noqa: PLC0415

    from django.utils import timezone  # noqa: PLC0415

    from apps.billing.exchange_rate_service import ExchangeRateError, ExchangeRateService  # noqa: PLC0415
    from apps.settings.services import SettingsService  # noqa: PLC0415

    pairs = [str(c).strip().upper() for c in SettingsService.get_list_setting("billing.fx.pairs", ["EUR", "USD"])]
    foreign = [c for c in pairs if c and c != "RON"]
    if not foreign:
        return SubsystemStatus(
            name="FX rates",
            level=StatusLevel.GREY,
            message="No foreign currencies",
            detail="billing.fx.pairs lists no non-RON currency",
        )

    today = timezone.localdate()
    stale_after = SettingsService.get_integer_setting("billing.fx.stale_after_days", 4)
    missing: list[str] = []
    stale: list[str] = []
    for code in foreign:
        try:
            snapshot = ExchangeRateService.resolve(code, "RON", today)
        except ExchangeRateError:
            missing.append(code)
            continue
        if snapshot.as_of < today - timedelta(days=stale_after):
            stale.append(f"{code} (as of {snapshot.as_of})")

    # H3: a failed daily fetch must stay visible even when last-good rates still resolve.
    fetch_failure = cache.get(_FX_FETCH_OUTCOME_KEY)

    if missing:
        return SubsystemStatus(
            name="FX rates",
            level=StatusLevel.RED,
            message=f"No usable rate today: {', '.join(missing)}",
            detail="Foreign-currency issuance is blocked for these until a provenanced rate is provisioned.",
        )
    if stale:
        return SubsystemStatus(
            name="FX rates",
            level=StatusLevel.AMBER,
            message=f"Stale (> {stale_after}d): {', '.join(stale)}",
            detail="Rates still resolve, but a fresher publication is overdue.",
        )
    if fetch_failure:
        return SubsystemStatus(
            name="FX rates",
            level=StatusLevel.AMBER,
            message="Last BNR fetch failed",
            detail=(
                f"All pairs still resolve on last-good rates, but the most recent ingestion "
                f"failed ({fetch_failure.get('detail')} at {fetch_failure.get('at')}). "
                f"Fix ingestion before the rates go stale."
            ),
        )
    return SubsystemStatus(
        name="FX rates",
        level=StatusLevel.GREEN,
        message="Fresh",
        detail=f"Resolvable today: {', '.join(foreign)}",
    )


def check_all_subsystems() -> list[SubsystemStatus]:
    """
    Check all subsystems and return their status.

    Called by the daily Django-Q2 task and by the on-demand
    dashboard refresh endpoint.
    """
    results = [
        _check_database(),
        _check_hmac(),
        _check_email(),
        _check_stripe(),
        _check_efactura(),
        _check_encryption(),
        _check_credential_vault(),
        _check_sentry(),
        _check_backup(),
        _check_fx_freshness(),
    ]

    # Log warnings for any non-green statuses
    for r in results:
        if r.level == StatusLevel.RED:
            logger.warning("🔴 [SystemStatus] %s: %s — %s", r.name, r.message, r.detail)
        elif r.level == StatusLevel.AMBER:
            logger.warning("🟡 [SystemStatus] %s: %s — %s", r.name, r.message, r.detail)

    return results


def get_cached_status() -> list[SubsystemStatus]:
    """Get system status from cache, or return empty list if not yet checked."""
    cached: list[SubsystemStatus] = cache.get(CACHE_KEY, [])
    return cached


def refresh_and_cache_status() -> list[SubsystemStatus]:
    """Run all checks, cache results, and return them."""
    results = check_all_subsystems()
    cache.set(CACHE_KEY, results, timeout=CACHE_TIMEOUT)
    return results
