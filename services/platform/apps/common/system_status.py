"""Runtime-aware dashboard checks and a timestamped, best-effort status snapshot."""

from __future__ import annotations

import json
import logging
import os
import shlex
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

from django.conf import settings
from django.core.cache import cache
from django.db import DatabaseError, InterfaceError, connection, transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac
from django.utils.functional import Promise
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

from apps.common.operator import operator_is_romanian
from apps.common.system_status_probes import ProbeBudget, ProbeCode, email_probe_config

if TYPE_CHECKING:
    from apps.common.credential_vault import EncryptedCredential
    from apps.provisioning.virtualmin_models import VirtualminServer


def node_input_identity(server: VirtualminServer, *, credentials: Sequence[EncryptedCredential] | None = None) -> str:
    """Bind evidence to effective connection inputs without decrypting or publishing credentials."""
    from apps.common.credential_vault import EncryptedCredential  # noqa: PLC0415

    fields = ("hostname", "api_username", "api_port", "api_path", "use_ssl", "ssl_verify", "ssl_cert_fingerprint")
    values: list[object] = [getattr(server, field) for field in fields]
    values.append(bytes(server.encrypted_api_password or b"").hex())
    if credentials is None:
        credentials = list(
            EncryptedCredential.objects.filter(service_type="virtualmin", service_identifier=server.hostname).order_by(
                "pk"
            )
        )
    # Access counters/timestamps are deliberately excluded: reading a credential does not change its identity.
    values.extend(
        (
            str(credential.id),
            bytes(credential.encrypted_username).hex(),
            bytes(credential.encrypted_password).hex(),
            credential.is_active,
            credential.expires_at.isoformat(),
            credential.expires_at <= timezone.now(),
        )
        for credential in credentials
    )
    values.extend(
        (str(getattr(settings, key, "")))
        for key in ("CREDENTIAL_VAULT_MASTER_KEY", "ENCRYPTION_KEY", "ENCRYPTION_KEYS")
    )
    return salted_hmac("praho.node-check.v1", json.dumps(values, sort_keys=True), algorithm="sha256").hexdigest()


def node_input_identities(nodes: Iterable[VirtualminServer]) -> dict[UUID, str]:
    """Batch local identity reads for rendered fleet views; no decryption or external calls."""
    from apps.common.credential_vault import EncryptedCredential  # noqa: PLC0415

    servers = {node.id: node for node in nodes}
    grouped: dict[str, list[EncryptedCredential]] = {}
    credentials = EncryptedCredential.objects.filter(
        service_type="virtualmin", service_identifier__in=[node.hostname for node in servers.values()]
    ).order_by("pk")
    for credential in credentials:
        grouped.setdefault(credential.service_identifier, []).append(credential)
    return {node.id: node_input_identity(node, credentials=grouped.get(node.hostname, [])) for node in servers.values()}


logger = logging.getLogger(__name__)
CACHE_KEY = "system_status_snapshot_v4"
CACHE_TIMEOUT = 86400 * 2
SNAPSHOT_VERSION = 4
STALE_AFTER = timedelta(minutes=25)
_FX_FETCH_OUTCOME_KEY = "fx:last_fetch_outcome"
_FX_FETCH_OUTCOME_TTL = 86400 * 7


def record_fx_fetch_outcome(*, success: bool, detail: str) -> None:
    """Keep fetch failure visible even while last-good rates still resolve."""
    if success:
        cache.delete(_FX_FETCH_OUTCOME_KEY)
        return
    cache.set(
        _FX_FETCH_OUTCOME_KEY, {"detail": detail, "at": timezone.now().isoformat()}, timeout=_FX_FETCH_OUTCOME_TTL
    )


class StatusLevel(StrEnum):
    GREEN = "green"
    AMBER = "amber"
    RED = "red"
    GREY = "grey"


@dataclass(frozen=True)
class SubsystemStatus:
    name: str | Promise
    level: StatusLevel
    message: str | Promise
    detail: str | Promise = ""
    key: str = ""
    checked_at: datetime | None = None


@dataclass(frozen=True)
class StatusSnapshot:
    results: list[SubsystemStatus]
    checked_at: datetime | None = None
    saved: bool = True
    cache_available: bool = True
    version: int = SNAPSHOT_VERSION
    input_identity: str = ""
    check_id: str = field(default_factory=lambda: uuid4().hex)

    @property
    def stale(self) -> bool:
        return self.checked_at is not None and timezone.now() - self.checked_at >= STALE_AFTER


def _check_database() -> SubsystemStatus:
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return SubsystemStatus(_("Database"), StatusLevel.GREEN, _("Connected"), connection.display_name)
    except Exception:  # A failed health check must not prevent the other checks.
        return SubsystemStatus(_("Database"), StatusLevel.RED, _("Connection failed"), _("Database query failed."))


def _probe_status(name: str | Promise, code: ProbeCode, success: str | Promise) -> SubsystemStatus:
    descriptions = {
        ProbeCode.OK: (success, _("Read-only connectivity check passed; no transaction or message was sent.")),
        ProbeCode.TIMEOUT: (_("Check timed out"), _("The provider or overall check deadline was reached.")),
        ProbeCode.UNAVAILABLE: (
            _("Check failed"),
            _("The provider could not be verified. Check configuration and connectivity."),
        ),
        ProbeCode.INVALID_RESPONSE: (
            _("Unexpected response"),
            _("The provider did not return a valid success response."),
        ),
        ProbeCode.TOO_LARGE: (_("Response too large"), _("The response exceeded the 256 KiB check limit.")),
        ProbeCode.UNAUTHORIZED: (_("Credentials rejected"), _("The provider rejected authentication.")),
        ProbeCode.FORBIDDEN: (_("Access rejected"), _("The provider denied this check; the cause is unverified.")),
        ProbeCode.PERMISSION: (
            _("Required permission missing"),
            _("The provider explicitly reports a missing permission for sending or this diagnostic check."),
        ),
        ProbeCode.THROTTLED: (_("Rate limited"), _("The provider rate limit was reached. No retry was attempted.")),
        ProbeCode.DISABLED: (_("Not ready"), _("The provider reports that sending or charging is not enabled.")),
        ProbeCode.SANDBOX: (_("Sandbox verified"), _("SES sending is enabled with sandbox restrictions.")),
        ProbeCode.UNVERIFIED: (
            _("Not verified"),
            _("This backend or endpoint is not supported by the read-only check."),
        ),
    }
    message, detail = descriptions[code]
    level = {ProbeCode.OK: StatusLevel.GREEN, ProbeCode.UNAUTHORIZED: StatusLevel.RED}.get(code, StatusLevel.AMBER)
    return SubsystemStatus(name, level, message, detail)


def _check_email(budget: ProbeBudget | None = None) -> SubsystemStatus:
    backend = settings.EMAIL_BACKEND
    local_backends = {
        "django.core.mail.backends.console.EmailBackend": _("Console backend"),
        "django.core.mail.backends.filebased.EmailBackend": _("File backend"),
        "django.core.mail.backends.locmem.EmailBackend": _("In-memory backend"),
        "django.core.mail.backends.dummy.EmailBackend": _("Delivery disabled"),
    }
    if backend in local_backends:
        return SubsystemStatus(
            _("Email"), StatusLevel.GREY, local_backends[backend], _("This backend does not deliver external email.")
        )
    try:
        provider, config = email_probe_config()
    except Exception:
        return SubsystemStatus(
            _("Email"),
            StatusLevel.RED,
            _("Invalid configuration"),
            _("The configured email backend could not be initialized."),
        )
    return _probe_status(_("Email"), (budget or ProbeBudget()).run(provider, config), _("Connection verified"))


def _check_stripe(budget: ProbeBudget | None = None) -> SubsystemStatus:
    from apps.billing.gateways.stripe_contract import STRIPE_API_VERSION  # noqa: PLC0415
    from apps.settings.services import SettingsService  # noqa: PLC0415

    if not SettingsService.get_setting("integrations.stripe_enabled", False):
        return SubsystemStatus(
            _("Stripe"), StatusLevel.GREY, _("Disabled"), _("Stripe is disabled in integration settings.")
        )
    secret = SettingsService.get_setting("integrations.stripe_secret_key", "")
    public = SettingsService.get_setting("integrations.stripe_publishable_key", "")
    webhook = SettingsService.get_setting("integrations.stripe_webhook_secret", "")
    if not secret or not public:
        return SubsystemStatus(
            _("Stripe"),
            StatusLevel.RED,
            _("Missing keys"),
            _("Configure the secret and publishable keys in integration settings."),
        )
    test_mode = str(secret).startswith(("sk_test_", "rk_test_"))
    mode = _("test") if test_mode else _("live")
    expected_public = "pk_test_" if test_mode else "pk_live_"
    if not str(public).startswith(expected_public):
        return SubsystemStatus(
            _("Stripe"),
            StatusLevel.RED,
            _("Key modes differ"),
            _("The secret and publishable keys must use the same mode."),
        )
    code = (budget or ProbeBudget()).run(
        "stripe",
        {
            "url": "https://api.stripe.com/v1/account",
            "headers": {"Authorization": f"Bearer {secret}", "Stripe-Version": STRIPE_API_VERSION},
        },
    )
    result = _probe_status(_("Stripe"), code, format_lazy(_("API verified ({mode})"), mode=mode))
    if not webhook:
        return replace(
            result,
            level=StatusLevel.AMBER if code == ProbeCode.OK else result.level,
            message=_("Webhook secret missing") if code == ProbeCode.OK else result.message,
            detail=format_lazy(
                "{detail} {warning}",
                detail=result.detail,
                warning=_("The webhook signing secret is missing; payment event processing is not ready."),
            ),
        )
    return result


def _check_efactura(budget: ProbeBudget | None = None) -> SubsystemStatus:
    from apps.billing.efactura.client import (  # noqa: PLC0415
        AuthenticationError,
        EFacturaClient,
        EFacturaConfig,
        LocalQuotaError,
    )
    from apps.billing.efactura.settings import efactura_enabled  # noqa: PLC0415
    from apps.billing.efactura.xml_builder import get_supplier_info  # noqa: PLC0415

    if not operator_is_romanian() or not efactura_enabled():
        return SubsystemStatus(
            _("e-Factura"), StatusLevel.GREY, _("Disabled"), _("e-Factura is not enabled for this operator.")
        )
    config = EFacturaConfig.from_settings()
    cui = get_supplier_info().numeric_tax_id
    if not config.is_valid(company_cui=cui):
        return SubsystemStatus(
            _("e-Factura"),
            StatusLevel.AMBER,
            _("Missing configuration"),
            _("Configure OAuth credentials and the issuer tax identity."),
        )
    budget = budget or ProbeBudget()
    if budget.remaining <= 0:
        return _probe_status(_("e-Factura"), ProbeCode.TIMEOUT, "")
    try:
        request = EFacturaClient(config).prepare_status_probe(cui)
    except AuthenticationError:
        return SubsystemStatus(
            _("e-Factura"),
            StatusLevel.AMBER,
            _("Authorization required"),
            _("No valid existing token is available. This check does not refresh tokens."),
        )
    except LocalQuotaError:
        return SubsystemStatus(
            _("e-Factura"), StatusLevel.AMBER, _("Local quota reached"), _("No ANAF request was sent.")
        )
    return _probe_status(
        _("e-Factura"),
        budget.run("efactura", request),
        format_lazy(_("API verified ({mode})"), mode=config.environment.value),
    )


def _check_encryption() -> SubsystemStatus:
    from apps.common.encryption import (  # noqa: PLC0415
        decrypt_sensitive_data,
        encrypt_sensitive_data,
        get_encryption_keys,
    )

    try:
        keys = get_encryption_keys()  # Validate every key, including previous decryption keys.
        data = "system-status-self-test"
        aad = b"praho:system-status"
        if decrypt_sensitive_data(encrypt_sensitive_data(data, aad=aad), aad=aad) != data:
            raise ValueError("Encryption self-test failed")
        return SubsystemStatus(
            _("Encryption"),
            StatusLevel.GREEN,
            _("Ready"),
            format_lazy(_("AES-256-GCM self-test passed; {count} key(s) validated."), count=len(keys)),
        )
    except Exception:
        return SubsystemStatus(
            _("Encryption"),
            StatusLevel.RED,
            _("Key validation failed"),
            _("The runtime encryption keyring is missing or invalid. Encrypted operations are unavailable."),
        )


def _check_credential_vault() -> SubsystemStatus:
    from apps.common.credential_vault import CredentialVault  # noqa: PLC0415

    try:
        CredentialVault()  # Fresh key validation and in-memory integrity self-test; no DB writes.
        return SubsystemStatus(
            _("Credential Vault"), StatusLevel.GREEN, _("Ready"), _("Master key and in-memory self-test passed.")
        )
    except Exception:
        return SubsystemStatus(
            _("Credential Vault"),
            StatusLevel.RED,
            _("Key validation failed"),
            _("The credential vault cannot initialize with its configured master key."),
        )


def _check_sentry() -> SubsystemStatus:
    try:
        import sentry_sdk  # noqa: PLC0415

        if sentry_sdk.is_initialized() and sentry_sdk.get_client().dsn:
            return SubsystemStatus(
                _("Sentry"),
                StatusLevel.GREEN,
                _("Initialized"),
                _("The SDK client is active. Event delivery was not tested."),
            )
    except ImportError:
        pass
    if getattr(settings, "SENTRY_DSN", "") or os.environ.get("SENTRY_DSN", ""):
        return SubsystemStatus(
            _("Sentry"),
            StatusLevel.AMBER,
            _("Configured but inactive"),
            _("A DSN is configured, but no active SDK client was found."),
        )
    return SubsystemStatus(
        _("Sentry"), StatusLevel.GREY, _("Not configured"), _("Optional error tracking is not configured.")
    )


def _check_hmac() -> SubsystemStatus:
    from apps.common.portal_hmac import get_mode, get_registry, validate_at_startup  # noqa: PLC0415

    try:
        validate_at_startup()
        mode = get_mode()
        registry = get_registry()
        shared = bool(getattr(settings, "PLATFORM_API_SECRET", ""))
        ready = shared if mode == "legacy" else bool(registry) if mode == "enforce" else bool(registry) or shared
        if not ready:
            raise ValueError("No usable HMAC credentials")
        return SubsystemStatus(
            _("Portal Auth"),
            StatusLevel.GREEN,
            format_lazy(_("Configured ({mode})"), mode=mode),
            _("Runtime HMAC configuration is valid. Portal connectivity was not tested."),
        )
    except Exception:
        return SubsystemStatus(
            _("Portal Auth"),
            StatusLevel.RED,
            _("Invalid HMAC configuration"),
            _("Check PLATFORM_API_SECRET and the portal HMAC mode, registry and isolation settings."),
        )


def _has_backup_job(crontab: str) -> bool:
    root = Path(settings.REPO_ROOT)
    scripts = {str(root / "scripts/backup.sh"), str(root / "deploy/scripts/backup.sh")}
    for line in crontab.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            tokens = shlex.split(stripped, comments=True)
        except ValueError:
            continue
        schedule_fields = 1 if stripped.startswith("@") else 5
        command = tokens[schedule_fields:]
        if command and (
            command[0] in scripts
            or (command[0] in {"bash", "/bin/bash", "sh", "/bin/sh"} and len(command) > 1 and command[1] in scripts)
        ):
            return True
    return False


def _check_backup() -> SubsystemStatus:  # noqa: PLR0911  # Configuration, failure, deadline and verified-success outcomes.
    from croniter import croniter  # noqa: PLC0415

    from apps.common.management.commands.upload_platform_backup import storage_identity  # noqa: PLC0415
    from apps.common.status_models import SystemCheckState  # noqa: PLC0415

    row = SystemCheckState.objects.filter(check_key="platform_backup", node=None).first()
    if row is None or not row.details.get("configuration_applied") or not row.details.get("runner_enabled"):
        return SubsystemStatus(
            _("Platform backups"),
            StatusLevel.AMBER,
            _("Configure backups"),
            _("Apply an enabled Platform backup runner and configure off-server storage."),
        )
    if row.level == "red":
        return SubsystemStatus(
            _("Platform backups"),
            StatusLevel.RED,
            _("Backup failed"),
            _("The latest backup attempt failed. Local artifacts are retained for recovery."),
        )
    try:
        clock = timezone.now().astimezone(ZoneInfo(str(row.details.get("schedule_timezone", settings.TIME_ZONE))))
        due = croniter(str(row.details.get("schedule", "")), clock).get_prev(datetime)
    except (ValueError, KeyError):
        return SubsystemStatus(_("Platform backups"), StatusLevel.AMBER, _("Schedule unverified"))
    if (
        due >= row.created_at
        and timezone.now() >= due + timedelta(hours=2)
        and (row.last_success_at is None or row.last_success_at < due)
    ):
        return SubsystemStatus(
            _("Platform backups"),
            StatusLevel.RED,
            _("Off-server backup overdue"),
            _(
                "No verified database/media pair was completed for the scheduled backup within its two-hour grace period."
            ),
        )
    if row.last_success_at is None:
        return SubsystemStatus(_("Platform backups"), StatusLevel.AMBER, _("Awaiting first backup"))
    if row.input_identity != storage_identity() or row.verified_generation != row.configuration_generation:
        return SubsystemStatus(
            _("Platform backups"),
            StatusLevel.AMBER,
            _("Storage configuration changed"),
            _("A successful backup must verify the current off-server destination."),
        )
    return SubsystemStatus(
        _("Platform backups"),
        StatusLevel.GREEN,
        _("Verified off-server pair"),
        _("Database and media were uploaded and their remote checksums verified."),
    )


def _check_fx_freshness() -> SubsystemStatus:
    """FX-rate freshness for foreign-currency issuance (#103), guarded so an unexpected
    error cannot silently disable the daily FX pager.

    This guard also covers live dashboard reads outside the check aggregator. Errors
    remain RED, never GREY: unknown freshness must not clear the alert dedup as recovery.
    """
    try:
        return _compute_fx_freshness()
    except Exception:  # a status check must degrade to RED, never take the task down
        logger.warning("🔴 [SystemStatus] FX freshness check errored")
        return SubsystemStatus(
            name=_("FX rates"),
            level=StatusLevel.RED,
            message=_("Freshness check errored"),
            detail=_("Could not verify FX freshness; foreign-currency issuance remains unverified."),
        )


def _compute_fx_freshness() -> SubsystemStatus:
    """Resolver-accurate, computed LIVE (never trusts a cached level for its
    date-sensitivity): for each configured foreign pair it attempts today's
    currency->home-currency resolution with the same semantics ``Invoice.issue()`` uses.
    RED  = a pair cannot resolve today (missing / unprovenanced) → foreign issuance
           for it is blocked;
    AMBER= resolves but the rate is older than the staleness window, or the last daily
           fetch failed while last-good rates still resolve;
    GREEN= every configured pair resolves and is fresh;
    GREY = no foreign pairs configured.
    """
    from apps.billing.exchange_rate_service import ExchangeRateError, ExchangeRateService  # noqa: PLC0415
    from apps.settings.services import SettingsService  # noqa: PLC0415

    pairs = [str(c).strip().upper() for c in SettingsService.get_list_setting("billing.fx.pairs", ["EUR", "USD"])]
    from apps.billing.currency_service import home_currency  # noqa: PLC0415

    home = home_currency()
    foreign = [c for c in pairs if c and c != home]
    if not foreign:
        return SubsystemStatus(
            name=_("FX rates"),
            level=StatusLevel.GREY,
            message=_("No foreign currencies"),
            detail=format_lazy(_("No currencies differ from the home currency ({home})."), home=home),
        )

    today = timezone.localdate()
    stale_after = SettingsService.get_integer_setting("billing.fx.stale_after_days", 4)
    missing: list[str] = []
    stale: list[str] = []
    for code in foreign:
        try:
            snapshot = ExchangeRateService.resolve(code, home, today)
        except ExchangeRateError:
            missing.append(code)
            continue
        if snapshot.as_of < today - timedelta(days=stale_after):
            stale.append(_("%(code)s (as of %(date)s)") % {"code": code, "date": snapshot.as_of})

    # H3: a failed daily fetch must stay visible even when last-good rates still resolve.
    fetch_failure = cache.get(_FX_FETCH_OUTCOME_KEY)

    if missing:
        return SubsystemStatus(
            name=_("FX rates"),
            level=StatusLevel.RED,
            message=format_lazy(_("No usable rate today: {currencies}"), currencies=", ".join(missing)),
            detail=_("Foreign-currency issuance is blocked for these until a provenanced rate is provisioned."),
        )
    if stale:
        return SubsystemStatus(
            name=_("FX rates"),
            level=StatusLevel.AMBER,
            message=format_lazy(_("Stale (> {days}d): {currencies}"), days=stale_after, currencies=", ".join(stale)),
            detail=_("Rates still resolve, but a fresher publication is overdue."),
        )
    if fetch_failure:
        return SubsystemStatus(
            name=_("FX rates"),
            level=StatusLevel.AMBER,
            message=_("Last BNR fetch failed"),
            detail=_(
                "All pairs still resolve on last-good rates, but the most recent ingestion failed. Fix ingestion before the rates go stale."
            ),
        )
    return SubsystemStatus(
        name=_("FX rates"),
        level=StatusLevel.GREEN,
        message=_("Fresh"),
        detail=format_lazy(_("Resolvable today: {currencies}"), currencies=", ".join(foreign)),
    )


def check_all_subsystems() -> list[SubsystemStatus]:
    """Isolate individual failures and share one external-work deadline."""
    from apps.provisioning.scheduled_backups import customer_backup_health  # noqa: PLC0415

    budget = ProbeBudget()
    checks: list[tuple[str, str | Promise, Callable[[], SubsystemStatus]]] = [
        ("database", _("Database"), _check_database),
        ("hmac", _("Portal Auth"), _check_hmac),
        ("email", _("Email"), lambda: _check_email(budget)),
        ("stripe", _("Stripe"), lambda: _check_stripe(budget)),
        ("efactura", _("e-Factura"), lambda: _check_efactura(budget)),
        ("encryption", _("Encryption"), _check_encryption),
        ("vault", _("Credential Vault"), _check_credential_vault),
        ("sentry", _("Sentry"), _check_sentry),
        ("backup", _("Backup"), _check_backup),
        ("hosting_backups", _("Customer hosting backups"), customer_backup_health),
        ("fx", _("FX rates"), _check_fx_freshness),
    ]
    results = []
    for key, name, check in checks:
        try:
            if key == "efactura" and not operator_is_romanian():
                continue
            result = check()
        except Exception:  # Health-check boundary; never expose raw exception text or suppress other checks.
            result = SubsystemStatus(
                name, StatusLevel.RED, _("Check failed"), _("This subsystem could not be verified.")
            )
        results.append(replace(result, key=key, checked_at=timezone.now()))
        if result.level in (StatusLevel.AMBER, StatusLevel.RED):
            logger.warning("⚠️ [SystemStatus] %s: %s", key, result.message)
    return results


def get_cached_status() -> StatusSnapshot:
    """Never contact providers on GET; recompute date-sensitive FX locally."""
    try:
        snapshot = cache.get(CACHE_KEY)
    except Exception:
        logger.warning("⚠️ [SystemStatus] Snapshot cache unavailable")
        return StatusSnapshot([], cache_available=False)
    if not isinstance(snapshot, StatusSnapshot) or snapshot.version != SNAPSHOT_VERSION:
        return StatusSnapshot([])
    results = [
        replace(_check_fx_freshness(), key="fx", checked_at=timezone.now()) if row.key == "fx" else row
        for row in snapshot.results
    ]
    from apps.common.status_models import SystemCheckState  # noqa: PLC0415

    try:
        with transaction.atomic():
            owner = SystemCheckState.objects.filter(check_key="status_refresh", node=None).first()
            current_identity = runtime_input_identity() if owner or snapshot.input_identity else ""
            if (
                owner and (owner.input_identity != current_identity or snapshot.input_identity != current_identity)
            ) or (snapshot.input_identity and owner is None):
                results = [
                    replace(row, level=StatusLevel.AMBER, message=_("Unknown · configuration changed"))
                    for row in results
                ]
    except (DatabaseError, InterfaceError):
        results = [
            replace(row, level=StatusLevel.AMBER, message=_("Unknown · current state unavailable")) for row in results
        ]
    if snapshot.stale:
        results = [
            row if row.key == "fx" else replace(row, level=StatusLevel.AMBER, message=_("Unknown · check overdue"))
            for row in results
        ]
    return replace(snapshot, results=results)


def refresh_and_cache_status() -> StatusSnapshot:
    """Manual and scheduled checks share one writer; cache failure cannot discard results."""
    snapshot = StatusSnapshot(check_all_subsystems(), checked_at=timezone.now())
    return _cache_status(snapshot)


def _cache_status(snapshot: StatusSnapshot) -> StatusSnapshot:
    try:
        cache.set(CACHE_KEY, snapshot, timeout=CACHE_TIMEOUT)
        # DatabaseCache can swallow write errors. A read-back must confirm this
        # write (or a concurrent newer one), not merely the absence of an exception.
        persisted = cache.get(CACHE_KEY)
        confirmed = (
            isinstance(persisted, StatusSnapshot)
            and persisted.version == SNAPSHOT_VERSION
            and (
                persisted.check_id == snapshot.check_id
                or (
                    persisted.checked_at is not None
                    and snapshot.checked_at is not None
                    and persisted.checked_at > snapshot.checked_at
                )
            )
        )
        if not confirmed:
            logger.warning("⚠️ [SystemStatus] Snapshot write could not be confirmed")
            return replace(snapshot, saved=False, cache_available=False)
    except Exception:
        logger.warning("⚠️ [SystemStatus] Results computed but snapshot could not be saved")
        return replace(snapshot, saved=False, cache_available=False)
    return snapshot


def runtime_input_identity() -> str:
    """Private configuration identity; never publish the inputs or their fingerprint."""
    from apps.settings.models import SystemSetting  # noqa: PLC0415

    runtime = (
        "EMAIL_BACKEND",
        "EMAIL_HOST",
        "EMAIL_PORT",
        "EMAIL_HOST_USER",
        "EMAIL_HOST_PASSWORD",
        "DEFAULT_FROM_EMAIL",
        "PLATFORM_API_SECRET",
        "PORTAL_HMAC_CREDENTIALS",
        "ENCRYPTION_KEYS",
        "CREDENTIAL_VAULT_MASTER_KEY",
        "ANYMAIL",
    )
    data = (
        [str(getattr(settings, name, "")) for name in runtime],
        list(
            SystemSetting.objects.order_by("key").values_list(
                "key", "revision", "value", "default_value", "data_type", "is_sensitive", "is_active"
            )
        ),
    )
    return salted_hmac("praho.system-check.v2", json.dumps(data, sort_keys=True), algorithm="sha256").hexdigest()


def run_status_refresh(*, force: bool = False) -> StatusSnapshot:
    """Shared worker entry point: no network under locks and no obsolete publication."""
    from apps.common.status_models import SystemCheckState  # noqa: PLC0415
    from apps.common.status_observations import (  # noqa: PLC0415
        Observation,
        claim_check,
        finish_check,
        prune_hourly_summaries,
    )

    identity = runtime_input_identity()
    previous = SystemCheckState.objects.filter(check_key="status_refresh", node__isnull=True).first()
    if (
        not force
        and previous
        and previous.input_identity == identity
        and previous.observed_at
        and timezone.now() - previous.observed_at < timedelta(minutes=10)
    ):
        return get_cached_status()
    claim = claim_check("status_refresh", identity=identity)
    if claim is None:
        return get_cached_status()
    snapshot = StatusSnapshot(check_all_subsystems(), checked_at=timezone.now(), input_identity=claim.input_identity)

    def publish() -> None:
        for result in snapshot.results:
            row, _ = SystemCheckState.objects.get_or_create(check_key=result.key, node__isnull=True)
            if row.level != result.level.value:
                row.changed_at = timezone.now()
            row.level = result.level.value
            row.input_identity = claim.input_identity
            row.reason = "observed"
            row.details = {
                "name": str(result.name)[:500],
                "message": str(result.message)[:500],
                "detail": str(result.detail)[:500],
            }
            row.observed_at = result.checked_at
            row.last_attempt_at = claim.started_at
            if result.level == StatusLevel.GREEN:
                row.last_success_at = result.checked_at
            row.save()

    accepted = finish_check(
        claim,
        identity=runtime_input_identity,
        observation=Observation("green", "observed", {"message": "Background checks"}),
        on_accept=publish,
    )
    prune_hourly_summaries()
    if accepted:
        # Evidence must commit before an external cache can expose it. Re-lock the owner
        # while caching so an older publisher cannot overwrite a newer accepted snapshot.
        with transaction.atomic():
            current = SystemCheckState.objects.select_for_update().get(pk=claim.state_id)
            if current.sequence == claim.sequence and current.claim_token is None:
                return _cache_status(snapshot)
    return get_cached_status()
