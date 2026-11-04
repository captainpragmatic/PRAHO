"""Fixed privacy-preserving Portal authentication events for local host detection."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from io import TextIOWrapper
from logging.handlers import RotatingFileHandler
from time import monotonic, sleep
from typing import TYPE_CHECKING, Any, NoReturn, TextIO

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest
from django.utils import timezone

from apps.common.request_ip import get_safe_client_ip

EVENT_LOGGER = logging.getLogger("praho.crowdsec.auth")
logger = logging.getLogger(__name__)
EVENTS = frozenset({"auth_failure", "mfa_failure", "password_reset_request", "throttle_refusal", "protection_degraded"})
REASONS = frozenset(
    {
        "credentials",
        "second_factor",
        "policy_refusal",
        "login",
        "mfa",
        "reset",
        "password_reset",
        "registration",
        "upstream_unavailable",
        "unclassified_response",
        "observation_failed",
        "client_ip_unavailable",
    }
)
HEALTH_KEYS = {
    "auth_events": "crowdsec:health:auth-events",
    "customer_ip_observations": "crowdsec:health:customer-ip-observations",
}
MAX_ACCOUNT_BYTES = 512
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
WRITER_LOCK_SECONDS = 0.1
WRITER_LOCK_POLL_SECONDS = 0.005
_health_store_available = True


class _RaiseHandlerErrors:
    def handleError(self, record: logging.LogRecord) -> NoReturn:  # noqa: N802 -- stdlib logging override
        raise OSError("Security event recording unavailable")


if TYPE_CHECKING:
    _EventStreamHandler = logging.StreamHandler[TextIO]
else:
    _EventStreamHandler = logging.StreamHandler


class SecurityEventStreamHandler(_RaiseHandlerErrors, _EventStreamHandler):
    """Let the caller observe a failed write, without changing authentication."""


class SecurityEventFileHandler(_RaiseHandlerErrors, RotatingFileHandler):
    """Keep bounded event files inside the pre-provisioned private Portal directory."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            with self._writer_lock():
                # Another Gunicorn worker may have rotated the inode since our last event.
                if self.stream is not None:
                    self.stream.close()
                self.stream = self._open()
                super().emit(record)
        except Exception:
            self.handleError(record)

    @contextmanager
    def _writer_lock(self) -> Iterator[None]:
        # Open separately for every write; an inherited pre-fork descriptor shares flock ownership.
        with self._private_open(self.baseFilename + ".lock") as lock:
            deadline = monotonic() + WRITER_LOCK_SECONDS
            while True:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if monotonic() >= deadline:
                        raise OSError("Security event writer is busy") from None
                    sleep(WRITER_LOCK_POLL_SECONDS)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _open(self) -> TextIOWrapper[Any]:
        return self._private_open(self.baseFilename)

    def _private_open(self, path: str) -> TextIOWrapper[Any]:
        parent, filename = os.path.split(path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptor = None
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != PRIVATE_DIRECTORY_MODE:
                raise OSError("Security event directory must be privately owned")
            descriptor = os.open(
                filename,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                PRIVATE_FILE_MODE,
                dir_fd=directory,
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE
            ):
                raise OSError("Security event file must be private and regular")
            stream = open(descriptor, "a", encoding=self.encoding, errors=self.errors, closefd=True)  # noqa: SIM115  # The logging handler owns and closes this validated stream.
            descriptor = None
            return stream
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)


def _event_handler() -> SecurityEventFileHandler | SecurityEventStreamHandler | None:
    if not EVENT_LOGGER.isEnabledFor(logging.INFO) or len(EVENT_LOGGER.handlers) != 1:
        return None
    handler = EVENT_LOGGER.handlers[0]
    if handler.level > logging.INFO or getattr(handler, "_closed", False):
        return None
    path = getattr(settings, "CROWDSEC_AUTH_LOG_PATH", "")
    if path:
        if isinstance(handler, SecurityEventFileHandler) and handler.baseFilename == os.path.abspath(path):
            return handler
    elif isinstance(handler, SecurityEventStreamHandler):
        return handler
    return None


def _write_auth_event(message: str) -> None:
    handler = _event_handler()
    if handler is None:
        raise OSError("Dedicated security event writer is unavailable")
    record = EVENT_LOGGER.makeRecord(EVENT_LOGGER.name, logging.INFO, __file__, 0, message, (), None)
    filtered = EVENT_LOGGER.filter(record)
    if not filtered:
        raise OSError("Security event was filtered")
    if isinstance(filtered, logging.LogRecord):
        record = filtered
    # Handle only the approved sink, never an ordinary logger reached by propagation.
    # Handler.handle() reports filter refusal; the dedicated emitters raise on I/O failure.
    if not handler.handle(record):
        raise OSError("Security event was not recorded")


def account_pseudonym(value: str, *, at: datetime | None = None) -> str:
    now = (at or timezone.now()).astimezone(UTC)
    secret = getattr(settings, "CROWDSEC_AUTH_PSEUDONYM_KEY", "") or settings.SECRET_KEY
    if not isinstance(secret, str) or not secret:
        raise ValueError("An event pseudonym key is required")
    daily_key = hmac.digest(
        secret.encode(), b"praho/crowdsec/portal-auth/v1/day\0" + now.date().isoformat().encode(), "sha256"
    )
    identifier = value.strip().lower().encode()[:MAX_ACCOUNT_BYTES]
    return hmac.new(daily_key, b"account\0" + identifier, hashlib.sha256).hexdigest()


def _cache_health(values: dict[str, bool]) -> None:
    global _health_store_available  # noqa: PLW0603  # Per-worker fail state supplements shared-cache health.
    try:
        for key, value in values.items():
            cache.set(key, value, timeout=None)
    except Exception:
        _health_store_available = False
    else:
        _health_store_available = True


def _health(name: str, healthy: bool) -> None:
    _cache_health({HEALTH_KEYS[name]: healthy})


def _degraded_health(enabled: bool) -> dict[str, bool]:
    return {
        "auth_events_enabled": enabled,
        "auth_events": False,
        "customer_ip_observations_enabled": False,
        "customer_ip_observations": False,
    }


def recording_health() -> dict[str, bool]:
    enabled = bool(getattr(settings, "CROWDSEC_AUTH_EVENTS_ENABLED", False))
    if not _health_store_available:
        return _degraded_health(enabled)
    try:
        return {
            "auth_events_enabled": enabled,
            "auth_events": enabled
            and _event_handler() is not None
            and cache.get(HEALTH_KEYS["auth_events"], False) is True,
            "customer_ip_observations_enabled": cache.get("crowdsec:health:customer-ip-enabled", False) is True,
            "customer_ip_observations": cache.get(HEALTH_KEYS["customer_ip_observations"], False) is True,
        }
    except Exception:
        return _degraded_health(enabled)


def observation_health(state: object) -> None:
    enabled = healthy = False
    if (
        isinstance(state, dict)
        and set(state) == {"enabled", "recorded", "degraded"}
        and all(type(value) is bool for value in state.values())
    ):
        enabled = state["enabled"] is True
        healthy = enabled and state["degraded"] is False
    _cache_health(
        {
            HEALTH_KEYS["customer_ip_observations"]: healthy,
            "crowdsec:health:customer-ip-enabled": enabled,
        }
    )


def _account(request: HttpRequest) -> str | None:
    value = request.POST.get("email") or request.session.get("email")
    if not isinstance(value, str) or not value:
        identifier = request.session.get("user_id")
        value = f"user:{identifier}" if isinstance(identifier, (int, str)) else None
    return value


def emit_auth_event(request: HttpRequest, event: str, reason: str) -> bool:
    """Only enumerated metadata leaves the request; recording never refuses a login."""
    if not getattr(settings, "CROWDSEC_AUTH_EVENTS_ENABLED", False):
        return False
    try:
        if event not in EVENTS or reason not in REASONS:
            raise ValueError("Unrecognized authentication event")
        # Limiter imports this event writer.
        from apps.common.rate_limiting import _client_ip_is_distinguishable  # noqa: PLC0415

        raw_ip = get_safe_client_ip(request)
        address = ipaddress.ip_address(raw_ip) if "%" not in raw_ip else None
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        ip = str(address) if address is not None else None
        if not _client_ip_is_distinguishable() or ip is None:
            event, reason, ip = "protection_degraded", "client_ip_unavailable", None
        now = timezone.now().astimezone(UTC)
        account = _account(request)
        payload = {
            "schema": 1,
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "event": event,
            "ip": ip,
            "account": account_pseudonym(account, at=now) if account else None,
            "reason": reason,
        }
        _write_auth_event(json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False))
        _health("auth_events", True)
        return True
    except Exception:
        _health("auth_events", False)
        try:
            logger.critical("Portal authentication event recording is degraded")
        except Exception:
            return False  # The failed writer and health state are already recorded above.
        return False


def record_auth_refusal(request: HttpRequest, category: object) -> None:
    if category == "credentials":
        emit_auth_event(request, "auth_failure", "credentials")
    elif category == "second_factor":
        emit_auth_event(request, "mfa_failure", "second_factor")
    elif category == "policy_refusal":
        emit_auth_event(request, "protection_degraded", "policy_refusal")
    else:
        emit_auth_event(request, "protection_degraded", "unclassified_response")
