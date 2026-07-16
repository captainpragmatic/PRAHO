"""
Abstract base class for domain registrar gateways.

Follows the billing gateway ABC + factory pattern and cloud gateway Result[T, E] pattern.
All registrar HTTP goes through safe_request() with a per-registrar OutboundPolicy.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.cache import cache

from apps.common.outbound_http import OutboundPolicy, safe_request
from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from .errors import (
    RegistrarAPIError,
    RegistrarAuthError,
    RegistrarConflictError,
    RegistrarErrorCode,
    RegistrarNotFoundError,
    RegistrarRateLimitError,
    RegistrarTransientError,
)

if TYPE_CHECKING:
    import requests

    from apps.domains.models import Registrar

logger = logging.getLogger(__name__)

# Circuit breaker defaults
CIRCUIT_BREAKER_THRESHOLD = 5  # failures before tripping
CIRCUIT_BREAKER_RESET_SECONDS = 300  # 5 minutes
IDEMPOTENCY_TTL_SECONDS = 3600  # 1 hour
# Sentinel stored under the idempotency key while a registrar call is in flight, so a
# second concurrent request for the same domain is rejected instead of issuing a
# duplicate (and chargeable) registration. Replaced with the real result on success.
_IDEMPOTENCY_IN_PROGRESS = "__in_progress__"


def _redact_secrets(result: Any) -> Any:
    """Return a copy of a gateway result with any secret-bearing field cleared.

    Used before writing a result to the plaintext idempotency cache — the EPP/auth
    transfer code must never be persisted there (it is stored encrypted on the
    Domain row instead).
    """
    if isinstance(result, DomainRegistrationResult) and result.epp_code:
        return replace(result, epp_code="")
    return result


# Retry defaults
MAX_RETRIES = 3
BACKOFF_BASE_SECONDS = 0.5

# Registrar JSON responses are small (domain/order records). Cap the body before
# deserializing so a malicious or misbehaving registrar can't exhaust memory (M5).
MAX_RESPONSE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

# HTTP status codes used in error mapping
HTTP_OK = 200
HTTP_CREATED = 201
HTTP_ACCEPTED = 202
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409
HTTP_UNPROCESSABLE = 422
HTTP_RATE_LIMITED = 429
HTTP_SERVER_ERROR = 500


# ===============================================================================
# RESULT TYPES
# ===============================================================================


@dataclass(frozen=True)
class DomainRegistrationResult:
    """Successful domain registration response from a registrar."""

    registrar_domain_id: str
    expires_at: datetime
    nameservers: list[str]
    epp_code: str = ""


@dataclass(frozen=True)
class DomainRenewalResult:
    """Successful domain renewal response from a registrar."""

    new_expires_at: datetime


@dataclass(frozen=True)
class DomainAvailabilityResult:
    """Domain availability check response from a registrar."""

    domain_name: str
    available: bool
    premium: bool = False
    price_cents: int | None = None
    checked: bool = True  # False when the registrar check FAILED — 'available' is then not meaningful


# -- Phase 2 result types ---------------------------------------------------


@dataclass(frozen=True)
class DomainTransferResult:
    """Result from initiating a domain transfer."""

    transfer_id: str
    status: str  # e.g. "pending", "approved", "rejected"
    expected_completion: datetime | None = None


@dataclass(frozen=True)
class DomainInfoResult:
    """Current domain state at the registrar."""

    registrar_domain_id: str
    domain_name: str
    status: str
    expires_at: datetime | None
    nameservers: list[str]
    locked: bool = False
    whois_privacy: bool = False
    epp_code: str = ""


@dataclass(frozen=True)
class NameserverUpdateResult:
    """Result from a nameserver update operation."""

    nameservers: list[str]


@dataclass(frozen=True)
class DomainLockResult:
    """Result from a lock/unlock operation."""

    locked: bool


# ===============================================================================
# ABSTRACT BASE GATEWAY
# ===============================================================================


class BaseRegistrarGateway(ABC):
    """Abstract base class for all domain registrar gateways.

    Subclasses implement the four core operations against a specific registrar API.
    The base class provides: circuit breaker, idempotency, retry with backoff,
    SSRF-safe HTTP via OutboundPolicy, and audit logging.
    """

    def __init__(self, registrar: Registrar) -> None:
        self.registrar = registrar
        self.logger = logging.getLogger(f"apps.domains.gateways.{self.gateway_name}")

    # -- Abstract interface --------------------------------------------------

    @property
    @abstractmethod
    def gateway_name(self) -> str:
        """Machine-readable gateway identifier (e.g. 'gandi', 'rotld')."""

    @abstractmethod
    def _get_outbound_policy(self) -> OutboundPolicy:
        """Return the OutboundPolicy for this registrar's API."""

    @abstractmethod
    def _do_register(
        self,
        domain_name: str,
        years: int,
        registrant_data: dict[str, Any],
        nameservers: list[str] | None,
    ) -> Result[DomainRegistrationResult, RegistrarAPIError]:
        """Registrar-specific registration logic."""

    @abstractmethod
    def _do_renew(
        self,
        registrar_domain_id: str,
        domain_name: str,
        years: int,
    ) -> Result[DomainRenewalResult, RegistrarAPIError]:
        """Registrar-specific renewal logic."""

    @abstractmethod
    def _do_check_availability(
        self,
        domain_name: str,
    ) -> Result[DomainAvailabilityResult, RegistrarAPIError]:
        """Registrar-specific availability check."""

    @abstractmethod
    def _do_verify_webhook(self, payload: str, signature: str, secret: str) -> bool:
        """Registrar-specific webhook signature verification."""

    # -- Phase 2 optional interface (override to enable) ---------------------

    def _do_initiate_transfer(
        self,
        domain_name: str,
        epp_code: str,
    ) -> Result[DomainTransferResult, RegistrarAPIError]:
        """Registrar-specific transfer initiation. Override to enable."""
        raise NotImplementedError(f"{self.gateway_name} does not support transfers")

    def _do_get_domain_info(
        self,
        domain_name: str,
    ) -> Result[DomainInfoResult, RegistrarAPIError]:
        """Registrar-specific domain info retrieval. Override to enable."""
        raise NotImplementedError(f"{self.gateway_name} does not support domain info")

    def _do_update_nameservers(
        self,
        domain_name: str,
        nameservers: list[str],
    ) -> Result[NameserverUpdateResult, RegistrarAPIError]:
        """Registrar-specific nameserver update. Override to enable."""
        raise NotImplementedError(f"{self.gateway_name} does not support nameserver updates")

    def _do_set_lock(
        self,
        domain_name: str,
        locked: bool,
    ) -> Result[DomainLockResult, RegistrarAPIError]:
        """Registrar-specific lock/unlock. Override to enable."""
        raise NotImplementedError(f"{self.gateway_name} does not support lock/unlock")

    def _do_check_availability_bulk(
        self,
        domain_names: list[str],
    ) -> Result[list[DomainAvailabilityResult], RegistrarAPIError]:
        """Bulk availability check. Override for registrar-native batch API."""
        # Default: sequential fallback
        results: list[DomainAvailabilityResult] = []
        for name in domain_names:
            r = self._do_check_availability(name)
            if r.is_ok():
                results.append(r.unwrap())
            else:
                # A failed check is NOT "taken": mark checked=False so callers can tell a
                # registrar outage from a genuinely-registered domain (M9).
                results.append(DomainAvailabilityResult(domain_name=name, available=False, checked=False))
        return Ok(results)

    # -- Public interface (with circuit breaker + idempotency) ----------------

    def register_domain(
        self,
        domain_name: str,
        years: int,
        registrant_data: dict[str, Any],
        nameservers: list[str] | None = None,
    ) -> Result[DomainRegistrationResult, RegistrarAPIError]:
        """Register a domain, with circuit breaker and idempotency protection."""
        if guard := self._verified_adapter_guard():
            return guard
        return self._execute_idempotent_operation(
            idempotency_key=f"domain_reg:{self.gateway_name}:{domain_name}",
            fn=lambda: self._do_register(domain_name, years, registrant_data, nameservers),
            operation=f"register:{domain_name}",
            audit_event="domain_registration",
            domain_name=domain_name,
        )

    def renew_domain(
        self,
        registrar_domain_id: str,
        domain_name: str,
        years: int,
    ) -> Result[DomainRenewalResult, RegistrarAPIError]:
        """Renew a domain, with circuit breaker and idempotency protection."""
        if guard := self._verified_adapter_guard():
            return guard
        return self._execute_idempotent_operation(
            idempotency_key=f"domain_renew:{self.gateway_name}:{domain_name}:{years}",
            fn=lambda: self._do_renew(registrar_domain_id, domain_name, years),
            operation=f"renew:{domain_name}",
            audit_event="domain_renewal",
            domain_name=domain_name,
            audit_metadata={"years": years},
        )

    def _verified_adapter_guard(self) -> Err[RegistrarAPIError] | None:
        """Refuse chargeable register/renew calls until the adapter is sandbox-verified.

        The concrete response schemas were built from documentation without a live
        sandbox; ``settings.REGISTRAR_ADAPTERS_VERIFIED`` must be flipped on by an
        operator after validating an adapter against the real registrar. Returns an
        Err to short-circuit, or None when verified.
        """
        from django.conf import settings  # noqa: PLC0415  # avoid import-time settings access

        if getattr(settings, "REGISTRAR_ADAPTERS_VERIFIED", False):
            return None
        return Err(
            RegistrarAPIError(
                f"{self.gateway_name} adapter is not verified against the registrar sandbox; "
                "refusing chargeable operation (set REGISTRAR_ADAPTERS_VERIFIED=true once validated)",
                code=RegistrarErrorCode.NOT_CONFIGURED,
                registrar_name=self.registrar.name,
            ),
            # Definite refusal, not a transient state: the registration lifecycle must
            # delete the pending row so the domain can be registered once verified,
            # rather than stranding it as pending_unknown forever.
            retriability=Retriability.NOT_RETRIABLE,
        )

    def _run_phase2_op(self, fn: Any, operation: str, unsupported: str) -> Result[Any, RegistrarAPIError]:
        """Run a Phase 2 gateway op through _retry, converting every escape into a graceful Err.

        The Phase 2 public methods are the fail-closed boundary: a gateway that raises
        NotImplementedError (adapter doesn't support the op), a RegistrarAPIError, or an
        unexpected exception (e.g. a malformed 200 body in response.json()) must NOT
        propagate to the service layer as an unhandled crash. NotImplementedError is a
        permanent NOT_RETRIABLE refusal; other escapes stay UNKNOWN (a mutation may have
        applied).
        """
        try:
            return self._retry(fn, operation=operation)
        except NotImplementedError:
            return Err(
                RegistrarAPIError(
                    unsupported, code=RegistrarErrorCode.INTERNAL_ERROR, registrar_name=self.registrar.name
                ),
                retriability=Retriability.NOT_RETRIABLE,
            )
        except RegistrarAPIError as exc:
            return Err(exc)
        except Exception as exc:
            return Err(
                RegistrarAPIError(
                    f"Unexpected error during {operation}",
                    code=RegistrarErrorCode.INTERNAL_ERROR,
                    registrar_name=self.registrar.name,
                    detail=str(exc),
                )
            )

    def _execute_idempotent_operation(  # noqa: PLR0913  # cohesive call + audit context for one op
        self,
        idempotency_key: str,
        fn: Any,
        operation: str,
        audit_event: str,
        domain_name: str,
        audit_metadata: dict[str, Any] | None = None,
    ) -> Result[Any, RegistrarAPIError]:
        """Run a state-changing registrar call with circuit-breaker + idempotency.

        Idempotency claims the key atomically *before* the call (cache.add), so a
        second concurrent request for the same domain is refused instead of issuing
        a duplicate, chargeable operation — the previous get-then-call had a window
        where two requests both missed the cache and both called the registrar. The
        claim is replaced with the result on success and released on failure so a
        legitimate retry can proceed.
        """
        if err := self._check_circuit_breaker():
            return err

        cached = cache.get(idempotency_key)
        if cached is not None and cached != _IDEMPOTENCY_IN_PROGRESS:
            self.logger.info("Idempotency hit for %s", operation)
            return Ok(cached)

        # Atomically claim the slot. add() only succeeds if the key is absent, so a
        # concurrent in-flight request loses the race and is rejected.
        if not cache.add(idempotency_key, _IDEMPOTENCY_IN_PROGRESS, IDEMPOTENCY_TTL_SECONDS):
            existing = cache.get(idempotency_key)
            if existing is not None and existing != _IDEMPOTENCY_IN_PROGRESS:
                return Ok(existing)
            self.logger.warning("Concurrent %s already in progress — rejecting duplicate", operation)
            return Err(RegistrarConflictError(domain_name, self.registrar.name))

        # Exception-safety: _retry(fn) can raise (e.g. _safe_json → RegistrarAPIError on
        # an oversized body). Convert any escape to an Err so the claim-release path below
        # always runs — otherwise the in-progress claim would strand the key for the full
        # TTL and block every legitimate retry.
        try:
            result = self._retry(fn, operation=operation)
        except RegistrarAPIError as exc:
            result = Err(exc)
        except Exception as exc:
            result = Err(
                RegistrarAPIError(
                    f"Unexpected error during {operation}",
                    code=RegistrarErrorCode.INTERNAL_ERROR,
                    registrar_name=self.registrar.name,
                    detail=str(exc),
                )
            )

        if result.is_ok():
            # Cache a secret-free copy: the EPP/auth code is a transfer credential and
            # the idempotency cache is plaintext (DatabaseCache/Redis). The immediate
            # caller still receives the full result (with the EPP) to store encrypted;
            # only the replay copy is redacted.
            cache.set(idempotency_key, _redact_secrets(result.unwrap()), IDEMPOTENCY_TTL_SECONDS)
            self._record_success()
            self.logger.info("%s succeeded via %s", operation, self.gateway_name)
            self._audit_api_call(audit_event, domain_name, success=True, metadata=audit_metadata)
        else:
            cache.delete(idempotency_key)  # release the claim so a legitimate retry can proceed
            error = result.unwrap_err()
            self._record_failure(error)
            # Log/audit the machine-readable code, never the raw registrar body — it can
            # echo registrant PII (CNP, address) supplied in the request (W4).
            self.logger.error("%s failed with %s", operation, error.code.value)
            self._audit_api_call(
                audit_event, domain_name, success=False, error=error.code.value, metadata=audit_metadata
            )

        return result

    def check_availability(
        self,
        domain_name: str,
    ) -> Result[DomainAvailabilityResult, RegistrarAPIError]:
        """Check domain availability (no idempotency needed, but respects circuit breaker)."""
        if err := self._check_circuit_breaker():
            return err

        # Exception-safety: _safe_json (oversized/malformed body) or credential
        # decryption can raise out of the availability lambda. Convert to an Err so the
        # AJAX endpoint fails closed ("could not verify") instead of returning a 500.
        try:
            result = self._retry(
                lambda: self._do_check_availability(domain_name),
                operation=f"check:{domain_name}",
                retry_on_unknown=True,  # availability is a safe read — replaying it is harmless
            )
        except RegistrarAPIError as exc:
            result = Err(exc)
        except Exception as exc:
            result = Err(
                RegistrarAPIError(
                    f"Unexpected error during availability check for {domain_name}",
                    code=RegistrarErrorCode.INTERNAL_ERROR,
                    registrar_name=self.registrar.name,
                    detail=str(exc),
                )
            )

        if result.is_ok():
            self._record_success()
        else:
            error = result.unwrap_err()
            self._record_failure(error)
            self._audit_api_call("domain_availability_check", domain_name, success=False, error=error.code.value)

        return result

    def verify_webhook_signature(self, payload: str, signature: str) -> bool:
        """Verify webhook signature. Fail-closed: returns False on any error."""
        if not signature:
            return False

        try:
            secret = self.registrar.get_decrypted_webhook_secret()
        except Exception:
            self.logger.error("Webhook secret decryption failed for %s", self.registrar.name)
            return False

        if not secret or not secret.strip():
            self.logger.error("Webhook secret for %s is empty", self.registrar.name)
            return False

        return self._do_verify_webhook(payload, signature, secret.strip())

    # -- Phase 2 public interface --------------------------------------------

    def initiate_transfer(
        self,
        domain_name: str,
        epp_code: str,
    ) -> Result[DomainTransferResult, RegistrarAPIError]:
        """Initiate domain transfer with circuit breaker and atomic idempotency.

        The idempotency slot is claimed atomically (cache.add) BEFORE the registrar
        call, so two concurrent transfer requests for the same domain can't both submit
        a chargeable transfer — the loser of the add() race is rejected. The claim is
        replaced with the result on success and released on failure so a legitimate
        retry can proceed. (A bare get-then-call had a window where both requests missed
        the cache and both posted.)
        """
        if guard := self._verified_adapter_guard():
            return guard
        if err := self._check_circuit_breaker():
            return err

        idempotency_key = f"domain_transfer:{self.gateway_name}:{domain_name}"
        cached = cache.get(idempotency_key)
        if cached is not None and cached != _IDEMPOTENCY_IN_PROGRESS:
            self.logger.info("Idempotency hit for %s transfer", domain_name)
            return Ok(cached)

        # Atomically claim the slot before posting. add() only succeeds if the key is
        # absent, so a concurrent in-flight request loses the race and is rejected
        # instead of issuing a duplicate, chargeable transfer.
        if not cache.add(idempotency_key, _IDEMPOTENCY_IN_PROGRESS, IDEMPOTENCY_TTL_SECONDS):
            existing = cache.get(idempotency_key)
            if existing is not None and existing != _IDEMPOTENCY_IN_PROGRESS:
                return Ok(existing)
            self.logger.warning("Concurrent %s transfer already in progress — rejecting duplicate", domain_name)
            return Err(RegistrarConflictError(domain_name, self.registrar.name))

        result = self._run_phase2_op(
            lambda: self._do_initiate_transfer(domain_name, epp_code),
            operation=f"transfer:{domain_name}",
            unsupported=f"{self.gateway_name} does not support transfers",
        )

        if result.is_ok():
            cache.set(idempotency_key, _redact_secrets(result.unwrap()), IDEMPOTENCY_TTL_SECONDS)
            self._record_success()
            self._audit_api_call("domain_transfer", domain_name, success=True)
        else:
            cache.delete(idempotency_key)  # release the claim so a legitimate retry can proceed
            error = result.unwrap_err()
            self._record_failure(error)
            self._audit_api_call("domain_transfer", domain_name, success=False, error=error.code.value)

        return result

    def get_domain_info(
        self,
        domain_name: str,
    ) -> Result[DomainInfoResult, RegistrarAPIError]:
        """Get current domain state from the registrar (read-only — no verification guard)."""
        if err := self._check_circuit_breaker():
            return err

        result = self._run_phase2_op(
            lambda: self._do_get_domain_info(domain_name),
            operation=f"info:{domain_name}",
            unsupported=f"{self.gateway_name} does not support domain info",
        )

        if result.is_ok():
            self._record_success()
        else:
            self._record_failure(result.unwrap_err())

        return result

    def update_nameservers(
        self,
        domain_name: str,
        nameservers: list[str],
    ) -> Result[NameserverUpdateResult, RegistrarAPIError]:
        """Update domain nameservers at the registrar."""
        if guard := self._verified_adapter_guard():
            return guard
        if err := self._check_circuit_breaker():
            return err

        result = self._run_phase2_op(
            lambda: self._do_update_nameservers(domain_name, nameservers),
            operation=f"ns_update:{domain_name}",
            unsupported=f"{self.gateway_name} does not support nameserver updates",
        )

        if result.is_ok():
            self._record_success()
            self._audit_api_call("nameserver_update", domain_name, success=True, metadata={"nameservers": nameservers})
        else:
            error = result.unwrap_err()
            self._record_failure(error)
            self._audit_api_call("nameserver_update", domain_name, success=False, error=error.code.value)

        return result

    def set_lock(
        self,
        domain_name: str,
        locked: bool,
    ) -> Result[DomainLockResult, RegistrarAPIError]:
        """Lock or unlock a domain at the registrar."""
        if guard := self._verified_adapter_guard():
            return guard
        if err := self._check_circuit_breaker():
            return err

        result = self._run_phase2_op(
            lambda: self._do_set_lock(domain_name, locked),
            operation=f"lock:{domain_name}",
            unsupported=f"{self.gateway_name} does not support lock/unlock",
        )

        if result.is_ok():
            self._record_success()
            self._audit_api_call("domain_lock", domain_name, success=True, metadata={"locked": locked})
        else:
            error = result.unwrap_err()
            self._record_failure(error)
            self._audit_api_call("domain_lock", domain_name, success=False, error=error.code.value)

        return result

    def check_availability_bulk(
        self,
        domain_names: list[str],
    ) -> Result[list[DomainAvailabilityResult], RegistrarAPIError]:
        """Check availability of multiple domains in one call."""
        if err := self._check_circuit_breaker():
            return err

        # Exception-safety: _retry can raise (RegistrarAPIError / malformed body) out of
        # the bulk lambda; convert to an Err so a registrar outage fails closed instead of
        # surfacing as an unhandled 500 (mirrors check_availability).
        try:
            result = self._retry(
                lambda: self._do_check_availability_bulk(domain_names),
                operation=f"bulk_check:{len(domain_names)}_domains",
            )
        except RegistrarAPIError as exc:
            result = Err(exc)
        except Exception as exc:
            result = Err(
                RegistrarAPIError(
                    f"Unexpected error during bulk availability check ({len(domain_names)} domains)",
                    code=RegistrarErrorCode.INTERNAL_ERROR,
                    registrar_name=self.registrar.name,
                    detail=str(exc),
                )
            )

        if result.is_ok():
            self._record_success()
        else:
            self._record_failure(result.unwrap_err())

        return result

    # -- HTTP helper for subclasses ------------------------------------------

    def _api_request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Make an API request using safe_request() with this gateway's OutboundPolicy.

        Raises requests.RequestException on transport errors.
        """
        return safe_request(method, url, policy=self._get_outbound_policy(), **kwargs)

    def _safe_json(self, response: requests.Response) -> Any:
        """Parse a JSON response, rejecting oversized payloads (M5, defense-in-depth).

        ``safe_request`` does not cap body size, so guard before deserializing —
        a 5 MB JSON body explodes into a far larger Python object graph. Mirrors
        ``VirtualminGateway._validate_response_size``. Raises an INVALID_RESPONSE
        ``RegistrarAPIError`` when the declared or actual body exceeds the cap.
        """
        content_length = response.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > MAX_RESPONSE_SIZE_BYTES:
            raise RegistrarAPIError(
                f"{self.gateway_name} response too large: {content_length} bytes",
                code=RegistrarErrorCode.INVALID_RESPONSE,
                registrar_name=self.registrar.name,
            )
        if len(response.content) > MAX_RESPONSE_SIZE_BYTES:
            raise RegistrarAPIError(
                f"{self.gateway_name} response exceeds size limit ({MAX_RESPONSE_SIZE_BYTES} bytes)",
                code=RegistrarErrorCode.INVALID_RESPONSE,
                registrar_name=self.registrar.name,
            )
        return response.json()

    # -- Audit logging -------------------------------------------------------

    def _audit_api_call(
        self,
        event_type: str,
        domain_name: str,
        *,
        success: bool,
        error: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log an audit event for a registrar API call."""
        try:
            from apps.audit.services import AuditService  # noqa: PLC0415

            audit_metadata: dict[str, Any] = {
                "registrar": self.registrar.name,
                "gateway": self.gateway_name,
                "domain_name": domain_name,
                "success": success,
            }
            if error:
                audit_metadata["error"] = error[:500]
            if metadata:
                audit_metadata.update(metadata)

            AuditService.log_simple_event(
                f"registrar_api_{event_type}",
                description=f"{'OK' if success else 'FAIL'}: {event_type} for {domain_name} via {self.gateway_name}",
                metadata=audit_metadata,
                actor_type="system",
            )
        except Exception:
            self.logger.warning("Audit logging failed for %s:%s", event_type, domain_name, exc_info=True)

    # -- Circuit breaker (Django cache-backed) -------------------------------

    def _circuit_breaker_key(self) -> str:
        return f"cb:{self.gateway_name}:failures"

    def _check_circuit_breaker(self) -> Err[RegistrarAPIError] | None:
        failures = cache.get(self._circuit_breaker_key(), 0)
        if failures >= CIRCUIT_BREAKER_THRESHOLD:
            self.logger.warning("Circuit breaker OPEN for %s (%d failures)", self.gateway_name, failures)
            return Err(
                RegistrarTransientError(
                    self.registrar.name,
                    f"Circuit breaker open for {self.gateway_name} ({failures} consecutive failures)",
                ),
                # The call was never attempted while the breaker is open — provably safe to replay.
                retriability=Retriability.RETRIABLE,
            )
        return None

    def _record_failure(self, error: RegistrarAPIError) -> None:
        # Only systemic failures (transport/rate-limit/5xx) indicate a registrar-wide
        # outage worth tripping the breaker. A domain conflict, auth error, or invalid
        # registrant is request-specific and must NOT count — otherwise a burst of bad
        # requests would open the breaker for healthy traffic (W3).
        if not isinstance(error, RegistrarTransientError | RegistrarRateLimitError):
            return

        key = self._circuit_breaker_key()
        # Atomic first-failure seed: add() only succeeds if the key is absent, so two
        # concurrent first failures can't both reset the counter to 1 (W3). incr on an
        # existing key preserves the TTL set here, so the window doesn't slide and the
        # breaker auto-closes CIRCUIT_BREAKER_RESET_SECONDS after it first opened.
        if cache.add(key, 1, CIRCUIT_BREAKER_RESET_SECONDS):
            return
        try:
            cache.incr(key)
        except ValueError:
            # The key expired between add() and incr() — reseed.
            cache.set(key, 1, CIRCUIT_BREAKER_RESET_SECONDS)

    def _record_success(self) -> None:
        cache.delete(self._circuit_breaker_key())

    # -- Retry with exponential backoff --------------------------------------

    def _retry(
        self,
        fn: Any,
        operation: str,
        max_retries: int = MAX_RETRIES,
        *,
        retry_on_unknown: bool = False,
    ) -> Result[Any, RegistrarAPIError]:
        last_result: Result[Any, RegistrarAPIError] = Err(
            RegistrarAPIError("No attempts made", code=RegistrarErrorCode.INTERNAL_ERROR)
        )

        for attempt in range(max_retries):
            last_result = fn()

            if last_result.is_ok():
                return last_result

            # Honor the Retriability tag, NOT the error class: a mutating POST tagged
            # UNKNOWN (may have reached the registrar) must not be auto-replayed —
            # doing so risks a duplicate registration/renewal charge. Only RETRIABLE
            # (and, for idempotent reads, UNKNOWN) is safe to retry.
            error = last_result.unwrap_err()
            retriability = retriability_of(last_result)
            is_retryable = retriability == Retriability.RETRIABLE or (
                retry_on_unknown and retriability == Retriability.UNKNOWN
            )
            if not is_retryable or attempt == max_retries - 1:
                break

            backoff = BACKOFF_BASE_SECONDS * (2**attempt)
            self.logger.info(
                "Retrying %s (attempt %d/%d, backoff %.1fs): %s",
                operation,
                attempt + 1,
                max_retries,
                backoff,
                error,
            )
            time.sleep(backoff)

        return last_result

    # -- Default webhook HMAC-SHA256 verification ----------------------------

    @staticmethod
    def _verify_hmac_sha256(payload: str, signature: str, secret: str) -> bool:
        """Standard HMAC-SHA256 verification with timing-safe comparison."""
        expected = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(f"sha256={expected}", signature)

    # -- Shared HTTP error mapping -------------------------------------------

    def _handle_error_response(
        self, response: requests.Response, operation: str, domain_name: str = ""
    ) -> Err[RegistrarAPIError]:
        """Map HTTP error status codes to typed RegistrarAPIError variants.

        ``operation`` is a human label for the generic message (e.g. "register
        example.com"); ``domain_name`` is the bare domain used to build the typed
        not-found/conflict errors so their message reads "Domain 'example.com' ..."
        rather than leaking the operation label (M3).
        """
        status = response.status_code

        try:
            data = self._safe_json(response)
            message = data.get("message", data.get("error", response.text[:200]))
        except Exception:
            message = response.text[:200]

        # Single-exit mapping of HTTP status → (typed error, retriability). The retriability
        # tag is load-bearing: NOT_RETRIABLE lets the registration/transfer lifecycle delete the
        # pending row instead of stranding it as pending_unknown, which the domain-name uniqueness
        # precondition would then block forever (the #260 class).
        error: RegistrarAPIError
        retriability: Retriability
        if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
            # 401/403 are definite rejections (bad/insufficient credentials).
            detail = message if status == HTTP_UNAUTHORIZED else f"Forbidden: {message}"
            error = RegistrarAuthError(self.registrar.name, detail=detail)
            retriability = Retriability.NOT_RETRIABLE
        elif status == HTTP_NOT_FOUND:
            error = RegistrarNotFoundError(domain_name or operation, self.registrar.name)
            retriability = Retriability.NOT_RETRIABLE
        elif status == HTTP_CONFLICT:
            error = RegistrarConflictError(domain_name or operation, self.registrar.name)
            retriability = Retriability.NOT_RETRIABLE
        elif status == HTTP_RATE_LIMITED:
            # Retry-After may be an integer (seconds) or an HTTP-date; only the integer
            # form is usable and a non-integer must not raise out of error mapping.
            retry_after_raw = response.headers.get("Retry-After")
            retry_after = int(retry_after_raw) if retry_after_raw and retry_after_raw.isdigit() else None
            error = RegistrarRateLimitError(self.registrar.name, retry_after)
            # 429 means the registrar rejected the request before processing it — safe to replay.
            retriability = Retriability.RETRIABLE
        elif status >= HTTP_SERVER_ERROR:
            # A 5xx on a mutating call (register/renew) may have committed server-side;
            # this generic handler can't prove non-application, so leave it UNKNOWN.
            error = RegistrarTransientError(
                self.registrar.name, f"{self.gateway_name} server error ({status}): {message}"
            )
            retriability = Retriability.UNKNOWN
        elif status in (HTTP_BAD_REQUEST, HTTP_UNPROCESSABLE):
            # 400/422 are definite client-side rejections (bad EPP code, invalid registrant,
            # malformed request) — the registrar did NOT apply the operation. NOT_RETRIABLE so
            # the lifecycle deletes the pending row and a corrected retry can proceed.
            error = RegistrarAPIError(
                f"{self.gateway_name} rejected {operation}: {status} {message}",
                code=RegistrarErrorCode.INVALID_REGISTRANT_DATA,
                registrar_name=self.registrar.name,
            )
            retriability = Retriability.NOT_RETRIABLE
        else:
            # Unmapped status — can't prove non-application, leave UNKNOWN.
            error = RegistrarAPIError(
                f"{self.gateway_name} API error for {operation}: {status} {message}",
                code=RegistrarErrorCode.INTERNAL_ERROR,
                registrar_name=self.registrar.name,
            )
            retriability = Retriability.UNKNOWN

        return Err(error, retriability=retriability)


# ===============================================================================
# GATEWAY FACTORY
# ===============================================================================


class RegistrarGatewayFactory:
    """Factory for creating registrar gateway instances.

    Follows the PaymentGatewayFactory pattern from apps/billing/gateways/.
    """

    _gateways: ClassVar[dict[str, type[BaseRegistrarGateway]]] = {}

    @classmethod
    def register_gateway(cls, name: str, gateway_cls: type[BaseRegistrarGateway]) -> None:
        cls._gateways[name] = gateway_cls

    @classmethod
    def create_gateway(cls, registrar: Registrar) -> BaseRegistrarGateway:
        """Create a gateway instance for the given registrar.

        The registrar's `name` field must match a registered gateway name.
        """
        gateway_cls = cls._gateways.get(registrar.name)
        if not gateway_cls:
            raise ValueError(f"No gateway registered for registrar: {registrar.name}")
        return gateway_cls(registrar)

    @classmethod
    def list_available_gateways(cls) -> list[str]:
        return list(cls._gateways.keys())
