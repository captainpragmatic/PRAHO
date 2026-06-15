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
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.cache import cache

from apps.common.outbound_http import OutboundPolicy, safe_request
from apps.common.types import Err, Ok, Result

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
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409
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

    # -- Public interface (with circuit breaker + idempotency) ----------------

    def register_domain(
        self,
        domain_name: str,
        years: int,
        registrant_data: dict[str, Any],
        nameservers: list[str] | None = None,
    ) -> Result[DomainRegistrationResult, RegistrarAPIError]:
        """Register a domain, with circuit breaker and idempotency protection."""
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
        return self._execute_idempotent_operation(
            idempotency_key=f"domain_renew:{self.gateway_name}:{domain_name}:{years}",
            fn=lambda: self._do_renew(registrar_domain_id, domain_name, years),
            operation=f"renew:{domain_name}",
            audit_event="domain_renewal",
            domain_name=domain_name,
            audit_metadata={"years": years},
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

        result = self._retry(fn, operation=operation)

        if result.is_ok():
            cache.set(idempotency_key, result.unwrap(), IDEMPOTENCY_TTL_SECONDS)
            self._record_success()
            self.logger.info("%s succeeded via %s", operation, self.gateway_name)
            self._audit_api_call(audit_event, domain_name, success=True, metadata=audit_metadata)
        else:
            cache.delete(idempotency_key)  # release the claim so a legitimate retry can proceed
            self._record_failure(result.unwrap_err())
            self.logger.error("%s failed: %s", operation, result.unwrap_err())
            self._audit_api_call(
                audit_event, domain_name, success=False, error=str(result.unwrap_err()), metadata=audit_metadata
            )

        return result

    def check_availability(
        self,
        domain_name: str,
    ) -> Result[DomainAvailabilityResult, RegistrarAPIError]:
        """Check domain availability (no idempotency needed, but respects circuit breaker)."""
        if err := self._check_circuit_breaker():
            return err

        result = self._retry(
            lambda: self._do_check_availability(domain_name),
            operation=f"check:{domain_name}",
        )

        if result.is_ok():
            self._record_success()
        else:
            self._record_failure(result.unwrap_err())
            self._audit_api_call(
                "domain_availability_check", domain_name, success=False, error=str(result.unwrap_err())
            )

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
                retriable=True,
            )
        return None

    def _record_failure(self, error: RegistrarAPIError) -> None:
        key = self._circuit_breaker_key()
        try:
            # incr preserves the TTL set on the first failure — do NOT touch() here.
            # Touching on every failure slid the window forward, so under sustained
            # failures the counter never expired and the breaker never auto-recovered.
            cache.incr(key)
        except ValueError:
            # First failure in this window: seed the counter with a fixed TTL so the
            # breaker auto-closes CIRCUIT_BREAKER_RESET_SECONDS after it first opened.
            cache.set(key, 1, CIRCUIT_BREAKER_RESET_SECONDS)

    def _record_success(self) -> None:
        cache.delete(self._circuit_breaker_key())

    # -- Retry with exponential backoff --------------------------------------

    def _retry(
        self,
        fn: Any,
        operation: str,
        max_retries: int = MAX_RETRIES,
    ) -> Result[Any, RegistrarAPIError]:
        last_result: Result[Any, RegistrarAPIError] = Err(
            RegistrarAPIError("No attempts made", code=RegistrarErrorCode.INTERNAL_ERROR)
        )

        for attempt in range(max_retries):
            last_result = fn()

            if last_result.is_ok():
                return last_result

            error = last_result.unwrap_err()
            is_retryable = isinstance(error, RegistrarTransientError | RegistrarRateLimitError)
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

        if status in (HTTP_UNAUTHORIZED, HTTP_FORBIDDEN):
            detail = message if status == HTTP_UNAUTHORIZED else f"Forbidden: {message}"
            return Err(RegistrarAuthError(self.registrar.name, detail=detail))

        if status == HTTP_NOT_FOUND:
            return Err(RegistrarNotFoundError(domain_name or operation, self.registrar.name))

        if status == HTTP_CONFLICT:
            return Err(RegistrarConflictError(domain_name or operation, self.registrar.name))

        if status == HTTP_RATE_LIMITED:
            retry_after = response.headers.get("Retry-After")
            return Err(
                RegistrarRateLimitError(self.registrar.name, int(retry_after) if retry_after else None),
                retriable=True,
            )

        if status >= HTTP_SERVER_ERROR:
            return Err(
                RegistrarTransientError(self.registrar.name, f"{self.gateway_name} server error ({status}): {message}"),
                retriable=True,
            )

        return Err(
            RegistrarAPIError(
                f"{self.gateway_name} API error for {operation}: {status} {message}",
                code=RegistrarErrorCode.INTERNAL_ERROR,
                registrar_name=self.registrar.name,
            )
        )


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
