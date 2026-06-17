"""
Domain registrar error types.

Modeled after the Virtualmin gateway exception hierarchy.
Each error carries a machine-readable code and optional registrar-specific detail.
"""

from __future__ import annotations

from enum import StrEnum


class RegistrarErrorCode(StrEnum):
    """Machine-readable error codes for registrar operations."""

    AUTH_FAILED = "auth_failed"
    DOMAIN_ALREADY_REGISTERED = "domain_already_registered"
    DOMAIN_NOT_FOUND = "domain_not_found"
    DOMAIN_LOCKED = "domain_locked"
    DOMAIN_NOT_ELIGIBLE = "domain_not_eligible"
    INVALID_REGISTRANT_DATA = "invalid_registrant_data"
    INVALID_NAMESERVERS = "invalid_nameservers"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    INVALID_RESPONSE = "invalid_response"
    WEBHOOK_SIGNATURE_INVALID = "webhook_signature_invalid"
    INTERNAL_ERROR = "internal_error"


class RegistrarAPIError(Exception):
    """Base exception for all registrar API errors."""

    def __init__(
        self,
        message: str,
        code: RegistrarErrorCode = RegistrarErrorCode.INTERNAL_ERROR,
        registrar_name: str = "",
        detail: str = "",
    ) -> None:
        self.code = code
        self.registrar_name = registrar_name
        self.detail = detail
        super().__init__(message)


class RegistrarAuthError(RegistrarAPIError):
    """Authentication or authorization failure with the registrar API."""

    def __init__(self, registrar_name: str, detail: str = "") -> None:
        super().__init__(
            f"Authentication failed for registrar '{registrar_name}'",
            code=RegistrarErrorCode.AUTH_FAILED,
            registrar_name=registrar_name,
            detail=detail,
        )


class RegistrarConflictError(RegistrarAPIError):
    """Domain already exists at the registrar (registration conflict)."""

    def __init__(self, domain_name: str, registrar_name: str) -> None:
        super().__init__(
            f"Domain '{domain_name}' already registered at '{registrar_name}'",
            code=RegistrarErrorCode.DOMAIN_ALREADY_REGISTERED,
            registrar_name=registrar_name,
        )


class RegistrarNotFoundError(RegistrarAPIError):
    """Domain not found at the registrar."""

    def __init__(self, domain_name: str, registrar_name: str) -> None:
        super().__init__(
            f"Domain '{domain_name}' not found at '{registrar_name}'",
            code=RegistrarErrorCode.DOMAIN_NOT_FOUND,
            registrar_name=registrar_name,
        )


class RegistrarRateLimitError(RegistrarAPIError):
    """Registrar API rate limit exceeded."""

    def __init__(self, registrar_name: str, retry_after: int | None = None) -> None:
        self.retry_after = retry_after
        detail = f"retry_after={retry_after}s" if retry_after else ""
        super().__init__(
            f"Rate limit exceeded for registrar '{registrar_name}'",
            code=RegistrarErrorCode.RATE_LIMITED,
            registrar_name=registrar_name,
            detail=detail,
        )


class RegistrarTransientError(RegistrarAPIError):
    """Transient/retryable error (timeout, network issue, 5xx)."""

    def __init__(self, registrar_name: str, message: str, detail: str = "") -> None:
        super().__init__(
            message,
            code=RegistrarErrorCode.NETWORK_ERROR,
            registrar_name=registrar_name,
            detail=detail,
        )
