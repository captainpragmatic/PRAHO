"""
Domain Registrar Gateways — PRAHO Platform

Abstract gateway interface + concrete implementations for domain registrar APIs.
Follows the billing gateway pattern (ABC + factory + Result types).
"""

from .base import (
    BaseRegistrarGateway,
    DomainAvailabilityResult,
    DomainInfoResult,
    DomainLockResult,
    DomainRegistrationResult,
    DomainRenewalResult,
    DomainTransferResult,
    NameserverUpdateResult,
    RegistrarGatewayFactory,
)
from .errors import (
    RegistrarAPIError,
    RegistrarAuthError,
    RegistrarConflictError,
    RegistrarErrorCode,
    RegistrarNotFoundError,
    RegistrarRateLimitError,
    RegistrarTransientError,
)

__all__ = [
    "BaseRegistrarGateway",
    "DomainAvailabilityResult",
    "DomainInfoResult",
    "DomainLockResult",
    "DomainRegistrationResult",
    "DomainRenewalResult",
    "DomainTransferResult",
    "NameserverUpdateResult",
    "RegistrarAPIError",
    "RegistrarAuthError",
    "RegistrarConflictError",
    "RegistrarErrorCode",
    "RegistrarGatewayFactory",
    "RegistrarNotFoundError",
    "RegistrarRateLimitError",
    "RegistrarTransientError",
]
