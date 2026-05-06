"""
Domain Registrar Gateways — PRAHO Platform

Abstract gateway interface + concrete implementations for domain registrar APIs.
Follows the billing gateway pattern (ABC + factory + Result types).
"""

from .base import (
    BaseRegistrarGateway,
    DomainAvailabilityResult,
    DomainRegistrationResult,
    DomainRenewalResult,
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
    "DomainRegistrationResult",
    "DomainRenewalResult",
    "RegistrarAPIError",
    "RegistrarAuthError",
    "RegistrarConflictError",
    "RegistrarErrorCode",
    "RegistrarGatewayFactory",
    "RegistrarNotFoundError",
    "RegistrarRateLimitError",
    "RegistrarTransientError",
]
