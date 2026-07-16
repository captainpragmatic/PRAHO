"""
Domain Registrar Gateways — PRAHO Platform

Abstract gateway interface + concrete implementations for domain registrar APIs.
Follows the billing gateway pattern (ABC + factory + Result types).
"""

# Import the concrete gateways for their registration side effects. Each module
# calls RegistrarGatewayFactory.register_gateway(...) at import time, so without
# importing them here the factory registry stays empty at runtime and every
# create_gateway() call raises "No gateway registered" — the whole gateway layer
# would be dead code in production (it only worked in tests because the test suite
# imports the concrete modules directly). Importing gandi/rotld pulls in .base
# transitively, so registration is complete once this package finishes importing.
from . import gandi, rotld  # noqa: F401  # registration side effects
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
