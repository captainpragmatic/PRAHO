"""
e-Factura integration module for Romanian ANAF compliance.

This module provides complete e-Factura (electronic invoicing) integration
with ANAF (Romanian National Agency for Fiscal Administration).

Production-grade features:
- Configurable settings via database or Django settings
- Multi-VAT rate support (19%, 9%, 5%, 0%, exempt, reverse charge)
- B2B and B2C invoice handling with CNP validation
- XSD schema validation against official ANAF schemas
- CIUS-RO schematron validation
- Canonical XML (C14N) for signatures
- ANAF API quota tracking per CUI
- Database-backed OAuth2 token storage with encryption
- Prometheus metrics for observability
- Romanian timezone handling

Components:
- settings: Configurable settings for all e-Factura parameters
- models: EFacturaDocument for tracking submission lifecycle
- client: ANAF API client with OAuth2 authentication
- xml_builder: UBL 2.1 XML generation with CIUS-RO compliance
- validator: XML validation against CIUS-RO schematron rules
- xsd_validator: XSD schema validation
- service: High-level service for e-Factura operations
- tasks: Async tasks for submission and status polling
- audit: Audit logging integration
- quota: ANAF API quota tracking
- token_storage: Secure OAuth2 token storage
- b2c: B2C invoice handling with CNP validation
- metrics: Prometheus metrics collection
"""

# Core models and enums
from .models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus

# Service layer
from .service import EFacturaService

# XML generation
from .xml_builder import UBLCreditNoteBuilder, UBLInvoiceBuilder, XMLBuilderError

# Validation
from .validator import CIUSROValidator, ValidationError, ValidationResult
from .xsd_validator import (
    CanonicalXMLGenerator,
    XSDSchemaNotFoundError,
    XSDValidationError,
    XSDValidationResult,
    XSDValidator,
)

# Settings and configuration
from .settings import (
    CIUS_RO_CUSTOMIZATION_ID,
    CIUS_RO_VERSION,
    PEPPOL_PROFILE_ID,
    ROMANIA_TIMEZONE,
    ROMANIAN_VAT_RATES,
    UBL_NAMESPACES,
    EFacturaEnvironment,
    EFacturaSettings,
    EFacturaSettingKeys,
    VATCategory,
    VATRateConfig,
    efactura_settings,
)

# Quota tracking
from .quota import (
    ANAFQuotaTracker,
    QuotaEndpoint,
    QuotaExceededError,
    QuotaStatus,
    quota_tracker,
)

# Token storage
from .token_storage import OAuthToken, TokenStorageService, token_storage

# B2C support
from .b2c import (
    B2CDetector,
    B2CInvoiceInfo,
    B2CXMLBuilder,
    CNPValidationResult,
    CNPValidator,
    b2c_detector,
    cnp_validator,
)

# Metrics
from .metrics import EFacturaMetrics, metrics, timed_operation

__all__ = [
    # Models and enums
    "EFacturaDocument",
    "EFacturaDocumentType",
    "EFacturaStatus",
    # Service
    "EFacturaService",
    # XML generation
    "UBLInvoiceBuilder",
    "UBLCreditNoteBuilder",
    "XMLBuilderError",
    # Validation
    "CIUSROValidator",
    "ValidationResult",
    "ValidationError",
    "XSDValidator",
    "XSDValidationResult",
    "XSDValidationError",
    "XSDSchemaNotFoundError",
    "CanonicalXMLGenerator",
    # Settings
    "EFacturaSettings",
    "EFacturaSettingKeys",
    "EFacturaEnvironment",
    "VATCategory",
    "VATRateConfig",
    "efactura_settings",
    "CIUS_RO_VERSION",
    "CIUS_RO_CUSTOMIZATION_ID",
    "PEPPOL_PROFILE_ID",
    "UBL_NAMESPACES",
    "ROMANIA_TIMEZONE",
    "ROMANIAN_VAT_RATES",
    # Quota
    "ANAFQuotaTracker",
    "QuotaEndpoint",
    "QuotaExceededError",
    "QuotaStatus",
    "quota_tracker",
    # Token storage
    "OAuthToken",
    "TokenStorageService",
    "token_storage",
    # B2C
    "CNPValidator",
    "CNPValidationResult",
    "B2CDetector",
    "B2CInvoiceInfo",
    "B2CXMLBuilder",
    "cnp_validator",
    "b2c_detector",
    # Metrics
    "EFacturaMetrics",
    "metrics",
    "timed_operation",
]
