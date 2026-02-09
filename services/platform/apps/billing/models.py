"""
Billing models for PRAHO Platform
Romanian invoice generation with VAT compliance and e-Factura support.
Aligned with PostgreSQL hosting panel schema v1 with separate proforma handling.

Includes comprehensive usage-based billing system:
- Usage metering and event tracking
- Aggregation and rating engine
- Subscription and billing cycle management
- Tiered pricing support
- Usage alerts and thresholds
- Stripe Meter integration

This file serves as a re-export hub following ADR-0012 feature-based organization.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# Feature-based model imports
from .currency_models import Currency, FXRate
from .efactura.models import EFacturaDocument, EFacturaDocumentType, EFacturaStatus
from .efactura.token_storage import OAuthToken
from .invoice_models import Invoice, InvoiceLine, InvoiceSequence

# Usage-based billing model imports
from .metering_models import (
    BillingCycle,
    PricingTier,
    PricingTierBracket,
    UsageAggregation,
    UsageAlert,
    UsageEvent,
    UsageMeter,
    UsageThreshold,
)
from .payment_models import CreditLedger, Payment, PaymentCollectionRun, PaymentRetryAttempt, PaymentRetryPolicy
from .proforma_models import ProformaInvoice, ProformaLine, ProformaSequence
from .refund_models import Refund, RefundNote, RefundStatusHistory
from .subscription_models import (
    PriceGrandfathering,
    Subscription,
    SubscriptionChange,
    SubscriptionItem,
)
from .tax_models import TaxRule, VATValidation
from .validators import (
    DANGEROUS_FINANCIAL_PATTERNS,
    MAX_ADDRESS_FIELD_LENGTH,
    MAX_DESCRIPTION_LENGTH,
    MAX_FINANCIAL_AMOUNT_CENTS,
    MAX_JSON_DEPTH,
    MAX_JSON_SIZE_BYTES,
    MIN_FINANCIAL_AMOUNT_CENTS,
    SENSITIVE_FINANCIAL_KEYS,
    log_security_event,
    validate_financial_amount,
    validate_financial_json,
    validate_financial_text_field,
    validate_invoice_sequence_increment,
)

logger = logging.getLogger(__name__)

# Date constants for tax rate validation
JANUARY = 1  # First month of year
DECEMBER = 12  # Last month of year
FIRST_DAY_OF_MONTH = 1  # First day of month
LAST_DAY_OF_DECEMBER = 31  # Last day of December


# ===============================================================================
# MODEL RE-EXPORTS - All imports moved to top of file for PEP 8 compliance
# ===============================================================================

# Expose all models in __all__ for explicit imports
__all__ = [
    # Constants
    "DANGEROUS_FINANCIAL_PATTERNS",
    "DECEMBER",
    "FIRST_DAY_OF_MONTH",
    "JANUARY",
    "LAST_DAY_OF_DECEMBER",
    "MAX_ADDRESS_FIELD_LENGTH",
    "MAX_DESCRIPTION_LENGTH",
    "MAX_FINANCIAL_AMOUNT_CENTS",
    "MAX_JSON_DEPTH",
    "MAX_JSON_SIZE_BYTES",
    "MIN_FINANCIAL_AMOUNT_CENTS",
    "SENSITIVE_FINANCIAL_KEYS",
    # Usage-based billing models
    "BillingCycle",
    # Currency Models
    "CreditLedger",
    "Currency",
    # E-Factura models
    "EFacturaDocument",
    "EFacturaDocumentType",
    "EFacturaStatus",
    "FXRate",
    # Invoice Models
    "Invoice",
    "InvoiceLine",
    "InvoiceSequence",
    "OAuthToken",
    # Payment Models
    "Payment",
    "PaymentCollectionRun",
    "PaymentRetryAttempt",
    "PaymentRetryPolicy",
    # Subscription Models
    "PriceGrandfathering",
    "PricingTier",
    "PricingTierBracket",
    # Proforma Models
    "ProformaInvoice",
    "ProformaLine",
    "ProformaSequence",
    # Refund Models
    "Refund",
    "RefundNote",
    "RefundStatusHistory",
    "Subscription",
    "SubscriptionChange",
    "SubscriptionItem",
    # Tax Models
    "TaxRule",
    "UsageAggregation",
    "UsageAlert",
    "UsageEvent",
    "UsageMeter",
    "UsageThreshold",
    "VATValidation",
    # Validators
    "log_security_event",
    "validate_financial_amount",
    "validate_financial_json",
    "validate_financial_text_field",
    "validate_invoice_sequence_increment",
]
