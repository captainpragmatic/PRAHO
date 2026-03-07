"""
B2C (Business-to-Consumer) support for e-Factura.

From January 2025, B2C invoices are mandatory for Romanian e-Factura.
B2C invoices use CNP (Cod Numeric Personal) instead of CUI for buyers.

This module provides:
- CNP validation
- B2C invoice detection
- B2C-specific XML generation requirements
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from apps.common.cnp_validator import CNPValidationResult, CNPValidator

from .settings import efactura_settings

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class B2CInvoiceInfo:
    """Information about a B2C invoice."""

    is_b2c: bool
    customer_cnp: str | None = None
    customer_name: str = ""
    requires_efactura: bool = False
    validation_result: CNPValidationResult | None = None


class B2CDetector:
    """
    Detect and validate B2C invoices.

    B2C invoices are identified by:
    - No tax ID (CUI) on the buyer
    - Romanian buyer country
    - Amount above minimum threshold
    """

    def __init__(self, settings: Any = None):
        """Initialize with optional settings override."""
        self._settings = settings or efactura_settings

    def detect(
        self,
        invoice: object,
        customer_identifier: str | None = None,
    ) -> B2CInvoiceInfo:
        """
        Detect if an invoice is B2C and validate customer identifier.

        Args:
            invoice: Invoice object with bill_to_* attributes
            customer_identifier: Optional CNP or other identifier

        Returns:
            B2CInvoiceInfo with detection results
        """
        # Get invoice attributes
        bill_to_country = getattr(invoice, "bill_to_country", None)
        bill_to_tax_id = getattr(invoice, "bill_to_tax_id", None)
        bill_to_name = getattr(invoice, "bill_to_name", "")
        total_cents = getattr(invoice, "total_cents", 0)

        # Not B2C if has tax ID (CUI)
        if bill_to_tax_id:
            return B2CInvoiceInfo(is_b2c=False)

        # Not B2C if not Romanian
        if bill_to_country != "RO":
            return B2CInvoiceInfo(is_b2c=False)

        # Check if B2C e-Factura is enabled
        if not self._settings.b2c_enabled:
            return B2CInvoiceInfo(
                is_b2c=True,
                customer_name=bill_to_name,
                requires_efactura=False,
            )

        # Check minimum amount
        minimum = self._settings.b2c_minimum_amount_cents
        if minimum > 0 and total_cents < minimum:
            return B2CInvoiceInfo(
                is_b2c=True,
                customer_name=bill_to_name,
                requires_efactura=False,
            )

        # Validate CNP if provided
        validation_result = None
        if customer_identifier:
            validation_result = CNPValidator.validate(customer_identifier)

        return B2CInvoiceInfo(
            is_b2c=True,
            customer_cnp=customer_identifier if validation_result and validation_result.is_valid else None,
            customer_name=bill_to_name,
            requires_efactura=True,
            validation_result=validation_result,
        )

    def is_b2c_required(self, invoice: object) -> bool:
        """Check if B2C e-Factura is required for this invoice."""
        info = self.detect(invoice)
        return info.is_b2c and info.requires_efactura


class B2CXMLBuilder:
    """
    Helper for B2C-specific XML generation.

    B2C invoices have different requirements:
    - Use CNP instead of CUI for buyer identification
    - Different scheme ID (RO:CNP instead of RO:CUI)
    - Buyer VAT scheme may be omitted
    """

    B2C_SCHEME_ID = "RO:CNP"
    ANAF_TEST_CNP = "0000000000000"  # For testing in sandbox

    @classmethod
    def get_buyer_identification(
        cls,
        cnp: str | None,
        name: str,
        is_test_environment: bool = False,
    ) -> dict[str, Any]:
        """
        Get buyer identification for B2C invoice XML.

        Args:
            cnp: Customer CNP (optional)
            name: Customer name
            is_test_environment: Whether in test/sandbox mode

        Returns:
            Dictionary with buyer identification info for XML builder
        """
        # In test environment, ANAF accepts all zeros CNP
        if is_test_environment and not cnp:
            cnp = cls.ANAF_TEST_CNP

        return {
            "identifier": cnp or "",
            "scheme_id": cls.B2C_SCHEME_ID if cnp else "",
            "name": name,
            "is_b2c": True,
            "has_vat_registration": False,
        }

    @classmethod
    def validate_for_submission(
        cls,
        cnp: str | None,
        is_test_environment: bool = False,
    ) -> tuple[bool, str]:
        """
        Validate B2C invoice is ready for submission.

        Args:
            cnp: Customer CNP
            is_test_environment: Whether in test/sandbox mode

        Returns:
            Tuple of (is_valid, error_message)
        """
        if is_test_environment:
            # Test environment accepts any CNP including all zeros
            return True, ""

        if not cnp:
            return False, "CNP is required for B2C e-Factura submission"

        result = CNPValidator.validate(cnp)
        if not result.is_valid:
            return False, f"Invalid CNP: {result.error_message}"

        return True, ""


# Module-level instances
cnp_validator = CNPValidator()
b2c_detector = B2CDetector()
