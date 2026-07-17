"""
B2C (Business-to-Consumer) support for e-Factura.

From January 2025, B2C invoices are mandatory for Romanian e-Factura.
Consumers may provide a CNP, but unidentified consumers use the statutory
thirteen-zero fiscal identifier.

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

from .eligibility import ANONYMOUS_B2C_BUYER_ID, is_romanian_b2c

if TYPE_CHECKING:
    pass

__all__ = [
    "B2CDetector",
    "B2CInvoiceInfo",
    "CNPValidationResult",
    "CNPValidator",
]

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

    B2C invoices are identified by a Romanian buyer without a business tax ID.
    """

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
        bill_to_name = getattr(invoice, "bill_to_name", "")
        if not is_romanian_b2c(invoice):
            return B2CInvoiceInfo(is_b2c=False)

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
    - Use CNP or thirteen zeroes in buyer legal identifier BT-47
    - Do not invent a RO:CNP scheme attribute
    - Buyer VAT scheme may be omitted
    """

    B2C_SCHEME_ID = ""  # Compatibility key: BT-47 carries no RO:CNP scheme attribute.
    ANAF_TEST_CNP = ANONYMOUS_B2C_BUYER_ID

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
        del is_test_environment
        identifier = cnp or cls.ANAF_TEST_CNP

        return {
            "identifier": identifier,
            "scheme_id": cls.B2C_SCHEME_ID,
            "business_term": "BT-47",
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
        if not cnp or cnp == cls.ANAF_TEST_CNP:
            return True, ""

        result = CNPValidator.validate(cnp)
        if not result.is_valid:
            return False, f"Invalid CNP: {result.error_message}"

        return True, ""


# Module-level instances
cnp_validator = CNPValidator()
b2c_detector = B2CDetector()
