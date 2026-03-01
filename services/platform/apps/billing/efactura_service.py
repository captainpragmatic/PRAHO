"""
Romanian e-Factura Integration Service for PRAHO Platform.

Implements integration with ANAF SPV (Spatiul Privat Virtual) for
mandatory electronic invoice submission in Romania.

Reference:
- ANAF e-Factura documentation: https://www.anaf.ro/efactura/
- UBL 2.1 Invoice specification
- Romanian invoice requirements (Codul Fiscal Art. 319)

Features:
- UBL 2.1 XML generation for invoices
- Digital signature support (optional)
- ANAF SPV API integration
- Validation and error handling
- Submission tracking and status polling
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from xml.etree import ElementTree as ET

from django.conf import settings
from django.utils import timezone

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from .invoice_models import Invoice

logger = logging.getLogger(__name__)

# ===============================================================================
# CONSTANTS
# ===============================================================================

# UBL 2.1 Namespaces
UBL_NAMESPACES: dict[str, str] = {
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "cec": "urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2",
    "ubl": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
}

# Romanian VAT codes
RO_VAT_CATEGORY_CODES = {
    "standard": "S",  # Standard rate (19%)
    "reduced_9": "AA",  # Reduced rate (9%)
    "reduced_5": "AA",  # Reduced rate (5%)
    "zero": "Z",  # Zero rate
    "exempt": "E",  # Exempt
    "reverse_charge": "AE",  # Reverse charge
}

# ANAF SPV endpoints
ANAF_SPV_ENDPOINTS = {
    "production": "https://api.anaf.ro/prod/FCTEL/rest",
    "test": "https://api.anaf.ro/test/FCTEL/rest",
}


# e-Factura submission states
class EFacturaStatus(StrEnum):
    PENDING = "pending"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    PROCESSING = "processing"
    ERROR = "error"


# ===============================================================================
# DATA CLASSES
# ===============================================================================


@dataclass
class EFacturaSubmissionResult:
    """Result of e-Factura submission."""

    success: bool
    efactura_id: str | None = None
    upload_index: str | None = None
    status: EFacturaStatus = EFacturaStatus.PENDING
    message: str = ""
    errors: list[str] = field(default_factory=list)
    xml_content: str | None = None
    response_data: dict[str, Any] = field(default_factory=dict)


@dataclass
class EFacturaValidationResult:
    """Result of e-Factura validation."""

    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class PartyInfo:
    """Party information for invoice."""

    name: str
    registration_name: str
    tax_id: str
    country_code: str
    city: str
    postal_code: str
    street_address: str
    county: str = ""
    email: str = ""
    phone: str = ""
    bank_account: str = ""
    bank_name: str = ""


# ===============================================================================
# XML GENERATION SERVICE
# ===============================================================================


class EFacturaXMLGenerator:
    """
    Generates UBL 2.1 compliant XML for Romanian e-Factura.

    Implements the Romanian national invoice format based on EN 16931
    with Romanian-specific extensions.
    """

    def __init__(self) -> None:
        # Register namespaces
        for prefix, uri in UBL_NAMESPACES.items():
            ET.register_namespace(prefix, uri)

    def generate_invoice_xml(self, invoice: Invoice) -> Result[str, str]:
        """
        Generate UBL 2.1 XML for an invoice.

        Args:
            invoice: Invoice model instance

        Returns:
            Result with XML string or error message
        """
        try:
            # Validate invoice data
            validation = self._validate_invoice_for_efactura(invoice)
            if not validation.is_valid:
                return Err(f"Validation failed: {', '.join(validation.errors)}")

            # Build XML tree
            root = self._create_invoice_root()

            # Add invoice header
            self._add_invoice_header(root, invoice)

            # Add supplier party (seller)
            self._add_supplier_party(root, invoice)

            # Add customer party (buyer)
            self._add_customer_party(root, invoice)

            # Add payment means
            self._add_payment_means(root, invoice)

            # Add payment terms
            self._add_payment_terms(root, invoice)

            # Add tax totals
            self._add_tax_totals(root, invoice)

            # Add monetary totals
            self._add_monetary_totals(root, invoice)

            # Add invoice lines
            self._add_invoice_lines(root, invoice)

            # Convert to string
            xml_string = ET.tostring(root, encoding="unicode", xml_declaration=True)

            # Format with proper indentation
            xml_string = self._format_xml(xml_string)

            return Ok(xml_string)

        except Exception as e:
            logger.exception(f"Failed to generate e-Factura XML: {e}")
            return Err(f"XML generation failed: {e}")

    def _validate_invoice_for_efactura(self, invoice: Invoice) -> EFacturaValidationResult:
        """Validate invoice has required data for e-Factura."""
        errors: list[str] = []
        warnings: list[str] = []

        # Required fields
        if not invoice.number:
            errors.append("Invoice number is required")

        if not invoice.issued_at:
            errors.append("Issue date is required")

        if not invoice.due_at:
            warnings.append("Due date is recommended")

        # Customer validation
        if not invoice.bill_to_name:
            errors.append("Customer name is required")

        if invoice.bill_to_country == "RO" and not invoice.bill_to_tax_id:
            warnings.append("Romanian customers should have a tax ID (CUI/CIF)")

        # Seller validation (from settings)
        seller_tax_id = getattr(settings, "COMPANY_TAX_ID", None)
        if not seller_tax_id:
            errors.append("Company tax ID (COMPANY_TAX_ID) must be configured")

        # Amount validation
        if invoice.total_cents <= 0:
            errors.append("Invoice total must be positive")

        # Lines validation
        if not invoice.lines.exists():
            errors.append("Invoice must have at least one line item")

        return EFacturaValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

    def _create_invoice_root(self) -> ET.Element:
        """Create the root Invoice element with namespaces."""
        root = ET.Element(
            "{urn:oasis:names:specification:ubl:schema:xsd:Invoice-2}Invoice",
            attrib={f"xmlns:{prefix}": uri for prefix, uri in UBL_NAMESPACES.items()},
        )
        root.set("xmlns", UBL_NAMESPACES["ubl"])
        return root

    def _add_invoice_header(self, root: ET.Element, invoice: Invoice) -> None:
        """Add invoice header elements."""
        cbc = UBL_NAMESPACES["cbc"]

        # UBL Version
        ET.SubElement(root, f"{{{cbc}}}UBLVersionID").text = "2.1"

        # Customization ID (Romanian CIUS-RO)
        ET.SubElement(
            root, f"{{{cbc}}}CustomizationID"
        ).text = "urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1"

        # Invoice ID
        ET.SubElement(root, f"{{{cbc}}}ID").text = invoice.number

        # Issue date
        ET.SubElement(root, f"{{{cbc}}}IssueDate").text = (
            invoice.issued_at.strftime("%Y-%m-%d") if invoice.issued_at else timezone.now().strftime("%Y-%m-%d")
        )

        # Due date
        if invoice.due_at:
            ET.SubElement(root, f"{{{cbc}}}DueDate").text = invoice.due_at.strftime("%Y-%m-%d")

        # Invoice type code (380 = Commercial invoice)
        ET.SubElement(root, f"{{{cbc}}}InvoiceTypeCode").text = "380"

        # Note (optional)  # noqa: ERA001
        if invoice.notes:  # type: ignore[attr-defined]
            ET.SubElement(root, f"{{{cbc}}}Note").text = invoice.notes[:500]  # type: ignore[attr-defined]

        # Document currency code
        ET.SubElement(root, f"{{{cbc}}}DocumentCurrencyCode").text = invoice.currency.code

    def _add_supplier_party(self, root: ET.Element, invoice: Invoice) -> None:
        """Add supplier (seller) party information."""
        cbc = UBL_NAMESPACES["cbc"]
        cac = UBL_NAMESPACES["cac"]

        # Get company info from settings
        company_name = getattr(settings, "COMPANY_NAME", "PRAHO SRL")
        company_tax_id = getattr(settings, "COMPANY_TAX_ID", "")
        company_reg_no = getattr(settings, "COMPANY_REG_NO", "")
        company_address = getattr(settings, "COMPANY_ADDRESS", "")
        company_city = getattr(settings, "COMPANY_CITY", "")
        company_county = getattr(settings, "COMPANY_COUNTY", "")
        company_postal = getattr(settings, "COMPANY_POSTAL_CODE", "")
        company_country = getattr(settings, "COMPANY_COUNTRY", "RO")
        company_email = getattr(settings, "COMPANY_EMAIL", "")
        company_phone = getattr(settings, "COMPANY_PHONE", "")

        supplier_party = ET.SubElement(root, f"{{{cac}}}AccountingSupplierParty")
        party = ET.SubElement(supplier_party, f"{{{cac}}}Party")

        # Party identification (tax ID)
        if company_tax_id:
            party_id = ET.SubElement(party, f"{{{cac}}}PartyIdentification")
            id_elem = ET.SubElement(party_id, f"{{{cbc}}}ID")
            id_elem.text = company_tax_id
            id_elem.set("schemeID", "RO:CUI")

        # Party name
        party_name = ET.SubElement(party, f"{{{cac}}}PartyName")
        ET.SubElement(party_name, f"{{{cbc}}}Name").text = company_name

        # Postal address
        postal_address = ET.SubElement(party, f"{{{cac}}}PostalAddress")
        if company_address:
            ET.SubElement(postal_address, f"{{{cbc}}}StreetName").text = company_address
        if company_city:
            ET.SubElement(postal_address, f"{{{cbc}}}CityName").text = company_city
        if company_postal:
            ET.SubElement(postal_address, f"{{{cbc}}}PostalZone").text = company_postal
        if company_county:
            ET.SubElement(postal_address, f"{{{cbc}}}CountrySubentity").text = company_county
        country = ET.SubElement(postal_address, f"{{{cac}}}Country")
        ET.SubElement(country, f"{{{cbc}}}IdentificationCode").text = company_country

        # Tax scheme (VAT)
        party_tax = ET.SubElement(party, f"{{{cac}}}PartyTaxScheme")
        ET.SubElement(party_tax, f"{{{cbc}}}CompanyID").text = f"RO{company_tax_id.replace('RO', '')}"
        tax_scheme = ET.SubElement(party_tax, f"{{{cac}}}TaxScheme")
        ET.SubElement(tax_scheme, f"{{{cbc}}}ID").text = "VAT"

        # Legal entity
        legal_entity = ET.SubElement(party, f"{{{cac}}}PartyLegalEntity")
        ET.SubElement(legal_entity, f"{{{cbc}}}RegistrationName").text = company_name
        if company_reg_no:
            ET.SubElement(legal_entity, f"{{{cbc}}}CompanyID").text = company_reg_no

        # Contact
        if company_email or company_phone:
            contact = ET.SubElement(party, f"{{{cac}}}Contact")
            if company_email:
                ET.SubElement(contact, f"{{{cbc}}}ElectronicMail").text = company_email
            if company_phone:
                ET.SubElement(contact, f"{{{cbc}}}Telephone").text = company_phone

    def _add_customer_party(self, root: ET.Element, invoice: Invoice) -> None:
        """Add customer (buyer) party information."""
        cbc = UBL_NAMESPACES["cbc"]
        cac = UBL_NAMESPACES["cac"]

        customer_party = ET.SubElement(root, f"{{{cac}}}AccountingCustomerParty")
        party = ET.SubElement(customer_party, f"{{{cac}}}Party")

        # Party identification (tax ID if available)
        if invoice.bill_to_tax_id:
            party_id = ET.SubElement(party, f"{{{cac}}}PartyIdentification")
            id_elem = ET.SubElement(party_id, f"{{{cbc}}}ID")
            id_elem.text = invoice.bill_to_tax_id
            scheme = "RO:CUI" if invoice.bill_to_country == "RO" else "VAT"
            id_elem.set("schemeID", scheme)

        # Party name
        party_name = ET.SubElement(party, f"{{{cac}}}PartyName")
        ET.SubElement(party_name, f"{{{cbc}}}Name").text = invoice.bill_to_name

        # Postal address
        postal_address = ET.SubElement(party, f"{{{cac}}}PostalAddress")
        if invoice.bill_to_address1:
            ET.SubElement(postal_address, f"{{{cbc}}}StreetName").text = invoice.bill_to_address1
        if invoice.bill_to_city:
            ET.SubElement(postal_address, f"{{{cbc}}}CityName").text = invoice.bill_to_city
        if invoice.bill_to_postal:
            ET.SubElement(postal_address, f"{{{cbc}}}PostalZone").text = invoice.bill_to_postal
        if invoice.bill_to_region:
            ET.SubElement(postal_address, f"{{{cbc}}}CountrySubentity").text = invoice.bill_to_region
        country = ET.SubElement(postal_address, f"{{{cac}}}Country")
        ET.SubElement(country, f"{{{cbc}}}IdentificationCode").text = invoice.bill_to_country or "RO"

        # Tax scheme (if B2B with VAT ID)
        if invoice.bill_to_tax_id:
            party_tax = ET.SubElement(party, f"{{{cac}}}PartyTaxScheme")
            ET.SubElement(party_tax, f"{{{cbc}}}CompanyID").text = invoice.bill_to_tax_id
            tax_scheme = ET.SubElement(party_tax, f"{{{cac}}}TaxScheme")
            ET.SubElement(tax_scheme, f"{{{cbc}}}ID").text = "VAT"

        # Legal entity
        legal_entity = ET.SubElement(party, f"{{{cac}}}PartyLegalEntity")
        ET.SubElement(legal_entity, f"{{{cbc}}}RegistrationName").text = invoice.bill_to_name

        # Contact
        if invoice.bill_to_email:
            contact = ET.SubElement(party, f"{{{cac}}}Contact")
            ET.SubElement(contact, f"{{{cbc}}}ElectronicMail").text = invoice.bill_to_email

    def _add_payment_means(self, root: ET.Element, invoice: Invoice) -> None:
        """Add payment means information."""
        cbc = UBL_NAMESPACES["cbc"]
        cac = UBL_NAMESPACES["cac"]

        payment_means = ET.SubElement(root, f"{{{cac}}}PaymentMeans")

        # Payment means code (30 = bank transfer, 10 = cash)
        ET.SubElement(payment_means, f"{{{cbc}}}PaymentMeansCode").text = "30"

        # Payment ID (invoice number as reference)
        ET.SubElement(payment_means, f"{{{cbc}}}PaymentID").text = invoice.number

        # Bank account (if configured)
        company_iban = getattr(settings, "COMPANY_BANK_IBAN", None)
        if company_iban:
            payee_account = ET.SubElement(payment_means, f"{{{cac}}}PayeeFinancialAccount")
            ET.SubElement(payee_account, f"{{{cbc}}}ID").text = company_iban

            company_bank_name = getattr(settings, "COMPANY_BANK_NAME", None)
            if company_bank_name:
                bank_branch = ET.SubElement(payee_account, f"{{{cac}}}FinancialInstitutionBranch")
                ET.SubElement(bank_branch, f"{{{cbc}}}Name").text = company_bank_name

    def _add_payment_terms(self, root: ET.Element, invoice: Invoice) -> None:
        """Add payment terms."""
        cbc = UBL_NAMESPACES["cbc"]
        cac = UBL_NAMESPACES["cac"]

        if invoice.due_at and invoice.issued_at:
            payment_terms = ET.SubElement(root, f"{{{cac}}}PaymentTerms")
            days_due = (invoice.due_at - invoice.issued_at).days
            ET.SubElement(payment_terms, f"{{{cbc}}}Note").text = f"Termen de plata: {days_due} zile"

    def _add_tax_totals(self, root: ET.Element, invoice: Invoice) -> None:
        """Add tax totals."""
        cbc = UBL_NAMESPACES["cbc"]
        cac = UBL_NAMESPACES["cac"]

        tax_total = ET.SubElement(root, f"{{{cac}}}TaxTotal")

        # Total tax amount
        tax_amount = ET.SubElement(tax_total, f"{{{cbc}}}TaxAmount")
        tax_amount.text = f"{invoice.tax_cents / 100:.2f}"
        tax_amount.set("currencyID", invoice.currency.code)

        # Tax subtotal (assuming single VAT rate for simplicity)
        tax_subtotal = ET.SubElement(tax_total, f"{{{cac}}}TaxSubtotal")

        taxable_amount = ET.SubElement(tax_subtotal, f"{{{cbc}}}TaxableAmount")
        taxable_amount.text = f"{invoice.subtotal_cents / 100:.2f}"
        taxable_amount.set("currencyID", invoice.currency.code)

        subtotal_tax = ET.SubElement(tax_subtotal, f"{{{cbc}}}TaxAmount")
        subtotal_tax.text = f"{invoice.tax_cents / 100:.2f}"
        subtotal_tax.set("currencyID", invoice.currency.code)

        # Tax category
        tax_category = ET.SubElement(tax_subtotal, f"{{{cac}}}TaxCategory")
        ET.SubElement(tax_category, f"{{{cbc}}}ID").text = "S"  # Standard rate

        # Calculate effective tax rate
        tax_rate = (invoice.tax_cents / invoice.subtotal_cents) * 100 if invoice.subtotal_cents > 0 else 21.0
        ET.SubElement(tax_category, f"{{{cbc}}}Percent").text = f"{tax_rate:.2f}"

        tax_scheme = ET.SubElement(tax_category, f"{{{cac}}}TaxScheme")
        ET.SubElement(tax_scheme, f"{{{cbc}}}ID").text = "VAT"

    def _add_monetary_totals(self, root: ET.Element, invoice: Invoice) -> None:
        """Add monetary totals."""
        cbc = UBL_NAMESPACES["cbc"]
        cac = UBL_NAMESPACES["cac"]

        monetary_total = ET.SubElement(root, f"{{{cac}}}LegalMonetaryTotal")

        currency = invoice.currency.code

        # Line extension amount (sum of line totals excluding tax)
        line_ext = ET.SubElement(monetary_total, f"{{{cbc}}}LineExtensionAmount")
        line_ext.text = f"{invoice.subtotal_cents / 100:.2f}"
        line_ext.set("currencyID", currency)

        # Tax exclusive amount
        tax_excl = ET.SubElement(monetary_total, f"{{{cbc}}}TaxExclusiveAmount")
        tax_excl.text = f"{invoice.subtotal_cents / 100:.2f}"
        tax_excl.set("currencyID", currency)

        # Tax inclusive amount
        tax_incl = ET.SubElement(monetary_total, f"{{{cbc}}}TaxInclusiveAmount")
        tax_incl.text = f"{invoice.total_cents / 100:.2f}"
        tax_incl.set("currencyID", currency)

        # Payable amount
        payable = ET.SubElement(monetary_total, f"{{{cbc}}}PayableAmount")
        payable.text = f"{invoice.total_cents / 100:.2f}"
        payable.set("currencyID", currency)

    def _add_invoice_lines(self, root: ET.Element, invoice: Invoice) -> None:
        """Add invoice line items."""
        cbc = UBL_NAMESPACES["cbc"]
        cac = UBL_NAMESPACES["cac"]

        currency = invoice.currency.code

        for idx, line in enumerate(invoice.lines.all(), start=1):
            inv_line = ET.SubElement(root, f"{{{cac}}}InvoiceLine")

            # Line ID
            ET.SubElement(inv_line, f"{{{cbc}}}ID").text = str(idx)

            # Quantity
            quantity = ET.SubElement(inv_line, f"{{{cbc}}}InvoicedQuantity")
            quantity.text = f"{line.quantity:.2f}"
            quantity.set("unitCode", "C62")  # Unit (generic)

            # Line extension amount
            line_ext = ET.SubElement(inv_line, f"{{{cbc}}}LineExtensionAmount")
            # Calculate line total without tax
            line_net = line.unit_price_cents * float(line.quantity) / 100
            line_ext.text = f"{line_net:.2f}"
            line_ext.set("currencyID", currency)

            # Item
            item = ET.SubElement(inv_line, f"{{{cac}}}Item")
            ET.SubElement(item, f"{{{cbc}}}Description").text = line.description[:200]
            ET.SubElement(item, f"{{{cbc}}}Name").text = line.description[:100]

            # Tax category for item
            tax_cat = ET.SubElement(item, f"{{{cac}}}ClassifiedTaxCategory")
            ET.SubElement(tax_cat, f"{{{cbc}}}ID").text = "S"
            ET.SubElement(tax_cat, f"{{{cbc}}}Percent").text = f"{float(line.tax_rate) * 100:.2f}"
            tax_scheme = ET.SubElement(tax_cat, f"{{{cac}}}TaxScheme")
            ET.SubElement(tax_scheme, f"{{{cbc}}}ID").text = "VAT"

            # Price
            price = ET.SubElement(inv_line, f"{{{cac}}}Price")
            price_amount = ET.SubElement(price, f"{{{cbc}}}PriceAmount")
            price_amount.text = f"{line.unit_price_cents / 100:.2f}"
            price_amount.set("currencyID", currency)

    def _format_xml(self, xml_string: str) -> str:
        """Format XML with proper indentation."""
        return xml_string


# ===============================================================================
# ANAF SPV API SERVICE
# ===============================================================================


class EFacturaSubmissionService:
    """
    Service for submitting invoices to ANAF SPV.

    Handles:
    - XML generation
    - API authentication (OAuth2)
    - Invoice submission
    - Status polling
    - Error handling
    """

    def __init__(self) -> None:
        self.xml_generator = EFacturaXMLGenerator()
        self.is_production = getattr(settings, "EFACTURA_PRODUCTION", False)
        self.api_base = ANAF_SPV_ENDPOINTS["production" if self.is_production else "test"]

    def submit_invoice(self, invoice: Invoice) -> EFacturaSubmissionResult:
        """
        Submit an invoice to ANAF e-Factura.

        Args:
            invoice: Invoice model instance

        Returns:
            EFacturaSubmissionResult with submission details
        """
        # Generate XML
        xml_result = self.xml_generator.generate_invoice_xml(invoice)
        if not xml_result.is_ok():
            return EFacturaSubmissionResult(
                success=False,
                status=EFacturaStatus.ERROR,
                message=f"XML generation failed: {xml_result.error}",  # type: ignore[union-attr]
                errors=[xml_result.error],  # type: ignore[union-attr]
            )

        xml_content = xml_result.unwrap()

        # Calculate XML hash for verification
        xml_hash = hashlib.sha256(xml_content.encode("utf-8")).hexdigest()

        # Submit to ANAF via EFacturaClient (if configured)
        from apps.billing.efactura.client import EFacturaClient, EFacturaClientError, EFacturaConfig  # noqa: PLC0415

        config = EFacturaConfig.from_settings()
        if not config.is_valid():
            # Only simulate in DEBUG mode; in production, missing config is a hard failure
            if getattr(settings, "DEBUG", False):
                logger.warning("⚠️ [e-Factura] Not configured (DEBUG) — returning simulated result")
                mock_efactura_id = f"EFRO-{invoice.number}-{uuid.uuid4().hex[:8].upper()}"
                return EFacturaSubmissionResult(
                    success=True,
                    efactura_id=mock_efactura_id,
                    upload_index=f"UI{uuid.uuid4().hex[:12].upper()}",
                    status=EFacturaStatus.SUBMITTED,
                    message="Invoice submitted to e-Factura (simulated — not configured)",
                    xml_content=xml_content,
                    response_data={"xml_hash": xml_hash, "simulated": True},
                )
            logger.error("🔥 [e-Factura] Not configured — cannot submit in production")
            return EFacturaSubmissionResult(
                success=False,
                status=EFacturaStatus.ERROR,
                message="e-Factura not configured — submission blocked",
                errors=["e-Factura credentials are not configured"],
                xml_content=xml_content,
                response_data={"xml_hash": xml_hash},
            )

        logger.info(f"🏛️ [e-Factura] Submitting invoice {invoice.number} to ANAF")
        try:
            client = EFacturaClient(config)
            upload_resp = client.upload_invoice(xml_content)
        except EFacturaClientError as exc:
            logger.error(f"🔥 [e-Factura] Client error submitting {invoice.number}: {exc}")
            return EFacturaSubmissionResult(
                success=False,
                status=EFacturaStatus.ERROR,
                message=f"e-Factura client error: {exc}",
                errors=[str(exc)],
                xml_content=xml_content,
                response_data={"xml_hash": xml_hash},
            )

        if not upload_resp.success:
            return EFacturaSubmissionResult(
                success=False,
                status=EFacturaStatus.ERROR,
                message=f"ANAF upload failed: {upload_resp.message}",
                errors=upload_resp.errors,
                xml_content=xml_content,
                response_data={"xml_hash": xml_hash, "raw": upload_resp.raw_response},
            )

        logger.info(f"✅ [e-Factura] Invoice {invoice.number} uploaded, index={upload_resp.upload_index}")
        return EFacturaSubmissionResult(
            success=True,
            upload_index=upload_resp.upload_index,
            status=EFacturaStatus.SUBMITTED,
            message="Invoice submitted to e-Factura",
            xml_content=xml_content,
            response_data={"xml_hash": xml_hash, "raw": upload_resp.raw_response},
        )

    def check_status(self, upload_index: str) -> EFacturaSubmissionResult:
        """
        Check the status of a submitted invoice.

        Args:
            upload_index: Upload index from submission

        Returns:
            EFacturaSubmissionResult with current status
        """
        from apps.billing.efactura.client import EFacturaClient, EFacturaClientError, EFacturaConfig  # noqa: PLC0415

        config = EFacturaConfig.from_settings()
        if not config.is_valid():
            if getattr(settings, "DEBUG", False):
                logger.warning("⚠️ [e-Factura] Not configured (DEBUG) — returning simulated status")
                return EFacturaSubmissionResult(
                    success=True,
                    upload_index=upload_index,
                    status=EFacturaStatus.ACCEPTED,
                    message="Status check successful (simulated — not configured)",
                )
            logger.error("🔥 [e-Factura] Not configured — cannot check status in production")
            return EFacturaSubmissionResult(
                success=False,
                upload_index=upload_index,
                status=EFacturaStatus.ERROR,
                message="e-Factura not configured — status check blocked",
                errors=["e-Factura credentials are not configured"],
            )

        logger.info(f"🏛️ [e-Factura] Checking status for upload index: {upload_index}")
        try:
            client = EFacturaClient(config)
            status_resp = client.get_upload_status(upload_index)
        except EFacturaClientError as exc:
            logger.error(f"🔥 [e-Factura] Client error checking status for {upload_index}: {exc}")
            return EFacturaSubmissionResult(
                success=False,
                upload_index=upload_index,
                status=EFacturaStatus.ERROR,
                message=f"e-Factura client error: {exc}",
                errors=[str(exc)],
            )

        if status_resp.is_accepted:
            efactura_status = EFacturaStatus.ACCEPTED
        elif status_resp.is_rejected:
            efactura_status = EFacturaStatus.REJECTED
        else:
            efactura_status = EFacturaStatus.PROCESSING

        return EFacturaSubmissionResult(
            success=True,
            upload_index=upload_index,
            status=efactura_status,
            message=f"Status: {status_resp.status}",
            response_data=status_resp.raw_response,
        )

    def download_response(self, download_id: str) -> Result[bytes, str]:
        """
        Download the response/confirmation from ANAF.

        Args:
            download_id: Download ID from status check

        Returns:
            Result with PDF/XML bytes or error
        """
        from apps.billing.efactura.client import EFacturaConfig  # noqa: PLC0415

        config = EFacturaConfig.from_settings()
        if not config.is_valid():
            logger.warning("⚠️ [e-Factura] Not configured — cannot download")
            return Err("e-Factura not configured")

        from apps.billing.efactura.client import EFacturaClient, EFacturaClientError  # noqa: PLC0415

        logger.info(f"🏛️ [e-Factura] Downloading response: {download_id}")
        try:
            client = EFacturaClient(config)
            content = client.download_response(download_id)
            return Ok(content)
        except EFacturaClientError as exc:
            logger.error(f"🔥 [e-Factura] Client error downloading {download_id}: {exc}")
            return Err(f"e-Factura client error: {exc}")
        except (OSError, ValueError, RuntimeError) as exc:
            logger.error(f"🔥 [e-Factura] Download failed for {download_id}: {exc}")
            return Err("Download failed — check logs for details")


# ===============================================================================
# EXPORTS
# ===============================================================================

__all__ = [
    "EFacturaStatus",
    "EFacturaSubmissionResult",
    "EFacturaSubmissionService",
    "EFacturaValidationResult",
    "EFacturaXMLGenerator",
]
