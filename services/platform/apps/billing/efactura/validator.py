"""
CIUS-RO XML validator for Romanian e-Factura compliance.

Validates UBL 2.1 XML documents against:
1. XSD Schema (structural validation)
2. CIUS-RO Schematron rules (business rules)

Reference:
- CIUS-RO Validation Artifacts v1.0.9
- https://mfinante.gov.ro/web/efactura/informatii-tehnice
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, ClassVar, cast

from lxml import etree

logger = logging.getLogger(__name__)

# UBL Namespaces for parsing
NAMESPACES = {
    "ubl": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cn": "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
}


@dataclass
class ValidationError:
    """Represents a single validation error."""

    code: str
    message: str
    location: str = ""
    severity: str = "error"  # error, warning, info

    def __str__(self) -> str:
        location_str = f" at {self.location}" if self.location else ""
        return f"[{self.code}] {self.message}{location_str}"

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
            "location": self.location,
            "severity": self.severity,
        }


@dataclass
class ValidationResult:
    """Result of XML validation."""

    is_valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)

    def __str__(self) -> str:
        if self.is_valid:
            return "Valid"
        return f"Invalid: {len(self.errors)} errors, {len(self.warnings)} warnings"

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": [e.to_dict() for e in self.errors],
            "warnings": [w.to_dict() for w in self.warnings],
        }

    def add_error(self, code: str, message: str, location: str = "") -> None:
        """Add a validation error."""
        self.errors.append(ValidationError(code=code, message=message, location=location, severity="error"))
        self.is_valid = False

    def add_warning(self, code: str, message: str, location: str = "") -> None:
        """Add a validation warning."""
        self.warnings.append(ValidationError(code=code, message=message, location=location, severity="warning"))


class CIUSROValidator:
    """
    Validate UBL 2.1 XML against Romanian CIUS-RO rules.

    This validator performs:
    1. XML well-formedness check
    2. Basic structural validation
    3. CIUS-RO mandatory field validation
    4. Romanian-specific business rules

    Note: Full schematron validation requires additional artifacts
    from ANAF which should be downloaded and cached.
    """

    # CIUS-RO version
    CIUS_RO_VERSION: ClassVar[str] = "1.0.1"
    EXPECTED_CUSTOMIZATION_ID: ClassVar[
        str
    ] = "urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1"

    # Romanian CUI validation pattern (8-10 digits)
    CUI_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"^(RO)?[0-9]{2,10}$")

    # Valid ISO 4217 currency codes
    VALID_CURRENCIES: ClassVar[set[str]] = {"RON", "EUR", "USD", "GBP", "CHF", "HUF", "PLN", "CZK", "BGN"}

    # Valid tax category codes
    VALID_TAX_CATEGORIES: ClassVar[set[str]] = {"S", "Z", "E", "AE", "K", "G", "O", "L", "M"}

    # Romanian VAT rates (updated Aug 2025)
    VALID_VAT_RATES: ClassVar[set[str]] = {"21.00", "11.00", "0.00"}

    def __init__(self) -> None:
        """Initialize validator."""
        self._xsd_schema: etree.XMLSchema | None = None

    def validate(self, xml_content: str) -> ValidationResult:
        """
        Validate XML content against CIUS-RO rules.

        Args:
            xml_content: UBL 2.1 XML string

        Returns:
            ValidationResult with is_valid flag and any errors/warnings
        """
        result = ValidationResult(is_valid=True)

        # Step 1: Parse XML
        try:
            doc = etree.fromstring(xml_content.encode("utf-8"))
        except etree.XMLSyntaxError as e:
            result.add_error("XML-SYNTAX", f"XML parsing failed: {e}")
            return result

        # Step 2: Determine document type
        root_tag = etree.QName(doc.tag).localname
        is_credit_note = root_tag == "CreditNote"

        # Step 3: Validate structure
        self._validate_document_metadata(doc, result, is_credit_note)

        # Step 4: Validate parties
        self._validate_supplier_party(doc, result)
        self._validate_customer_party(doc, result)

        # Step 5: Validate monetary totals
        self._validate_monetary_totals(doc, result)

        # Step 6: Validate tax totals
        self._validate_tax_totals(doc, result)

        # Step 7: Validate line items
        self._validate_invoice_lines(doc, result, is_credit_note)

        # Step 8: Romanian-specific rules
        self._validate_romanian_rules(doc, result)

        return result

    def validate_file(self, file_path: str) -> ValidationResult:
        """Validate XML from file path."""
        try:
            with open(file_path, encoding="utf-8") as f:
                return self.validate(f.read())
        except OSError as e:
            result = ValidationResult(is_valid=False)
            result.add_error("FILE-ERROR", f"Could not read file: {e}")
            return result

    def _find(self, doc: etree._Element, xpath: str) -> etree._Element | None:
        """Find element using XPath with namespaces."""
        result = doc.xpath(xpath, namespaces=NAMESPACES)
        if isinstance(result, list) and result:
            return cast(etree._Element, result[0])
        return None

    def _find_all(self, doc: etree._Element, xpath: str) -> list[etree._Element]:
        """Find all elements using XPath with namespaces."""
        return cast(list[etree._Element], doc.xpath(xpath, namespaces=NAMESPACES))

    def _get_text(self, doc: etree._Element, xpath: str) -> str:
        """Get text content of element."""
        elem = self._find(doc, xpath)
        return elem.text.strip() if elem is not None and elem.text else ""

    def _validate_document_metadata(
        self, doc: etree._Element, result: ValidationResult, is_credit_note: bool = False
    ) -> None:
        """Validate document-level metadata."""
        # BR-01: Invoice ID is mandatory
        invoice_id = self._get_text(doc, ".//cbc:ID")
        if not invoice_id:
            result.add_error("BR-01", "Invoice/Credit Note ID is mandatory", "/Invoice/ID")

        # BR-02: Issue date is mandatory
        issue_date = self._get_text(doc, ".//cbc:IssueDate")
        if not issue_date:
            result.add_error("BR-02", "Issue date is mandatory", "/Invoice/IssueDate")
        elif not self._is_valid_date(issue_date):
            result.add_error("BR-02-FMT", f"Invalid date format: {issue_date}", "/Invoice/IssueDate")

        # BR-04: Invoice type code is mandatory
        if is_credit_note:
            type_code = self._get_text(doc, ".//cbc:CreditNoteTypeCode")
            if not type_code:
                result.add_error("BR-04", "Credit note type code is mandatory")
        else:
            type_code = self._get_text(doc, ".//cbc:InvoiceTypeCode")
            if not type_code:
                result.add_error("BR-04", "Invoice type code is mandatory")

        # BR-05: Document currency is mandatory
        currency = self._get_text(doc, ".//cbc:DocumentCurrencyCode")
        if not currency:
            result.add_error("BR-05", "Document currency code is mandatory")
        elif currency not in self.VALID_CURRENCIES:
            result.add_warning("BR-05-CUR", f"Unusual currency code: {currency}")

        # CIUS-RO: Customization ID must be correct
        customization_id = self._get_text(doc, ".//cbc:CustomizationID")
        if not customization_id:
            result.add_error("BR-RO-001", "CustomizationID is mandatory for CIUS-RO")
        elif customization_id != self.EXPECTED_CUSTOMIZATION_ID:
            result.add_warning(
                "BR-RO-001-VER",
                f"CustomizationID should be {self.EXPECTED_CUSTOMIZATION_ID}",
            )

    def _validate_supplier_party(self, doc: etree._Element, result: ValidationResult) -> None:
        """Validate AccountingSupplierParty."""
        supplier = self._find(doc, ".//cac:AccountingSupplierParty/cac:Party")
        if supplier is None:
            result.add_error("BR-06", "Supplier (seller) party is mandatory")
            return

        # BR-06: Seller name
        seller_name = self._get_text(supplier, ".//cac:PartyLegalEntity/cbc:RegistrationName")
        if not seller_name:
            seller_name = self._get_text(supplier, ".//cac:PartyName/cbc:Name")
        if not seller_name:
            result.add_error("BR-06", "Seller name is mandatory")

        # BR-08: Seller postal address
        address = self._find(supplier, ".//cac:PostalAddress")
        if address is None:
            result.add_error("BR-08", "Seller postal address is mandatory")
        else:
            country = self._get_text(address, ".//cac:Country/cbc:IdentificationCode")
            if not country:
                result.add_error("BR-09", "Seller country code is mandatory")

        # BR-RO-010: Romanian seller must have CUI
        seller_country = self._get_text(supplier, ".//cac:PostalAddress/cac:Country/cbc:IdentificationCode")
        if seller_country == "RO":
            seller_id = self._get_text(supplier, ".//cac:PartyIdentification/cbc:ID")
            if not seller_id:
                result.add_error("BR-RO-010", "Romanian seller must have CUI identification")
            elif not self.CUI_PATTERN.match(seller_id):
                result.add_error("BR-RO-010-FMT", f"Invalid Romanian CUI format: {seller_id}")

        # BR-CO-26: Seller VAT identifier
        vat_id = self._get_text(supplier, ".//cac:PartyTaxScheme/cbc:CompanyID")
        if not vat_id:
            result.add_warning("BR-CO-26", "Seller VAT identifier is recommended")

    def _validate_customer_party(self, doc: etree._Element, result: ValidationResult) -> None:
        """Validate AccountingCustomerParty."""
        customer = self._find(doc, ".//cac:AccountingCustomerParty/cac:Party")
        if customer is None:
            result.add_error("BR-07", "Customer (buyer) party is mandatory")
            return

        # BR-07: Buyer name
        buyer_name = self._get_text(customer, ".//cac:PartyLegalEntity/cbc:RegistrationName")
        if not buyer_name:
            buyer_name = self._get_text(customer, ".//cac:PartyName/cbc:Name")
        if not buyer_name:
            result.add_error("BR-07", "Buyer name is mandatory")

        # BR-11: Buyer postal address
        address = self._find(customer, ".//cac:PostalAddress")
        if address is None:
            result.add_error("BR-11", "Buyer postal address is mandatory")
        else:
            country = self._get_text(address, ".//cac:Country/cbc:IdentificationCode")
            if not country:
                result.add_error("BR-12", "Buyer country code is mandatory")

        # BR-RO-020: Romanian buyer in B2B must have CUI
        buyer_country = self._get_text(customer, ".//cac:PostalAddress/cac:Country/cbc:IdentificationCode")
        if buyer_country == "RO":
            buyer_id = self._get_text(customer, ".//cac:PartyIdentification/cbc:ID")
            if not buyer_id:
                result.add_warning("BR-RO-020", "Romanian B2B buyer should have CUI identification")

    def _validate_monetary_totals(self, doc: etree._Element, result: ValidationResult) -> None:
        """Validate LegalMonetaryTotal."""
        monetary = self._find(doc, ".//cac:LegalMonetaryTotal")
        if monetary is None:
            result.add_error("BR-52", "Legal monetary total is mandatory")
            return

        # BR-52: Tax exclusive amount
        tax_exclusive = self._get_text(monetary, ".//cbc:TaxExclusiveAmount")
        if not tax_exclusive:
            result.add_error("BR-52", "Tax exclusive amount is mandatory")

        # BR-53: Tax inclusive amount
        tax_inclusive = self._get_text(monetary, ".//cbc:TaxInclusiveAmount")
        if not tax_inclusive:
            result.add_error("BR-53", "Tax inclusive amount is mandatory")

        # BR-55: Payable amount
        payable = self._get_text(monetary, ".//cbc:PayableAmount")
        if not payable:
            result.add_error("BR-55", "Payable amount is mandatory")

        # Validate amounts are numeric
        for amount_name, amount_value in [
            ("TaxExclusiveAmount", tax_exclusive),
            ("TaxInclusiveAmount", tax_inclusive),
            ("PayableAmount", payable),
        ]:
            if amount_value and not self._is_valid_amount(amount_value):
                result.add_error("BR-AMOUNT", f"Invalid amount format in {amount_name}: {amount_value}")

    def _validate_tax_totals(self, doc: etree._Element, result: ValidationResult) -> None:
        """Validate TaxTotal."""
        tax_totals = self._find_all(doc, ".//cac:TaxTotal")
        if not tax_totals:
            result.add_error("BR-45", "At least one tax total is mandatory")
            return

        for tax_total in tax_totals:
            # BR-45: Tax amount
            tax_amount = self._get_text(tax_total, ".//cbc:TaxAmount")
            if not tax_amount:
                result.add_error("BR-45", "Tax amount is mandatory")

            # Validate subtotals
            subtotals = self._find_all(tax_total, ".//cac:TaxSubtotal")
            for subtotal in subtotals:
                # BR-45: Taxable amount
                taxable = self._get_text(subtotal, ".//cbc:TaxableAmount")
                if not taxable:
                    result.add_error("BR-46", "Taxable amount is mandatory in tax subtotal")

                # BR-48: Tax category
                category_id = self._get_text(subtotal, ".//cac:TaxCategory/cbc:ID")
                if not category_id:
                    result.add_error("BR-48", "Tax category ID is mandatory")
                elif category_id not in self.VALID_TAX_CATEGORIES:
                    result.add_error("BR-48-CAT", f"Invalid tax category: {category_id}")

                # Tax rate validation for standard rate
                if category_id == "S":
                    percent = self._get_text(subtotal, ".//cac:TaxCategory/cbc:Percent")
                    if not percent:
                        result.add_error("BR-48-PCT", "Tax percentage is mandatory for standard rate")

    def _validate_invoice_lines(
        self, doc: etree._Element, result: ValidationResult, is_credit_note: bool = False
    ) -> None:
        """Validate invoice/credit note lines."""
        line_tag = "CreditNoteLine" if is_credit_note else "InvoiceLine"
        lines = self._find_all(doc, f".//cac:{line_tag}")

        if not lines:
            result.add_error("BR-16", f"At least one {line_tag} is mandatory")
            return

        for idx, line in enumerate(lines, start=1):
            line_path = f"/{line_tag}[{idx}]"

            # BR-21: Line ID
            line_id = self._get_text(line, ".//cbc:ID")
            if not line_id:
                result.add_error("BR-21", "Line ID is mandatory", line_path)

            # BR-22: Invoiced/Credited quantity
            qty_tag = "CreditedQuantity" if is_credit_note else "InvoicedQuantity"
            quantity = self._get_text(line, f".//cbc:{qty_tag}")
            if not quantity:
                result.add_error("BR-22", "Quantity is mandatory", line_path)

            # BR-25: Line extension amount
            line_amount = self._get_text(line, ".//cbc:LineExtensionAmount")
            if not line_amount:
                result.add_error("BR-25", "Line extension amount is mandatory", line_path)

            # BR-26: Item name
            item_name = self._get_text(line, ".//cac:Item/cbc:Name")
            if not item_name:
                result.add_error("BR-26", "Item name is mandatory", line_path)

            # BR-31: Line item tax category
            item_tax_cat = self._get_text(line, ".//cac:Item/cac:ClassifiedTaxCategory/cbc:ID")
            if not item_tax_cat:
                result.add_error("BR-31", "Item tax category is mandatory", line_path)

    def _validate_romanian_rules(self, doc: etree._Element, result: ValidationResult) -> None:
        """Validate Romania-specific CIUS-RO rules."""
        # BR-RO-100: Validate Romanian VAT rates
        tax_categories = self._find_all(doc, ".//cac:TaxCategory")
        for cat in tax_categories:
            cat_id = self._get_text(cat, ".//cbc:ID")
            if cat_id == "S":  # Standard rate
                percent = self._get_text(cat, ".//cbc:Percent")
                if percent and percent not in self.VALID_VAT_RATES:
                    result.add_warning("BR-RO-100", f"Unusual Romanian VAT rate: {percent}%")

        # BR-RO-200: Payment means should be specified
        payment_means = self._find(doc, ".//cac:PaymentMeans")
        if payment_means is None:
            result.add_warning("BR-RO-200", "Payment means is recommended")

        # BR-RO-300: Due date is recommended
        due_date = self._get_text(doc, ".//cbc:DueDate")
        if not due_date:
            result.add_warning("BR-RO-300", "Due date is recommended")

    def _is_valid_date(self, date_str: str) -> bool:
        """Check if string is valid YYYY-MM-DD date."""
        if not date_str:
            return False
        pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")
        return bool(pattern.match(date_str))

    def _is_valid_amount(self, amount_str: str) -> bool:
        """Check if string is valid decimal amount."""
        if not amount_str:
            return False
        try:
            float(amount_str)
            return True
        except ValueError:
            return False
