"""
UBL 2.1 XML builder for Romanian e-Factura with CIUS-RO compliance.

Generates valid UBL 2.1 Invoice and Credit Note XML documents
following the Romanian CIUS-RO national specification.

Reference:
- UBL 2.1: https://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.html
- CIUS-RO: https://mfinante.gov.ro/web/efactura/informatii-tehnice
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import TYPE_CHECKING

from django.conf import settings
from lxml import etree

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice, InvoiceLine

logger = logging.getLogger(__name__)

# UBL 2.1 Namespaces
NAMESPACES = {
    "ubl": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cn": "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
}

# CIUS-RO Customization ID (version 1.0.1)
CIUS_RO_CUSTOMIZATION_ID = "urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1"

# PEPPOL BIS Billing 3.0 Profile ID
PEPPOL_PROFILE_ID = "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0"

# Invoice type codes (UNCL1001)
INVOICE_TYPE_COMMERCIAL = "380"  # Commercial invoice
INVOICE_TYPE_CREDIT_NOTE = "381"  # Credit note
INVOICE_TYPE_DEBIT_NOTE = "383"  # Debit note

# Tax category codes (UNCL5305)
TAX_CATEGORY_STANDARD = "S"  # Standard rate
TAX_CATEGORY_ZERO = "Z"  # Zero rated
TAX_CATEGORY_EXEMPT = "E"  # Exempt
TAX_CATEGORY_REVERSE_CHARGE = "AE"  # Reverse charge
TAX_CATEGORY_NOT_SUBJECT = "O"  # Not subject to VAT

# Unit codes (UN/ECE Recommendation 20)
UNIT_CODE_PIECE = "C62"  # One (piece)
UNIT_CODE_HOUR = "HUR"  # Hour
UNIT_CODE_DAY = "DAY"  # Day
UNIT_CODE_MONTH = "MON"  # Month
UNIT_CODE_YEAR = "ANN"  # Year


@dataclass
class CompanyInfo:
    """Company information for invoice parties."""

    name: str
    tax_id: str  # CUI/VAT number
    registration_number: str  # J number for Romanian companies
    street: str
    city: str
    postal_code: str
    country_code: str = "RO"
    country_name: str = "Romania"
    email: str = ""
    phone: str = ""

    @property
    def vat_number(self) -> str:
        """Get full VAT number with country prefix."""
        if self.tax_id.startswith(self.country_code):
            return self.tax_id
        return f"{self.country_code}{self.tax_id}"

    @property
    def numeric_tax_id(self) -> str:
        """Get numeric tax ID without country prefix."""
        tax_id = self.tax_id
        if tax_id.startswith("RO"):
            tax_id = tax_id[2:]
        return tax_id.strip()


class XMLBuilderError(Exception):
    """Exception raised when XML building fails."""


class BaseUBLBuilder:
    """Base class for UBL document builders."""

    def __init__(self, invoice: Invoice):
        self.invoice = invoice
        self.root: etree._Element | None = None
        self._supplier: CompanyInfo | None = None
        self._customer: CompanyInfo | None = None

    def _get_supplier_info(self) -> CompanyInfo:
        """Get supplier (seller) information from settings."""
        if self._supplier is None:
            self._supplier = CompanyInfo(
                name=getattr(settings, "COMPANY_NAME", ""),
                tax_id=getattr(settings, "EFACTURA_COMPANY_CUI", ""),
                registration_number=getattr(settings, "COMPANY_REGISTRATION_NUMBER", ""),
                street=getattr(settings, "COMPANY_STREET", ""),
                city=getattr(settings, "COMPANY_CITY", ""),
                postal_code=getattr(settings, "COMPANY_POSTAL_CODE", ""),
                country_code=getattr(settings, "COMPANY_COUNTRY_CODE", "RO"),
                country_name=getattr(settings, "COMPANY_COUNTRY_NAME", "Romania"),
                email=getattr(settings, "COMPANY_EMAIL", ""),
                phone=getattr(settings, "COMPANY_PHONE", ""),
            )
        return self._supplier

    def _get_customer_info(self) -> CompanyInfo:
        """Get customer (buyer) information from invoice."""
        if self._customer is None:
            bill_to_country = getattr(self.invoice, "bill_to_country", None) or "RO"
            street = (
                getattr(self.invoice, "bill_to_street", None) or getattr(self.invoice, "bill_to_address1", "") or ""
            )
            postal_code = (
                getattr(self.invoice, "bill_to_postal_code", None) or getattr(self.invoice, "bill_to_postal", "") or ""
            )
            self._customer = CompanyInfo(
                name=getattr(self.invoice, "bill_to_name", "") or "",
                tax_id=getattr(self.invoice, "bill_to_tax_id", "") or "",
                registration_number=getattr(self.invoice, "bill_to_registration_number", "") or "",
                street=street,
                city=getattr(self.invoice, "bill_to_city", "") or "",
                postal_code=postal_code,
                country_code=bill_to_country,
                country_name=self._get_country_name(bill_to_country),
                email=getattr(self.invoice, "bill_to_email", "") or "",
                phone=getattr(self.invoice, "bill_to_phone", "") or "",
            )
        return self._customer

    def _get_country_name(self, country_code: str) -> str:
        """Get country name from country code."""
        country_names = {
            "RO": "Romania",
            "DE": "Germany",
            "FR": "France",
            "IT": "Italy",
            "ES": "Spain",
            "NL": "Netherlands",
            "BE": "Belgium",
            "AT": "Austria",
            "PL": "Poland",
            "HU": "Hungary",
            "BG": "Bulgaria",
            "CZ": "Czech Republic",
            "SK": "Slovakia",
            "SI": "Slovenia",
            "HR": "Croatia",
            "GR": "Greece",
            "PT": "Portugal",
            "SE": "Sweden",
            "DK": "Denmark",
            "FI": "Finland",
            "IE": "Ireland",
            "LU": "Luxembourg",
            "EE": "Estonia",
            "LV": "Latvia",
            "LT": "Lithuania",
            "CY": "Cyprus",
            "MT": "Malta",
            "GB": "United Kingdom",
            "US": "United States",
        }
        return country_names.get(country_code, country_code)

    def _cbc(self, tag: str) -> str:
        """Create CommonBasicComponents tag."""
        return f"{{{NAMESPACES['cbc']}}}{tag}"

    def _cac(self, tag: str) -> str:
        """Create CommonAggregateComponents tag."""
        return f"{{{NAMESPACES['cac']}}}{tag}"

    def _add_element(self, parent: etree._Element, tag: str, text: str | None = None, **attribs: str) -> etree._Element:
        """Add element with optional text and attributes."""
        elem = etree.SubElement(parent, tag)
        if text is not None:
            elem.text = str(text)
        for key, value in attribs.items():
            elem.set(key, value)
        return elem

    def _add_cbc(self, parent: etree._Element, tag: str, text: str | None = None, **attribs: str) -> etree._Element:
        """Add CommonBasicComponents element."""
        return self._add_element(parent, self._cbc(tag), text, **attribs)

    def _add_cac(self, parent: etree._Element, tag: str) -> etree._Element:
        """Add CommonAggregateComponents element."""
        return self._add_element(parent, self._cac(tag))

    def _format_date(self, dt: date | None) -> str:
        """Format date as YYYY-MM-DD."""
        if dt is None:
            return ""
        return dt.strftime("%Y-%m-%d")

    def _format_amount(self, amount: Decimal | float | int) -> str:
        """Format monetary amount with 2 decimal places."""
        return f"{Decimal(str(amount)):.2f}"

    def _format_quantity(self, quantity: Decimal | float | int) -> str:
        """Format quantity with up to 6 decimal places."""
        return f"{Decimal(str(quantity)):.6f}".rstrip("0").rstrip(".")

    def _format_percent(self, percent: Decimal | float | int) -> str:
        """Format percentage with 2 decimal places."""
        return f"{Decimal(str(percent)):.2f}"

    def _get_tax_category(self) -> str:
        """Determine tax category code based on invoice."""
        # Check for reverse charge (B2B EU)
        customer = self._get_customer_info()
        if customer.country_code != "RO" and customer.tax_id:
            return TAX_CATEGORY_REVERSE_CHARGE

        # Check for zero rate
        tax_total_cents = getattr(self.invoice, "tax_total_cents", None)
        if tax_total_cents is None:
            tax_total_cents = getattr(self.invoice, "tax_cents", 0)

        if tax_total_cents == 0:
            return TAX_CATEGORY_ZERO

        # Default to standard rate
        return TAX_CATEGORY_STANDARD

    def _get_tax_rate(self) -> Decimal:
        """Get tax rate as percentage from the invoice's own stored data.

        Uses the invoice's line-level tax rates (frozen at creation time) to
        preserve document immutability. Falls back to TaxService only when
        the invoice has no lines or no stored rate.
        """
        # Try to derive from invoice lines (frozen at invoice creation)
        lines = getattr(self.invoice, "lines", None)
        if lines is not None:
            first_line = lines.first() if hasattr(lines, "first") else None
            if first_line is not None:
                tax_rate = getattr(first_line, "tax_rate", None)
                if tax_rate is not None:
                    return (Decimal(str(tax_rate)) * 100).quantize(Decimal("0.01"))

        # Fallback: current rate from TaxService (only for invoices with no lines)
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        return TaxService.get_vat_rate("RO", as_decimal=False)

    def _add_postal_address(self, parent: etree._Element, company: CompanyInfo) -> etree._Element:
        """Add PostalAddress element."""
        address = self._add_cac(parent, "PostalAddress")

        if company.street:
            self._add_cbc(address, "StreetName", company.street)

        if company.city:
            self._add_cbc(address, "CityName", company.city)

        if company.postal_code:
            self._add_cbc(address, "PostalZone", company.postal_code)

        # Country is mandatory
        country = self._add_cac(address, "Country")
        self._add_cbc(country, "IdentificationCode", company.country_code)
        self._add_cbc(country, "Name", company.country_name)

        return address

    def _add_party_tax_scheme(self, parent: etree._Element, vat_number: str) -> etree._Element:
        """Add PartyTaxScheme element."""
        tax_scheme = self._add_cac(parent, "PartyTaxScheme")
        self._add_cbc(tax_scheme, "CompanyID", vat_number)

        scheme = self._add_cac(tax_scheme, "TaxScheme")
        self._add_cbc(scheme, "ID", "VAT")

        return tax_scheme

    def _add_party_legal_entity(
        self, parent: etree._Element, name: str, registration_number: str = ""
    ) -> etree._Element:
        """Add PartyLegalEntity element."""
        legal = self._add_cac(parent, "PartyLegalEntity")
        self._add_cbc(legal, "RegistrationName", name)

        if registration_number:
            self._add_cbc(legal, "CompanyID", registration_number)

        return legal

    def _add_contact(self, parent: etree._Element, company: CompanyInfo) -> etree._Element | None:
        """Add Contact element if contact info available."""
        if not company.email and not company.phone:
            return None

        contact = self._add_cac(parent, "Contact")

        if company.phone:
            self._add_cbc(contact, "Telephone", company.phone)

        if company.email:
            self._add_cbc(contact, "ElectronicMail", company.email)

        return contact


class UBLInvoiceBuilder(BaseUBLBuilder):
    """
    Build UBL 2.1 Invoice XML compliant with Romanian CIUS-RO.

    Usage:
        builder = UBLInvoiceBuilder(invoice)
        xml_string = builder.build()
    """

    def build(self) -> str:
        """
        Generate complete UBL 2.1 Invoice XML.

        Returns:
            XML string encoded as UTF-8

        Raises:
            XMLBuilderError: If required data is missing or invalid
        """
        self._validate_invoice()
        self._create_root()
        self._add_document_metadata()
        self._add_supplier_party()
        self._add_customer_party()
        self._add_payment_means()
        self._add_payment_terms()
        self._add_tax_total()
        self._add_legal_monetary_total()
        self._add_invoice_lines()

        xml_body = etree.tostring(
            self.root,
            pretty_print=True,
            xml_declaration=False,
            encoding="UTF-8",
        ).decode("utf-8")
        return f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_body.lstrip()}'

    def _validate_invoice(self) -> None:
        """Validate invoice has required data for e-Factura."""
        errors = []

        if not self.invoice.number:
            errors.append("Invoice number is required")

        if not self.invoice.issued_at:
            errors.append("Issue date is required")

        if not self.invoice.bill_to_name:
            errors.append("Customer name is required")

        if not self.invoice.bill_to_country:
            errors.append("Customer country is required")

        # Romanian B2B requires tax ID
        if self.invoice.bill_to_country == "RO" and not self.invoice.bill_to_tax_id:
            errors.append("Romanian B2B invoice requires customer tax ID (CUI)")

        if not self.invoice.lines.exists():
            errors.append("Invoice must have at least one line item")

        supplier = self._get_supplier_info()
        if not supplier.name:
            errors.append("Supplier company name not configured (COMPANY_NAME setting)")

        if not supplier.tax_id:
            errors.append("Supplier tax ID not configured (EFACTURA_COMPANY_CUI setting)")

        if errors:
            raise XMLBuilderError(f"Invalid invoice data: {'; '.join(errors)}")

    def _create_root(self) -> None:
        """Create Invoice root element with namespaces."""
        nsmap = {
            None: NAMESPACES["ubl"],
            "cac": NAMESPACES["cac"],
            "cbc": NAMESPACES["cbc"],
        }
        self.root = etree.Element(f"{{{NAMESPACES['ubl']}}}Invoice", nsmap=nsmap)

    def _add_document_metadata(self) -> None:
        """Add invoice document metadata."""
        # Mandatory CIUS-RO customization identifier.
        self._add_cbc(self.root, "CustomizationID", CIUS_RO_CUSTOMIZATION_ID)

        # ProfileID (PEPPOL BIS) - Mandatory
        self._add_cbc(self.root, "ProfileID", PEPPOL_PROFILE_ID)

        # Invoice ID (sequential number) - Mandatory
        self._add_cbc(self.root, "ID", self.invoice.number)

        # Issue Date - Mandatory
        self._add_cbc(self.root, "IssueDate", self._format_date(self.invoice.issued_at.date()))

        # Due Date - Optional but recommended
        if self.invoice.due_at:
            self._add_cbc(self.root, "DueDate", self._format_date(self.invoice.due_at.date()))

        # Invoice Type Code - Mandatory
        self._add_cbc(self.root, "InvoiceTypeCode", INVOICE_TYPE_COMMERCIAL)

        # Note - Optional
        notes = getattr(self.invoice, "notes", "")
        if notes:
            self._add_cbc(self.root, "Note", notes[:1000])  # Limit to 1000 chars

        # Document Currency Code - Mandatory
        self._add_cbc(self.root, "DocumentCurrencyCode", self.invoice.currency.code)

        # Buyer Reference - Optional but useful
        if hasattr(self.invoice, "customer_reference") and self.invoice.customer_reference:
            self._add_cbc(self.root, "BuyerReference", self.invoice.customer_reference)

    def _add_supplier_party(self) -> None:
        """Add AccountingSupplierParty (seller)."""
        supplier_party = self._add_cac(self.root, "AccountingSupplierParty")
        party = self._add_cac(supplier_party, "Party")

        supplier = self._get_supplier_info()

        # PartyIdentification with CUI - Mandatory for Romania
        party_id = self._add_cac(party, "PartyIdentification")
        id_elem = self._add_cbc(party_id, "ID", supplier.numeric_tax_id)
        id_elem.set("schemeID", "RO:CUI")

        # PartyName - Mandatory
        party_name = self._add_cac(party, "PartyName")
        self._add_cbc(party_name, "Name", supplier.name)

        # PostalAddress - Mandatory
        self._add_postal_address(party, supplier)

        # Mandatory VAT tax scheme details.
        self._add_party_tax_scheme(party, supplier.vat_number)

        # PartyLegalEntity - Mandatory
        self._add_party_legal_entity(party, supplier.name, supplier.registration_number)

        # Contact - Optional
        self._add_contact(party, supplier)

    def _add_customer_party(self) -> None:
        """Add AccountingCustomerParty (buyer)."""
        customer_party = self._add_cac(self.root, "AccountingCustomerParty")
        party = self._add_cac(customer_party, "Party")

        customer = self._get_customer_info()

        # PartyIdentification with CUI - Mandatory for Romanian B2B
        if customer.tax_id:
            party_id = self._add_cac(party, "PartyIdentification")
            id_elem = self._add_cbc(party_id, "ID", customer.numeric_tax_id)

            # Set scheme based on country
            if customer.country_code == "RO":
                id_elem.set("schemeID", "RO:CUI")
            else:
                # For EU VAT numbers
                id_elem.set("schemeID", f"{customer.country_code}:VAT")

        # PartyName - Mandatory
        party_name = self._add_cac(party, "PartyName")
        self._add_cbc(party_name, "Name", customer.name)

        # PostalAddress - Mandatory
        self._add_postal_address(party, customer)

        # PartyTaxScheme - Mandatory if VAT registered
        if customer.tax_id:
            self._add_party_tax_scheme(party, customer.vat_number)

        # PartyLegalEntity - Mandatory
        self._add_party_legal_entity(party, customer.name, customer.registration_number)

        # Contact - Optional
        self._add_contact(party, customer)

    def _add_payment_means(self) -> None:
        """Add PaymentMeans element."""
        payment_means = self._add_cac(self.root, "PaymentMeans")

        # Payment Means Code - Mandatory
        # 30 = Credit transfer, 49 = Direct debit, 48 = Bank card
        self._add_cbc(payment_means, "PaymentMeansCode", "30")

        # Payment Due Date
        if self.invoice.due_at:
            self._add_cbc(payment_means, "PaymentDueDate", self._format_date(self.invoice.due_at.date()))

        # Payment ID (reference for bank transfer)
        self._add_cbc(payment_means, "PaymentID", self.invoice.number)

        # Payee Financial Account (bank account details)
        bank_account = getattr(settings, "COMPANY_BANK_ACCOUNT", "")
        if bank_account:
            account = self._add_cac(payment_means, "PayeeFinancialAccount")
            self._add_cbc(account, "ID", bank_account)

            bank_name = getattr(settings, "COMPANY_BANK_NAME", "")
            if bank_name:
                branch = self._add_cac(account, "FinancialInstitutionBranch")
                self._add_cbc(branch, "Name", bank_name)

    def _add_payment_terms(self) -> None:
        """Add PaymentTerms element."""
        if self.invoice.due_at and self.invoice.issued_at:
            payment_terms = self._add_cac(self.root, "PaymentTerms")

            # Calculate days
            days = (self.invoice.due_at - self.invoice.issued_at).days
            note = f"Net {days} days" if days > 0 else "Due on receipt"

            self._add_cbc(payment_terms, "Note", note)

    def _add_tax_total(self) -> None:
        """Add TaxTotal element."""
        tax_total = self._add_cac(self.root, "TaxTotal")

        # Total tax amount
        tax_amount_cents = getattr(self.invoice, "tax_total_cents", None)
        if tax_amount_cents is None:
            tax_amount_cents = getattr(self.invoice, "tax_cents", 0)
        tax_amount = Decimal(tax_amount_cents) / 100
        tax_amount_elem = self._add_cbc(tax_total, "TaxAmount", self._format_amount(tax_amount))
        tax_amount_elem.set("currencyID", self.invoice.currency.code)

        # Tax subtotal (breakdown by tax category)
        tax_subtotal = self._add_cac(tax_total, "TaxSubtotal")

        # Taxable amount
        taxable_amount = Decimal(self.invoice.subtotal_cents or 0) / 100
        taxable_elem = self._add_cbc(tax_subtotal, "TaxableAmount", self._format_amount(taxable_amount))
        taxable_elem.set("currencyID", self.invoice.currency.code)

        # Tax amount for this category
        tax_elem = self._add_cbc(tax_subtotal, "TaxAmount", self._format_amount(tax_amount))
        tax_elem.set("currencyID", self.invoice.currency.code)

        # Tax Category
        tax_category = self._add_cac(tax_subtotal, "TaxCategory")
        self._add_cbc(tax_category, "ID", self._get_tax_category())
        self._add_cbc(tax_category, "Percent", self._format_percent(self._get_tax_rate()))

        tax_scheme = self._add_cac(tax_category, "TaxScheme")
        self._add_cbc(tax_scheme, "ID", "VAT")

    def _add_legal_monetary_total(self) -> None:
        """Add LegalMonetaryTotal element."""
        monetary_total = self._add_cac(self.root, "LegalMonetaryTotal")
        currency = self.invoice.currency.code

        # Line Extension Amount (sum of line totals without tax)
        subtotal = Decimal(self.invoice.subtotal_cents or 0) / 100
        line_ext = self._add_cbc(monetary_total, "LineExtensionAmount", self._format_amount(subtotal))
        line_ext.set("currencyID", currency)

        # Tax Exclusive Amount (same as line extension for simple invoices)
        tax_excl = self._add_cbc(monetary_total, "TaxExclusiveAmount", self._format_amount(subtotal))
        tax_excl.set("currencyID", currency)

        # Tax Inclusive Amount (total with tax)
        total = Decimal(self.invoice.total_cents or 0) / 100
        tax_incl = self._add_cbc(monetary_total, "TaxInclusiveAmount", self._format_amount(total))
        tax_incl.set("currencyID", currency)

        # Payable Amount (amount to be paid)
        payable = self._add_cbc(monetary_total, "PayableAmount", self._format_amount(total))
        payable.set("currencyID", currency)

    def _add_invoice_lines(self) -> None:
        """Add InvoiceLine elements for each line item."""
        for idx, line in enumerate(self.invoice.lines.all().order_by("id"), start=1):
            self._add_invoice_line(idx, line)

    def _add_invoice_line(self, line_id: int, line: InvoiceLine) -> None:
        """Add a single InvoiceLine element."""
        invoice_line = self._add_cac(self.root, "InvoiceLine")

        # Line ID - Mandatory
        self._add_cbc(invoice_line, "ID", str(line_id))

        # Note - Optional
        if hasattr(line, "notes") and line.notes:
            self._add_cbc(invoice_line, "Note", line.notes[:200])

        # Invoiced Quantity - Mandatory
        quantity = getattr(line, "quantity", 1) or 1
        quantity_elem = self._add_cbc(invoice_line, "InvoicedQuantity", self._format_quantity(quantity))
        quantity_elem.set("unitCode", self._get_unit_code(line))

        # Line Extension Amount (quantity * unit price, without tax)
        unit_price = Decimal(line.unit_price_cents or 0) / 100
        line_amount = unit_price * Decimal(str(quantity))
        line_ext = self._add_cbc(invoice_line, "LineExtensionAmount", self._format_amount(line_amount))
        line_ext.set("currencyID", self.invoice.currency.code)

        # Item
        self._add_line_item(invoice_line, line)

        # Price
        self._add_line_price(invoice_line, line)

    def _add_line_item(self, parent: etree._Element, line: InvoiceLine) -> None:
        """Add Item element to invoice line."""
        item = self._add_cac(parent, "Item")

        # Description - Optional but recommended
        description = line.description or ""
        if description:
            self._add_cbc(item, "Description", description[:1000])

        # Name - Mandatory
        name = description[:100] if description else f"Item {line.id}"
        self._add_cbc(item, "Name", name)

        # ClassifiedTaxCategory - Mandatory
        tax_category = self._add_cac(item, "ClassifiedTaxCategory")
        self._add_cbc(tax_category, "ID", self._get_tax_category())

        # Get line-specific tax rate or default
        tax_rate = getattr(line, "tax_rate", None)
        percent = Decimal(str(tax_rate)) * 100 if tax_rate is not None else self._get_tax_rate()
        self._add_cbc(tax_category, "Percent", self._format_percent(percent))

        tax_scheme = self._add_cac(tax_category, "TaxScheme")
        self._add_cbc(tax_scheme, "ID", "VAT")

    def _add_line_price(self, parent: etree._Element, line: InvoiceLine) -> None:
        """Add Price element to invoice line."""
        price = self._add_cac(parent, "Price")

        unit_price = Decimal(line.unit_price_cents or 0) / 100
        price_amount = self._add_cbc(price, "PriceAmount", self._format_amount(unit_price))
        price_amount.set("currencyID", self.invoice.currency.code)

    def _get_unit_code(self, line: InvoiceLine) -> str:
        """Get UN/ECE unit code for the line item."""
        # Check for unit type on line
        unit_type = getattr(line, "unit_type", None)
        if unit_type:
            unit_mapping = {
                "hour": UNIT_CODE_HOUR,
                "day": UNIT_CODE_DAY,
                "month": UNIT_CODE_MONTH,
                "year": UNIT_CODE_YEAR,
                "piece": UNIT_CODE_PIECE,
            }
            return unit_mapping.get(unit_type.lower(), UNIT_CODE_PIECE)

        # Default to piece/unit
        return UNIT_CODE_PIECE


class UBLCreditNoteBuilder(BaseUBLBuilder):
    """
    Build UBL 2.1 Credit Note XML compliant with Romanian CIUS-RO.

    Used for refunds and corrections to previously issued invoices.

    Usage:
        builder = UBLCreditNoteBuilder(credit_note_invoice, original_invoice)
        xml_string = builder.build()
    """

    def __init__(self, invoice: Invoice, original_invoice: Invoice | None = None):
        super().__init__(invoice)
        self.original_invoice = original_invoice

    def build(self) -> str:
        """Generate complete UBL 2.1 Credit Note XML."""
        self._validate_invoice()
        self._create_root()
        self._add_document_metadata()
        self._add_billing_reference()
        self._add_supplier_party()
        self._add_customer_party()
        self._add_tax_total()
        self._add_legal_monetary_total()
        self._add_credit_note_lines()

        xml_body = etree.tostring(
            self.root,
            pretty_print=True,
            xml_declaration=False,
            encoding="UTF-8",
        ).decode("utf-8")
        return f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_body.lstrip()}'

    def _validate_invoice(self) -> None:
        """Validate credit note has required data."""
        errors = []

        if not self.invoice.number:
            errors.append("Credit note number is required")

        if not self.invoice.issued_at:
            errors.append("Credit note issue date is required")

        if not self.invoice.bill_to_name:
            errors.append("Customer name is required")

        if self.original_invoice is None:
            errors.append("Original invoice reference is required for credit notes")

        if errors:
            raise XMLBuilderError(f"Invalid credit note data: {'; '.join(errors)}")

    def _create_root(self) -> None:
        """Create CreditNote root element with namespaces."""
        nsmap = {
            None: NAMESPACES["cn"],
            "cac": NAMESPACES["cac"],
            "cbc": NAMESPACES["cbc"],
        }
        self.root = etree.Element(f"{{{NAMESPACES['cn']}}}CreditNote", nsmap=nsmap)

    def _add_document_metadata(self) -> None:
        """Add credit note document metadata."""
        self._add_cbc(self.root, "CustomizationID", CIUS_RO_CUSTOMIZATION_ID)
        self._add_cbc(self.root, "ProfileID", PEPPOL_PROFILE_ID)
        self._add_cbc(self.root, "ID", self.invoice.number)
        self._add_cbc(self.root, "IssueDate", self._format_date(self.invoice.issued_at.date()))
        self._add_cbc(self.root, "CreditNoteTypeCode", INVOICE_TYPE_CREDIT_NOTE)

        notes = getattr(self.invoice, "notes", "")
        if notes:
            self._add_cbc(self.root, "Note", notes[:1000])

        self._add_cbc(self.root, "DocumentCurrencyCode", self.invoice.currency.code)

    def _add_billing_reference(self) -> None:
        """Add BillingReference to original invoice."""
        if self.original_invoice:
            billing_ref = self._add_cac(self.root, "BillingReference")
            invoice_ref = self._add_cac(billing_ref, "InvoiceDocumentReference")
            self._add_cbc(invoice_ref, "ID", self.original_invoice.number)

            if self.original_invoice.issued_at:
                self._add_cbc(invoice_ref, "IssueDate", self._format_date(self.original_invoice.issued_at.date()))

    def _add_supplier_party(self) -> None:
        """Add supplier party (same as invoice)."""
        supplier_party = self._add_cac(self.root, "AccountingSupplierParty")
        party = self._add_cac(supplier_party, "Party")
        supplier = self._get_supplier_info()

        party_id = self._add_cac(party, "PartyIdentification")
        id_elem = self._add_cbc(party_id, "ID", supplier.numeric_tax_id)
        id_elem.set("schemeID", "RO:CUI")

        party_name = self._add_cac(party, "PartyName")
        self._add_cbc(party_name, "Name", supplier.name)

        self._add_postal_address(party, supplier)
        self._add_party_tax_scheme(party, supplier.vat_number)
        self._add_party_legal_entity(party, supplier.name, supplier.registration_number)

    def _add_customer_party(self) -> None:
        """Add customer party (same as invoice)."""
        customer_party = self._add_cac(self.root, "AccountingCustomerParty")
        party = self._add_cac(customer_party, "Party")
        customer = self._get_customer_info()

        if customer.tax_id:
            party_id = self._add_cac(party, "PartyIdentification")
            id_elem = self._add_cbc(party_id, "ID", customer.numeric_tax_id)
            id_elem.set("schemeID", "RO:CUI" if customer.country_code == "RO" else f"{customer.country_code}:VAT")

        party_name = self._add_cac(party, "PartyName")
        self._add_cbc(party_name, "Name", customer.name)

        self._add_postal_address(party, customer)

        if customer.tax_id:
            self._add_party_tax_scheme(party, customer.vat_number)

        self._add_party_legal_entity(party, customer.name, customer.registration_number)

    def _add_tax_total(self) -> None:
        """Add TaxTotal element."""
        tax_total = self._add_cac(self.root, "TaxTotal")

        tax_amount_cents = getattr(self.invoice, "tax_total_cents", None)
        if tax_amount_cents is None:
            tax_amount_cents = getattr(self.invoice, "tax_cents", 0)
        tax_amount = Decimal(tax_amount_cents) / 100
        tax_amount_elem = self._add_cbc(tax_total, "TaxAmount", self._format_amount(tax_amount))
        tax_amount_elem.set("currencyID", self.invoice.currency.code)

        tax_subtotal = self._add_cac(tax_total, "TaxSubtotal")

        taxable_amount = Decimal(self.invoice.subtotal_cents or 0) / 100
        taxable_elem = self._add_cbc(tax_subtotal, "TaxableAmount", self._format_amount(taxable_amount))
        taxable_elem.set("currencyID", self.invoice.currency.code)

        tax_elem = self._add_cbc(tax_subtotal, "TaxAmount", self._format_amount(tax_amount))
        tax_elem.set("currencyID", self.invoice.currency.code)

        tax_category = self._add_cac(tax_subtotal, "TaxCategory")
        self._add_cbc(tax_category, "ID", self._get_tax_category())
        self._add_cbc(tax_category, "Percent", self._format_percent(self._get_tax_rate()))

        tax_scheme = self._add_cac(tax_category, "TaxScheme")
        self._add_cbc(tax_scheme, "ID", "VAT")

    def _add_legal_monetary_total(self) -> None:
        """Add LegalMonetaryTotal element."""
        monetary_total = self._add_cac(self.root, "LegalMonetaryTotal")
        currency = self.invoice.currency.code

        subtotal = Decimal(self.invoice.subtotal_cents or 0) / 100
        line_ext = self._add_cbc(monetary_total, "LineExtensionAmount", self._format_amount(subtotal))
        line_ext.set("currencyID", currency)

        tax_excl = self._add_cbc(monetary_total, "TaxExclusiveAmount", self._format_amount(subtotal))
        tax_excl.set("currencyID", currency)

        total = Decimal(self.invoice.total_cents or 0) / 100
        tax_incl = self._add_cbc(monetary_total, "TaxInclusiveAmount", self._format_amount(total))
        tax_incl.set("currencyID", currency)

        payable = self._add_cbc(monetary_total, "PayableAmount", self._format_amount(total))
        payable.set("currencyID", currency)

    def _add_credit_note_lines(self) -> None:
        """Add CreditNoteLine elements."""
        for idx, line in enumerate(self.invoice.lines.all().order_by("id"), start=1):
            self._add_credit_note_line(idx, line)

    def _add_credit_note_line(self, line_id: int, line: InvoiceLine) -> None:
        """Add a single CreditNoteLine element."""
        cn_line = self._add_cac(self.root, "CreditNoteLine")

        self._add_cbc(cn_line, "ID", str(line_id))

        quantity = getattr(line, "quantity", 1) or 1
        quantity_elem = self._add_cbc(cn_line, "CreditedQuantity", self._format_quantity(quantity))
        quantity_elem.set("unitCode", UNIT_CODE_PIECE)

        unit_price = Decimal(line.unit_price_cents or 0) / 100
        line_amount = unit_price * Decimal(str(quantity))
        line_ext = self._add_cbc(cn_line, "LineExtensionAmount", self._format_amount(line_amount))
        line_ext.set("currencyID", self.invoice.currency.code)

        # Item
        item = self._add_cac(cn_line, "Item")
        description = line.description or f"Credit for item {line.id}"
        self._add_cbc(item, "Description", description[:1000])
        self._add_cbc(item, "Name", description[:100])

        tax_category = self._add_cac(item, "ClassifiedTaxCategory")
        self._add_cbc(tax_category, "ID", self._get_tax_category())
        self._add_cbc(tax_category, "Percent", self._format_percent(self._get_tax_rate()))
        tax_scheme = self._add_cac(tax_category, "TaxScheme")
        self._add_cbc(tax_scheme, "ID", "VAT")

        # Price
        price = self._add_cac(cn_line, "Price")
        price_amount = self._add_cbc(price, "PriceAmount", self._format_amount(unit_price))
        price_amount.set("currencyID", self.invoice.currency.code)
