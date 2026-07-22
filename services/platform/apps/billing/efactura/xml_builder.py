"""
UBL 2.1 XML builder for Romanian e-Factura with CIUS-RO compliance.

Generates valid UBL 2.1 Invoice and Credit Note XML documents
following the Romanian CIUS-RO national specification.

Reference:
- UBL 2.1: https://docs.oasis-open.org/ubl/os-UBL-2.1/UBL-2.1.html
- CIUS-RO: https://mfinante.gov.ro/web/efactura/informatii-tehnice
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from django.conf import settings
from lxml import etree

if TYPE_CHECKING:
    from apps.billing.invoice_models import Invoice, InvoiceLine

from apps.billing.config import is_eu_country
from apps.billing.document_adjustments import (
    UnsupportedDocumentAdjustmentError,
    validate_no_unsupported_adjustments,
)
from apps.billing.efactura.settings import ro_local_date
from apps.billing.exchange_rate_service import ExchangeRateService
from apps.billing.fiscal_identity import normalize_business_tax_id, normalize_country_code, validated_cnp_or_empty
from apps.common.tax_service import TaxService

# UBL 2.1 Namespaces
NAMESPACES = {
    "ubl": "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2",
    "cbc": "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2",
    "cac": "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2",
    "cn": "urn:oasis:names:specification:ubl:schema:xsd:CreditNote-2",
}

# CIUS-RO CustomizationID (BT-24). Intentionally "1.0.1": this is the ANAF-accepted
# customization identifier, which is NOT the same as the CIUS-RO validation-artifacts
# (Schematron) version (currently 1.0.8/1.0.9). Emitting a higher value here is a
# non-standard BT-24 and is rejected. Override via EFACTURA_CIUS_RO_CUSTOMIZATION_ID only
# if ANAF changes the accepted identifier; the Schematron version is handled separately.
CIUS_RO_CUSTOMIZATION_ID = "urn:cen.eu:en16931:2017#compliant#urn:efactura.mfinante.ro:CIUS-RO:1.0.1"

# PEPPOL BIS Billing 3.0 Profile ID
PEPPOL_PROFILE_ID = "urn:fdc:peppol.eu:2017:poacc:billing:01:1.0"

# Invoice type codes (UNCL1001)
INVOICE_TYPE_COMMERCIAL = "380"  # Commercial invoice
INVOICE_TYPE_CREDIT_NOTE = "381"  # Credit note
INVOICE_TYPE_DEBIT_NOTE = "383"  # Debit note
B2C_NO_FISCAL_IDENTIFIER = "0000000000000"

# Payment means codes (UNCL4461). Keys are the canonical Payment.payment_method values
# (Payment.METHOD_CHOICES); inbound aliases like "card" are normalized to these before
# storage (PAYMENT_METHOD_MAP), so only the stored values need a mapping here.
PAYMENT_MEANS_CODES: dict[str, str] = {
    "bank": "30",  # Credit transfer
    "stripe": "48",  # Bank card payment (Stripe)
    "paypal": "68",  # Online payment service
    "cash": "10",  # Cash
    "other": "30",  # Default to credit transfer
}

# Tax category codes (UNCL5305)
TAX_CATEGORY_STANDARD = "S"  # Standard rate
TAX_CATEGORY_ZERO = "Z"  # Zero rated
TAX_CATEGORY_EXEMPT = "E"  # Exempt
TAX_CATEGORY_REVERSE_CHARGE = "AE"  # Reverse charge
TAX_CATEGORY_INTRA_COMMUNITY = "K"  # Intra-community supply
TAX_CATEGORY_NOT_SUBJECT = "O"  # Not subject to VAT

# EN16931 BT-121: Tax exemption reason text
TAX_EXEMPTION_REASONS: dict[str, str] = {
    "AE": "Reverse charge — Art. 196 Council Directive 2006/112/EC",
    "E": "Exempt from tax",
    "K": "Intra-community supply — Art. 138 Council Directive 2006/112/EC",
    "O": "Not subject to VAT",
}

# EN16931 BT-121: Tax exemption reason codes (VATEX codelist).
# Only categories with a valid VATEX code (BR-CL-22). S/Z carry NO exemption code
# (BR-S-10/BR-Z-10); E uses BT-120 free-text only (no generic "VATEX-EU-E" exists).
TAX_EXEMPTION_REASON_CODES: dict[str, str] = {
    "AE": "VATEX-EU-AE",
    "K": "VATEX-EU-IC",
    "O": "VATEX-EU-O",
    "G": "VATEX-EU-G",
}

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
        self.root: etree._Element = None  # type: ignore[assignment]
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
            bill_to_country = normalize_country_code(getattr(self.invoice, "bill_to_country", None)) or "RO"
            street = (
                getattr(self.invoice, "bill_to_street", None) or getattr(self.invoice, "bill_to_address1", "") or ""
            )
            postal_code = (
                getattr(self.invoice, "bill_to_postal_code", None) or getattr(self.invoice, "bill_to_postal", "") or ""
            )
            self._customer = CompanyInfo(
                name=getattr(self.invoice, "bill_to_name", "") or "",
                tax_id=normalize_business_tax_id(getattr(self.invoice, "bill_to_tax_id", "")),
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

    def _get_customization_id(self) -> str:
        """ANAF-accepted CIUS-RO CustomizationID (BT-24); overridable via settings."""
        return getattr(settings, "EFACTURA_CIUS_RO_CUSTOMIZATION_ID", CIUS_RO_CUSTOMIZATION_ID)

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
        """Format a plain calendar date as YYYY-MM-DD.

        Rejects datetime instances: datetime subclasses date, so passing an aware datetime here
        type-checks cleanly but silently formats its UTC wall clock, emitting the wrong legal
        calendar date (#220). MyPy cannot catch this — hence the runtime guard. Convert with
        ro_local_date() at the call site.
        """
        if isinstance(dt, datetime):
            raise TypeError(
                "_format_date received a datetime; use ro_local_date(dt) to get the Romanian "
                "local calendar date first (see issue #220)"
            )
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

    def _get_unit_code(self, line: InvoiceLine) -> str:
        """Get UN/ECE unit code from the line model field (BT-130)."""
        return line.unit_code if line.unit_code else UNIT_CODE_PIECE

    def _get_tax_category(self) -> str:
        """Determine the document-level VAT category (UNCL5305) from customer + tax.

        Derived authoritatively from customer location and the invoice tax total — NOT
        from the stored line.tax_category_code, which is only ever "S"/"Z" ("Z" being
        overloaded: zero VAT can be domestic zero-rated OR EU reverse charge). Single
        category per invoice — every line shares it (BR-AE-1 etc.). Deterministic.
        """
        customer = self._get_customer_info()
        country = (customer.country_code or "").upper()

        tax_total_cents = getattr(self.invoice, "tax_total_cents", None)
        if tax_total_cents is None:
            tax_total_cents = getattr(self.invoice, "tax_cents", 0)

        if tax_total_cents == 0:
            # EU cross-border B2B with a VAT ID → reverse charge (taxare inversa, AE),
            # detected BEFORE the domestic zero-rated fallback.
            if country != "RO" and customer.tax_id and is_eu_country(country):
                return TAX_CATEGORY_REVERSE_CHARGE
            # Non-RO customer without a VAT ID → outside the Romanian VAT system.
            if not customer.tax_id and country != "RO":
                return TAX_CATEGORY_NOT_SUBJECT
            # Domestic (RO) zero VAT → zero-rated.
            return TAX_CATEGORY_ZERO

        return TAX_CATEGORY_STANDARD

    def _get_tax_amount(self) -> Decimal:
        """Document tax total (BT-110) in major units; explicit zero preserved."""
        _tax = getattr(self.invoice, "tax_total_cents", None)
        cents = int(_tax if _tax is not None else getattr(self.invoice, "tax_cents", 0))
        return Decimal(cents) / 100

    def _get_line_gross(self) -> Decimal:
        """Sum of line gross amounts (BT-106), before any document-level discount.

        InvoiceLine.subtotal_cents is gross (qty x unit_price) and includes any setup-fee
        lines, so this is the EN16931 document LineExtensionAmount = the sum of line nets.
        """
        total = sum((line.subtotal_cents for line in self.invoice.lines.all()), 0)
        return Decimal(total) / 100

    def _get_document_discount(self) -> Decimal:
        """Document-level discount (BT-92/BT-107) in major units.

        Derived from the totals invariant (line gross sum minus net subtotal) rather than read
        from the stored ``discount_cents``, so it reconciles for BOTH invoices created
        after that field existed (where it equals the stored value) AND legacy invoices
        created before it (where it bridges the gross lines to the net header), with no
        backfill of the immutable ledger. ``discount_cents`` remains the authoritative
        stored record.
        """
        subtotal = Decimal(int(getattr(self.invoice, "subtotal_cents", 0) or 0)) / 100
        return max(Decimal(0), self._get_line_gross() - subtotal)

    def _validate_supported_adjustments(self, errors: list[str]) -> None:
        """Collect unsupported adjustment errors before any XML is emitted."""
        try:
            validate_no_unsupported_adjustments(
                meta=self.invoice.meta,
                line_discount_cents=self.invoice.lines.values_list("discount_amount_cents", flat=True),
            )
        except UnsupportedDocumentAdjustmentError as exc:
            errors.append(str(exc))

    def _add_discount_allowance(self) -> None:
        """Emit the ledger-reconciled document discount as a BG-20 AllowanceCharge with the
        document tax category (reason code 95 = Discount). No-op when discount is zero.
        """
        discount = self._get_document_discount()
        if discount <= 0:
            return
        currency = self.invoice.currency.code
        ac = self._add_cac(self.root, "AllowanceCharge")
        self._add_cbc(ac, "ChargeIndicator", "false")
        self._add_cbc(ac, "AllowanceChargeReasonCode", "95")
        self._add_cbc(ac, "AllowanceChargeReason", "Discount")
        amount_elem = self._add_cbc(ac, "Amount", self._format_amount(discount))
        amount_elem.set("currencyID", currency)
        tax_cat = self._add_cac(ac, "TaxCategory")
        category = self._get_tax_category()
        self._add_cbc(tax_cat, "ID", category)
        rate = Decimal(0) if category != TAX_CATEGORY_STANDARD else self._get_tax_rate()
        self._add_cbc(tax_cat, "Percent", self._format_percent(rate))
        scheme = self._add_cac(tax_cat, "TaxScheme")
        self._add_cbc(scheme, "ID", "VAT")

    def _get_tax_exemption_reason(self, category: str) -> str | None:
        """Get EN16931 BT-121 tax exemption reason text for non-standard categories."""
        return TAX_EXEMPTION_REASONS.get(category)

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

    def _customer_fiscal_identifier(self, customer: CompanyInfo) -> tuple[str, str] | None:
        """Return the buyer identifier and PRAHO display scheme for UBL party fields."""
        if customer.tax_id:
            identifier = customer.numeric_tax_id
            scheme_id = "RO:CUI" if customer.country_code == "RO" else f"{customer.country_code}:VAT"
        elif customer.country_code == "RO":
            identifier = validated_cnp_or_empty(getattr(self.invoice, "bill_to_cnp", "")) or B2C_NO_FISCAL_IDENTIFIER
            scheme_id = "RO:CNP"
        else:
            return None

        return identifier, scheme_id

    def _add_customer_identification(self, party: etree._Element, customer: CompanyInfo) -> None:
        """Add the general buyer identifier while BT-47 is emitted by PartyLegalEntity."""
        fiscal_identifier = self._customer_fiscal_identifier(customer)
        if fiscal_identifier is None:
            return
        identifier, scheme_id = fiscal_identifier

        party_id = self._add_cac(party, "PartyIdentification")
        id_elem = self._add_cbc(party_id, "ID", identifier)
        id_elem.set("schemeID", scheme_id)

    def _customer_legal_identifier(self, customer: CompanyInfo) -> str:
        """Return BT-47, which ANAF uses for a Romanian buyer's fiscal identifier."""
        fiscal_identifier = self._customer_fiscal_identifier(customer)
        if customer.country_code == "RO" and fiscal_identifier is not None:
            return fiscal_identifier[0]
        return customer.registration_number

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
        self._add_document_allowances_charges()
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

        if not self.invoice.lines.exists():
            errors.append("Invoice must have at least one line item")

        self._validate_supported_adjustments(errors)
        self._validate_foreign_currency_snapshot(errors)

        # Single-category invariant: the builder emits ONE TaxSubtotal at one document rate, so the
        # e-Factura XML cannot faithfully represent an invoice whose lines carry multiple distinct
        # VAT rates. Reject it here rather than silently emit a VAT breakdown that fails ANAF
        # arithmetic (the system issues single-rate invoices; a multi-rate one is a bug to surface).
        distinct_rates = {Decimal(line.tax_rate) for line in self.invoice.lines.all()}
        if len(distinct_rates) > 1:
            errors.append(
                f"Invoice has multiple VAT rates {sorted(distinct_rates)}; the e-Factura builder "
                "supports a single rate per document (single-category invariant)"
            )

        supplier = self._get_supplier_info()
        if not supplier.name:
            errors.append("Supplier company name not configured (COMPANY_NAME setting)")

        if not supplier.tax_id:
            errors.append("Supplier tax ID not configured (EFACTURA_COMPANY_CUI setting)")

        if errors:
            raise XMLBuilderError(f"Invalid invoice data: {'; '.join(errors)}")

    def _validate_foreign_currency_snapshot(self, errors: list[str]) -> None:
        """Require the immutable fiscal evidence used to calculate BT-111."""
        currency_code = self.invoice.currency.code
        if currency_code == "RON":
            return

        rate = getattr(self.invoice, "exchange_to_ron", None)
        rate_as_of = getattr(self.invoice, "exchange_rate_as_of", None)
        source = getattr(self.invoice, "exchange_rate_source", "")
        reference = getattr(self.invoice, "exchange_rate_source_reference", "")
        tax_point = getattr(self.invoice, "tax_point_date", None)
        if rate is None or rate_as_of is None or not source or not reference or tax_point is None:
            errors.append(f"Foreign-currency invoice requires a complete provenanced {currency_code}/RON snapshot")
        elif source not in ExchangeRateService.APPROVED_SOURCES:
            errors.append(f"Foreign-currency invoice requires an approved {currency_code}/RON source")
        elif Decimal(str(rate)) <= 0:
            errors.append(f"Foreign-currency invoice requires a positive {currency_code}/RON exchange rate")
        elif rate_as_of > tax_point:
            errors.append(f"{currency_code}/RON exchange-rate date cannot be after the invoice tax point")

    def _create_root(self) -> None:
        """Create Invoice root element with namespaces."""
        nsmap = {
            None: NAMESPACES["ubl"],
            "cac": NAMESPACES["cac"],
            "cbc": NAMESPACES["cbc"],
        }
        self.root = etree.Element(f"{{{NAMESPACES['ubl']}}}Invoice", nsmap=nsmap)  # type: ignore[arg-type]

    def _add_document_metadata(self) -> None:
        """Add invoice document metadata."""
        # Mandatory CIUS-RO customization identifier.
        self._add_cbc(self.root, "CustomizationID", self._get_customization_id())

        # ProfileID (PEPPOL BIS) - Mandatory
        self._add_cbc(self.root, "ProfileID", PEPPOL_PROFILE_ID)

        # Invoice ID (sequential number) - Mandatory
        self._add_cbc(self.root, "ID", self.invoice.number)

        # Issue Date - Mandatory (validated in _validate_invoice)
        if self.invoice.issued_at is None:
            raise ValueError("Invoice must have issued_at set for e-Factura XML generation")
        self._add_cbc(self.root, "IssueDate", self._format_date(ro_local_date(self.invoice.issued_at)))

        # Due Date - Optional but recommended
        if self.invoice.due_at:
            self._add_cbc(self.root, "DueDate", self._format_date(ro_local_date(self.invoice.due_at)))

        # Invoice Type Code - Mandatory
        self._add_cbc(self.root, "InvoiceTypeCode", INVOICE_TYPE_COMMERCIAL)

        # Note - Optional
        notes = getattr(self.invoice, "notes", "")
        if notes:
            self._add_cbc(self.root, "Note", notes[:1000])  # Limit to 1000 chars

        tax_point_date = getattr(self.invoice, "tax_point_date", None)
        issue_date = ro_local_date(self.invoice.issued_at)
        if tax_point_date is not None and tax_point_date != issue_date:
            self._add_cbc(self.root, "TaxPointDate", self._format_date(tax_point_date))

        # Document Currency Code - Mandatory
        self._add_cbc(self.root, "DocumentCurrencyCode", self.invoice.currency.code)

        if self.invoice.currency.code != "RON":
            self._add_cbc(self.root, "TaxCurrencyCode", "RON")

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

        self._add_customer_identification(party, customer)

        # PartyName - Mandatory
        party_name = self._add_cac(party, "PartyName")
        self._add_cbc(party_name, "Name", customer.name)

        # PostalAddress - Mandatory
        self._add_postal_address(party, customer)

        # PartyTaxScheme - Mandatory if VAT registered
        if customer.tax_id:
            self._add_party_tax_scheme(party, customer.vat_number)

        # PartyLegalEntity - Mandatory
        self._add_party_legal_entity(party, customer.name, self._customer_legal_identifier(customer))

        # Contact - Optional
        self._add_contact(party, customer)

    def _get_payment_means_code(self) -> str:
        """Derive UNCL4461 payment means code from invoice's payment method."""
        # Check associated payments for the method
        payments = getattr(self.invoice, "payments", None)
        if payments is not None:
            payment = payments.order_by("-created_at").first() if hasattr(payments, "order_by") else None
            if payment is not None:
                method = getattr(payment, "payment_method", "")
                if method in PAYMENT_MEANS_CODES:
                    return PAYMENT_MEANS_CODES[method]

        # Check invoice meta for payment_method hint
        meta = getattr(self.invoice, "meta", {}) or {}
        method = meta.get("payment_method", "")
        if method in PAYMENT_MEANS_CODES:
            return PAYMENT_MEANS_CODES[method]

        # Default: credit transfer (bank)
        return PAYMENT_MEANS_CODES["bank"]

    def _add_payment_means(self) -> None:
        """Add PaymentMeans element (BG-16)."""
        payment_means = self._add_cac(self.root, "PaymentMeans")

        # Payment Means Code (BT-81) - Mandatory
        self._add_cbc(payment_means, "PaymentMeansCode", self._get_payment_means_code())

        # Payment Due Date
        if self.invoice.due_at:
            self._add_cbc(payment_means, "PaymentDueDate", self._format_date(ro_local_date(self.invoice.due_at)))

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
        """Add PaymentTerms element (BG-17, BT-20).

        Generates structured note with net days and explicit due date
        per EN16931 requirements.
        """
        if self.invoice.due_at and self.invoice.issued_at:
            payment_terms = self._add_cac(self.root, "PaymentTerms")

            # Net days and the emitted due date must share ONE calendar basis — the Romanian one
            # (#220). Deriving days from the raw aware datetimes floors a partial day and can
            # contradict the two dates printed alongside it in the same note.
            due_local = ro_local_date(self.invoice.due_at)
            issued_local = ro_local_date(self.invoice.issued_at)

            days = (due_local - issued_local).days
            due_date_str = self._format_date(due_local)

            note = f"Net {days} days, due {due_date_str}" if days > 0 else f"Due on receipt ({due_date_str})"

            self._add_cbc(payment_terms, "Note", note)

    def _add_tax_total(self) -> None:
        """Add document tax total and, for non-RON invoices, BT-111 in RON."""
        if self.invoice.currency.code != "RON":
            accounting_tax_total = self._add_cac(self.root, "TaxTotal")
            rate = Decimal(str(self.invoice.exchange_to_ron))
            accounting_tax_cents = ExchangeRateService.convert_cents(
                int(getattr(self.invoice, "tax_cents", 0)),
                rate,
            )
            accounting_tax_amount = Decimal(accounting_tax_cents) / 100
            accounting_amount_elem = self._add_cbc(
                accounting_tax_total,
                "TaxAmount",
                self._format_amount(accounting_tax_amount),
            )
            accounting_amount_elem.set("currencyID", "RON")

        tax_total = self._add_cac(self.root, "TaxTotal")

        tax_amount = self._get_tax_amount()
        tax_amount_elem = self._add_cbc(tax_total, "TaxAmount", self._format_amount(tax_amount))
        tax_amount_elem.set("currencyID", self.invoice.currency.code)

        # Tax subtotal (breakdown by tax category)
        tax_subtotal = self._add_cac(tax_total, "TaxSubtotal")

        # Taxable amount = tax-exclusive base = line gross - allowances + charges (= net
        # subtotal). Same base as LegalMonetaryTotal so the two reconcile (BR-CO-17).
        allowance_total, charge_total = self._get_document_level_totals()
        taxable_amount = self._get_line_gross() - allowance_total + charge_total
        taxable_elem = self._add_cbc(tax_subtotal, "TaxableAmount", self._format_amount(taxable_amount))
        taxable_elem.set("currencyID", self.invoice.currency.code)

        # Tax amount for this category
        tax_elem = self._add_cbc(tax_subtotal, "TaxAmount", self._format_amount(tax_amount))
        tax_elem.set("currencyID", self.invoice.currency.code)

        # Tax Category
        tax_category = self._add_cac(tax_subtotal, "TaxCategory")
        category_code = self._get_tax_category()
        self._add_cbc(tax_category, "ID", category_code)
        # EN16931 BR-AE-05/BR-E-05/BR-Z-05/BR-K-05/BR-O-05 require Percent=0 for
        # any non-standard category — ANAF Schematron rejects otherwise.
        rate = Decimal(0) if category_code != TAX_CATEGORY_STANDARD else self._get_tax_rate()
        self._add_cbc(tax_category, "Percent", self._format_percent(rate))

        # BT-121/BT-120: Tax exemption reason (mandatory for non-S categories)
        # BT-121 ONLY with a real VATEX code (AE/K/O/G); never the raw category code.
        # S/Z emit neither code nor text (BR-S-10/BR-Z-10); E uses BT-120 text (BR-E-10).
        exemption_code = TAX_EXEMPTION_REASON_CODES.get(category_code)
        if exemption_code:
            self._add_cbc(tax_category, "TaxExemptionReasonCode", exemption_code)
        exemption_reason = self._get_tax_exemption_reason(category_code)
        if exemption_reason:
            self._add_cbc(tax_category, "TaxExemptionReason", exemption_reason)

        tax_scheme = self._add_cac(tax_category, "TaxScheme")
        self._add_cbc(tax_scheme, "ID", "VAT")

    def _add_document_allowances_charges(self) -> None:
        """Add the ledger-reconciled document discount as a BG-20 AllowanceCharge."""
        self._add_discount_allowance()

    def _get_document_level_totals(self) -> tuple[Decimal, Decimal]:
        """Return ledger-backed document allowance and charge totals (BT-107/BT-108)."""
        return self._get_document_discount(), Decimal(0)

    def _add_legal_monetary_total(self) -> None:
        """Add LegalMonetaryTotal in UBL element order with reconciled totals."""
        monetary_total = self._add_cac(self.root, "LegalMonetaryTotal")
        currency = self.invoice.currency.code

        line_gross = self._get_line_gross()
        allowance_total, charge_total = self._get_document_level_totals()
        tax_exclusive = line_gross - allowance_total + charge_total
        tax_inclusive = tax_exclusive + self._get_tax_amount()

        # UBL cac:LegalMonetaryTotal sequence: LineExtension, TaxExclusive, TaxInclusive,
        # then AllowanceTotal, ChargeTotal, PrepaidAmount, PayableAmount (BR-CO-13/15/16).
        line_ext = self._add_cbc(monetary_total, "LineExtensionAmount", self._format_amount(line_gross))
        line_ext.set("currencyID", currency)
        tax_excl = self._add_cbc(monetary_total, "TaxExclusiveAmount", self._format_amount(tax_exclusive))
        tax_excl.set("currencyID", currency)
        tax_incl = self._add_cbc(monetary_total, "TaxInclusiveAmount", self._format_amount(tax_inclusive))
        tax_incl.set("currencyID", currency)
        if allowance_total > 0:
            allow_elem = self._add_cbc(monetary_total, "AllowanceTotalAmount", self._format_amount(allowance_total))
            allow_elem.set("currencyID", currency)
        if charge_total > 0:
            charge_elem = self._add_cbc(monetary_total, "ChargeTotalAmount", self._format_amount(charge_total))
            charge_elem.set("currencyID", currency)
        # BT-113 PrepaidAmount: payments already collected (refund-aware via #189), so a
        # partially-paid invoice reports the correct balance due — PayableAmount =
        # TaxInclusive - Prepaid (BR-CO-16), floored at 0.
        remaining_cents = self.invoice.get_remaining_amount()
        prepaid_cents = max(0, (self.invoice.total_cents or 0) - remaining_cents)
        # Cap to the XML tax-inclusive total: a legacy invoice whose stored total_cents
        # diverges above the line-derived tax-inclusive total must not emit
        # PrepaidAmount > TaxInclusiveAmount (BR-CO-16).
        prepaid = min(Decimal(prepaid_cents) / 100, tax_inclusive)
        if prepaid > 0:
            prepaid_elem = self._add_cbc(monetary_total, "PrepaidAmount", self._format_amount(prepaid))
            prepaid_elem.set("currencyID", currency)
        payable = self._add_cbc(
            monetary_total, "PayableAmount", self._format_amount(max(Decimal(0), tax_inclusive - prepaid))
        )
        payable.set("currencyID", currency)

    def _add_invoice_lines(self) -> None:
        """Add InvoiceLine elements for each line item."""
        for idx, line in enumerate(self.invoice.lines.all().order_by("sort_order", "id"), start=1):
            self._add_invoice_line(idx, line)

    def _add_invoice_line(self, line_id: int, line: InvoiceLine) -> None:
        """Add a single InvoiceLine element."""
        invoice_line = self._add_cac(self.root, "InvoiceLine")

        # Line ID - Mandatory
        self._add_cbc(invoice_line, "ID", str(line_id))

        # Note (BT-127) - Optional, from model field
        if line.note:
            self._add_cbc(invoice_line, "Note", line.note[:1000])

        # Invoiced Quantity - Mandatory
        quantity = getattr(line, "quantity", 1) or 1
        quantity_elem = self._add_cbc(invoice_line, "InvoicedQuantity", self._format_quantity(quantity))
        quantity_elem.set("unitCode", self._get_unit_code(line))

        # Line Extension Amount (BT-131). Use the same cents-based value the document total
        # sums (line.subtotal_cents = int(qty * unit_price_cents)) so Σ lines == BT-106 exactly.
        # Computing unit_price * qty and rounding can differ by 0.01 on fractional quantities,
        # which ANAF rejects (BR-CO-10). The unit price is emitted separately by _add_line_price.
        line_amount = Decimal(line.subtotal_cents or 0) / 100
        line_ext = self._add_cbc(invoice_line, "LineExtensionAmount", self._format_amount(line_amount))
        line_ext.set("currencyID", self.invoice.currency.code)

        # BT-134/BT-135: Service period at line level
        if line.period_start and line.period_end:
            period = self._add_cac(invoice_line, "InvoicePeriod")
            self._add_cbc(period, "StartDate", line.period_start.isoformat())
            self._add_cbc(period, "EndDate", line.period_end.isoformat())

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

        # BT-155: Seller's item identification — optional
        if line.seller_item_id:
            sellers_id = self._add_cac(item, "SellersItemIdentification")
            self._add_cbc(sellers_id, "ID", line.seller_item_id)

        # ClassifiedTaxCategory - Mandatory
        tax_category = self._add_cac(item, "ClassifiedTaxCategory")
        # Single-category invoice: every line shares the document category so AE/Z/E/O
        # invoices stay coherent (BR-AE-1 etc.) — derived, not the stored line code.
        category_id = self._get_tax_category()
        self._add_cbc(tax_category, "ID", category_id)

        # Line VAT rate, clamped to 0 for non-standard categories (BR-AE-05/Z-05/...).
        if category_id != TAX_CATEGORY_STANDARD:
            percent = Decimal(0)
        else:
            tax_rate = getattr(line, "tax_rate", None)
            percent = Decimal(str(tax_rate)) * 100 if tax_rate is not None else self._get_tax_rate()
        self._add_cbc(tax_category, "Percent", self._format_percent(percent))

        tax_scheme = self._add_cac(tax_category, "TaxScheme")
        self._add_cbc(tax_scheme, "ID", "VAT")

        # AdditionalItemProperty for domain_name (BT-160)
        if line.domain_name:
            prop = self._add_cac(item, "AdditionalItemProperty")
            self._add_cbc(prop, "Name", "domain")
            self._add_cbc(prop, "Value", line.domain_name)

    def _add_line_price(self, parent: etree._Element, line: InvoiceLine) -> None:
        """Add Price element to invoice line."""
        price = self._add_cac(parent, "Price")

        unit_price = Decimal(line.unit_price_cents or 0) / 100
        price_amount = self._add_cbc(price, "PriceAmount", self._format_amount(unit_price))
        price_amount.set("currencyID", self.invoice.currency.code)


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
        self._add_discount_allowance()
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

        if self.invoice.currency.code != "RON":
            # The credit note builder cannot yet emit the RON accounting totals
            # BR-RO-030/BR-53 require (fiscal credit-note ledger, #219). Fail
            # here with an honest message instead of persisting invalid XML.
            errors.append("Foreign-currency credit notes are not supported yet; RON only")

        self._validate_supported_adjustments(errors)

        if errors:
            raise XMLBuilderError(f"Invalid credit note data: {'; '.join(errors)}")

    def _create_root(self) -> None:
        """Create CreditNote root element with namespaces."""
        nsmap = {
            None: NAMESPACES["cn"],
            "cac": NAMESPACES["cac"],
            "cbc": NAMESPACES["cbc"],
        }
        self.root = etree.Element(f"{{{NAMESPACES['cn']}}}CreditNote", nsmap=nsmap)  # type: ignore[arg-type]

    def _add_document_metadata(self) -> None:
        """Add credit note document metadata."""
        self._add_cbc(self.root, "CustomizationID", self._get_customization_id())
        self._add_cbc(self.root, "ProfileID", PEPPOL_PROFILE_ID)
        self._add_cbc(self.root, "ID", self.invoice.number)
        if self.invoice.issued_at is None:
            raise ValueError("Invoice must have issued_at set for e-Factura XML generation")
        self._add_cbc(self.root, "IssueDate", self._format_date(ro_local_date(self.invoice.issued_at)))
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
                self._add_cbc(
                    invoice_ref, "IssueDate", self._format_date(ro_local_date(self.original_invoice.issued_at))
                )

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

        self._add_customer_identification(party, customer)

        party_name = self._add_cac(party, "PartyName")
        self._add_cbc(party_name, "Name", customer.name)

        self._add_postal_address(party, customer)

        if customer.tax_id:
            self._add_party_tax_scheme(party, customer.vat_number)

        self._add_party_legal_entity(party, customer.name, self._customer_legal_identifier(customer))

    def _add_tax_total(self) -> None:
        """Add TaxTotal element."""
        tax_total = self._add_cac(self.root, "TaxTotal")

        tax_amount = self._get_tax_amount()
        tax_amount_elem = self._add_cbc(tax_total, "TaxAmount", self._format_amount(tax_amount))
        tax_amount_elem.set("currencyID", self.invoice.currency.code)

        tax_subtotal = self._add_cac(tax_total, "TaxSubtotal")

        taxable_amount = self._get_line_gross() - self._get_document_discount()
        taxable_elem = self._add_cbc(tax_subtotal, "TaxableAmount", self._format_amount(taxable_amount))
        taxable_elem.set("currencyID", self.invoice.currency.code)

        tax_elem = self._add_cbc(tax_subtotal, "TaxAmount", self._format_amount(tax_amount))
        tax_elem.set("currencyID", self.invoice.currency.code)

        tax_category = self._add_cac(tax_subtotal, "TaxCategory")
        category_code = self._get_tax_category()
        self._add_cbc(tax_category, "ID", category_code)
        # EN16931 BR-AE-05/BR-E-05/BR-Z-05/BR-K-05/BR-O-05 require Percent=0 for
        # any non-standard category — ANAF Schematron rejects otherwise.
        rate = Decimal(0) if category_code != TAX_CATEGORY_STANDARD else self._get_tax_rate()
        self._add_cbc(tax_category, "Percent", self._format_percent(rate))

        # BT-121 ONLY with a real VATEX code (AE/K/O/G); never the raw category code.
        # S/Z emit neither code nor text (BR-S-10/BR-Z-10); E uses BT-120 text (BR-E-10).
        exemption_code = TAX_EXEMPTION_REASON_CODES.get(category_code)
        if exemption_code:
            self._add_cbc(tax_category, "TaxExemptionReasonCode", exemption_code)
        exemption_reason = self._get_tax_exemption_reason(category_code)
        if exemption_reason:
            self._add_cbc(tax_category, "TaxExemptionReason", exemption_reason)

        tax_scheme = self._add_cac(tax_category, "TaxScheme")
        self._add_cbc(tax_scheme, "ID", "VAT")

    def _add_legal_monetary_total(self) -> None:
        """Add LegalMonetaryTotal element (BT-106 = line gross, document discount as BG-20)."""
        monetary_total = self._add_cac(self.root, "LegalMonetaryTotal")
        currency = self.invoice.currency.code

        line_gross = self._get_line_gross()
        discount = self._get_document_discount()
        tax_exclusive = line_gross - discount
        tax_inclusive = tax_exclusive + self._get_tax_amount()

        line_ext = self._add_cbc(monetary_total, "LineExtensionAmount", self._format_amount(line_gross))
        line_ext.set("currencyID", currency)
        tax_excl = self._add_cbc(monetary_total, "TaxExclusiveAmount", self._format_amount(tax_exclusive))
        tax_excl.set("currencyID", currency)
        tax_incl = self._add_cbc(monetary_total, "TaxInclusiveAmount", self._format_amount(tax_inclusive))
        tax_incl.set("currencyID", currency)
        if discount > 0:
            allow_elem = self._add_cbc(monetary_total, "AllowanceTotalAmount", self._format_amount(discount))
            allow_elem.set("currencyID", currency)
        payable = self._add_cbc(monetary_total, "PayableAmount", self._format_amount(tax_inclusive))
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
        quantity_elem.set("unitCode", self._get_unit_code(line))

        # BT-131: same cents-based value the document total sums, so Σ lines == BT-106 even
        # for fractional quantities (BR-CO-10) — see the invoice builder for detail.
        unit_price = Decimal(line.unit_price_cents or 0) / 100
        line_amount = Decimal(line.subtotal_cents or 0) / 100
        line_ext = self._add_cbc(cn_line, "LineExtensionAmount", self._format_amount(line_amount))
        line_ext.set("currencyID", self.invoice.currency.code)

        # Item
        item = self._add_cac(cn_line, "Item")
        description = line.description or f"Credit for item {line.id}"
        self._add_cbc(item, "Description", description[:1000])
        self._add_cbc(item, "Name", description[:100])

        cn_category = self._get_tax_category()
        tax_category = self._add_cac(item, "ClassifiedTaxCategory")
        self._add_cbc(tax_category, "ID", cn_category)
        cn_rate = Decimal(0) if cn_category != TAX_CATEGORY_STANDARD else self._get_tax_rate()
        self._add_cbc(tax_category, "Percent", self._format_percent(cn_rate))
        tax_scheme = self._add_cac(tax_category, "TaxScheme")
        self._add_cbc(tax_scheme, "ID", "VAT")

        # Price
        price = self._add_cac(cn_line, "Price")
        price_amount = self._add_cbc(price, "PriceAmount", self._format_amount(unit_price))
        price_amount.set("currencyID", self.invoice.currency.code)
