# ===============================================================================
# ROMANIAN PDF GENERATORS FOR BILLING DOCUMENTS
# EN16931-compliant with Romanian Cod Fiscal art. 319 / art. 331 support
# ===============================================================================

from __future__ import annotations

import logging
from collections import defaultdict
from decimal import Decimal
from io import BytesIO
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.utils.translation import gettext as _t
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from apps.billing.models import Invoice, ProformaInvoice

logger = logging.getLogger(__name__)

# Romanian fiscal documents are diacritic-heavy (ă â î ș ț), and the legal disclaimers
# — the whole point of these PDFs — are written in Romanian. ReportLab's built-in
# Helvetica is WinAnsi-encoded and SILENTLY substitutes missing glyphs (no exception),
# so those characters render as blanks/boxes. We register a vendored Unicode TTF
# (DejaVuSans, broad Latin coverage) and use it for every text run.
_FONT = "DejaVuSans"
_FONT_BOLD = "DejaVuSans-Bold"
_FONT_DIR = Path(__file__).resolve().parent / "assets" / "fonts"


def _register_fonts() -> None:
    """Register the vendored Unicode fonts once (idempotent). Called lazily from the
    generator constructor — NOT at import time — so a missing font asset degrades to a clear
    error when a PDF is actually generated, instead of crashing every import of this module
    (which would take down all of billing). If packaging a wheel/sdist, the assets/fonts TTFs
    must be declared in package_data / MANIFEST.in.
    """
    registered = set(pdfmetrics.getRegisteredFontNames())
    if _FONT in registered and _FONT_BOLD in registered:
        return
    for name, filename in ((_FONT, "DejaVuSans.ttf"), (_FONT_BOLD, "DejaVuSans-Bold.ttf")):
        if name in registered:
            continue
        path = _FONT_DIR / filename
        if not path.exists():
            raise ImproperlyConfigured(
                f"Vendored PDF font missing: {path}. The billing app's assets/fonts/ TTFs must "
                f"ship with the deployment (declare them in package_data/MANIFEST.in for a wheel)."
            )
        pdfmetrics.registerFont(TTFont(name, str(path)))
    # Map the family so bold resolution is correct for any future flowable use.
    pdfmetrics.registerFontFamily(_FONT, normal=_FONT, bold=_FONT_BOLD, italic=_FONT, boldItalic=_FONT_BOLD)

# Coordinate-based layout has no text wrapping/clipping, so free-text fields must
# be clamped to a width that fits their column — otherwise long values overrun the
# page or overlap neighbouring content.
_MAX_DESC_CHARS = 40
_MAX_SUBLINE_CHARS = 60
_MAX_CLIENT_FIELD_CHARS = 45


class RomanianDocumentPDFGenerator:
    """
    Base class for Romanian document PDF generation with common functionality.
    Handles company information, Romanian compliance, and standard formatting.
    EN16931-compliant line-level detail and VAT breakdown.
    """

    # Line content must stay above the footer (drawn at 1.5-2 cm). When the cursor drops
    # below this the table/totals break to a new page; the margin leaves room for a main
    # line plus its EN16931 sub-lines above the footer.
    _BOTTOM_MARGIN = 4 * cm

    def __init__(self, document: Invoice | ProformaInvoice) -> None:
        _register_fonts()  # lazy: surface a missing font asset here, not at module import
        self.document = document
        self.buffer = BytesIO()
        self.canvas = canvas.Canvas(self.buffer, pagesize=A4)
        self.width, self.height = A4
        self._table_end_y: float = 0.0

    def generate_response(self) -> HttpResponse:
        """Generate complete PDF response with proper headers."""
        self._create_pdf_document()
        self.canvas.showPage()
        self.canvas.save()

        self.buffer.seek(0)
        response = HttpResponse(self.buffer.getvalue(), content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="{self._get_filename()}"'

        return response

    def _create_pdf_document(self) -> None:
        """Create the complete PDF document."""
        self._setup_document_header()
        self._render_company_information()
        self._render_client_information()
        self._render_items_table()
        self._render_totals_section()
        self._render_document_footer()

    def _get_currency_code(self) -> str:
        """Get the currency code from the document, defaulting to RON."""
        if self.document.currency:
            return self.document.currency.code
        return "RON"

    @staticmethod
    def _fit(text: object, max_chars: int) -> str:
        """Clamp free-text to max_chars for the no-wrap coordinate layout, with an ellipsis."""
        s = str(text)
        if len(s) <= max_chars:
            return s
        return s[: max_chars - 1] + "…"

    @staticmethod
    def _format_vat_percent(tax_rate: Decimal) -> str:
        """Format a stored tax rate (e.g. 0.1900) as a percent without truncation: '19', '9.5'.

        ``int(tax_rate * 100)`` silently dropped fractional rates (9.5% rendered as
        "9%") and collapsed distinct rates into one VAT-breakdown bucket.
        """
        pct = Decimal(tax_rate) * 100
        if pct % 1 == 0:
            return f"{int(pct)}"
        return f"{pct.normalize()}"

    def _get_company_info(self) -> dict[str, str]:
        """Get company information from settings with Romanian defaults."""
        return {
            "name": getattr(settings, "COMPANY_NAME", "PRAHO Platform"),
            "address": getattr(settings, "COMPANY_ADDRESS", "Str. Exemplu Nr. 1"),
            "city": getattr(settings, "COMPANY_CITY", "București"),
            "country": getattr(settings, "COMPANY_COUNTRY", "România"),
            "cui": getattr(settings, "COMPANY_CUI", "RO12345678"),
            "email": getattr(settings, "COMPANY_EMAIL", "contact@praho.ro"),
            "registration_number": getattr(settings, "COMPANY_REGISTRATION_NUMBER", ""),
            "bank_name": getattr(settings, "COMPANY_BANK_NAME", ""),
            "bank_account": getattr(settings, "COMPANY_BANK_ACCOUNT", ""),
            "phone": getattr(settings, "COMPANY_PHONE", ""),
        }

    def _setup_document_header(self) -> None:
        """Setup document header with company branding and document info."""
        company_info = self._get_company_info()

        # Company branding
        self.canvas.setFont(_FONT_BOLD, 24)
        self.canvas.drawString(2 * cm, self.height - 3 * cm, company_info["name"])

        # Document title
        self.canvas.setFont(_FONT_BOLD, 16)
        self.canvas.drawString(2 * cm, self.height - 4 * cm, str(self._get_document_title()))

        # Document details
        self._render_document_details()

    def _render_document_details(self) -> None:
        """Render document-specific details (number, dates, status)."""
        raise NotImplementedError("Subclasses must implement document details rendering")

    def _get_document_title(self) -> str:
        """Get the document title for the header."""
        raise NotImplementedError("Subclasses must implement document title")

    def _get_filename(self) -> str:
        """Get the filename for the PDF download."""
        raise NotImplementedError("Subclasses must implement filename")

    def _render_company_information(self) -> None:
        """Render supplier (company) information section with full Romanian details."""
        company_info = self._get_company_info()
        y_pos = self.height - 8 * cm

        self.canvas.setFont(_FONT_BOLD, 14)
        self.canvas.drawString(2 * cm, y_pos, str(_t("Supplier:")))

        self.canvas.setFont(_FONT, 10)
        step = 0.4 * cm
        current_y = y_pos - step

        self.canvas.drawString(2 * cm, current_y, company_info["name"])
        current_y -= step

        self.canvas.drawString(
            2 * cm, current_y, f"{company_info['address']}, {company_info['city']}, {company_info['country']}"
        )
        current_y -= step

        self.canvas.drawString(2 * cm, current_y, str(_t("CUI/CIF: {cui}")).format(cui=company_info["cui"]))
        current_y -= step

        if company_info["registration_number"]:
            self.canvas.drawString(
                2 * cm,
                current_y,
                str(_t("Nr. Reg. Com.: {reg}")).format(reg=company_info["registration_number"]),
            )
            current_y -= step

        self.canvas.drawString(2 * cm, current_y, str(_t("Email: {email}")).format(email=company_info["email"]))
        current_y -= step

        if company_info["phone"]:
            self.canvas.drawString(2 * cm, current_y, str(_t("Tel: {phone}")).format(phone=company_info["phone"]))
            current_y -= step

        if company_info["bank_name"]:
            self.canvas.drawString(2 * cm, current_y, str(_t("Banca: {bank}")).format(bank=company_info["bank_name"]))
            current_y -= step

        if company_info["bank_account"]:
            self.canvas.drawString(2 * cm, current_y, str(_t("IBAN: {iban}")).format(iban=company_info["bank_account"]))

    def _render_client_information(self) -> None:
        """Render client information section with full address and tax details."""
        y_pos = self.height - 8 * cm
        x_pos = 11 * cm
        step = 0.4 * cm

        self.canvas.setFont(_FONT_BOLD, 14)
        self.canvas.drawString(x_pos, y_pos, str(_t("Client:")))

        self.canvas.setFont(_FONT, 10)
        current_y = y_pos - step

        # Name
        self.canvas.drawString(x_pos, current_y, self._fit(self.document.bill_to_name or "", _MAX_CLIENT_FIELD_CHARS))
        current_y -= step

        # Address line 1
        if self.document.bill_to_address1:
            self.canvas.drawString(x_pos, current_y, self._fit(self.document.bill_to_address1, _MAX_CLIENT_FIELD_CHARS))
            current_y -= step

        # Address line 2
        if self.document.bill_to_address2:
            self.canvas.drawString(x_pos, current_y, self._fit(self.document.bill_to_address2, _MAX_CLIENT_FIELD_CHARS))
            current_y -= step

        # City, region, postal code
        city_parts = []
        if self.document.bill_to_city:
            city_parts.append(self.document.bill_to_city)
        region_postal = ""
        if self.document.bill_to_region:
            region_postal += self.document.bill_to_region
        if self.document.bill_to_postal:
            region_postal += f" {self.document.bill_to_postal}" if region_postal else self.document.bill_to_postal
        if region_postal:
            city_parts.append(region_postal)

        if city_parts:
            self.canvas.drawString(x_pos, current_y, self._fit(", ".join(city_parts), _MAX_CLIENT_FIELD_CHARS))
            current_y -= step

        # Country
        if self.document.bill_to_country:
            self.canvas.drawString(x_pos, current_y, self.document.bill_to_country)
            current_y -= step

        # Tax ID
        if self.document.bill_to_tax_id:
            self.canvas.drawString(
                x_pos, current_y, str(_t("CUI/CIF: {tax_id}")).format(tax_id=self.document.bill_to_tax_id)
            )
            current_y -= step

        # Registration number
        if self.document.bill_to_registration_number:
            self.canvas.drawString(
                x_pos,
                current_y,
                str(_t("Nr. Reg. Com.: {reg}")).format(reg=self.document.bill_to_registration_number),
            )
            current_y -= step

        # Email
        if self.document.bill_to_email:
            self.canvas.drawString(
                x_pos, current_y, str(_t("Email: {email}")).format(email=self.document.bill_to_email)
            )

    def _render_items_table(self) -> None:
        """Render items table with headers and line items."""
        table_y = self.height - 15 * cm

        # Table headers
        self._render_table_headers(table_y)

        # Table data
        self._render_table_data(table_y)

    def _render_table_headers(self, table_y: float) -> None:
        """Render table column headers with VAT% column."""
        self.canvas.setFont(_FONT_BOLD, 10)
        self.canvas.drawString(2 * cm, table_y, str(_t("Description")))
        self.canvas.drawString(9 * cm, table_y, str(_t("Qty")))
        self.canvas.drawString(11 * cm, table_y, str(_t("Unit Price")))
        self.canvas.drawString(13.5 * cm, table_y, str(_t("VAT%")))
        self.canvas.drawString(15.5 * cm, table_y, str(_t("Total")))

        # Draw line under headers
        self.canvas.line(2 * cm, table_y - 0.3 * cm, 18 * cm, table_y - 0.3 * cm)

    def _render_table_data(self, table_y: float) -> None:
        """Render table line items data with EN16931 sub-line details, paginating when a
        line group would otherwise overrun the page footer."""
        currency = self._get_currency_code()
        current_y = table_y - 0.8 * cm

        lines = self.document.lines.all()
        for line in lines:
            # Break to a fresh page (re-drawing the column headers) before a line group that
            # would collide with the pinned footer. Account for the WHOLE group height — the
            # main row PLUS its EN16931 sub-lines — so a row whose sub-lines would spill into
            # the footer breaks before the main row, not after it.
            group_height = 0.5 * cm
            if line.domain_name:
                group_height += 0.35 * cm
            if line.period_start and line.period_end:
                group_height += 0.35 * cm
            if line.seller_item_id:
                group_height += 0.35 * cm
            if current_y - group_height < self._BOTTOM_MARGIN:
                current_y = self._new_page_with_headers()

            # Main line
            self.canvas.setFont(_FONT, 9)
            self.canvas.drawString(2 * cm, current_y, self._fit(line.description, _MAX_DESC_CHARS))
            self.canvas.drawString(9 * cm, current_y, f"{line.quantity:.2f}")
            self.canvas.drawString(11 * cm, current_y, f"{line.unit_price:.2f} {currency}")

            self.canvas.drawString(13.5 * cm, current_y, f"{self._format_vat_percent(line.tax_rate)}%")
            self.canvas.drawString(15.5 * cm, current_y, f"{line.line_total:.2f} {currency}")
            current_y -= 0.5 * cm

            # Sub-lines (EN16931 detail fields) in smaller font, indented
            self.canvas.setFont(_FONT, 8)

            if line.domain_name:
                self.canvas.drawString(
                    2.5 * cm,
                    current_y,
                    str(_t("Domeniu: {domain}")).format(domain=self._fit(line.domain_name, _MAX_SUBLINE_CHARS)),
                )
                current_y -= 0.35 * cm

            if line.period_start and line.period_end:
                self.canvas.drawString(
                    2.5 * cm,
                    current_y,
                    str(_t("Perioada: {start} - {end}")).format(
                        start=line.period_start.strftime("%d.%m.%Y"),
                        end=line.period_end.strftime("%d.%m.%Y"),
                    ),
                )
                current_y -= 0.35 * cm

            if line.seller_item_id:
                self.canvas.drawString(
                    2.5 * cm,
                    current_y,
                    str(_t("Cod produs: {code}")).format(code=self._fit(line.seller_item_id, _MAX_SUBLINE_CHARS)),
                )
                current_y -= 0.35 * cm

            # Document-level discounts (the live BG-20 path) are rendered in the totals
            # section, not per line — the dead per-line discount_amount_cents that used
            # to be drawn here is never populated and disagreed with the e-Factura XML.

        self._table_end_y = current_y

    def _new_page_with_headers(self) -> float:
        """Start a new page, re-draw the table column headers, and return the y at which
        line rendering should resume."""
        self.canvas.showPage()
        top_y = self.height - 3 * cm
        self._render_table_headers(top_y)
        return top_y - 0.8 * cm

    def _render_vat_breakdown(
        self,
        totals_y: float,
        vat_groups: dict[Decimal, dict[str, Decimal]],
        discount: Decimal,
        net: Decimal,
        currency: str,
    ) -> float:
        """Render the VAT breakdown lines and return the updated y cursor.

        With a document discount the taxable base is reduced, so a SINGLE net bucket is shown
        (base = net subtotal, tax = invoice tax) — exactly the single TaxSubtotal the e-Factura
        XML emits (this system is single-category). Without a discount gross == net, so the
        richer per-rate breakdown is exact and kept.
        """
        self.canvas.setFont(_FONT, 11)
        line_tmpl = _t("TVA {rate}%: {tax} {currency} (baza: {base} {currency})")
        if discount > 0:
            # Deterministically pick the dominant (largest-base) rate for the collapsed
            # net bucket — independent of queryset ordering. Single-category invoices
            # (the only kind this system issues) have exactly one bucket, so this is the
            # one true rate. A discounted MULTI-rate invoice violates that invariant and
            # the XML can't represent it either; surface it rather than silently mislabel.
            if len(vat_groups) > 1:
                logger.warning(
                    "PDF VAT breakdown: document %s has a discount across %d tax rates "
                    "(unsupported single-category invariant violation); showing dominant rate.",
                    getattr(self.document, "number", "?"),
                    len(vat_groups),
                )
            rate = max(vat_groups, key=lambda r: vat_groups[r]["base"], default=Decimal("0"))
            self.canvas.drawString(
                12 * cm,
                totals_y,
                str(line_tmpl).format(
                    rate=self._format_vat_percent(rate),
                    tax=f"{self.document.tax_amount:.2f}",
                    base=f"{net:.2f}",
                    currency=currency,
                ),
            )
            return totals_y - 0.5 * cm
        for rate in sorted(vat_groups.keys()):
            group = vat_groups[rate]
            self.canvas.drawString(
                12 * cm,
                totals_y,
                str(line_tmpl).format(
                    rate=self._format_vat_percent(rate),
                    tax=f"{group['tax']:.2f}",
                    base=f"{group['base']:.2f}",
                    currency=currency,
                ),
            )
            totals_y -= 0.5 * cm
        return totals_y

    def _render_totals_section(self) -> None:
        """Render totals section with the document-level discount and a VAT breakdown that
        reconciles with the e-Factura XML (BG-20 allowance + single net TaxSubtotal)."""
        currency = self._get_currency_code()

        # VAT breakdown by rate from the GROSS line subtotals. Keyed by the Decimal
        # tax_rate (not int(rate*100)) so e.g. 9% and 9.5% are distinct buckets.
        vat_groups: dict[Decimal, dict[str, Decimal]] = defaultdict(lambda: {"base": Decimal("0"), "tax": Decimal("0")})
        has_reverse_charge = False
        gross = Decimal("0")

        lines = self.document.lines.all()
        for line in lines:
            rate_key = Decimal(line.tax_rate)
            vat_groups[rate_key]["base"] += line.subtotal
            vat_groups[rate_key]["tax"] += line.line_total - line.subtotal
            gross += line.subtotal

            if getattr(line, "tax_category_code", "") == "AE":
                has_reverse_charge = True

        # Document-level discount (BT-92/107), DERIVED the same way the e-Factura XML
        # derives it (gross line sum minus the net header subtotal) so the PDF and XML
        # agree, including on legacy invoices. net/tax/total come from the invoice ledger.
        net = self.document.subtotal
        discount = max(Decimal("0"), gross - net)
        # For a (degenerate) line-less document fall back to the stored net so Subtotal
        # is never shown as 0.00.
        subtotal_shown = gross if gross > 0 else net

        # Page-break if the whole totals block would collide with the footer. The block
        # height is variable (one VAT line when discounted, else one per rate; plus the
        # optional discount / reverse-charge / exchange / status lines), so estimate it
        # from what will actually be drawn rather than a fixed guess.
        vat_lines = 1 if discount > 0 else max(1, len(vat_groups))
        block_lines = (
            3                              # subtotal, total-VAT, grand-total
            + vat_lines
            + (1 if discount > 0 else 0)   # discount line
            + (1 if has_reverse_charge else 0)
            + 2                            # generous allowance for exchange-rate + status lines
        )
        needed = block_lines * 0.7 * cm
        totals_y = self._table_end_y - 1 * cm
        if totals_y - needed < self._BOTTOM_MARGIN:
            self.canvas.showPage()
            totals_y = self.height - 3 * cm

        # Subtotal (gross line-extension total = e-Factura LineExtensionAmount/BT-106)
        self.canvas.setFont(_FONT_BOLD, 12)
        self.canvas.drawString(
            12 * cm,
            totals_y,
            str(_t("Subtotal: {amount} {currency}")).format(amount=f"{subtotal_shown:.2f}", currency=currency),
        )
        totals_y -= 0.5 * cm

        # Document discount (BG-20), only when present
        if discount > 0:
            self.canvas.setFont(_FONT, 11)
            self.canvas.drawString(
                12 * cm,
                totals_y,
                str(_t("Discount: -{amount} {currency}")).format(amount=f"{discount:.2f}", currency=currency),
            )
            totals_y -= 0.5 * cm

        # VAT breakdown (re-based to reconcile with the discounted total / e-Factura XML).
        totals_y = self._render_vat_breakdown(totals_y, vat_groups, discount, net, currency)

        # Total VAT
        self.canvas.setFont(_FONT_BOLD, 11)
        self.canvas.drawString(
            12 * cm,
            totals_y,
            str(_t("Total TVA: {amount} {currency}")).format(
                amount=f"{self.document.tax_amount:.2f}", currency=currency
            ),
        )
        totals_y -= 0.6 * cm

        # Grand total
        total_label = self._get_total_label()
        self.canvas.setFont(_FONT_BOLD, 12)
        self.canvas.drawString(
            12 * cm,
            totals_y,
            str(total_label).format(amount=f"{self.document.total:.2f}", currency=currency),
        )
        totals_y -= 0.8 * cm

        # Reverse charge notice
        if has_reverse_charge:
            self.canvas.setFont(_FONT_BOLD, 9)
            self.canvas.drawString(
                2 * cm,
                totals_y,
                str(_t("Taxare inversă / Reverse charge — Art. 331 Cod Fiscal")),
            )
            totals_y -= 0.5 * cm

        # Exchange rate line for non-RON currencies
        if currency != "RON":
            meta = self.document.meta or {}
            exchange_rate = meta.get("exchange_rate")
            if exchange_rate:
                self.canvas.setFont(_FONT, 9)
                self.canvas.drawString(
                    2 * cm,
                    totals_y,
                    str(_t("Curs valutar: 1 {currency} = {rate} RON")).format(currency=currency, rate=exchange_rate),
                )
                totals_y -= 0.5 * cm

        # Additional status information
        self._render_status_information(totals_y)

    def _get_total_label(self) -> str:
        """Get the appropriate total label for the document type."""
        return _t("TOTAL: {amount} {currency}")

    def _render_status_information(self, totals_y: float) -> None:
        """Render document-specific status information."""
        # Override in subclasses if needed

    def _render_document_footer(self) -> None:
        """Render document footer with legal disclaimers."""
        company_info = self._get_company_info()

        self.canvas.setFont(_FONT, 8)
        self.canvas.drawString(2 * cm, 2 * cm, str(self._get_legal_disclaimer()))
        self.canvas.drawString(
            2 * cm, 1.5 * cm, str(_t("Generated automatically by {platform}")).format(platform=company_info["name"])
        )

    def _get_legal_disclaimer(self) -> str:
        """Get the legal disclaimer text for the document."""
        raise NotImplementedError("Subclasses must implement legal disclaimer")


class RomanianInvoicePDFGenerator(RomanianDocumentPDFGenerator):
    """
    Romanian fiscal invoice PDF generator with VAT compliance.
    Handles proper invoice formatting according to Romanian legislation.
    """

    def __init__(self, invoice: Invoice) -> None:
        super().__init__(invoice)
        self.invoice = invoice  # Type-specific reference

    def _get_document_title(self) -> str:
        return _t("FISCAL INVOICE")

    def _get_filename(self) -> str:
        return f"factura_{self.invoice.number}.pdf"

    def _get_legal_disclaimer(self) -> str:
        return _t("Factură fiscală emisă conform art. 319 din Legea nr. 227/2015 privind Codul fiscal.")

    def _get_total_label(self) -> str:
        return _t("TOTAL TO PAY: {amount} {currency}")

    def _render_document_details(self) -> None:
        """Render invoice-specific details."""
        self.canvas.setFont(_FONT, 12)
        self.canvas.drawString(
            2 * cm, self.height - 5 * cm, str(_t("Number: {number}")).format(number=self.invoice.number)
        )

        if self.invoice.issued_at:
            self.canvas.drawString(
                2 * cm,
                self.height - 5.5 * cm,
                str(_t("Issue date: {date}")).format(date=self.invoice.issued_at.strftime("%d.%m.%Y")),
            )

        if self.invoice.due_at:
            self.canvas.drawString(
                2 * cm,
                self.height - 6 * cm,
                str(_t("Due date: {date}")).format(date=self.invoice.due_at.strftime("%d.%m.%Y")),
            )

        # Status indicator
        self.canvas.setFont(_FONT_BOLD, 10)
        self.canvas.drawString(
            14 * cm, self.height - 5 * cm, str(_t("Status: {status}")).format(status=self.invoice.status.upper())
        )

    def _render_status_information(self, totals_y: float) -> None:
        """Render payment status information."""
        if self.invoice.status != "paid":
            self.canvas.setFont(_FONT_BOLD, 10)
            due_date_str = self.invoice.due_at.strftime("%d.%m.%Y") if self.invoice.due_at else str(_t("undefined"))
            self.canvas.drawString(
                2 * cm, totals_y - 0.5 * cm, str(_t("Unpaid invoice - Due: {date}")).format(date=due_date_str)
            )
        elif self.invoice.status == "paid" and hasattr(self.invoice, "paid_at") and self.invoice.paid_at:
            self.canvas.setFont(_FONT_BOLD, 10)
            self.canvas.drawString(
                2 * cm,
                totals_y - 0.5 * cm,
                str(_t("Invoice paid on: {date}")).format(date=self.invoice.paid_at.strftime("%d.%m.%Y")),
            )


class RomanianProformaPDFGenerator(RomanianDocumentPDFGenerator):
    """
    Romanian proforma invoice PDF generator.
    Handles proforma-specific formatting and legal requirements.
    """

    def __init__(self, proforma: ProformaInvoice) -> None:
        super().__init__(proforma)
        self.proforma = proforma  # Type-specific reference

    def _get_document_title(self) -> str:
        return _t("FACTURĂ PROFORMA")

    def _get_filename(self) -> str:
        return f"proforma_{self.proforma.number}.pdf"

    def _get_legal_disclaimer(self) -> str:
        return _t("Factura proforma nu constituie document fiscal. Nu dă drept de deducere a TVA.")

    def _render_document_details(self) -> None:
        """Render proforma-specific details."""
        self.canvas.setFont(_FONT, 12)
        self.canvas.drawString(
            2 * cm, self.height - 5 * cm, str(_t("Number: {number}")).format(number=self.proforma.number)
        )
        self.canvas.drawString(
            2 * cm,
            self.height - 5.5 * cm,
            str(_t("Date: {date}")).format(date=self.proforma.created_at.strftime("%d.%m.%Y")),
        )
        self.canvas.drawString(
            2 * cm,
            self.height - 6 * cm,
            str(_t("Valid until: {date}")).format(date=self.proforma.valid_until.strftime("%d.%m.%Y")),
        )


# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================


def generate_invoice_pdf(invoice: Invoice) -> bytes:
    """
    Generate PDF bytes for an invoice.

    Args:
        invoice: Invoice model instance

    Returns:
        PDF content as bytes
    """
    generator = RomanianInvoicePDFGenerator(invoice)
    generator._create_pdf_document()
    generator.canvas.showPage()
    generator.canvas.save()
    generator.buffer.seek(0)
    return generator.buffer.getvalue()


def generate_proforma_pdf(proforma: ProformaInvoice) -> bytes:
    """
    Generate PDF bytes for a proforma invoice.

    Args:
        proforma: ProformaInvoice model instance

    Returns:
        PDF content as bytes
    """
    generator = RomanianProformaPDFGenerator(proforma)
    generator._create_pdf_document()
    generator.canvas.showPage()
    generator.canvas.save()
    generator.buffer.seek(0)
    return generator.buffer.getvalue()


def generate_invoice_pdf_response(invoice: Invoice) -> HttpResponse:
    """
    Generate HTTP response with invoice PDF.

    Args:
        invoice: Invoice model instance

    Returns:
        HttpResponse with PDF content
    """
    generator = RomanianInvoicePDFGenerator(invoice)
    return generator.generate_response()


def generate_proforma_pdf_response(proforma: ProformaInvoice) -> HttpResponse:
    """
    Generate HTTP response with proforma PDF.

    Args:
        proforma: ProformaInvoice model instance

    Returns:
        HttpResponse with PDF content
    """
    generator = RomanianProformaPDFGenerator(proforma)
    return generator.generate_response()
