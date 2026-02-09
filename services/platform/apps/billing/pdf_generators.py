# ===============================================================================
# ROMANIAN PDF GENERATORS FOR BILLING DOCUMENTS
# ===============================================================================

from __future__ import annotations

from io import BytesIO

from django.conf import settings
from django.http import HttpResponse
from django.utils.translation import gettext as _t
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas

from apps.billing.models import Invoice, ProformaInvoice


class RomanianDocumentPDFGenerator:
    """
    Base class for Romanian document PDF generation with common functionality.
    Handles company information, Romanian compliance, and standard formatting.
    """

    def __init__(self, document: Invoice | ProformaInvoice) -> None:
        self.document = document
        self.buffer = BytesIO()
        self.canvas = canvas.Canvas(self.buffer, pagesize=A4)
        self.width, self.height = A4

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

    def _get_company_info(self) -> dict[str, str]:
        """Get company information from settings with Romanian defaults."""
        return {
            "name": getattr(settings, "COMPANY_NAME", "PRAHO Platform"),
            "address": getattr(settings, "COMPANY_ADDRESS", "Str. Exemplu Nr. 1"),
            "city": getattr(settings, "COMPANY_CITY", "București"),
            "country": getattr(settings, "COMPANY_COUNTRY", "România"),
            "cui": getattr(settings, "COMPANY_CUI", "RO12345678"),
            "email": getattr(settings, "COMPANY_EMAIL", "contact@praho.ro"),
        }

    def _setup_document_header(self) -> None:
        """Setup document header with company branding and document info."""
        company_info = self._get_company_info()

        # Company branding
        self.canvas.setFont("Helvetica-Bold", 24)
        self.canvas.drawString(2 * cm, self.height - 3 * cm, f"🇷🇴 {company_info['name']}")

        # Document title
        self.canvas.setFont("Helvetica-Bold", 16)
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
        """Render supplier (company) information section."""
        company_info = self._get_company_info()
        y_pos = self.height - 8 * cm

        self.canvas.setFont("Helvetica-Bold", 14)
        self.canvas.drawString(2 * cm, y_pos, str(_t("Supplier:")))

        self.canvas.setFont("Helvetica", 10)
        self.canvas.drawString(2 * cm, y_pos - 0.5 * cm, company_info["name"])
        self.canvas.drawString(
            2 * cm, y_pos - 1 * cm, f"{company_info['address']}, {company_info['city']}, {company_info['country']}"
        )
        self.canvas.drawString(2 * cm, y_pos - 1.5 * cm, str(_t("Tax ID: {cui}")).format(cui=company_info["cui"]))
        self.canvas.drawString(2 * cm, y_pos - 2 * cm, str(_t("Email: {email}")).format(email=company_info["email"]))

    def _render_client_information(self) -> None:
        """Render client information section."""
        y_pos = self.height - 8 * cm

        self.canvas.setFont("Helvetica-Bold", 14)
        self.canvas.drawString(11 * cm, y_pos, str(_t("Client:")))

        self.canvas.setFont("Helvetica", 10)
        self.canvas.drawString(11 * cm, y_pos - 0.5 * cm, self.document.bill_to_name or "")

        if self.document.bill_to_address1:
            self.canvas.drawString(11 * cm, y_pos - 1 * cm, self.document.bill_to_address1)

        if self.document.bill_to_tax_id:
            self.canvas.drawString(
                11 * cm, y_pos - 1.5 * cm, str(_t("Tax ID: {tax_id}")).format(tax_id=self.document.bill_to_tax_id)
            )

        if self.document.bill_to_email:
            self.canvas.drawString(
                11 * cm, y_pos - 2 * cm, str(_t("Email: {email}")).format(email=self.document.bill_to_email)
            )

    def _render_items_table(self) -> None:
        """Render items table with headers and line items."""
        table_y = self.height - 13 * cm

        # Table headers
        self._render_table_headers(table_y)

        # Table data
        self._render_table_data(table_y)

    def _render_table_headers(self, table_y: float) -> None:
        """Render table column headers."""
        self.canvas.setFont("Helvetica-Bold", 10)
        self.canvas.drawString(2 * cm, table_y, str(_t("Description")))
        self.canvas.drawString(10 * cm, table_y, str(_t("Quantity")))
        self.canvas.drawString(12 * cm, table_y, str(_t("Unit Price")))
        self.canvas.drawString(15 * cm, table_y, str(_t("Total")))

        # Draw line under headers
        self.canvas.line(2 * cm, table_y - 0.3 * cm, 18 * cm, table_y - 0.3 * cm)

    def _render_table_data(self, table_y: float) -> None:
        """Render table line items data."""
        self.canvas.setFont("Helvetica", 9)
        current_y = table_y - 0.8 * cm

        lines = self.document.lines.all()
        for line in lines:
            self.canvas.drawString(2 * cm, current_y, str(line.description)[:40])  # Truncate long descriptions
            self.canvas.drawString(10 * cm, current_y, f"{line.quantity:.2f}")
            self.canvas.drawString(12 * cm, current_y, f"{line.unit_price:.2f} RON")
            self.canvas.drawString(15 * cm, current_y, f"{line.line_total:.2f} RON")
            current_y -= 0.5 * cm

    def _render_totals_section(self) -> None:
        """Render totals section with Romanian VAT calculations."""
        # Calculate position after table items
        lines_count = self.document.lines.count()
        current_y = self.height - 13 * cm - 0.8 * cm - (lines_count * 0.5 * cm)
        totals_y = current_y - 1 * cm

        self.canvas.setFont("Helvetica-Bold", 12)
        self.canvas.drawString(
            12 * cm, totals_y, str(_t("Subtotal: {amount} RON")).format(amount=f"{self.document.subtotal:.2f}")
        )
        self.canvas.drawString(
            12 * cm,
            totals_y - 0.5 * cm,
            str(_t("VAT (19%): {amount} RON")).format(amount=f"{self.document.tax_amount:.2f}"),
        )

        # Document-specific total label
        total_label = self._get_total_label()
        self.canvas.drawString(12 * cm, totals_y - 1 * cm, str(total_label).format(amount=f"{self.document.total:.2f}"))

        # Additional status information
        self._render_status_information(totals_y)

    def _get_total_label(self) -> str:
        """Get the appropriate total label for the document type."""
        return _t("TOTAL: {amount} RON")

    def _render_status_information(self, totals_y: float) -> None:
        """Render document-specific status information."""
        # Override in subclasses if needed

    def _render_document_footer(self) -> None:
        """Render document footer with legal disclaimers."""
        company_info = self._get_company_info()

        self.canvas.setFont("Helvetica", 8)
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
        return _t("Fiscal invoice issued according to Romanian legislation.")

    def _get_total_label(self) -> str:
        return _t("TOTAL TO PAY: {amount} RON")

    def _render_document_details(self) -> None:
        """Render invoice-specific details."""
        self.canvas.setFont("Helvetica", 12)
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
        self.canvas.setFont("Helvetica-Bold", 10)
        self.canvas.drawString(
            14 * cm, self.height - 5 * cm, str(_t("Status: {status}")).format(status=self.invoice.status.upper())
        )

    def _render_status_information(self, totals_y: float) -> None:
        """Render payment status information."""
        if self.invoice.status != "paid":
            self.canvas.setFont("Helvetica-Bold", 10)
            due_date_str = self.invoice.due_at.strftime("%d.%m.%Y") if self.invoice.due_at else str(_t("undefined"))
            self.canvas.drawString(
                2 * cm, totals_y - 2 * cm, str(_t("⚠️  Unpaid invoice - Due: {date}")).format(date=due_date_str)
            )
        elif self.invoice.status == "paid" and hasattr(self.invoice, "paid_at") and self.invoice.paid_at:
            self.canvas.setFont("Helvetica-Bold", 10)
            self.canvas.drawString(
                2 * cm,
                totals_y - 2 * cm,
                str(_t("✅ Invoice paid on: {date}")).format(date=self.invoice.paid_at.strftime("%d.%m.%Y")),
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
        return _t("This proforma is not a fiscal invoice.")

    def _render_document_details(self) -> None:
        """Render proforma-specific details."""
        self.canvas.setFont("Helvetica", 12)
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
