# ===============================================================================
# PORTAL BILLING VIEWS - CUSTOMER INVOICE INTERFACE 💳
# ===============================================================================

import json
import logging
from typing import Any

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

from apps.common.decorators import log_access_attempt, require_billing_access

from .services import BillingDataSyncService, InvoiceViewService

logger = logging.getLogger(__name__)


# ===============================================================================
# INVOICE LIST VIEW 📋
# ===============================================================================


@require_http_methods(["GET"])
@require_billing_access()
@log_access_attempt
def invoices_list_view(request: HttpRequest) -> HttpResponse:
    """
    🔒 Customer Billing Documents List View

    GET /billing/invoices/

    Displays paginated list of customer's invoices and proformas with filtering options.
    Integrates with platform API for real-time data. Requires billing access.
    """
    # Customer ID is available from decorator via request.current_customer_id
    customer_id = getattr(request, "current_customer_id", None)

    try:
        invoice_service = InvoiceViewService()

        # Get filter parameters
        status_filter = request.GET.get("status", "")
        doc_type = request.GET.get("type", "all")
        force_sync = request.GET.get("sync") == "true"

        # Get both invoices and proformas from service
        documents: list[Any] = []
        user_id = int(request.user.id)  # type: ignore[union-attr, arg-type]
        cid = int(customer_id)  # type: ignore[arg-type]

        if doc_type in ["all", "invoice"]:
            invoices = invoice_service.get_customer_invoices(customer_id=cid, user_id=user_id, force_sync=force_sync)
            # Add document type to each invoice
            for invoice in invoices:
                invoice.document_type = "invoice"
            documents.extend(invoices)

        if doc_type in ["all", "proforma"]:
            proformas = invoice_service.get_customer_proformas(customer_id=cid, user_id=user_id, force_sync=force_sync)
            # Add document type to each proforma
            for proforma in proformas:
                proforma.document_type = "proforma"
            documents.extend(proformas)

        # Apply status filter if provided
        if status_filter and (
            status_filter in ["draft", "issued", "paid", "overdue", "void", "refunded"]
            or status_filter in ["sent", "accepted", "expired"]
        ):
            documents = [doc for doc in documents if doc.status == status_filter]

        # Sort documents by creation date (newest first)
        documents.sort(key=lambda x: x.created_at, reverse=True)

        # Simple pagination (could be enhanced)
        try:
            page = max(1, int(request.GET.get("page", 1)))
        except (ValueError, TypeError):
            page = 1
        per_page = 20
        total_documents = len(documents)
        start_index = (page - 1) * per_page
        end_index = start_index + per_page

        paginated_documents = documents[start_index:end_index]
        total_pages = (total_documents + per_page - 1) // per_page

        context = {
            "invoices": paginated_documents,  # Keep template compatibility by using 'invoices'
            "status_filter": status_filter,
            "doc_type": doc_type,
            "pagination": {
                "current_page": page,
                "total_pages": total_pages,
                "has_previous": page > 1,
                "has_next": page < total_pages,
                "total_items": total_documents,
            },
            "status_choices": [
                ("", _("All Statuses")),
                ("draft", _("Draft")),
                ("issued", _("Issued")),
                ("sent", _("Sent")),
                ("accepted", _("Accepted")),
                ("paid", _("Paid")),
                ("overdue", _("Overdue")),
                ("expired", _("Expired")),
                ("void", _("Void")),
                ("refunded", _("Refunded")),
            ],
        }

        logger.info(f"✅ [Portal Billing] Invoice list displayed for customer {customer_id}")
        return render(request, "billing/invoices_list.html", context)

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] Invoice list error for customer {customer_id}: {e}")
        messages.error(request, _("Unable to load invoices. Please try again."))
        return render(request, "billing/invoices_list.html", {"invoices": [], "error": True})


# ===============================================================================
# INVOICE DETAIL VIEW 📄
# ===============================================================================


@require_http_methods(["GET"])
def invoice_detail_view(request: HttpRequest, invoice_number: str) -> HttpResponse:
    """
    📄 Customer Invoice Detail View

    GET /billing/invoices/{invoice_number}/

    Displays complete invoice details including line items and billing information.
    """
    # Check authentication via middleware (customer_id is set by PortalAuthenticationMiddleware)
    customer_id = getattr(request, "customer_id", None)
    user_id = getattr(request, "user_id", None)
    if not customer_id or not user_id:
        return redirect("/login/")

    try:
        invoice_service = InvoiceViewService()
        force_sync = request.GET.get("sync") == "true"

        # Get invoice details
        invoice = invoice_service.get_invoice_detail(
            invoice_number=invoice_number, customer_id=customer_id, user_id=user_id, force_sync=force_sync
        )

        if not invoice:
            # Fallback: if not an invoice, try as proforma and route accordingly
            proforma = invoice_service.get_proforma_detail(
                proforma_number=invoice_number,
                customer_id=customer_id,
                user_id=user_id,
                force_sync=force_sync,
            )
            if proforma:
                logger.info(f"➡️ [Portal Billing] {invoice_number} is a proforma; redirecting to proforma detail")
                return redirect("billing:proforma_detail", proforma_number=invoice_number)

            messages.error(request, _("Invoice not found or access denied."))
            return render(request, "billing/invoice_not_found.html", {"invoice_number": invoice_number})

        context = {"invoice": invoice, "invoice_number": invoice_number}

        logger.info(f"✅ [Portal Billing] Invoice detail displayed: {invoice_number} for customer {customer_id}")
        return render(request, "billing/invoice_detail.html", context)

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] Invoice detail error for {invoice_number}: {e}")
        messages.error(request, _("Unable to load invoice details. Please try again."))
        return render(request, "billing/invoice_not_found.html", {"invoice_number": invoice_number, "error": True})


# ===============================================================================
# DASHBOARD BILLING WIDGET 📊
# ===============================================================================


@require_http_methods(["GET"])
def billing_dashboard_widget(request: HttpRequest) -> JsonResponse:
    """
    📊 Billing Dashboard Widget API

    GET /billing/dashboard-widget/

    Returns JSON data for dashboard billing summary widget.
    Used via HTMX for dynamic dashboard updates.
    """
    # Check authentication via session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    if not customer_id:
        return JsonResponse({"success": False, "error": "Authentication required"}, status=401)

    try:
        invoice_service = InvoiceViewService()

        # Get invoice summary
        summary = invoice_service.get_invoice_summary(int(customer_id), int(request.user.id))  # type: ignore[union-attr, arg-type]

        # Format amounts for display
        if summary["total_amount_due"] > 0:
            total_due_formatted = f"{summary['total_amount_due'] / 100:.2f} RON"
        else:
            total_due_formatted = "0.00 RON"

        # Prepare response data
        widget_data = {
            "success": True,
            "summary": {
                "total_invoices": summary["total_invoices"],
                "overdue_count": summary["overdue_invoices"],
                "pending_count": summary["issued_invoices"],
                "total_due_formatted": total_due_formatted,
                "total_due_cents": summary["total_amount_due"],
                "recent_invoices": summary["recent_invoices"][:3],  # Limit to 3 for widget
            },
        }

        logger.info(f"✅ [Portal Billing] Dashboard widget data for customer {customer_id}")
        return JsonResponse(widget_data)

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] Dashboard widget error for customer {customer_id}: {e}")
        return JsonResponse({"success": False, "error": "Unable to load billing data"}, status=500)


# ===============================================================================
# SYNC INVOICES ACTION 🔄
# ===============================================================================


@require_http_methods(["POST"])
def sync_invoices_action(request: HttpRequest) -> JsonResponse:
    """
    🔄 Sync Invoices Action

    POST /billing/sync/

    Forces a sync of customer invoices from platform service.
    Used via HTMX for manual refresh functionality.
    """
    # Check authentication via session
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    if not customer_id:
        return JsonResponse({"success": False, "error": "Authentication required"}, status=401)

    try:
        sync_service = BillingDataSyncService()

        # Force sync from platform
        synced_invoices = sync_service.sync_customer_invoices(int(customer_id), int(request.user.id))  # type: ignore[union-attr, arg-type]

        messages.success(request, _(f"Successfully synced {len(synced_invoices)} invoices."))

        return JsonResponse(
            {
                "success": True,
                "message": f"Synced {len(synced_invoices)} invoices",
                "synced_count": len(synced_invoices),
            }
        )

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] Sync error for customer {customer_id}: {e}")
        messages.error(request, _("Unable to sync invoices. Please try again."))

        return JsonResponse({"success": False, "error": "Sync failed"}, status=500)


# ===============================================================================
# PDF EXPORT VIEWS 📄
# ===============================================================================


@require_http_methods(["GET"])
def invoice_pdf_export(request: HttpRequest, invoice_number: str) -> HttpResponse:
    """
    📄 Invoice PDF Export

    GET /billing/invoices/{invoice_number}/pdf/

    Downloads invoice as PDF using the platform's PDF generation service.
    """
    # Check authentication via middleware (customer_id is set by PortalAuthenticationMiddleware)
    customer_id = getattr(request, "customer_id", None)
    if not customer_id:
        return redirect("/login/")

    try:
        invoice_service = InvoiceViewService()

        # Get PDF data from platform API
        pdf_data = invoice_service.get_invoice_pdf(invoice_number, int(customer_id), int(request.user.id))  # type: ignore[union-attr, arg-type]

        # Create HTTP response with PDF
        response = HttpResponse(pdf_data, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="factura_{invoice_number}.pdf"'

        logger.info(f"✅ [Portal Billing] PDF export for invoice {invoice_number} by customer {customer_id}")
        return response

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] PDF export error for invoice {invoice_number}: {e}")
        messages.error(request, _("Unable to generate PDF. Please try again."))
        return redirect("billing:invoice_detail", invoice_number=invoice_number)


@require_http_methods(["GET"])
def proforma_pdf_export(request: HttpRequest, proforma_number: str) -> HttpResponse:
    """
    📄 Proforma PDF Export

    GET /billing/proformas/{proforma_number}/pdf/

    Downloads proforma as PDF using the platform's PDF generation service.
    """
    # Check authentication via middleware (customer_id is set by PortalAuthenticationMiddleware)
    customer_id = getattr(request, "customer_id", None)
    if not customer_id:
        return redirect("/login/")

    try:
        invoice_service = InvoiceViewService()

        # Get PDF data from platform API
        pdf_data = invoice_service.get_proforma_pdf(proforma_number, int(customer_id), int(request.user.id))  # type: ignore[union-attr, arg-type]

        # Create HTTP response with PDF
        response = HttpResponse(pdf_data, content_type="application/pdf")
        response["Content-Disposition"] = f'attachment; filename="proforma_{proforma_number}.pdf"'

        logger.info(f"✅ [Portal Billing] PDF export for proforma {proforma_number} by customer {customer_id}")
        return response

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] PDF export error for proforma {proforma_number}: {e}")
        messages.error(request, _("Unable to generate PDF. Please try again."))
        return redirect("billing:proforma_detail", proforma_number=proforma_number)


# ===============================================================================
# PROFORMA DETAIL VIEW 📄
# ===============================================================================


@require_http_methods(["GET"])
def proforma_detail_view(request: HttpRequest, proforma_number: str) -> HttpResponse:
    """
    📄 Customer Proforma Detail View

    GET /billing/proformas/{proforma_number}/

    Displays detailed view of a specific proforma with line items.
    Integrates with platform API for real-time data.
    """
    # Check authentication via middleware (customer_id is set by PortalAuthenticationMiddleware)
    customer_id = getattr(request, "customer_id", None)
    user_id = getattr(request, "user_id", None)
    if not customer_id or not user_id:
        return redirect("/login/")

    try:
        invoice_service = InvoiceViewService()
        force_sync = request.GET.get("sync") == "true"

        # Get proforma details
        proforma = invoice_service.get_proforma_detail(
            proforma_number=proforma_number, customer_id=customer_id, user_id=user_id, force_sync=force_sync
        )

        if not proforma:
            messages.error(request, _("Proforma not found or access denied."))
            return render(request, "billing/proforma_not_found.html", {"proforma_number": proforma_number})

        context = {
            "proforma": proforma,
            "proforma_number": proforma_number,
            "lines": proforma.lines,  # Make lines available to template
            "is_staff_user": False,  # Portal customers are not staff
            "can_edit": False,  # Portal customers cannot edit proformas
            "can_convert": False,  # Portal customers cannot convert proformas
        }

        logger.info(f"✅ [Portal Billing] Proforma detail displayed: {proforma_number} for customer {customer_id}")
        return render(request, "billing/proforma_detail.html", context)

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] Proforma detail error for {proforma_number}: {e}")
        messages.error(request, _("Unable to load proforma details. Please try again."))
        return render(request, "billing/proforma_not_found.html", {"proforma_number": proforma_number, "error": True})


# ===============================================================================
# PAYMENT METHODS VIEW 💳
# ===============================================================================


@require_http_methods(["GET"])
def payment_methods_view(request: HttpRequest) -> JsonResponse:
    """
    💳 Payment Methods API

    GET /billing/payment-methods/

    Returns available payment methods for the current customer.
    Used by checkout and account pages via HTMX/fetch.
    """
    customer_id = getattr(request, "customer_id", None) or request.session.get("customer_id")
    if not customer_id:
        return JsonResponse({"success": False, "error": "Authentication required"}, status=401)

    try:
        invoice_service = InvoiceViewService()
        user_id = getattr(request.user, "id", None)
        if not user_id:
            return JsonResponse({"success": False, "error": "Authentication required"}, status=401)
        methods = invoice_service.get_payment_methods(
            int(customer_id),
            int(user_id),
        )

        return JsonResponse({"success": True, "payment_methods": methods})

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] Payment methods error for customer {customer_id}: {e}")
        return JsonResponse({"success": False, "error": "Unable to load payment methods"}, status=500)


# ===============================================================================
# REFUND REQUEST VIEW 🔄
# ===============================================================================


@require_http_methods(["POST"])
def request_refund_view(request: HttpRequest, invoice_number: str) -> JsonResponse:
    """
    🔄 Request Invoice Refund

    POST /billing/invoices/{invoice_number}/refund/

    Submits a refund request for a specific invoice through the Platform API.
    """
    customer_id = getattr(request, "customer_id", None)
    user_id = getattr(request, "user_id", None)
    if not customer_id or not user_id:
        return JsonResponse({"success": False, "error": "Authentication required"}, status=401)

    try:
        data = json.loads(request.body) if request.body else {}
        reason = data.get("refund_reason", "customer_request")
        amount_cents = data.get("amount_cents")

        invoice_service = InvoiceViewService()
        result = invoice_service.request_refund(
            invoice_number=invoice_number,
            customer_id=int(customer_id),
            user_id=int(user_id),
            amount_cents=int(amount_cents) if amount_cents else None,
            reason=reason,
        )

        if result.get("success"):
            logger.info(f"✅ [Portal Billing] Refund requested for invoice {invoice_number} by customer {customer_id}")
            return JsonResponse(
                {
                    "success": True,
                    "message": _("Refund request submitted successfully."),
                    "refund_id": result.get("refund_id"),
                }
            )

        error_msg = result.get("error", _("Unable to process refund request."))
        logger.warning(f"⚠️ [Portal Billing] Refund request failed for {invoice_number}: {error_msg}")
        return JsonResponse({"success": False, "error": error_msg}, status=400)

    except Exception as e:
        logger.error(f"🔥 [Portal Billing] Refund request error for {invoice_number}: {e}")
        return JsonResponse(
            {"success": False, "error": _("Unable to process refund request. Please try again.")},
            status=500,
        )
