# ===============================================================================
# PORTAL BILLING VIEWS - CUSTOMER INVOICE INTERFACE 💳
# ===============================================================================

import json
import logging
import uuid
from typing import Any

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIError
from apps.common.decorators import log_access_attempt, require_billing_access
from apps.common.pagination import PaginatorData, build_pagination_params
from apps.common.rate_limit_feedback import handle_platform_error

from .services import BillingDataSyncService, InvoiceViewService, RecurringPaymentsService

logger = logging.getLogger(__name__)


# ===============================================================================
# STATUS → BADGE VARIANT MAPS 🏷️
# ===============================================================================

INVOICE_STATUS_VARIANT_MAP: dict[str, str] = {
    "paid": "success",
    "issued": "primary",
    "overdue": "danger",
    "draft": "secondary",
    "void": "secondary",
    "refunded": "warning",
    "sent": "primary",
    "cancelled": "danger",
}

PROFORMA_STATUS_VARIANT_MAP: dict[str, str] = {
    "draft": "secondary",
    "sent": "primary",
    "accepted": "success",
    "expired": "danger",
    "converted": "success",
    "cancelled": "danger",
}

PROFORMA_STATUS_ICON_MAP: dict[str, str] = {
    "draft": "document",
    "sent": "mail",
    "accepted": "check",
    "expired": "x",
    "converted": "check",
    "cancelled": "x",
}


# Tab configuration for document type filtering
# Labels are lazy: module-level gettext would freeze them to the import-time locale.
INVOICE_DOC_TYPE_TABS = [
    {
        "value": "all",
        "label": gettext_lazy("All Documents"),
        "border_class": "border-blue-500",
        "text_class": "text-blue-400",
    },
    {
        "value": "invoice",
        "label": gettext_lazy("Invoices"),
        "border_class": "border-green-500",
        "text_class": "text-green-400",
    },
    {
        "value": "proforma",
        "label": gettext_lazy("Proformas"),
        "border_class": "border-purple-500",
        "text_class": "text-purple-400",
    },
]

# Allowlist for the ?type= query param. The value is echoed into rendered
# context, and the shared tab component's roving tabindex needs a matching tab
# — unknown values fall back to the All Documents tab.
_VALID_DOC_TYPES = {tab["value"] for tab in INVOICE_DOC_TYPE_TABS}


def _validated_doc_type(raw: str) -> str:
    return raw if raw in _VALID_DOC_TYPES else "all"


INVOICE_STATUS_CHOICES = [
    ("", gettext_lazy("All Statuses")),
    ("draft", gettext_lazy("Draft")),
    ("issued", gettext_lazy("Issued")),
    ("sent", gettext_lazy("Sent")),
    ("accepted", gettext_lazy("Accepted")),
    ("paid", gettext_lazy("Paid")),
    ("overdue", gettext_lazy("Overdue")),
    ("expired", gettext_lazy("Expired")),
    ("void", gettext_lazy("Void")),
    ("refunded", gettext_lazy("Refunded")),
    ("partially_refunded", gettext_lazy("Partially Refunded")),
    ("converted", gettext_lazy("Converted")),
]

ALLOWED_STATUSES = {
    "draft",
    "issued",
    "paid",
    "overdue",
    "void",
    "refunded",
    "partially_refunded",
    "sent",
    "accepted",
    "expired",
    "converted",
}


def _invoices_base_context(  # noqa: PLR0913
    doc_type: str = "all",
    status_filter: str = "",
    search_query: str = "",
    total_documents: int = 0,
    invoice_count: int = 0,
    proforma_count: int = 0,
    unpaid_count: int = 0,
) -> dict[str, Any]:
    """Build shared context for both list view and search endpoint."""
    return {
        "doc_type": doc_type,
        "status_filter": status_filter,
        "search_query": search_query,
        "status_choices": INVOICE_STATUS_CHOICES,
        # Shared header component data
        "page_title": _("My Billing Documents"),
        "page_title_mobile": _("Billing"),
        "page_subtitle": _("View your invoices and proformas"),
        "search_placeholder": _("Search by type, number, amount, status, date, services…"),
        "header_stats": [
            {"value": str(invoice_count), "label": _("Invoices"), "color": "text-white"},
            {"value": str(proforma_count), "label": _("Proformas"), "color": "text-white"},
            {"value": str(unpaid_count), "label": _("Unpaid"), "color": "text-amber-400"},
            {"value": str(total_documents), "label": _("Total"), "color": "text-slate-400"},
        ],
        "filter_tabs": INVOICE_DOC_TYPE_TABS,
    }


# ===============================================================================
# INVOICE LIST VIEW 📋
# ===============================================================================


@require_http_methods(["GET"])
@require_billing_access()
@log_access_attempt
def invoices_list_view(request: HttpRequest) -> HttpResponse:
    """
    Customer Billing Documents List View.

    GET /billing/invoices/
    """
    customer_id = getattr(request, "current_customer_id", None)

    try:
        status_filter = request.GET.get("status", "")
        status_filter = status_filter if status_filter in ALLOWED_STATUSES else ""
        doc_type = _validated_doc_type(request.GET.get("type", "all"))
        search_query = request.GET.get("q", "").strip()
        force_sync = request.GET.get("sync") == "true"

        try:
            page = max(1, int(request.GET.get("page", 1)))
        except (ValueError, TypeError):
            page = 1

        assert request.user.is_authenticated, "require_billing_access should enforce auth"
        assert customer_id is not None, "require_billing_access should set customer_id"
        user_id = int(request.user.id)
        cid = int(customer_id)

        page_data = InvoiceViewService().get_customer_documents(
            customer_id=cid,
            user_id=user_id,
            page=page,
            limit=20,
            document_type=doc_type,
            status=status_filter,
            search=search_query,
            force_sync=force_sync,
        )
        total_documents = page_data.invoice_count + page_data.proforma_count
        paginator_data = PaginatorData(
            total_count=page_data.total_items,
            current_page=page_data.current_page,
            page_size=page_data.page_size,
        )
        pagination_params = build_pagination_params(type=doc_type, status=status_filter, q=search_query)

        context = {
            "invoices": page_data.documents,
            "paginator_data": paginator_data,
            "pagination_params": pagination_params,
            **_invoices_base_context(
                doc_type,
                status_filter,
                search_query,
                total_documents,
                invoice_count=page_data.invoice_count,
                proforma_count=page_data.proforma_count,
                unpaid_count=page_data.unpaid_invoice_count,
            ),
        }

        logger.info(f"✅ [Portal Billing] Invoice list displayed for customer {customer_id}")
        return render(request, "billing/invoices_list.html", context)

    except (PlatformAPIError, Exception) as e:
        error_ctx = handle_platform_error(
            request, e, logger, fallback_message=_("Unable to load invoices. Please try again.")
        )
        context = {
            "invoices": [],
            "error": True,
            "paginator_data": PaginatorData(total_count=0, current_page=1, page_size=20),
            "pagination_params": "",
            **_invoices_base_context(doc_type, status_filter, search_query),
            **error_ctx,
        }
        return render(request, "billing/invoices_list.html", context)


# ===============================================================================
# INVOICE SEARCH API (HTMX) 🔍
# ===============================================================================


@require_http_methods(["GET"])
def invoices_search_api(request: HttpRequest) -> HttpResponse:
    """
    HTMX search endpoint for live invoice filtering.
    Returns filtered invoices table partial.
    """
    customer_id = (
        getattr(request, "current_customer_id", None)
        or getattr(request, "customer_id", None)
        or request.session.get("customer_id")
    )
    user_id = getattr(request, "user_id", None) or request.session.get("user_id")
    if not customer_id or not user_id:
        return redirect("/login/")

    search_query = request.GET.get("q", "").strip()
    status_filter = request.GET.get("status", "")
    status_filter = status_filter if status_filter in ALLOWED_STATUSES else ""
    doc_type = _validated_doc_type(request.GET.get("type", "all"))
    try:
        page = max(1, int(request.GET.get("page", 1)))
    except (ValueError, TypeError):
        page = 1

    try:
        page_data = InvoiceViewService().get_customer_documents(
            customer_id=int(customer_id),
            user_id=int(user_id),
            page=page,
            limit=20,
            document_type=doc_type,
            status=status_filter,
            search=search_query,
        )
        paginator_data = PaginatorData(
            total_count=page_data.total_items,
            current_page=page_data.current_page,
            page_size=page_data.page_size,
        )
        pagination_params = build_pagination_params(type=doc_type, status=status_filter, q=search_query)

        return render(
            request,
            "billing/partials/invoices_table.html",
            {
                "invoices": page_data.documents,
                "paginator_data": paginator_data,
                "pagination_params": pagination_params,
                "status_choices": INVOICE_STATUS_CHOICES,
                "status_filter": status_filter,
            },
        )

    except (PlatformAPIError, Exception) as e:
        error_ctx = handle_platform_error(request, e, logger)
        context = {
            "invoices": [],
            "paginator_data": PaginatorData(total_count=0, current_page=1, page_size=20),
            "pagination_params": "",
            **error_ctx,
        }
        return render(request, "billing/partials/invoices_table.html", context)


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

        context = {
            "invoice": invoice,
            "invoice_number": invoice_number,
            "status_variant": INVOICE_STATUS_VARIANT_MAP.get(invoice.status, "secondary"),
        }

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
            "status_variant": PROFORMA_STATUS_VARIANT_MAP.get(proforma.status, "secondary"),
            "status_icon": PROFORMA_STATUS_ICON_MAP.get(proforma.status, ""),
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


def _positive_int(value: Any) -> int | None:
    """Parse an external identifier without accepting booleans as integers."""
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _recurring_session_ids(request: HttpRequest) -> tuple[int, int] | None:
    customer_id = _positive_int(getattr(request, "current_customer_id", None) or request.session.get("customer_id"))
    user_id = _positive_int(request.session.get("user_id"))
    if customer_id is None or user_id is None:
        return None
    return customer_id, user_id


def _json_body(request: HttpRequest) -> dict[str, Any] | None:
    try:
        data = json.loads(request.body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


@require_http_methods(["GET"])
@require_billing_access()
def recurring_payments_view(request: HttpRequest) -> HttpResponse:
    """Render customer-owned recurring-payment controls."""
    identity = _recurring_session_ids(request)
    if identity is None:
        return redirect("/login/")
    overview = RecurringPaymentsService().overview(customer_id=identity[0], user_id=identity[1])
    payment_methods: list[dict[str, Any]] = []
    for raw_method in overview.get("payment_methods", []):
        if not isinstance(raw_method, dict):
            continue
        method_id = _positive_int(raw_method.get("id"))
        if method_id is None:
            continue
        method = dict(raw_method)
        method["id"] = method_id
        method["last_four"] = str(method.get("last_four") or "")
        method["display_name"] = str(
            method.get("display_name") or (_("Card ending %(last_four)s") % {"last_four": method["last_four"]})
        )
        method["begin_attrs"] = f'data-payment-method-id="{method_id}"'
        authorization = method.get("authorization")
        if isinstance(authorization, dict):
            try:
                authorization_id = uuid.UUID(str(authorization.get("id")))
            except (TypeError, ValueError, AttributeError):
                method["authorization"] = None
            else:
                authorization["id"] = str(authorization_id)
                method["withdraw_attrs"] = f'data-authorization-id="{authorization_id}"'
        else:
            method["authorization"] = None
        payment_methods.append(method)

    subscription_options = [{"value": "", "label": _("Automatic payment off")}]
    subscription_options.extend(
        {
            "value": method["authorization"]["id"],
            "label": _("Pay automatically with %(card)s") % {"card": method["display_name"]},
        }
        for method in payment_methods
        if method.get("authorization")
    )
    subscriptions: list[dict[str, Any]] = []
    for raw_subscription in overview.get("subscriptions", []):
        if not isinstance(raw_subscription, dict):
            continue
        try:
            subscription_id = uuid.UUID(str(raw_subscription.get("id")))
        except (TypeError, ValueError, AttributeError):
            continue
        subscription = dict(raw_subscription)
        subscription["id"] = str(subscription_id)
        subscription["control_id"] = f"subscription-{subscription_id}"
        subscription["control_name"] = f"subscription_{subscription_id}"
        subscription["authorization_options"] = subscription_options
        subscriptions.append(subscription)
    return render(
        request,
        "billing/recurring_payments.html",
        {
            "page_title": _("Automatic payments"),
            "overview": overview,
            "payment_methods": payment_methods,
            "subscriptions": subscriptions,
        },
    )


@require_http_methods(["POST"])
@require_billing_access()
def recurring_authorization_begin(request: HttpRequest) -> JsonResponse:
    identity = _recurring_session_ids(request)
    data = _json_body(request)
    if identity is None or data is None:
        return JsonResponse({"success": False, "error": "Invalid request"}, status=400)
    payment_method_id = _positive_int(data.get("payment_method_id"))
    if payment_method_id is None:
        return JsonResponse({"success": False, "error": "Invalid payment method"}, status=400)
    result = RecurringPaymentsService().begin_authorization(
        customer_id=identity[0],
        user_id=identity[1],
        payment_method_id=payment_method_id,
        terms_accepted=data.get("terms_accepted") is True,
        terms_version=str(data.get("terms_version", "")),
    )
    return JsonResponse(result, status=200 if result.get("success") else 400)


@require_http_methods(["POST"])
@require_billing_access()
def recurring_authorization_complete(request: HttpRequest) -> JsonResponse:
    identity = _recurring_session_ids(request)
    data = _json_body(request)
    if identity is None or data is None:
        return JsonResponse({"success": False, "error": "Invalid request"}, status=400)
    payment_method_id = _positive_int(data.get("payment_method_id"))
    if payment_method_id is None:
        return JsonResponse({"success": False, "error": "Invalid payment method"}, status=400)
    result = RecurringPaymentsService().complete_authorization(
        customer_id=identity[0],
        user_id=identity[1],
        payment_method_id=payment_method_id,
        setup_intent_id=str(data.get("setup_intent_id", "")),
    )
    return JsonResponse(result, status=200 if result.get("success") else 400)


@require_http_methods(["POST"])
@require_billing_access()
def recurring_authorization_withdraw(request: HttpRequest) -> JsonResponse:
    identity = _recurring_session_ids(request)
    data = _json_body(request)
    if identity is None or data is None:
        return JsonResponse({"success": False, "error": "Invalid request"}, status=400)
    result = RecurringPaymentsService().withdraw_authorization(
        customer_id=identity[0],
        user_id=identity[1],
        authorization_id=str(data.get("authorization_id", "")),
    )
    return JsonResponse(result, status=200 if result.get("success") else 400)


@require_http_methods(["POST"])
@require_billing_access()
def subscription_auto_payment(request: HttpRequest) -> JsonResponse:
    identity = _recurring_session_ids(request)
    data = _json_body(request)
    if identity is None or data is None or not isinstance(data.get("enabled"), bool):
        return JsonResponse({"success": False, "error": "Invalid request"}, status=400)
    result = RecurringPaymentsService().set_subscription_auto_payment(
        customer_id=identity[0],
        user_id=identity[1],
        subscription_id=str(data.get("subscription_id", "")),
        authorization_id=str(data["authorization_id"]) if data.get("authorization_id") else None,
        enabled=data["enabled"],
    )
    return JsonResponse(result, status=200 if result.get("success") else 400)


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
