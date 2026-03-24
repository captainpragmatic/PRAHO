"""
Living Styleguide view - DEBUG only.

Renders all design-system components with every variant so developers can
verify the component library without running an application flow.

Access:  http://localhost:8701/styleguide/
Guard:   URL only registered when settings.DEBUG = True (see config/urls.py).
         View also checks DEBUG as belt-and-suspenders.
         No staff check -- Portal has no Django User model or is_staff concept.
"""

from __future__ import annotations

from django.conf import settings
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import render

from apps.ui.templatetags.ui_components import _ICON_PATHS

# ===============================================================================
# CONTEXT DATA
# ===============================================================================


BUTTON_VARIANTS = ["primary", "secondary", "success", "warning", "danger", "info"]

BADGE_VARIANTS = [
    ("Active", "success"),
    ("Pending", "warning"),
    ("Cancelled", "danger"),
    ("Draft", "secondary"),
    ("Info", "info"),
    ("Default", "default"),
]

ALERT_SAMPLES = [
    {"message": "Invoice has been issued successfully!", "variant": "success", "title": "Success"},
    {"message": "Payment is due to expire in 3 days.", "variant": "warning", "title": "Warning"},
    {"message": "An error occurred while processing the payment.", "variant": "danger", "title": "Error"},
    {"message": "The new billing cycle starts on September 1st.", "variant": "info", "title": "Info"},
]

STATUS_SAMPLES = [
    "active",
    "pending",
    "awaiting_payment",
    "suspended",
    "cancelled",
    "provisioning",
    "failed",
    "open",
    "paid",
    "in_review",
    "overdue",
    "draft",
]

# Keep styleguide icon list always in sync with the registry used by {% icon %}.
ICON_NAMES = sorted(_ICON_PATHS.keys())

STAT_TILE_SAMPLES = [
    {
        "label": "Total Due",
        "value": "1,234.56 RON",
        "icon": "currency",
        "variant": "warning",
        "meta": "Due: 2026-03-15",
    },
    {"label": "Active Services", "value": "12", "icon": "server", "variant": "success"},
    {"label": "Open Tickets", "value": "3", "icon": "ticket", "variant": "info"},
    {"label": "Domains", "value": "7", "icon": "globe", "variant": "default"},
]

BREADCRUMB_SAMPLES = [
    {"label": "Home", "url": "#"},
    {"label": "Billing", "url": "#"},
    {"label": "Invoice #PRH-2024-001"},
]

TABLE_HEADERS = [
    {"label": "Service"},
    {"label": "Plan"},
    {"label": "Status"},
    {"label": "Price"},
]
TABLE_ROWS = [
    {"cells": [{"value": "Web Hosting"}, {"value": "Basic"}, {"value": "Active"}, {"value": "39 RON"}]},
    {"cells": [{"value": "VPS Pro"}, {"value": "Standard"}, {"value": "Active"}, {"value": "149 RON"}]},
    {"cells": [{"value": "Email Business"}, {"value": "Pro"}, {"value": "Pending"}, {"value": "19 RON"}]},
]

STEP_PROGRESS_ORDER_STEPS = [
    {"label": "Product Selection", "icon": "orders", "url": "#"},
    {"label": "Cart Review", "icon": "orders", "url": "#"},
    {"label": "Checkout", "icon": "credit-card", "url": "#"},
    {"label": "Confirmation", "icon": "check"},
]

STEP_PROGRESS_SIMPLE_STEPS = [
    {"label": "Choose Method", "description": "Select authentication method"},
    {"label": "Set Up", "description": "Configure your authenticator"},
    {"label": "Complete", "description": "Save backup codes"},
]


def _build_context() -> dict[str, object]:
    """Build the styleguide context with all component variants."""
    return {
        "button_variants": BUTTON_VARIANTS,
        "badge_variants": BADGE_VARIANTS,
        "alert_samples": ALERT_SAMPLES,
        "status_samples": STATUS_SAMPLES,
        "icon_names": ICON_NAMES,
        "stat_tile_samples": STAT_TILE_SAMPLES,
        "breadcrumb_items": BREADCRUMB_SAMPLES,
        "table_headers": TABLE_HEADERS,
        "table_rows": TABLE_ROWS,
        "step_progress_order_steps": STEP_PROGRESS_ORDER_STEPS,
        "step_progress_simple_steps": STEP_PROGRESS_SIMPLE_STEPS,
        # Section anchors for the sidebar nav
        "sections": [
            {"id": "colors", "label": "Colors & Typography"},
            {"id": "icons", "label": "Icons"},
            {"id": "badges", "label": "Badges"},
            {"id": "buttons", "label": "Buttons"},
            {"id": "alerts", "label": "Alerts"},
            {"id": "status", "label": "Status Labels"},
            {"id": "stat-tiles", "label": "Stat Tiles"},
            {"id": "breadcrumbs", "label": "Breadcrumbs"},
            {"id": "step-progress", "label": "Step Progress"},
            {"id": "cards", "label": "Cards"},
            {"id": "tables", "label": "Tables"},
            {"id": "forms", "label": "Forms"},
            {"id": "modals", "label": "Modals"},
        ],
    }


# ===============================================================================
# VIEW
# ===============================================================================


def styleguide(request: HttpRequest) -> HttpResponse:
    """Render the living design-system styleguide.

    Belt-and-suspenders: URL only exists when DEBUG=True (config/urls.py),
    but we also check here in case someone wires it up incorrectly.
    No auth required — this is a dev-only tool and Portal has no staff users.
    """
    if not settings.DEBUG:
        raise Http404("Styleguide is only available in DEBUG mode.")

    context = _build_context()
    return render(request, "styleguide/index.html", context)
