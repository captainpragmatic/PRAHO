"""
Account Health Banner — persistent, non-dismissible alerts for critical account conditions.

Evaluates invoice, service, and ticket summaries to produce a single blended banner
shown on every portal page until the customer resolves the underlying issue.

Architecture:
- Pure functions (evaluate_conditions, blend_banner) for testability
- Session-cached summaries with TTL (same pattern as decorators.py membership caching)
- Context processor integration via get_account_health()
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from django.http import HttpRequest
from django.utils.translation import gettext as _
from django.utils.translation import ngettext

from apps.api_client.services import PlatformAPIError
from apps.billing.services import InvoiceViewService
from apps.services.services import ServicesAPIClient
from apps.tickets.services import TicketsAPIClient

logger = logging.getLogger(__name__)

# Same TTL as membership cache in decorators.py
ACCOUNT_HEALTH_CACHE_TTL = 300  # 5 minutes


@dataclass(frozen=True)
class AccountCondition:
    """A single detected account issue."""

    key: str
    severity: str  # "critical", "warning", "info"
    priority: int  # Lower = higher priority
    count: int
    message: str
    cta_text: str
    cta_url: str


@dataclass(frozen=True)
class AccountHealthBanner:
    """The blended banner shown to the customer."""

    severity: str  # "critical", "warning", "info"
    message: str
    cta_text: str
    cta_url: str
    condition_count: int


def evaluate_conditions(
    invoice_summary: dict[str, Any],
    services_summary: dict[str, Any],
    tickets_summary: dict[str, Any],
) -> list[AccountCondition]:
    """Evaluate account summaries and return active conditions sorted by priority.

    Pure function — no I/O, no side effects. Returns an empty list when everything is healthy.
    """
    conditions: list[AccountCondition] = []

    # Priority 1: Suspended services (critical)
    suspended = int(services_summary.get("suspended_services", 0))
    if suspended > 0:
        conditions.append(
            AccountCondition(
                key="suspended_services",
                severity="critical",
                priority=1,
                count=suspended,
                message=ngettext(
                    "You have %(count)d suspended service.",
                    "You have %(count)d suspended services.",
                    suspended,
                )
                % {"count": suspended},
                cta_text=_("View Services"),
                cta_url="/services/?status=suspended",
            )
        )

    # Priority 2: Overdue invoices (critical)
    overdue = int(invoice_summary.get("overdue_invoices", 0))
    if overdue > 0:
        conditions.append(
            AccountCondition(
                key="overdue_invoices",
                severity="critical",
                priority=2,
                count=overdue,
                message=ngettext(
                    "You have %(count)d overdue invoice.",
                    "You have %(count)d overdue invoices.",
                    overdue,
                )
                % {"count": overdue},
                cta_text=_("View Invoices"),
                cta_url="/billing/invoices/?status=overdue",
            )
        )

    # Priority 3: Services expiring soon (warning)
    expiring = int(services_summary.get("expiring_soon", 0))
    if expiring > 0:
        conditions.append(
            AccountCondition(
                key="expiring_soon",
                severity="warning",
                priority=3,
                count=expiring,
                message=ngettext(
                    "%(count)d service is expiring soon.",
                    "%(count)d services are expiring soon.",
                    expiring,
                )
                % {"count": expiring},
                cta_text=_("View Renewals"),
                cta_url="/services/?status=expiring",
            )
        )

    # Priority 4: Tickets waiting on customer (info)
    waiting = int(tickets_summary.get("waiting_on_customer", 0))
    if waiting > 0:
        conditions.append(
            AccountCondition(
                key="waiting_on_customer",
                severity="info",
                priority=4,
                count=waiting,
                message=ngettext(
                    "%(count)d ticket is waiting for your reply.",
                    "%(count)d tickets are waiting for your reply.",
                    waiting,
                )
                % {"count": waiting},
                cta_text=_("Reply"),
                cta_url="/tickets/?status=waiting_on_customer",
            )
        )

    conditions.sort(key=lambda c: c.priority)
    return conditions


# Severity ranking for escalation
_SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1}

# Threshold for switching from "X and Y" to "X, Y, and N more" blending
_TWO_CONDITIONS = 2


def blend_banner(conditions: list[AccountCondition]) -> AccountHealthBanner | None:
    """Blend multiple conditions into a single banner.

    Rules:
    - 0 conditions → None (no banner)
    - 1 condition  → that condition's message
    - 2 conditions → "X and Y."
    - 3+ conditions → "X, Y, and N more issues."

    Severity = highest among active conditions.
    CTA = from highest-priority (first) condition.
    """
    if not conditions:
        return None

    # Highest severity among all conditions
    severity = max(conditions, key=lambda c: _SEVERITY_RANK.get(c.severity, 0)).severity

    # CTA from highest-priority condition (already sorted, first item)
    top = conditions[0]

    if len(conditions) == 1:
        message = top.message
    elif len(conditions) == _TWO_CONDITIONS:
        message = _("%(first)s %(second)s") % {
            "first": conditions[0].message,
            "second": conditions[1].message,
        }
    else:
        remaining = len(conditions) - _TWO_CONDITIONS
        extra = ngettext(
            "and %(count)d more issue.",
            "and %(count)d more issues.",
            remaining,
        ) % {"count": remaining}
        message = f"{conditions[0].message} {conditions[1].message} {extra}"

    return AccountHealthBanner(
        severity=severity,
        message=message,
        cta_text=top.cta_text,
        cta_url=top.cta_url,
        condition_count=len(conditions),
    )


def _fetch_summaries(customer_id: int, user_id: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Fetch all three summaries from Platform API. Returns safe defaults on error."""
    invoice_summary: dict[str, Any] = {}
    services_summary: dict[str, Any] = {}
    tickets_summary: dict[str, Any] = {}

    try:
        invoice_summary = InvoiceViewService().get_invoice_summary(customer_id, user_id)
    except (PlatformAPIError, Exception) as e:
        logger.warning("⚠️ [AccountHealth] Failed to fetch invoice summary: %s", e)

    try:
        services_summary = ServicesAPIClient().get_services_summary(customer_id, user_id)
    except (PlatformAPIError, Exception) as e:
        logger.warning("⚠️ [AccountHealth] Failed to fetch services summary: %s", e)

    try:
        tickets_summary = TicketsAPIClient().get_tickets_summary(customer_id, user_id)
    except (PlatformAPIError, Exception) as e:
        logger.warning("⚠️ [AccountHealth] Failed to fetch tickets summary: %s", e)

    return invoice_summary, services_summary, tickets_summary


def get_account_health(request: HttpRequest) -> AccountHealthBanner | None:
    """Orchestrator: check session cache, fetch if stale, build banner.

    Follows the TTL-in-session pattern from decorators.py:
    - Stores raw summaries + fetch timestamp in session
    - Refreshes when TTL expires
    - Pure functions run every request (sub-ms on small dicts)
    """
    customer_id = request.session.get("customer_id")
    user_id = request.session.get("user_id")
    if not customer_id or not user_id:
        return None

    # Check session cache
    cached = request.session.get("account_health_data")
    fetched_at = request.session.get("account_health_fetched_at", 0)
    cache_expired = (time.time() - fetched_at) > ACCOUNT_HEALTH_CACHE_TTL

    if cached and not cache_expired:
        invoice_summary = cached.get("invoice", {})
        services_summary = cached.get("services", {})
        tickets_summary = cached.get("tickets", {})
    else:
        invoice_summary, services_summary, tickets_summary = _fetch_summaries(int(customer_id), int(user_id))
        # Cache in session
        request.session["account_health_data"] = {
            "invoice": invoice_summary,
            "services": services_summary,
            "tickets": tickets_summary,
        }
        request.session["account_health_fetched_at"] = time.time()

    conditions = evaluate_conditions(invoice_summary, services_summary, tickets_summary)
    return blend_banner(conditions)
