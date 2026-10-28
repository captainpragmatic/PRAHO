"""Every Platform path the Portal client calls must exist on Platform and accept the method used.

A Portal client method whose route was renamed, never built, or restricted to another method
fails only at runtime, as a 404 or 405 the caller often flattens to "no data". Seven such
methods shipped (a WebAuthn setup Platform never had, ticket comments, GET detail calls on
POST-only views, ticket routes keyed by number where Platform takes an id). This test calls each
public client method with converter-valid sample arguments in a Portal process (Portal and
Platform both own a top-level `apps` package), records the request exactly as `requests` would
send it, and resolves it against Platform's URLconf: the path must reach the intended view under
/api/, and that view must accept the method.

A new client method fails the completeness test until it has an entry in METHOD_ROUTES.
"""

import inspect
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

from django.http import HttpResponseNotAllowed
from django.test import RequestFactory, SimpleTestCase
from django.urls import Resolver404, resolve

REPO_ROOT = Path(__file__).resolve().parents[2]
EXPORT_ID = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7"
ORDER_ID = "0b6e7c1d-2f3a-4b5c-9d8e-7f6a5b4c3d2e"
SUBMISSION_ID = "3d2c1b0a-9f8e-4d7c-8b6a-5f4e3d2c1b0a"

# Generic wrappers that take the path as an argument: what they reach depends on the caller, so
# they are covered by the real call sites in CALL_SITE_ROUTES instead of a METHOD_ROUTES entry.
PASS_THROUGH_WRAPPERS = frozenset(
    f"PlatformAPIClient.{name}" for name in ("get", "post", "put", "delete", "post_billing", "get_billing")
)

# "<defining class>.<method>" -> the namespaced Platform view it must reach. Keyed by the class
# that defines the method, so an override (TicketsAPIClient.create_ticket,
# ServicesAPIClient.get_customer_services) is checked separately from the base it replaces, and
# an inherited method is checked once, on the class whose code it is.
METHOD_ROUTES = {
    "PlatformAPIClient.get_localisation_defaults": "api:localisation",
    "PlatformAPIClient.authenticate_customer": "api:portal_login",
    "PlatformAPIClient.request_password_reset": "api:password_reset_request",
    "PlatformAPIClient.confirm_password_reset": "api:password_reset_confirm",
    "PlatformAPIClient.register_customer": "api:customers:customer-register",
    "PlatformAPIClient.get_pending_registration": "api:registration_pending",
    "PlatformAPIClient.confirm_registration": "api:registration_confirm",
    "PlatformAPIClient.read_registration_prefill": "api:registration_prefill",
    "PlatformAPIClient.company_lookup": "api:customers:company-lookup",
    "PlatformAPIClient.get_legal_document": "api:legal_document",
    "PlatformAPIClient.validate_session_secure": "api:validate_session_secure",
    "PlatformAPIClient.end_session": "api:portal_session_end",
    "PlatformAPIClient.redeem_customer_view": "api:customer_view_redeem",
    "PlatformAPIClient.get_user_customers": "api:user_customers",
    "PlatformAPIClient.get_customer_details": "api:customers:customer-detail",
    "PlatformAPIClient.search_customers": "api:customers:customer-search-list",
    "PlatformAPIClient.get_customer_profile": "api:customer_profile",
    "PlatformAPIClient.update_customer_profile": "api:customer_profile",
    "PlatformAPIClient.update_customer_password": "api:password_change",
    "PlatformAPIClient.get_mfa_status": "api:mfa_status",
    "PlatformAPIClient.setup_totp_mfa": "api:mfa_setup",
    "PlatformAPIClient.verify_totp_mfa": "api:mfa_verify",
    "PlatformAPIClient.regenerate_backup_codes": "api:mfa_regenerate_backup_codes",
    "PlatformAPIClient.disable_mfa": "api:mfa_disable",
    "PlatformAPIClient.get_customer_invoices_secure": "api:api_billing:customer_invoices",
    "PlatformAPIClient.get_customer_proformas_secure": "api:api_billing:customer_proformas",
    "PlatformAPIClient.get_billing_summary_secure": "api:api_billing:customer_invoice_summary",
    "PlatformAPIClient.get_invoice_detail_secure": "api:api_billing:customer_invoice_detail",
    "PlatformAPIClient.get_proforma_detail_secure": "api:api_billing:customer_proforma_detail",
    "PlatformAPIClient.get_customer_tickets_secure": "api:tickets:customer_tickets_list",
    "PlatformAPIClient.create_ticket_secure": "api:tickets:customer_ticket_create",
    "PlatformAPIClient.get_customer_services_secure": "api:services:customer_services_list",
    "PlatformAPIClient.get_service_detail_secure": "api:services:customer_service_detail",
    "PlatformAPIClient.get_services_summary_secure": "api:services:customer_services_summary",
    "PlatformAPIClient.download_ticket_attachment": "api:tickets:ticket_attachment_download",
    "PlatformAPIClient.submit_cookie_consent": "api:gdpr_cookie_consent",
    "PlatformAPIClient.get_consent_history_secure": "api:gdpr_consent_history",
    "PlatformAPIClient.request_data_export_secure": "api:gdpr_data_export",
    "PlatformAPIClient.download_data_export": "api:gdpr_data_export_download",
    "PlatformAPIClient.get_data_export_status": "api:gdpr_data_export",
    "PlatformAPIClient.get_customer_users": "api:customers:customer-users-list",
    "PlatformAPIClient.add_customer_user": "api:customers:customer-users-add",
    "PlatformAPIClient.create_customer_user": "api:customers:customer-users-create",
    "PlatformAPIClient.change_customer_user_role": "api:customers:customer-users-role",
    "PlatformAPIClient.remove_customer_user": "api:customers:customer-users-remove",
    "PlatformAPIClient.toggle_customer_user_status": "api:customers:customer-users-toggle",
    "PlatformAPIClient.update_customer_company_profile": "api:customers:customer-update",
    "PlatformAPIClient.get_customer_tax_profile": "api:customers:customer-detail",
    "PlatformAPIClient.update_customer_tax_profile": "api:customers:customer-tax-profile",
    "PlatformAPIClient.get_customer_addresses": "api:customers:customer-addresses-list",
    "PlatformAPIClient.add_customer_address": "api:customers:customer-addresses-add",
    "PlatformAPIClient.update_customer_address": "api:customers:customer-addresses-update",
    "PlatformAPIClient.delete_customer_address": "api:customers:customer-addresses-delete",
    "PlatformAPIClient.set_address_primary": "api:customers:customer-addresses-set-primary",
    "PlatformAPIClient.set_address_billing": "api:customers:customer-addresses-set-billing",
    "TicketsAPIClient.get_customer_tickets": "api:tickets:customer_tickets_list",
    "TicketsAPIClient.get_ticket_detail": "api:tickets:customer_ticket_detail",
    "TicketsAPIClient.create_ticket": "api:tickets:customer_ticket_create",
    "TicketsAPIClient.add_ticket_reply": "api:tickets:customer_ticket_reply",
    "TicketsAPIClient.get_tickets_summary": "api:tickets:customer_tickets_summary",
    "ServicesAPIClient.get_customer_services": "api:services:customer_services_list",
    "ServicesAPIClient.get_service_detail": "api:services:customer_service_detail",
    "ServicesAPIClient.get_service_usage": "api:services:service_usage_stats",
    "ServicesAPIClient.get_services_summary": "api:services:customer_services_summary",
    "ServicesAPIClient.get_service_domains": "api:services:customer_service_domains",
    "ServicesAPIClient.request_service_action": "api:services:request_service_action",
    "ServicesAPIClient.get_available_plans": "api:services:available_service_plans",
}

GIFT_CARD_ACTIONS = ("catalog", "purchases", "create", "detail", "funding", "refresh", "reveal", "resend")

# The distinct paths real Portal code passes to the pass-through wrappers (and to the binary
# request helpers, which billing calls directly), as written at the call site. No Portal code
# calls `put` or `delete` with a path, so neither has an entry.
CALL_SITE_ROUTES = {
    # apps/users/views.py, apps/customers/views.py, apps/common/decorators.py
    "post customers/create/": "api:customers:customer-create",
    "post customers/details/": "api:customers:customer-detail",
    "post users/customers/": "api:user_customers",
    "post users/verify-customer-access/": "api:verify_customer_access",
    # apps/orders/services.py, apps/orders/views.py
    "post orders/calculate/": "api:orders:calculate_cart",
    "post orders/preflight/": "api:orders:preflight_order",
    "post orders/create/": "api:orders:create_order",
    "post orders/<order_id>/": "api:orders:order_detail",
    "post orders/<order_id>/confirm/": "api:orders:confirm_order",
    "post orders/domains/availability/": "api:orders:domain_availability",
    "post orders/<order_id>/items/<item_id>/transfer-code/": "api:orders:transfer_code",
    "post customers/tax-profile/": "api:customers:customer-tax-profile",
    "get /api/orders/products/": "api:orders:product_list",
    "get /api/orders/products/<slug>/": "api:orders:product_detail",
    "post_billing create-payment-intent/": "api:api_billing:api_create_payment_intent",
    "post_billing confirm-payment/": "api:api_billing:api_confirm_payment",
    "get_billing stripe-config/": "api:api_billing:api_stripe_config",
    # apps/billing/services.py, apps/billing/views.py
    **{f"post /billing/gift-cards/{action}/": f"api:api_billing:gift_card_{action}" for action in GIFT_CARD_ACTIONS},
    "post /billing/gift-card-payment/": "api:api_billing:gift_card_payment",
    "post /billing/documents/": "api:api_billing:customer_billing_documents",
    "post /billing/invoices/": "api:api_billing:customer_invoices",
    "post /billing/invoices/<number>/": "api:api_billing:customer_invoice_detail",
    "post /billing/proformas/": "api:api_billing:customer_proformas",
    "post /billing/proformas/<number>/": "api:api_billing:customer_proforma_detail",
    "post /billing/summary/": "api:api_billing:customer_invoice_summary",
    "get /billing/currencies/": "api:api_billing:currencies",
    "get /api/billing/currencies/": "api:api_billing:currencies",
    "post /billing/recurring-payments/": "api:api_billing:recurring_payments_overview",
    "post /billing/recurring-payments/authorize/begin/": "api:api_billing:begin_recurring_authorization",
    "post /billing/recurring-payments/authorize/complete/": "api:api_billing:complete_recurring_authorization",
    "post /billing/recurring-payments/authorize/withdraw/": "api:api_billing:withdraw_recurring_authorization",
    "post /billing/recurring-payments/subscriptions/auto-payment/": "api:api_billing:subscription_auto_payment",
    "binary /billing/invoices/<number>/pdf/": "api:api_billing:invoice_pdf_export",
    "binary /billing/proformas/<number>/pdf/": "api:api_billing:proforma_pdf_export",
}

# Runs with services/portal as the working directory, so `apps` is the Portal's package.
PORTAL_RECORDER = """
import inspect
import json
import sys
from unittest.mock import patch

import django
import requests
from django.conf import settings

settings.configure(
    INSTALLED_APPS=["apps.common"],  # login imports the rate-limit counter model
    SECRET_KEY="route-check-test-only",
    DEBUG=True,
    PLATFORM_API_BASE_URL="http://platform.example.test/api",  # read by the module-level clients
    PLATFORM_API_SECRET="route-check-secret",
    PORTAL_ID="portal-route-check",
    PLATFORM_API_TIMEOUT=5,
    PLATFORM_API_READ_MAX_RETRIES=0,
)
django.setup()

from apps.api_client.services import PlatformAPIClient
from apps.services.services import ServicesAPIClient
from apps.tickets.services import TicketCreateRequest, TicketsAPIClient

CLASSES = (PlatformAPIClient, TicketsAPIClient, ServicesAPIClient)
records = []
current = {}


def transport(*, method, url, headers, data=None, params=None, **kwargs):
    prepared = requests.Request(method, url, headers=headers, data=data, params=params).prepare()
    records.append({**current, "method": prepared.method, "path_url": prepared.path_url})
    response = requests.Response()
    response.status_code = 200
    response._content = json.dumps({"success": True, "data": {}}).encode()
    response.headers["Content-Type"] = "application/json"
    return response


base, tickets, services = PlatformAPIClient(), TicketsAPIClient(), ServicesAPIClient()
methods = {
    "PlatformAPIClient.get_localisation_defaults": lambda: base.get_localisation_defaults(),
    "PlatformAPIClient.authenticate_customer": lambda: base.authenticate_customer("c@example.test", "pw"),
    "PlatformAPIClient.request_password_reset": lambda: base.request_password_reset("c@example.test"),
    "PlatformAPIClient.confirm_password_reset": lambda: base.confirm_password_reset("uid", "token", "pw", "pw"),
    "PlatformAPIClient.register_customer": lambda: base.register_customer({"email": "c@example.test"}),
    "PlatformAPIClient.get_pending_registration": lambda: base.get_pending_registration("reg-1", "token"),
    "PlatformAPIClient.confirm_registration": lambda: base.confirm_registration(
        "reg-1", "token", "pw", "pw", marketing_consent=False, terms_accepted=True, terms_document_id=EXPORT_ID,
    ),
    "PlatformAPIClient.read_registration_prefill": lambda: base.read_registration_prefill("token"),
    "PlatformAPIClient.company_lookup": lambda: base.company_lookup("12345678"),
    "PlatformAPIClient.get_legal_document": lambda: base.get_legal_document({"kind": "terms", "language": "en"}),
    "PlatformAPIClient.validate_session_secure": lambda: base.validate_session_secure("1", "hash"),
    "PlatformAPIClient.end_session": lambda: base.end_session(1, "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"),
    "PlatformAPIClient.redeem_customer_view": lambda: base.redeem_customer_view("A" * 43, "203.0.113.9"),
    "PlatformAPIClient.get_user_customers": lambda: base.get_user_customers(1),
    "PlatformAPIClient.get_customer_details": lambda: base.get_customer_details(1, 1),
    "PlatformAPIClient.search_customers": lambda: base.search_customers("acme", 1),
    "PlatformAPIClient.get_customer_profile": lambda: base.get_customer_profile(1),
    "PlatformAPIClient.update_customer_profile": lambda: base.update_customer_profile(1, {"first_name": "Ana"}),
    "PlatformAPIClient.update_customer_password": lambda: base.update_customer_password(1, "new-pw", "old-pw"),
    "PlatformAPIClient.get_mfa_status": lambda: base.get_mfa_status(1),
    "PlatformAPIClient.setup_totp_mfa": lambda: base.setup_totp_mfa("1", user_id=1),
    "PlatformAPIClient.verify_totp_mfa": lambda: base.verify_totp_mfa("1", "123456", "pw", user_id=1),
    "PlatformAPIClient.regenerate_backup_codes": lambda: base.regenerate_backup_codes(1, "pw", "123456"),
    "PlatformAPIClient.disable_mfa": lambda: base.disable_mfa(1, "pw", "123456"),
    "PlatformAPIClient.get_customer_invoices_secure": lambda: base.get_customer_invoices_secure(1),
    "PlatformAPIClient.get_customer_proformas_secure": lambda: base.get_customer_proformas_secure(1),
    "PlatformAPIClient.get_billing_summary_secure": lambda: base.get_billing_summary_secure(1),
    "PlatformAPIClient.get_invoice_detail_secure": lambda: base.get_invoice_detail_secure(1, "INV-0001"),
    "PlatformAPIClient.get_proforma_detail_secure": lambda: base.get_proforma_detail_secure(1, "PRO-0001"),
    "PlatformAPIClient.get_customer_tickets_secure": lambda: base.get_customer_tickets_secure(1),
    "PlatformAPIClient.create_ticket_secure": lambda: base.create_ticket_secure(1, {"title": "t"}),
    "PlatformAPIClient.get_customer_services_secure": lambda: base.get_customer_services_secure(1),
    "PlatformAPIClient.get_service_detail_secure": lambda: base.get_service_detail_secure(1, 5),
    "PlatformAPIClient.get_services_summary_secure": lambda: base.get_services_summary_secure(1),
    "PlatformAPIClient.download_ticket_attachment": lambda: base.download_ticket_attachment(1, 1, 7, 3),
    "PlatformAPIClient.submit_cookie_consent": lambda: base.submit_cookie_consent({"user_id": 1, "status": "accepted"}),
    "PlatformAPIClient.get_consent_history_secure": lambda: base.get_consent_history_secure(1),
    "PlatformAPIClient.request_data_export_secure": lambda: base.request_data_export_secure(1),
    "PlatformAPIClient.download_data_export": lambda: base.download_data_export(1, EXPORT_ID),
    "PlatformAPIClient.get_data_export_status": lambda: base.get_data_export_status(1),
    "PlatformAPIClient.get_customer_users": lambda: base.get_customer_users(1, 1),
    "PlatformAPIClient.add_customer_user": lambda: base.add_customer_user(1, 1, 2, "tech"),
    "PlatformAPIClient.create_customer_user": lambda: base.create_customer_user(
        1, 1, "u@example.test", "Ana", "Pop", "tech"
    ),
    "PlatformAPIClient.change_customer_user_role": lambda: base.change_customer_user_role(1, 1, 2, "billing"),
    "PlatformAPIClient.remove_customer_user": lambda: base.remove_customer_user(1, 1, 2),
    "PlatformAPIClient.toggle_customer_user_status": lambda: base.toggle_customer_user_status(1, 1, 2),
    "PlatformAPIClient.update_customer_company_profile": lambda: base.update_customer_company_profile(1, 1, {}),
    "PlatformAPIClient.get_customer_tax_profile": lambda: base.get_customer_tax_profile(1, 1),
    "PlatformAPIClient.update_customer_tax_profile": lambda: base.update_customer_tax_profile(1, 1, {}),
    "PlatformAPIClient.get_customer_addresses": lambda: base.get_customer_addresses(1, 1),
    "PlatformAPIClient.add_customer_address": lambda: base.add_customer_address(1, 1, {}),
    "PlatformAPIClient.update_customer_address": lambda: base.update_customer_address(1, 1, 4, {}),
    "PlatformAPIClient.delete_customer_address": lambda: base.delete_customer_address(1, 1, 4),
    "PlatformAPIClient.set_address_primary": lambda: base.set_address_primary(1, 1, 4),
    "PlatformAPIClient.set_address_billing": lambda: base.set_address_billing(1, 1, 4),
    "TicketsAPIClient.get_customer_tickets": lambda: tickets.get_customer_tickets(1, 1),
    "TicketsAPIClient.get_ticket_detail": lambda: tickets.get_ticket_detail(1, 1, 7),
    "TicketsAPIClient.create_ticket": lambda: tickets.create_ticket(1, 1, TicketCreateRequest(title="t", description="d")),
    "TicketsAPIClient.add_ticket_reply": lambda: tickets.add_ticket_reply(1, 1, 7, "reply"),
    "TicketsAPIClient.get_tickets_summary": lambda: tickets.get_tickets_summary(1, 1),
    "ServicesAPIClient.get_customer_services": lambda: services.get_customer_services(1, 1),
    "ServicesAPIClient.get_service_detail": lambda: services.get_service_detail(1, 1, 5),
    "ServicesAPIClient.get_service_usage": lambda: services.get_service_usage(1, 1, 5),
    "ServicesAPIClient.get_services_summary": lambda: services.get_services_summary(1, 1),
    "ServicesAPIClient.get_service_domains": lambda: services.get_service_domains(1, 1, 5),
    "ServicesAPIClient.request_service_action": lambda: services.request_service_action(
        1, 1, 5, "upgrade_request", submission_id=SUBMISSION_ID
    ),
    "ServicesAPIClient.get_available_plans": lambda: services.get_available_plans(1, "shared"),
}
call_sites = {
    "post customers/create/": lambda: base.post("customers/create/", data={}, user_id=1),
    "post customers/details/": lambda: base.post("customers/details/", data={"customer_id": 1}),
    "post users/customers/": lambda: base.post("users/customers/", data={"customer_id": 1}, user_id=1),
    "post users/verify-customer-access/": lambda: base.post(
        "users/verify-customer-access/", {"user_id": 1, "customer_id": 1}, user_id=1
    ),
    "post orders/calculate/": lambda: base.post("orders/calculate/", {}, user_id=1),
    "post orders/preflight/": lambda: base.post("orders/preflight/", {}, user_id=1),
    "post orders/create/": lambda: base.post("orders/create/", {}, user_id=1),
    "post orders/<order_id>/": lambda: base.post(f"orders/{ORDER_ID}/", data={"customer_id": 1}),
    "post orders/<order_id>/confirm/": lambda: base.post(f"orders/{ORDER_ID}/confirm/", {}),
    "post orders/domains/availability/": lambda: base.post("orders/domains/availability/", {}, user_id=1),
    "post orders/<order_id>/items/<item_id>/transfer-code/": lambda: base.post(
        f"orders/{ORDER_ID}/items/{SUBMISSION_ID}/transfer-code/", {}, user_id=1
    ),
    "post customers/tax-profile/": lambda: base.post("customers/tax-profile/", {}, user_id=1),
    "get /api/orders/products/": lambda: base.get("/api/orders/products/", params={"page": 1}),
    "get /api/orders/products/<slug>/": lambda: base.get("/api/orders/products/shared-hosting-basic/"),
    "post_billing create-payment-intent/": lambda: base.post_billing("create-payment-intent/", data={}, user_id=1),
    "post_billing confirm-payment/": lambda: base.post_billing("confirm-payment/", {}, user_id=1),
    "get_billing stripe-config/": lambda: base.get_billing("stripe-config/", user_id=1),
    **{
        f"post /billing/gift-cards/{action}/": lambda action=action: base.post(f"/billing/gift-cards/{action}/", data={})
        for action in GIFT_CARD_ACTIONS
    },
    "post /billing/gift-card-payment/": lambda: base.post("/billing/gift-card-payment/", data={}),
    "post /billing/documents/": lambda: base.post("/billing/documents/", data={}),
    "post /billing/invoices/": lambda: base.post("/billing/invoices/", data={}),
    "post /billing/invoices/<number>/": lambda: base.post("/billing/invoices/INV-0001/", data={}),
    "post /billing/proformas/": lambda: base.post("/billing/proformas/", data={}),
    "post /billing/proformas/<number>/": lambda: base.post("/billing/proformas/PRO-0001/", data={}),
    "post /billing/summary/": lambda: base.post("/billing/summary/", data={}),
    "get /billing/currencies/": lambda: base.get("/billing/currencies/"),
    "get /api/billing/currencies/": lambda: base.get("/api/billing/currencies/"),
    "post /billing/recurring-payments/": lambda: base.post("/billing/recurring-payments/", data={}, user_id=1),
    "post /billing/recurring-payments/authorize/begin/": lambda: base.post(
        "/billing/recurring-payments/authorize/begin/", data={}, user_id=1
    ),
    "post /billing/recurring-payments/authorize/complete/": lambda: base.post(
        "/billing/recurring-payments/authorize/complete/", data={}, user_id=1
    ),
    "post /billing/recurring-payments/authorize/withdraw/": lambda: base.post(
        "/billing/recurring-payments/authorize/withdraw/", data={}, user_id=1
    ),
    "post /billing/recurring-payments/subscriptions/auto-payment/": lambda: base.post(
        "/billing/recurring-payments/subscriptions/auto-payment/", data={}, user_id=1
    ),
    "binary /billing/invoices/<number>/pdf/": lambda: base._make_binary_request(
        "POST", "/billing/invoices/INV-0001/pdf/", data={"customer_id": 1}
    ),
    "binary /billing/proformas/<number>/pdf/": lambda: base._make_binary_request(
        "POST", "/billing/proformas/PRO-0001/pdf/", data={"customer_id": 1}
    ),
}

# Public methods each class defines itself; an inherited one belongs to the class that wrote it.
discovered = sorted(
    f"{cls.__name__}.{name}"
    for cls in CLASSES
    for name, value in vars(cls).items()
    if not name.startswith("_") and inspect.isfunction(value)
)

with patch("apps.api_client.services.portal_request", side_effect=transport):
    for entry, invoke in {**methods, **call_sites}.items():
        current.clear()
        current["entry"] = entry
        try:
            invoke()
        except Exception as error:  # The reply is canned; only the request matters here.
            print(f"{entry}: {error!r}", file=sys.stderr)

print(json.dumps({"discovered": discovered, "records": records}), flush=True)
"""


def _record_portal_requests() -> tuple[list[str], list[dict[str, Any]], str]:
    environment = dict(os.environ)
    environment.pop("DJANGO_SETTINGS_MODULE", None)
    environment["PYTHONPATH"] = ""
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    constants = (
        f"EXPORT_ID = {EXPORT_ID!r}\nORDER_ID = {ORDER_ID!r}\nSUBMISSION_ID = {SUBMISSION_ID!r}\n"
        f"GIFT_CARD_ACTIONS = {GIFT_CARD_ACTIONS!r}\n"
    )
    completed = subprocess.run(  # noqa: S603 -- fixed interpreter and a test-owned script
        [sys.executable, "-c", constants + PORTAL_RECORDER],
        cwd=REPO_ROOT / "services/portal",
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise AssertionError(f"Portal recorder failed ({completed.returncode}):\n{completed.stderr}")
    output: dict[str, Any] = json.loads(completed.stdout.strip().splitlines()[-1])
    return output["discovered"], output["records"], completed.stderr


def _allowed_methods(view: Callable[..., Any]) -> set[str] | None:
    """The HTTP methods a resolved Platform view dispatches, or None when that cannot be read.

    Three kinds of view sit under /api/, and each records its methods differently:
    - a DRF ViewSet routed by a router: the resolved function carries `actions`, the
      method -> handler map the router bound; any other method is a 405.
    - `@api_view([...])` or `APIView.as_view()`: the function carries `cls`, and DRF dispatches
      only the names in `http_method_names` the class has a handler for (Django's
      `View._allowed_methods`). `@api_view` defines exactly one handler per listed method.
    - a plain Django view behind `require_http_methods` (also `require_POST`/`require_GET`): the
      list lives only in that decorator's closure as `request_method_list`. Decorators above it
      do not always use `functools.wraps` (`require_portal_authentication` does not), so the
      chain is followed through closure cells as well as `__wrapped__`.
    Nothing found means unknown, never "accepts everything"; the caller treats it as a failure.
    `test_plain_view_method_lists_are_enforced` checks the closure reading against real 405s.
    """
    seen: set[int] = set()
    pending: list[Any] = [view]
    while pending:
        layer = pending.pop()
        if id(layer) in seen:
            continue
        seen.add(id(layer))
        actions = getattr(layer, "actions", None)
        if isinstance(actions, dict):
            return {method.upper() for method in actions}
        view_class = getattr(layer, "cls", None)
        if view_class is not None:
            return {method.upper() for method in view_class.http_method_names if hasattr(view_class, method)}
        if not inspect.isfunction(layer):
            continue
        cells = inspect.getclosurevars(layer).nonlocals
        if "request_method_list" in cells:
            return {str(method).upper() for method in cells["request_method_list"]}
        pending.extend(value for value in cells.values() if inspect.isfunction(value))
        if (wrapped := getattr(layer, "__wrapped__", None)) is not None:
            pending.append(wrapped)
    return None


class PortalClientRoutesExistTests(SimpleTestCase):
    discovered: ClassVar[list[str]]
    records: ClassVar[list[dict[str, Any]]]
    recorder_stderr: ClassVar[str]

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.discovered, cls.records, cls.recorder_stderr = _record_portal_requests()

    def test_every_public_client_method_has_a_route_contract(self) -> None:
        contracted = set(self.discovered) - PASS_THROUGH_WRAPPERS
        self.assertEqual(
            contracted,
            set(METHOD_ROUTES),
            "Each public Portal client method needs a METHOD_ROUTES entry (and the recorder a call); "
            f"missing: {sorted(contracted - set(METHOD_ROUTES))}, stale: {sorted(set(METHOD_ROUTES) - contracted)}",
        )

    def test_pass_through_allowlist_names_real_methods(self) -> None:
        self.assertLessEqual(PASS_THROUGH_WRAPPERS, set(self.discovered))

    def test_each_entry_made_exactly_one_request(self) -> None:
        made = sorted(record["entry"] for record in self.records)
        expected = sorted({**METHOD_ROUTES, **CALL_SITE_ROUTES})
        self.assertEqual(made, expected, f"Recorder stderr:\n{self.recorder_stderr}")

    def test_every_recorded_request_reaches_its_platform_view(self) -> None:
        expected_views = {**METHOD_ROUTES, **CALL_SITE_ROUTES}
        violations = []
        for record in self.records:
            method, path_url, entry = record["method"], record["path_url"], record["entry"]
            # Built as a request so the query is dropped and escapes are decoded as Django does.
            path = RequestFactory().generic(method, path_url).path_info
            try:
                match = resolve(path)
            except Resolver404:
                violations.append(f"{entry}: {method} {path_url} -> no Platform route (404)")
                continue
            if match.namespaces[:1] != ["api"]:
                violations.append(f"{entry}: {method} {path_url} -> {match.view_name}, outside /api/")
                continue
            if match.view_name != expected_views[entry]:
                violations.append(
                    f"{entry}: {method} {path_url} -> {match.view_name}, expected {expected_views[entry]}"
                )
                continue
            allowed = _allowed_methods(match.func)
            if allowed is None:
                violations.append(
                    f"{entry}: {method} {path_url} -> cannot determine the methods {match.view_name} accepts"
                )
            elif method not in allowed:
                violations.append(
                    f"{entry}: {method} {path_url} -> {match.view_name} accepts only {sorted(allowed)} (405)"
                )
        self.assertEqual(violations, [], "\n" + "\n".join(violations))

    def test_plain_view_method_lists_are_enforced(self) -> None:
        # Pins the closure reading in `_allowed_methods` to behaviour: for each plain Django view
        # reached, a method outside the list read from the closure must get a 405 from the view.
        # The HMAC middleware's flag is set so the authentication decorator lets the request in.
        plain_views = 0
        for record in self.records:
            path = RequestFactory().generic(record["method"], record["path_url"]).path_info
            try:
                match = resolve(path)
            except Resolver404:
                continue
            if hasattr(match.func, "cls") or hasattr(match.func, "actions"):
                continue
            allowed = _allowed_methods(match.func)
            if allowed is None:
                continue  # reported by the routing test
            plain_views += 1
            rejected = next(method for method in ("PATCH", "DELETE", "PUT") if method not in allowed)
            request = RequestFactory().generic(rejected, path)
            request._portal_authenticated = True  # type: ignore[attr-defined]  # set by the HMAC middleware
            with self.subTest(view=match.view_name, method=rejected):
                response = match.func(request, *match.args, **match.kwargs)
                self.assertIsInstance(response, HttpResponseNotAllowed)
                self.assertEqual(response.status_code, 405)
        self.assertGreater(plain_views, 0, "No plain Django view was reached, so the closure reading is untested")
