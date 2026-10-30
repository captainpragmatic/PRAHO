"""Every portal-facing route says whether it needs a recent identity check, and why not if it does not.

A new route under ``api/`` fails here until someone decides: guarded (and covered by a behavioural
test) or exempt with a reason. A listed route that no longer exists fails too, so the
table cannot drift from the code. PRAHO signs reads as POSTs, so the method says nothing; the table
does.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterator

from django.test import SimpleTestCase
from django.urls import URLPattern, URLResolver, get_resolver

PREFIXES = ("api/",)
SAFE_METHODS = {"get", "head", "options"}

GUARDED: dict[str, str] = {
    "api/customers/users/add/": "adds an existing account to the company",
    "api/customers/users/create/": "creates an account in the company",
    "api/customers/users/role/": "changes a member's role",
    "api/customers/users/remove/": "removes a member",
    "api/customers/users/toggle-status/": "suspends or restores a member",
    "api/customers/update/": "changes the company's contact details",
    "api/customers/addresses/add/": "adds an address",
    "api/customers/addresses/update/": "changes an address",
    "api/customers/addresses/delete/": "removes an address",
    "api/customers/addresses/set-primary/": "changes the primary address",
    "api/customers/addresses/set-billing/": "changes the billing address",
    "api/customers/billing-address/": "changes contact, billing and tax details at once",
    "api/customers/tax-profile/": "changes an existing legal identity (a first fill is free)",
    "api/users/profile/": "a PUT that changes the person's name or phone (preferences are free)",
    "api/gdpr/data-export/": "asks for an export of everything held (status is free)",
    "api/gdpr/data-export/<uuid:export_id>/download/": "hands over that export",
    "api/billing/gift-cards/reveal/": "shows a paid gift-card code",
    "api/billing/recurring-payments/authorize/begin/": "lets a saved card be charged without the cardholder present",
    "api/dns/zones/<uuid:zone_id>/confirm/": "publishes an imported zone",
    "api/dns/zones/<uuid:zone_id>/switch/": "moves the domain to other name servers",
    "api/dns/zones/<uuid:zone_id>/delete/": "deletes the zone at the provider",
    "api/dns/zones/<uuid:zone_id>/records/": "adds a record, which can send the domain's mail or web traffic elsewhere",
    "api/dns/zones/<uuid:zone_id>/records/<uuid:record_id>/": "changes or deletes a record",
    "api/services/<int:service_id>/actions/": "asks staff to upgrade, downgrade, suspend or cancel the service",
}

EXEMPT: dict[str, str] = {
    "api/users/login/": "signed out: it opens the session, and counts as the check",
    "api/users/session/validate/": "session machinery, writes nothing",
    "api/users/session/end/": "logout only ends the session",
    "api/users/session/reauth/": "it is the identity check",
    "api/users/customer-view/redeem/": "exchanges a single-use staff code for a read-only view, changes nothing",
    "api/users/token/": "staff API tokens, not portal sessions",
    "api/users/token/me/": "a read, staff API tokens",
    "api/users/token/revoke/": "staff API tokens, and revoking only removes access",
    "api/users/user/": "a read",
    "api/users/health/": "a read",
    "api/users/mfa/setup/": "a read: shows a secret to confirm, which mfa/verify then checks",
    "api/users/mfa/verify/": "carries its own password and code, counted toward the lockout",
    "api/users/mfa/disable/": "carries its own password and code, counted toward the lockout",
    "api/users/mfa/regenerate-backup-codes/": "carries its own password and code, counted toward the lockout",
    "api/users/mfa/status/": "a read",
    "api/users/change-password/": "carries the current password, counted toward the lockout",
    "api/users/password/reset/": "signed out",
    "api/users/password/reset/confirm/": "signed out, proven by the emailed token",
    "api/users/register/pending/": "signed out",
    "api/users/register/prefill/": "signed out",
    "api/users/register/confirm/": "signed out, proven by the emailed token",
    "api/users/customers/": "a read",
    "api/users/verify-customer-access/": "a read",
    "api/customers/register/": "signed out: a new account",
    "api/customers/company-lookup/": "a read of the public company register",
    "api/customers/create/": "a new company, not a change to an existing one",
    "api/customers/profile/": "DRF session or token authentication only: no portal path reaches it",
    "api/customers/details/": "a read",
    "api/customers/users/": "a read",
    "api/customers/addresses/": "a read",
    "api/customers/": "the read-only customer viewset's root",
    "api/customers/<drf_format_suffix:format>": "the same root, with a format suffix",
    "api/billing/gift-cards/catalog/": "a read",
    "api/billing/gift-cards/purchases/": "a read",
    "api/billing/gift-cards/detail/": "a read, without the code",
    "api/billing/gift-cards/create/": "a purchase: the code is only shown after payment, by reveal",
    "api/billing/gift-cards/funding/": "starts a payment, charged to the buyer",
    "api/billing/gift-cards/refresh/": "re-reads a payment's status",
    "api/billing/gift-cards/resend/": "goes only to the recipient fixed at purchase",
    "api/gdpr/cookie-consent/": "a consent choice, which the person can change at any time",
    "api/gdpr/consent-history/": "a read",
    "api/billing/currencies/": "a read",
    "api/billing/documents/": "a read",
    "api/billing/invoices/": "a read",
    "api/billing/invoices/<str:invoice_number>/": "a read",
    "api/billing/invoices/<str:invoice_number>/pdf/": "a read",
    "api/billing/proformas/": "a read",
    "api/billing/proformas/<str:proforma_number>/": "a read",
    "api/billing/proformas/<str:proforma_number>/pdf/": "a read",
    "api/billing/summary/": "a read",
    "api/billing/stripe-config/": "a read of the public key",
    "api/billing/create-payment-intent/": "starts a card payment the cardholder completes in Stripe's form",
    "api/billing/confirm-payment/": "records a payment the cardholder made in Stripe's form",
    "api/billing/gift-card-payment/": "spends a gift card whose code the caller types in, on the company's own bill",
    "api/billing/recurring-payments/": "a read",
    "api/billing/recurring-payments/authorize/complete/": (
        "finishes the authorization begin checked; the bank's card check can outlast 300 seconds"
    ),
    "api/billing/recurring-payments/authorize/withdraw/": "stops future automatic charges, and charges nothing",
    "api/billing/recurring-payments/subscriptions/auto-payment/": (
        "picks which subscriptions a card already authorized through begin pays"
    ),
    "api/dns/zones/": "a read",
    "api/dns/zones/import/": "stages a preview; nothing is published until confirm",
    "api/dns/zones/<uuid:zone_id>/": "a read",
    "api/dns/zones/<uuid:zone_id>/crosscheck/": "compares the provider's records with the stored ones, changes none",
    "api/dns/zones/<uuid:zone_id>/export/": "a read of the records the zone publishes",
    "api/dns/zones/<uuid:zone_id>/records/<uuid:record_id>/detail/": "a read",
    "api/legal/document/": "a read",
    "api/localisation/": "a read of the default language and time zone",
    "api/orders/": "a read",
    "api/orders/<uuid:order_id>/": "a read",
    "api/orders/calculate/": "a read: prices a cart",
    "api/orders/preflight/": "a read: checks a cart",
    "api/orders/domains/availability/": "a read",
    "api/orders/products/": "a read of the public catalogue",
    "api/orders/products/<slug:slug>/": "a read of the public catalogue",
    "api/orders/create/": "places an order, paid separately with the cardholder present",
    "api/orders/<uuid:order_id>/confirm/": "confirms an order once its payment succeeded",
    "api/orders/<uuid:order_id>/items/<uuid:item_id>/transfer-code/": (
        "takes the code of a domain being moved in, and never shows one"
    ),
    "api/services/": "a read",
    "api/services/summary/": "a read",
    "api/services/plans/": "a read",
    "api/services/<int:service_id>/": "a read",
    "api/services/<int:service_id>/domains/": "a read",
    "api/services/<int:service_id>/usage/": "a read",
    "api/services/<int:service_id>/dns-status/": "a read",
    "api/services/<int:service_id>/dns-status/recheck/": "runs the DNS check again, changes nothing",
    "api/services/<int:service_id>/auto-renew/": "no portal page calls it",
    "api/tickets/": "a read",
    "api/tickets/summary/": "a read",
    "api/tickets/categories/": "a read",
    "api/tickets/<int:ticket_id>/": "a read",
    "api/tickets/<int:ticket_id>/attachments/<int:attachment_id>/download/": "a read of a file on the company's own ticket",
    "api/tickets/create/": "a message to support, which changes nothing by itself",
    "api/tickets/<int:ticket_id>/reply/": "a message to support, which changes nothing by itself",
}


# The test that proves each guarded route refuses a stale session and acts for a fresh one.
EVERY_ACTION = "tests.api.test_step_up_guarded_actions.StepUpCoverageTests.test_each_action_is_refused_when_stale_and_done_when_fresh"
_DNS = "tests.api.test_dns_zone_api.DnsZoneApiTests.test_publishing_needs_a_recent_identity_check_and_a_crosscheck_does_not"
PROVEN_BY: dict[str, str] = {
    "api/users/profile/": "tests.api.test_step_up_guarded_actions.StepUpCoverageTests.test_the_name_or_phone_needs_a_check_and_preferences_do_not",
    "api/gdpr/data-export/": "tests.api.test_step_up_guarded_actions.StepUpCoverageTests.test_an_export_request_needs_a_check_and_its_status_does_not",
    "api/gdpr/data-export/<uuid:export_id>/download/": "tests.api.test_step_up_guarded_actions.ExportDownloadStepUpTests.test_a_download_needs_a_check",
    "api/billing/gift-cards/reveal/": "tests.api.test_gift_purchase_api.GiftPurchaseAPITests.test_a_stale_session_confirms_before_the_code_is_revealed",
    "api/billing/recurring-payments/authorize/begin/": "tests.api.test_recurring_payments_api.RecurringPaymentsAPITestCase.test_begin_needs_a_recent_identity_check",
    "api/dns/zones/<uuid:zone_id>/confirm/": _DNS,
    "api/dns/zones/<uuid:zone_id>/switch/": _DNS,
    "api/dns/zones/<uuid:zone_id>/delete/": _DNS,
    "api/dns/zones/<uuid:zone_id>/records/": _DNS,
    "api/dns/zones/<uuid:zone_id>/records/<uuid:record_id>/": _DNS,
    "api/services/<int:service_id>/actions/": "tests.api.test_service_action_requests.ServiceActionRequestTests.test_a_request_needs_a_recent_identity_check",
}

def _routes() -> Iterator[tuple[str, object]]:
    def walk(patterns: list[object], prefix: str) -> Iterator[tuple[str, object]]:
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                yield from walk(pattern.url_patterns, prefix + str(pattern.pattern))
            elif isinstance(pattern, URLPattern):
                yield prefix + str(pattern.pattern), pattern.callback

    for route, callback in walk(get_resolver().url_patterns, ""):
        if route.startswith(PREFIXES):
            yield route, callback


def _read_only_router_route(callback: object) -> bool:
    """A route the DRF router generated for a viewset that maps only safe methods."""
    actions = getattr(callback, "actions", None)
    return bool(actions) and set(actions) <= SAFE_METHODS


class StepUpInventoryTests(SimpleTestCase):
    def test_every_route_is_guarded_or_exempt_with_a_reason(self) -> None:
        listed = set(GUARDED) | set(EXEMPT)
        routes = dict(_routes())
        unlisted = sorted(
            route for route, callback in routes.items() if route not in listed and not _read_only_router_route(callback)
        )
        self.assertEqual(unlisted, [], "decide: guard it (with a behavioural test) or exempt it with a reason")
        self.assertEqual(sorted(listed - set(routes)), [], "a listed route no longer exists")
        self.assertEqual(set(GUARDED) & set(EXEMPT), set())
        self.assertTrue(all(reason.strip() for reason in [*GUARDED.values(), *EXEMPT.values()]))

    def test_every_guarded_route_has_a_behavioural_test(self) -> None:
        from tests.api.test_step_up_guarded_actions import ACTIONS  # noqa: PLC0415

        tested = {"api/" + action.path: EVERY_ACTION for action in ACTIONS} | PROVEN_BY
        self.assertEqual(sorted(set(GUARDED) - set(tested)), [])
        self.assertEqual(sorted(set(tested) - set(GUARDED)), [])
        self.assertEqual(len(GUARDED), 24)
        for route, test in tested.items():
            with self.subTest(route=route):
                # The named test must exist: renaming or deleting it fails here, not silently.
                module, case, method = test.rsplit(".", 2)
                self.assertTrue(callable(getattr(getattr(importlib.import_module(module), case), method, None)), test)
