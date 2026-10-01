"""Platform preflight errors must reach a Romanian customer in Romanian.

The platform already wraps these messages in gettext (apps/orders/preflight.py) but
renders them with str() while serving an HMAC request, where no customer language is
active. They therefore always arrive in English, and the checkout page listed them
verbatim under a translated heading — a half-Romanian page.

The portal knows the language, and the msgid IS the English text, so it finishes the
translation by looking each string up.

WHY THIS FILE DRIVES THE REAL VIEW. Three earlier attempts at this fix passed their
tests while changing nothing a customer sees, because each tested a seam production
does not take: a fake client returning a dict the real client never returns, and a
translated exception that a bare `except Exception` upstream discarded. The
end-to-end tests below are what would have caught all three.
"""

from __future__ import annotations

import time
from unittest.mock import Mock, patch

from django.core.exceptions import ValidationError
from django.test import Client, TestCase
from django.utils import translation

from apps.api_client.services import PlatformAPIError
from apps.orders.services import OrderCreationService
from apps.orders.views import _localise_platform_error

# Exactly as apps/orders/preflight.py emits them.
ENGLISH_STREET = "Please provide your street address"
ENGLISH_CITY = "Please provide your city"
ENGLISH_CURRENCY = "Order currency not set"
INTERPOLATED = "Item 'Hosting Pro': invalid pricing (negative values)"


class LocalisePlatformErrorTests(TestCase):
    def test_a_known_platform_message_is_translated(self) -> None:
        with translation.override("ro"):
            result = _localise_platform_error(ENGLISH_STREET)

        self.assertNotEqual(result, ENGLISH_STREET, "the Romanian catalogue is missing this msgid")
        self.assertIn("adresa", result.lower())

    def test_an_unknown_string_passes_through_unchanged(self) -> None:
        """gettext returns its input on a miss, so an interpolated message cannot break."""
        with translation.override("ro"):
            self.assertEqual(_localise_platform_error(INTERPOLATED), INTERPOLATED)

    def test_english_stays_english(self) -> None:
        with translation.override("en"):
            self.assertEqual(_localise_platform_error(ENGLISH_STREET), ENGLISH_STREET)

    def test_non_string_input_does_not_raise(self) -> None:
        """Returns a str for anything. The value may be translated if it collides with
        an unrelated msgid — gettext("None") is "Niciunul" here — which is why this is
        applied only to platform error text."""
        with translation.override("ro"):
            self.assertIsInstance(_localise_platform_error(None), str)


class CheckoutPageLocalisationTests(TestCase):
    """End to end through the real view and template."""

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 1
        session["email"] = "cumparator@example.ro"
        session["user_memberships"] = [{"customer_id": 1, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        # A logged-in customer's language comes from their stored preference, NOT from
        # Accept-Language: LocalisationMiddleware skips browser negotiation once
        # PortalAuthenticationMiddleware has authenticated the request. Without this the
        # page renders lang="en" and every Romanian assertion below fails for the wrong
        # reason.
        session["_language"] = "ro"
        session.save()

    def _checkout(self, errors: list[str]):
        cart = Mock()
        cart.has_items.return_value = True
        cart.get_items.return_value = []
        cart.currency = "RON"
        cart.cart = {"created_at": "2026-01-01T00:00:00Z"}
        cart.get_cart_version.return_value = "v1"
        cart.get_warnings.return_value = []

        with (
            patch("apps.orders.views.GDPRCompliantCartSession", return_value=cart),
            patch(
                "apps.orders.views.CartCalculationService.calculate_cart_totals",
                return_value={
                    "items": [],
                    "currency": "RON",
                    "subtotal_cents": 0,
                    "tax_cents": 0,
                    "total_cents": 0,
                    "vat_rate_percent": 21,
                },
            ),
            patch(
                "apps.orders.views.OrderCreationService.preflight_order",
                return_value={"valid": False, "errors": errors, "warnings": []},
            ),
            translation.override("ro"),
        ):
            return self.client.get("/order/checkout/", HTTP_ACCEPT_LANGUAGE="ro")

    def test_the_page_shows_romanian_not_the_platforms_english(self) -> None:
        response = self._checkout([ENGLISH_STREET, ENGLISH_CITY])

        body = response.content.decode()
        self.assertNotIn(ENGLISH_STREET, body, "the platform's English reached the customer")
        self.assertNotIn(ENGLISH_CITY, body)
        self.assertIn("adresa", body.lower())

    def test_each_reason_still_gets_its_own_row(self) -> None:
        """A translation fix must not collapse N reasons into one generic sentence."""
        response = self._checkout([ENGLISH_STREET, ENGLISH_CITY])
        body = response.content.decode().lower()

        self.assertIn("adresa", body)
        self.assertIn("localitatea", body)

    def test_an_untranslatable_reason_still_appears(self) -> None:
        """Passing through English beats dropping the row entirely."""
        response = self._checkout([INTERPOLATED])

        self.assertIn("Hosting Pro", response.content.decode())


class OrderCreationMessageLocalisationTests(TestCase):
    """The POST path interpolates the reasons into a message; it must translate them too.

    This is the surface the original defect named. It is reached only by a NON-profile
    error: every "Please provide your ..." message matches _PROFILE_KEYWORDS and takes
    the generic "We need more information" branch instead, so this drives the currency
    error, which matches no keyword.
    """

    def setUp(self) -> None:
        self.client = Client()
        session = self.client.session
        session["customer_id"] = 1
        session["user_id"] = 1
        session["email"] = "cumparator@example.ro"
        session["user_memberships"] = [{"customer_id": 1, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session["_language"] = "ro"
        session.save()

    def test_the_interpolated_reason_is_romanian_too(self) -> None:
        cart = Mock()
        cart.has_items.return_value = True
        cart.get_items.return_value = []
        cart.currency = "RON"
        cart.cart = {"created_at": "2026-01-01T00:00:00Z"}
        cart.get_cart_version.return_value = "v1"
        cart.get_warnings.return_value = []

        with (
            patch("apps.orders.views.GDPRCompliantCartSession", return_value=cart),
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.counters.claim", return_value=True),
            patch("apps.orders.views.counters.release"),
            patch(
                "apps.orders.views.OrderCreationService.preflight_order",
                return_value={"valid": False, "errors": [ENGLISH_CURRENCY], "warnings": []},
            ),
        ):
            response = self.client.post(
                "/order/create/",
                {"cart_version": "v1", "payment_method": "bank_transfer", "agree_terms": "on"},
                follow=True,
            )

        shown = " ".join(str(m) for m in response.context["messages"])
        self.assertNotIn(ENGLISH_CURRENCY, shown, "the platform's English reached the customer")
        self.assertIn("Moneda comenzii nu este setată", shown)

    def test_a_platform_failure_during_creation_still_reads_romanian(self) -> None:
        """The production order-creation failure path, driven through the real service.

        An earlier round of this fix was verified only against a fake client that
        returned an error dict. The real client raises PlatformAPIError instead, which
        OrderCreationService converts to a translated generic message, so the branch that
        read the dict never ran in production. This asserts what the customer actually
        sees on that path rather than inferring it from a code read.
        """
        cart = Mock()
        cart.has_items.return_value = True
        cart.get_items.return_value = [{"product_id": "p1", "quantity": 1}]
        cart.currency = "RON"
        cart.cart = {"created_at": "2026-01-01T00:00:00Z"}
        cart.get_cart_version.return_value = "v1"
        cart.get_warnings.return_value = []

        exploding_client = Mock()
        exploding_client.post.side_effect = PlatformAPIError("Order currency not set")

        with (
            patch("apps.orders.views.GDPRCompliantCartSession", return_value=cart),
            patch("apps.orders.views.OrderSecurityHardening.fail_closed_on_cache_failure", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.validate_request_size", return_value=None),
            patch("apps.orders.views.OrderSecurityHardening.check_suspicious_patterns", return_value=None),
            patch("apps.orders.views.counters.claim", return_value=True),
            patch("apps.orders.views.counters.release"),
            patch("apps.orders.views.counters.complete", return_value=True),
            patch(
                "apps.orders.views.OrderCreationService.preflight_order",
                return_value={"valid": True, "errors": [], "warnings": []},
            ),
            patch("apps.orders.views.PlatformAPIClient", return_value=exploding_client),
        ):
            response = self.client.post(
                "/order/create/",
                {"cart_version": "v1", "payment_method": "bank_transfer", "agree_terms": "on"},
                follow=True,
            )

        shown = " ".join(str(m) for m in response.context["messages"])
        self.assertNotIn("Order currency not set", shown, "a raw platform string reached the customer")
        self.assertNotIn("Error creating order", shown, "the generic message was rendered untranslated")
        self.assertIn("Eroare la crearea comenzii", shown)


class RawPlatformErrorNeverReachesTheViewTests(TestCase):
    """Locks in what keeps a raw English platform string off the checkout page.

    views.py has `if result.get("error"): messages.error(request, result["error"])` on
    the order-creation result — the one place a platform string would be shown with no
    translation and no wrapper. It is unreachable only because create_draft_order raises
    on an error body instead of returning it. Nothing states that, so this does: if the
    service is ever changed to return the dict, this fails here rather than shipping raw
    English to a customer.
    """

    def test_an_error_body_raises_instead_of_returning_it_to_the_caller(self) -> None:
        cart = Mock()
        cart.has_items.return_value = True
        cart.get_items.return_value = [{"product_id": "p1", "quantity": 1}]
        cart.currency = "RON"

        client = Mock()
        client.post.return_value = {"error": "Order currency not set"}

        with self.assertRaises(ValidationError):
            OrderCreationService.create_draft_order(
                cart,
                customer_id="1",
                user_id="1",
                api_client_factory=Mock(return_value=client),
            )
