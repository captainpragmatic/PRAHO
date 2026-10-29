"""DNS status stays tenant scoped, read only on GET, and safe during API outages."""

import time
from unittest.mock import patch

from django.test import Client, SimpleTestCase, override_settings

from apps.services.services import PlatformAPIError, ServicesAPIClient, services_api


def status_payload(**changes):
    return {
        "version": 1,
        "state": "broken",
        "dns_path": "external_dns",
        "pending": False,
        "stale": False,
        "checked_at": "2026-10-27T00:00:00+00:00",
        "account_name": "a123.accounts.example.net",
        "instructions": [
            {"type": "CNAME", "name": "www.customer.example", "value": "a123.accounts.example.net"},
            {"type": "ALIAS", "name": "customer.example", "value": "a123.accounts.example.net"},
        ],
        "components": {
            "apex": {"state": "healthy", "code": "routing_reaches_account"},
            "www": {"state": "broken", "code": "address_mismatch", "evidence": "203.0.113.77"},
            "caa": {"state": "healthy", "code": "caa_unrestricted"},
            "dnssec": {"state": "not_applicable", "code": "dnssec_unsigned"},
            "mx": {"state": "not_applicable", "code": "external_mail"},
        },
        "private_node": "node-secret.example.net",
        **changes,
    }


class DnsStatusClientTests(SimpleTestCase):
    def test_read_uses_signed_post_identity_and_preserves_status(self):
        api = ServicesAPIClient()
        payload = status_payload()
        with patch.object(
            api, "_make_request", return_value={"success": True, "data": {"dns_status": payload}}
        ) as call:
            result = api.get_service_dns_status(42, 7, 5)
        self.assertEqual(result, payload)
        self.assertEqual(call.call_args.args, ("POST", "/services/5/dns-status/"))
        self.assertEqual(call.call_args.kwargs["data"], {"customer_id": 42, "user_id": 7})
        self.assertTrue(call.call_args.kwargs["idempotent"])

    def test_recheck_uses_the_deduplicated_post_endpoint(self):
        api = ServicesAPIClient()
        payload = status_payload(pending=True)
        with patch.object(
            api, "_make_request", return_value={"success": True, "data": {"dns_status": payload}}
        ) as call:
            self.assertEqual(api.recheck_service_dns(42, 7, 5), payload)
        self.assertEqual(call.call_args.args, ("POST", "/services/5/dns-status/recheck/"))
        self.assertEqual(call.call_args.kwargs["user_id"], 7)

    def test_missing_or_malformed_status_is_unavailable_instead_of_healthy(self):
        api = ServicesAPIClient()
        for response in (
            {},
            {"success": True, "data": {}},
            {"success": True, "data": {"dns_status": {}}},
            {"success": True, "data": {"dns_status": {"version": 1, "state": []}}},
            {"success": True, "data": {"dns_status": {"version": True, "state": "healthy"}}},
        ):
            with (
                self.subTest(response=response),
                patch.object(api, "_make_request", return_value=response),
                self.assertRaises(PlatformAPIError),
            ):
                api.get_service_dns_status(42, 7, 5)

    def test_non_mapping_response_is_a_typed_unavailable_result(self):
        api = ServicesAPIClient()
        for malformed in ([], None, "not an envelope"):
            with (
                self.subTest(response=malformed),
                patch.object(api, "_make_request", return_value=malformed),
                self.assertRaises(PlatformAPIError),
            ):
                api.get_service_dns_status(42, 7, 5)

    def test_incomplete_healthy_receipt_cannot_claim_that_checks_passed(self):
        api = ServicesAPIClient()
        payload = {"success": True, "data": {"dns_status": {"version": 1, "state": "healthy"}}}
        with patch.object(api, "_make_request", return_value=payload), self.assertRaises(PlatformAPIError):
            api.get_service_dns_status(42, 7, 5)

    def healthy_payload(self):
        value = status_payload(state="healthy")
        value["components"]["www"] = {"state": "healthy", "code": "routing_reaches_account"}
        return value

    def test_a_dated_complete_healthy_receipt_remains_usable(self):
        api = ServicesAPIClient()
        payload = self.healthy_payload()
        with patch.object(api, "_make_request", return_value={"success": True, "data": {"dns_status": payload}}):
            self.assertEqual(api.get_service_dns_status(42, 7, 5), payload)

    def test_healthy_proof_requires_five_components_valid_states_and_an_aware_check_time(self):
        api = ServicesAPIClient()
        variants = [
            {"checked_at": None}, {"checked_at": "bad date"}, {"checked_at": "2026-10-27T00:00:00"},
            {"pending": "true"}, {"stale": 0}, {"dns_path": []}, {"components": {}},
            {"account_name": {"private_node": "node-secret.example.net"}},
            {"instructions": "not records"},
        ]
        for changes in variants:
            payload = {**self.healthy_payload(), **changes}
            with (
                self.subTest(changes=changes),
                patch.object(api, "_make_request", return_value={"success": True, "data": {"dns_status": payload}}),
                self.assertRaises(PlatformAPIError),
            ):
                api.get_service_dns_status(42, 7, 5)
        for state in ("unknown", "broken", [], "not_a_state"):
            payload = self.healthy_payload()
            payload["components"]["www"]["state"] = state
            with (
                self.subTest(state=state),
                patch.object(api, "_make_request", return_value={"success": True, "data": {"dns_status": payload}}),
                self.assertRaises(PlatformAPIError),
            ):
                api.get_service_dns_status(42, 7, 5)

    def test_unknown_and_nonhosting_backend_receipts_with_no_check_time_remain_usable(self):
        api = ServicesAPIClient()
        unknown = status_payload(state="unknown", checked_at=None, pending=True)
        unknown["components"] = {
            name: {"state": "unknown", "code": "not_checked"} for name in unknown["components"]
        }
        unavailable = status_payload(state="not_applicable", checked_at=None, account_name=None, instructions=[], components={})
        for payload in (unknown, unavailable):
            with self.subTest(state=payload["state"]), patch.object(api, "_make_request", return_value={"success": True, "data": {"dns_status": payload}}):
                self.assertEqual(api.get_service_dns_status(42, 7, 5), payload)


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class DnsStatusCardTests(SimpleTestCase):
    path = "/services/5/dns/"

    def setUp(self):
        self.login_as("owner")
        self.read = self.enterContext(
            patch.object(services_api, "get_service_dns_status", return_value=status_payload(), create=True)
        )
        self.recheck = self.enterContext(
            patch.object(services_api, "recheck_service_dns", return_value=status_payload(pending=True), create=True)
        )

    def login_as(self, role, client=None):
        session = (client or self.client).session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": role}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    def test_card_renders_account_name_and_hides_private_trace(self):
        response = self.client.get(self.path, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        text = response.content.decode()
        self.assertIn("a123.accounts.example.net", text)
        self.assertIn("Check DNS again", text)
        self.assertNotIn("203.0.113.77", text)
        self.assertNotIn("node-secret", text)
        self.assertNotIn("https://a123", text, "website previews remain off")
        self.read.assert_called_once_with(42, 7, 5)
        self.recheck.assert_not_called()

    def test_viewer_and_billing_can_read_without_a_mutation_button(self):
        for role in ("viewer", "billing"):
            with self.subTest(role=role):
                self.login_as(role)
                response = self.client.get(self.path, HTTP_HX_REQUEST="true")
                self.assertEqual(response.status_code, 200)
                self.assertNotIn("Check DNS again", response.content.decode())

    def test_viewer_and_billing_cannot_forge_recheck_posts(self):
        for role in ("viewer", "billing"):
            with self.subTest(role=role):
                self.login_as(role)
                self.assertEqual(self.client.post(self.path).status_code, 403)
        self.recheck.assert_not_called()

    def test_owner_and_tech_can_queue_a_check(self):
        for role in ("owner", "tech"):
            with self.subTest(role=role):
                self.login_as(role)
                response = self.client.post(self.path, HTTP_HX_REQUEST="true")
                self.assertEqual(response.status_code, 202)
                self.assertIn("queued", response.content.decode().lower())
        self.assertEqual(self.recheck.call_count, 2)

    def test_post_without_csrf_never_reaches_platform(self):
        client = Client(enforce_csrf_checks=True)
        self.login_as("owner", client)
        self.assertEqual(client.post(self.path).status_code, 403)
        self.recheck.assert_not_called()

    def test_platform_membership_revocation_is_not_accepted_from_cached_portal_role(self):
        self.recheck.side_effect = PlatformAPIError("Access denied", status_code=403)
        self.assertEqual(self.client.post(self.path, HTTP_HX_REQUEST="true").status_code, 403)

    def test_missing_backend_endpoint_shows_unavailable_and_no_old_green(self):
        self.read.side_effect = PlatformAPIError("DNS endpoint missing", status_code=404)
        response = self.client.get(self.path, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("unavailable", response.content.decode().lower())

    def test_standalone_page_offers_name_records_without_private_address_fallbacks(self):
        self.read.return_value = status_payload(
            instructions=[
                {"type": "CNAME", "name": "www.customer.example", "value": "a123.accounts.example.net"},
                {"type": "A", "name": "customer.example", "value": "203.0.113.77"},
                {"type": "CNAME", "name": "old.customer.example", "value": "node-secret.example.net"},
            ]
        )
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200)
        self.assertIn("www.customer.example", response.content.decode())
        self.assertNotIn("203.0.113.77", response.content.decode())
        self.assertNotIn("node-secret.example.net", response.content.decode())

    def test_pending_polling_is_bounded(self):
        self.read.return_value = status_payload(state="unknown", pending=True)
        response = self.client.get(self.path, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("load delay:10s", response.content.decode())
        last = self.client.get(self.path + "?poll=12", HTTP_HX_REQUEST="true")
        self.assertNotIn("load delay:10s", last.content.decode())

    def test_stale_green_is_presented_as_unknown(self):
        self.read.return_value = status_payload(state="healthy", stale=True)
        response = self.client.get(self.path, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("waiting for a current check", response.content.decode().lower())

    def test_a_signed_out_session_redirects_without_an_api_call(self):
        self.client.session.flush()
        self.assertEqual(self.client.get(self.path).status_code, 302)
        self.read.assert_not_called()
