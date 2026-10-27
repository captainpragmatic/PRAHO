"""Mail status is a strict signed read, with no enrollment controls or guessed credentials."""

import copy
import time
from unittest.mock import patch

from django.template.loader import render_to_string
from django.test import SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.services.services import ServicesAPIClient, services_api

NAME = "a1b2c3d4.accounts.example.net"
PRIVATE = "private-mail-lease-or-node-value"


def status_payload(**changes):
    return {
        "version": 1,
        "applicability": "applicable",
        "mode": "external",
        "enrolled": False,
        "verification": "unverified",
        "verified_at": None,
        "account_name": NAME,
        "client_ports": {"imap_tls": 993, "pop3_tls": 995, "submission_tls": 465},
        "verified_login": None,
        "requires_owner_consent": True,
        "operation": None,
        **changes,
    }


def operation_payload(**changes):
    return {
        "intent": "enable",
        "status": "running",
        "checkpoint": "preflight",
        "error_code": "",
        "created_at": "2026-10-27T00:00:00+00:00",
        "updated_at": "2026-10-27T00:01:00+00:00",
        "resume_after": None,
        **changes,
    }


class MailStatusClientTests(SimpleTestCase):
    def test_mail_read_uses_get_with_a_signed_identity_body_and_a_typed_public_receipt(self):
        api = ServicesAPIClient()
        with patch.object(
            api, "_make_request", return_value={"success": True, "data": {"mail_status": status_payload()}}
        ) as request:
            result = api.get_service_mail_status(42, 7, 5)
        self.assertEqual(result, status_payload())
        request.assert_called_once_with(
            "GET", "/services/5/mail-status/", user_id=7, data={"customer_id": 42, "user_id": 7}, idempotent=True
        )

    def test_malformed_or_inconsistent_receipts_are_unavailable_instead_of_external_or_verified(self):
        api = ServicesAPIClient()
        variants = [
            None,
            {},
            status_payload(version=True),
            status_payload(mode="unexpected"),
            status_payload(mode="hosted", enrolled=False),
            status_payload(mode="external", enrolled=True),
            status_payload(enrolled=0),
            status_payload(verification="current"),
            status_payload(mode="hosted", enrolled=True, verification="current"),
            status_payload(account_name="<script>private</script>"),
            status_payload(verified_login="guessed-owner"),
            status_payload(client_ports={"imap_tls": 143}),
            status_payload(client_ports={"imap_tls": 993.0, "pop3_tls": 995, "submission_tls": 465}),
            status_payload(client_ports={}),
            status_payload(operation=operation_payload(status=PRIVATE)),
            status_payload(operation=operation_payload(checkpoint=PRIVATE)),
            status_payload(operation=operation_payload(error_code=PRIVATE)),
            status_payload(operation=operation_payload(created_at="2026-10-27T00:00:00")),
        ]
        for payload in variants:
            with (
                self.subTest(payload=payload),
                patch.object(api, "_make_request", return_value={"success": True, "data": {"mail_status": payload}}),
                self.assertRaises(PlatformAPIError),
            ):
                api.get_service_mail_status(42, 7, 5)

    def test_extra_private_fields_are_not_carried_beyond_the_client_boundary(self):
        api = ServicesAPIClient()
        payload = status_payload(
            lease_token=PRIVATE,
            consent_digest=PRIVATE,
            result={"private": PRIVATE},
            operation=operation_payload(result=PRIVATE, lease_token=PRIVATE),
        )
        with patch.object(api, "_make_request", return_value={"success": True, "data": {"mail_status": payload}}):
            result = api.get_service_mail_status(42, 7, 5)
        self.assertNotIn(PRIVATE, str(result))
        self.assertEqual(set(result), set(status_payload()))
        self.assertEqual(set(result["operation"]), set(operation_payload()))

    def test_explicit_unknown_state_remains_usable_without_inventing_enrollment(self):
        api = ServicesAPIClient()
        payload = status_payload(
            mode="unknown",
            enrolled=None,
            operation=operation_payload(
                intent="unknown", status="unknown", checkpoint="unknown", error_code="mail_operation_unrecognized"
            ),
        )
        with patch.object(api, "_make_request", return_value={"success": True, "data": {"mail_status": payload}}):
            self.assertEqual(api.get_service_mail_status(42, 7, 5), payload)


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    LANGUAGE_CODE="en",
)
class MailStatusCardTests(SimpleTestCase):
    path = "/services/5/mail-status/"

    def setUp(self):
        self.login_as("owner")
        self.read = self.enterContext(
            patch.object(services_api, "get_service_mail_status", return_value=status_payload(), create=True)
        )

    def login_as(self, role):
        session = self.client.session
        session.update(
            {
                "customer_id": 42,
                "user_id": 7,
                "user_memberships": [{"customer_id": 42, "role": role}],
                "user_memberships_fetched_at": time.time(),
            }
        )
        session.save()

    def test_existing_service_detail_loads_the_mail_section_without_enrollment_controls(self):
        text = render_to_string(
            "services/service_detail.html",
            {"service": {"status": "active", "service_name": "Hosting"}, "service_id": 5},
        )
        self.assertTrue('id="service-mail-status"' in text, "The service detail must include its mail section")
        self.assertTrue('hx-get="/services/5/mail-status/"' in text, "The section must load its read-only route")

    def test_external_intent_is_not_presented_as_observed_routing_and_the_name_has_no_preview_link(self):
        response = self.client.get(self.path, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        text = response.content.decode()
        self.assertIn("not enrolled in PRAHO hosted mail", text)
        self.assertIn("does not check your current mail routing", text)
        self.assertIn(NAME, text)
        self.assertIn("owner consent", text.lower())
        for forbidden in ("https://" + NAME, "http://" + NAME, "<form", "<button", "<script", "Enable hosted mail"):
            self.assertNotIn(forbidden, text)
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        self.read.assert_called_once_with(42, 7, 5)

    def test_all_existing_hosting_roles_can_read_without_mutation_controls(self):
        for role in ("owner", "tech", "billing", "viewer"):
            with self.subTest(role=role):
                self.login_as(role)
                response = self.client.get(self.path, HTTP_HX_REQUEST="true")
                self.assertEqual(response.status_code, 200)
                self.assertNotIn("<form", response.content.decode())

    def test_hosted_stale_verification_preserves_enrollment_without_a_current_ready_claim(self):
        self.read.return_value = status_payload(
            mode="hosted", enrolled=True, verification="stale", verified_at="2026-10-27T00:00:00+00:00"
        )
        text = self.client.get(self.path, HTTP_HX_REQUEST="true").content.decode()
        self.assertIn("enrolled in PRAHO hosted mail", text)
        self.assertIn("Earlier verification is no longer current", text)
        self.assertNotIn("verification is current", text)

    def test_unknown_enrollment_is_not_rendered_as_external_or_hosted(self):
        self.read.return_value = status_payload(mode="unknown", enrolled=None)
        text = self.client.get(self.path, HTTP_HX_REQUEST="true").content.decode()
        self.assertIn("enrollment status is not confirmed", text)
        self.assertNotIn("account is enrolled", text)
        self.assertNotIn("account is not enrolled", text)

    def test_retirement_review_uses_fixed_explanations_and_hides_raw_error_and_result(self):
        self.read.return_value = status_payload(
            mode="hosted",
            enrolled=True,
            verification="stale",
            operation=operation_payload(
                intent="disable",
                status="needs_review",
                checkpoint="native_inflight",
                error_code="mail_native_outcome_unknown",
            ),
            result=PRIVATE,
        )
        text = self.client.get(self.path, HTTP_HX_REQUEST="true").content.decode()
        self.assertIn("Return to external mail", text)
        self.assertIn("Staff review is required", text)
        self.assertNotIn("mail_native_outcome_unknown", text)
        self.assertNotIn(PRIVATE, text)

    def test_accountless_service_is_not_applicable_and_does_not_offer_a_login(self):
        self.read.return_value = status_payload(applicability="not_applicable", account_name=None, client_ports={})
        response = self.client.get(self.path, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        text = response.content.decode()
        self.assertIn("not available for this service", text)
        self.assertNotIn("993", text)
        self.assertNotIn("Username", text)

    def test_current_platform_revocation_wins_over_a_cached_owner_role(self):
        self.read.side_effect = PlatformAPIError(PRIVATE, status_code=403)
        response = self.client.get(self.path, HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(PRIVATE, response.content.decode())

    def test_foreign_or_missing_service_is_a_404_without_invented_external_state(self):
        self.read.side_effect = PlatformAPIError(PRIVATE, status_code=404)
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 404)
        self.assertNotIn(PRIVATE, response.content.decode())
        self.assertNotIn("not enrolled", response.content.decode())

    def test_read_outage_is_an_unavailable_card_with_truthful_http_status(self):
        self.read.side_effect = PlatformAPIError(PRIVATE, status_code=503, is_unavailable=True)
        for headers, expected in (({}, 503), ({"HTTP_HX_REQUEST": "true"}, 200)):
            with self.subTest(headers=headers):
                response = self.client.get(self.path, **headers)
                self.assertEqual(response.status_code, expected)
                self.assertIn("temporarily unavailable", response.content.decode())
                self.assertNotIn("not enrolled", response.content.decode())
                self.assertNotIn(PRIVATE, response.content.decode())

    def test_rate_limited_read_preserves_retry_after_and_standalone_429(self):
        self.read.side_effect = PlatformAPIError(PRIVATE, status_code=429, retry_after=17, is_rate_limited=True)
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers.get("Retry-After"), "17")
        fragment = self.client.get(self.path, HTTP_HX_REQUEST="true")
        self.assertEqual(fragment.status_code, 200)
        self.assertEqual(fragment.headers.get("Retry-After"), "17")
        self.assertNotIn("not enrolled", fragment.content.decode())

    def test_unsigned_session_or_missing_user_redirects_before_calling_platform(self):
        session = self.client.session
        session.pop("user_id")
        session.save()
        self.assertEqual(self.client.get(self.path).status_code, 302)
        self.read.assert_not_called()

    def test_only_current_session_identity_is_sent_and_posts_never_reach_platform(self):
        self.assertEqual(self.client.get(self.path + "?customer_id=999&user_id=999").status_code, 200)
        self.read.assert_called_once_with(42, 7, 5)
        self.read.reset_mock()
        self.assertEqual(self.client.post(self.path).status_code, 405)
        self.read.assert_not_called()

    def test_template_escapes_plaintext_connection_name_even_if_a_test_double_bypasses_validation(self):
        value = copy.deepcopy(status_payload())
        value["account_name"] = '<script>alert("private")</script>'
        self.read.return_value = value
        text = self.client.get(self.path, HTTP_HX_REQUEST="true").content.decode()
        self.assertNotIn("<script", text)
        self.assertIn("&lt;script&gt;", text)
