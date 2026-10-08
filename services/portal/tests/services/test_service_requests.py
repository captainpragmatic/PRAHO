"""Customer service requests use signed identities and durable ticket receipts."""

from __future__ import annotations

import re
import time
from html.parser import HTMLParser
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, SimpleTestCase
from django.urls import reverse

from apps.api_client.services import PlatformAPIError
from apps.services.services import ServicesAPIClient
from apps.services.views import service_detail, service_request_action


class _ActionRadioParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.radios: dict[str, dict[str, str | None]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        value = attributes.get("value")
        if tag == "input" and attributes.get("type") == "radio" and value is not None:
            self.radios[value] = attributes


class ServiceRequestAPIContractTests(SimpleTestCase):
    def setUp(self) -> None:
        self.client = ServicesAPIClient()
        self.submission_id = str(uuid4())
        self.receipt = {"request_id": str(uuid4()), "ticket_id": 91, "ticket_number": "TKT-2026-000091"}

    def _submit(self, **overrides: Any) -> dict[str, Any]:
        arguments = {
            "customer_id": 101,
            "user_id": 7,
            "service_id": 55,
            "action": "upgrade_request",
            "reason": "More storage, please",
            "submission_id": self.submission_id,
        }
        return self.client.request_service_action(**(arguments | overrides))

    @patch.object(ServicesAPIClient, "_make_request")
    def test_all_four_actions_sign_user_and_customer_and_unwrap_ticket_receipt(self, send: MagicMock) -> None:
        send.return_value = {"success": True, "data": self.receipt}
        for action in ("upgrade_request", "downgrade_request", "suspend_request", "cancel_request"):
            with self.subTest(action=action):
                send.reset_mock()
                self.assertEqual(self._submit(action=action), self.receipt)
                send.assert_called_once_with(
                    "POST",
                    "/services/55/actions/",
                    user_id=7,
                    data={
                        "customer_id": 101,
                        "user_id": 7,
                        "action": action,
                        "reason": "More storage, please",
                        "submission_id": self.submission_id,
                    },
                )

    @patch.object(ServicesAPIClient, "_make_request")
    def test_receipt_does_not_expose_internal_review_fields(self, send: MagicMock) -> None:
        send.return_value = {"success": True, "data": self.receipt | {"status": "approved", "reviewer_id": 2}}
        self.assertEqual(self._submit(), self.receipt)

    @patch.object(ServicesAPIClient, "_make_request")
    def test_invalid_or_missing_receipt_never_reports_success(self, send: MagicMock) -> None:
        invalid_receipts = [
            {"success": False, "data": self.receipt},
            {"success": True},
            {"success": True, "data": None},
            {"success": True, "data": {}},
            {"success": True, "data": self.receipt | {"request_id": "not-a-uuid"}},
            {"success": True, "data": self.receipt | {"ticket_id": True}},
            {"success": True, "data": self.receipt | {"ticket_id": 0}},
            {"success": True, "data": self.receipt | {"ticket_id": "91"}},
            {"success": True, "data": self.receipt | {"ticket_number": ""}},
        ]
        for response in invalid_receipts:
            with self.subTest(response=response):
                send.return_value = response
                with self.assertRaises(PlatformAPIError):
                    self._submit()

    @patch.object(ServicesAPIClient, "_make_request")
    def test_invalid_action_fails_before_platform_call(self, send: MagicMock) -> None:
        with self.assertRaises(PlatformAPIError):
            self._submit(action="activate")
        send.assert_not_called()

    @patch.object(ServicesAPIClient, "_make_request")
    def test_timeout_is_propagated_without_retrying_write(self, send: MagicMock) -> None:
        send.side_effect = PlatformAPIError("Request timed out", status_code=504)
        with self.assertRaises(PlatformAPIError):
            self._submit()
        self.assertEqual(send.call_count, 1)


class ServiceRequestViewTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.session: dict[str, Any] = {
            "customer_id": 101,
            "user_id": 7,
            "user_memberships": [{"customer_id": 101, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
        }
        self.path = reverse("services:request_action", kwargs={"service_id": 55})
        api_patch = patch("apps.services.views.services_api")
        self.api = api_patch.start()
        self.addCleanup(api_patch.stop)
        self.api.get_service_detail.return_value = {
            "id": 55,
            "service_name": "Example Hosting",
            "status": "active",
            "service_type": "shared",
            "service_plan": {"name": "Basic"},
            "monthly_price": "10.00",
            "currency_code": "EUR",
            "available_plans": [{"name": "Plus", "price_monthly": "20.00", "currency_code": "EUR"}],
        }
        self.api.get_available_plans.return_value = [{"name": "Plus", "price_monthly": "20.00"}]
        self.api.get_service_usage.return_value = {}
        self.api.get_service_domains.return_value = [{"name": "wp8-example.com", "status": "active"}]
        self.receipt = {"request_id": str(uuid4()), "ticket_id": 91, "ticket_number": "TKT-2026-000091"}
        self.api.request_service_action.return_value = self.receipt

    def _request(self, method: str = "get", data: dict[str, str] | None = None):
        request = getattr(self.factory, method)(self.path, data=data or {})
        request.session = self.session
        request._messages = FallbackStorage(request)
        request._dont_enforce_csrf_checks = True
        return request

    def _open_form(self) -> tuple[str, str]:
        response = service_request_action(self._request(), service_id=55)
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        match = re.search(r'name="submission_id" value="([^"]+)"', html)
        self.assertIsNotNone(match, "Service request form must carry its session-bound submission ID")
        submission_id = match[1]
        self.assertEqual(str(UUID(submission_id)), submission_id)
        return submission_id, html

    def _post(self, submission_id: str, **overrides: str):
        request = self._request(
            "post",
            {"submission_id": submission_id, "action": "upgrade_request", "reason": "More storage"} | overrides,
        )
        return service_request_action(request, service_id=55), request

    def test_detail_lists_domains_from_the_signed_platform_response(self) -> None:
        domains = [{"name": "blog.wp8-example.com", "status": "active", "domain_type": "subdomain"}]
        self.api.get_service_domains.side_effect = ServicesAPIClient().get_service_domains
        with patch.object(
            ServicesAPIClient, "_make_request", return_value={"success": True, "data": {"domains": domains}}
        ) as send:
            response = service_detail(self._request(), service_id=55)

        self.assertContains(response, "blog.wp8-example.com")
        self.assertContains(response, "Associated Domains")
        send.assert_called_once_with(
            "POST",
            "/services/55/domains/",
            user_id=7,
            data={"customer_id": 101, "user_id": 7},
            idempotent=True,
        )

    def test_get_keeps_same_submission_id_until_a_request_is_accepted(self) -> None:
        first, _ = self._open_form()
        second, _ = self._open_form()
        self.assertEqual(first, second)

    def test_each_success_opens_ticket_and_next_form_gets_new_submission_id(self) -> None:
        for action in ("upgrade_request", "downgrade_request", "suspend_request", "cancel_request"):
            with self.subTest(action=action):
                self.api.request_service_action.reset_mock()
                submission_id, _ = self._open_form()
                response, request = self._post(submission_id, action=action)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.url, reverse("tickets:detail", kwargs={"ticket_id": 91}))
                self.api.request_service_action.assert_called_once_with(
                    customer_id=101,
                    user_id=7,
                    service_id=55,
                    action=action,
                    reason="More storage",
                    submission_id=submission_id,
                )
                flash = " ".join(str(message) for message in get_messages(request))
                self.assertIn(self.receipt["ticket_number"], flash)
                self.assertNotIn("N/A", flash)
                next_id, _ = self._open_form()
                self.assertNotEqual(next_id, submission_id)

    def test_accepted_post_retry_recovers_the_same_ticket_before_a_fresh_get(self) -> None:
        submission_id, _ = self._open_form()
        first, _ = self._post(submission_id)
        self.assertEqual(first.status_code, 302)
        # The redirect was lost after the server persisted the session.
        second, _ = self._post(submission_id)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(second.url, first.url)
        self.assertEqual(
            [call.kwargs["submission_id"] for call in self.api.request_service_action.call_args_list],
            [submission_id, submission_id],
        )
        next_id, _ = self._open_form()
        self.assertNotEqual(next_id, submission_id)
        stale, _ = self._post(submission_id)
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(self.api.request_service_action.call_count, 2)
        fresh, _ = self._post(next_id)
        self.assertEqual(fresh.status_code, 302)
        self.assertEqual(self.api.request_service_action.call_args.kwargs["submission_id"], next_id)

    def test_changed_accepted_retry_keeps_original_identity_and_platform_conflict(self) -> None:
        submission_id, _ = self._open_form()
        self._post(submission_id)
        self.api.request_service_action.side_effect = PlatformAPIError("Different details", status_code=409)
        response, _ = self._post(submission_id, reason="A different request")
        self.assertContains(response, "different details", status_code=409)
        self.assertEqual(self.api.request_service_action.call_count, 2)
        self.assertEqual(self.api.request_service_action.call_args.kwargs["submission_id"], submission_id)

    def test_accepted_retry_reaches_platform_after_service_termination(self) -> None:
        submission_id, _ = self._open_form()
        first, _ = self._post(submission_id)
        self.api.get_service_detail.return_value["status"] = "terminated"
        replay, _ = self._post(submission_id)
        self.assertEqual(replay.status_code, 302)
        self.assertEqual(replay.url, first.url)
        self.assertEqual(self.api.request_service_action.call_count, 2)
        self.assertEqual(self.api.request_service_action.call_args.kwargs["submission_id"], submission_id)

        self.api.request_service_action.side_effect = PlatformAPIError("Different details", status_code=409)
        conflict, _ = self._post(submission_id, reason="Changed request")
        self.assertContains(conflict, "different details", status_code=409)
        self.session["user_memberships"][0]["role"] = "viewer"
        denied, _ = self._post(submission_id)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.api.request_service_action.call_count, 3)

    def test_uncertain_retry_reaches_platform_after_service_termination(self) -> None:
        submission_id, _ = self._open_form()
        self.api.request_service_action.side_effect = [PlatformAPIError("timeout", status_code=504), self.receipt]
        first, _ = self._post(submission_id)
        self.assertContains(first, "temporarily unavailable")
        self.api.get_service_detail.return_value["status"] = "terminated"
        replay, _ = self._post(submission_id)
        self.assertEqual(replay.status_code, 302)
        self.assertEqual(replay.url, reverse("tickets:detail", kwargs={"ticket_id": 91}))
        self.assertEqual(
            [call.kwargs["submission_id"] for call in self.api.request_service_action.call_args_list],
            [submission_id, submission_id],
        )

    def test_new_request_rejected_by_platform_after_status_change_is_not_acknowledged(self) -> None:
        submission_id, _ = self._open_form()
        self.api.get_service_detail.return_value["status"] = "terminated"
        self.api.request_service_action.side_effect = PlatformAPIError("Inactive service", status_code=400)
        response, request = self._post(submission_id)
        self.assertContains(response, "Unable to submit service request")
        self.assertFalse(any("submitted" in str(message) for message in get_messages(request)))
        self.api.request_service_action.assert_called_once()
        fresh_get = service_request_action(self._request(), service_id=55)
        self.assertEqual(fresh_get.status_code, 403)

    def test_timeout_retains_form_values_and_retry_uses_original_submission_id(self) -> None:
        submission_id, _ = self._open_form()
        self.api.request_service_action.side_effect = [PlatformAPIError("timeout", status_code=504), self.receipt]
        response, _ = self._post(submission_id, action="cancel_request", reason="No longer needed")
        self.assertContains(response, submission_id, status_code=200)
        self.assertContains(response, "No longer needed")
        html = response.content.decode()
        parser = _ActionRadioParser()
        parser.feed(html)
        parser.close()
        self.assertIn("checked", parser.radios["cancel_request"])
        self.assertNotIn("checked", parser.radios["upgrade_request"])
        self.assertIn(f'name="submission_id" value="{submission_id}"', html)
        reason = re.search(r'<textarea\b[^>]*name="reason"[^>]*>(.*?)</textarea>', html, re.DOTALL)
        self.assertIsNotNone(reason)
        assert reason is not None
        self.assertEqual(reason[1], "No longer needed")
        self.assertIn("temporarily unavailable", html)
        self.assertNotContains(response, 'aria-label="Try again"')

        response, _ = self._post(submission_id, action="cancel_request", reason=reason[1])
        self.assertEqual(response.url, reverse("tickets:detail", kwargs={"ticket_id": 91}))
        self.assertEqual(self.api.request_service_action.call_count, 2)
        self.assertEqual(
            [call.kwargs["submission_id"] for call in self.api.request_service_action.call_args_list],
            [submission_id, submission_id],
        )

    def test_conflicting_payload_explains_conflict_and_preserves_submission_id(self) -> None:
        submission_id, _ = self._open_form()
        self.api.request_service_action.side_effect = PlatformAPIError("conflict", status_code=409)
        response, _ = self._post(submission_id)
        self.assertContains(response, "different details", status_code=409)
        self.assertContains(response, submission_id, status_code=409)
        self.assertContains(response, reverse("tickets:list"), status_code=409)

    def test_rate_limit_preserves_submission_id_and_propagates_feedback(self) -> None:
        submission_id, _ = self._open_form()
        self.api.request_service_action.side_effect = PlatformAPIError("limited", status_code=429, retry_after=25)
        with self.assertRaises(PlatformAPIError) as raised:
            self._post(submission_id)
        self.assertEqual(raised.exception.retry_after, 25)
        self.assertEqual(self._open_form()[0], submission_id)

    def test_reason_limits_and_required_actions_fail_without_submitting(self) -> None:
        submission_id, _ = self._open_form()
        invalid = [
            {"action": "activate"},
            {"action": "suspend_request", "reason": "  "},
            {"action": "cancel_request", "reason": ""},
            {"reason": "x" * 4001},
        ]
        for data in invalid:
            with self.subTest(data=str(data)[:100]):
                response, _ = self._post(submission_id, **data)
                self.assertEqual(response.status_code, 400)
                self.api.request_service_action.assert_not_called()
                self.assertIn(submission_id, response.content.decode())

    def test_missing_action_is_rejected_instead_of_defaulting_to_upgrade(self) -> None:
        submission_id, _ = self._open_form()
        request = self._request("post", {"submission_id": submission_id, "reason": "More storage"})
        response = service_request_action(request, service_id=55)
        self.assertEqual(response.status_code, 400)
        self.api.request_service_action.assert_not_called()

    def test_maintenance_and_unexpected_failures_keep_form_for_safe_retry(self) -> None:
        submission_id, _ = self._open_form()
        errors = (
            PlatformAPIError("maintenance", status_code=503, response_data={"error": "maintenance"}),
            PlatformAPIError("server error", status_code=500),
        )
        for error in errors:
            with self.subTest(status=error.status_code):
                self.api.request_service_action.side_effect = error
                response, _ = self._post(submission_id)
                self.assertContains(response, submission_id)
                self.assertContains(response, "More storage")
                self.assertEqual(self._open_form()[0], submission_id)

    def test_missing_plan_metadata_does_not_discard_bound_request_form(self) -> None:
        submission_id, _ = self._open_form()
        self.api.request_service_action.side_effect = PlatformAPIError("timeout", status_code=504)
        self.api.get_service_detail.return_value.pop("available_plans")
        response, _ = self._post(submission_id, reason="Requested plan: Plus")
        self.assertContains(response, submission_id)
        self.assertContains(response, "Requested plan: Plus")
        self.api.get_available_plans.assert_not_called()

    def test_post_detail_outage_retains_bound_form_without_submitting_action(self) -> None:
        submission_id, _ = self._open_form()
        self.api.get_available_plans.reset_mock()
        for status_code in (503, 502, 504, 500, None):
            with self.subTest(status_code=status_code):
                self.api.get_service_detail.side_effect = PlatformAPIError(
                    "Service unavailable", status_code=status_code, retry_after=45
                )
                response, _ = self._post(submission_id, action="cancel_request", reason="No longer needed")
                self.assertContains(response, submission_id, status_code=503)
                self.assertContains(response, "No longer needed", status_code=503)
                radios = _ActionRadioParser()
                radios.feed(response.content.decode())
                radios.close()
                self.assertIn("cancel_request", radios.radios)
                cancel_radio = radios.radios["cancel_request"]
                self.assertEqual(cancel_radio["name"], "action")
                self.assertEqual(cancel_radio["id"], "action_cancel_request")
                self.assertEqual(cancel_radio["class"], "sr-only peer")
                self.assertIn("checked", cancel_radio)
                self.assertContains(response, "Service details are temporarily unavailable", status_code=503)
                self.assertEqual(response.headers["Retry-After"], "45")
                self.assertNotContains(response, "Monthly Cost", status_code=503)
                self.api.request_service_action.assert_not_called()
                self.api.get_available_plans.assert_not_called()

        self.api.get_service_detail.side_effect = None
        response, _ = self._post(submission_id, action="cancel_request", reason="No longer needed")
        self.assertEqual(response.url, reverse("tickets:detail", kwargs={"ticket_id": 91}))
        self.assertEqual(self.api.request_service_action.call_args.kwargs["submission_id"], submission_id)

    def test_optional_empty_reason_and_maximum_reason_are_accepted(self) -> None:
        for reason in ("", "x" * 4000):
            with self.subTest(reason_length=len(reason)):
                submission_id, _ = self._open_form()
                response, _ = self._post(submission_id, reason=reason)
                self.assertEqual(response.status_code, 302)
                self.assertEqual(self.api.request_service_action.call_args.kwargs["reason"], reason)

    def test_missing_or_unrelated_submission_id_cannot_create_ticket(self) -> None:
        self._open_form()
        for submission_id in ("", str(uuid4()), "not-a-uuid"):
            with self.subTest(submission_id=submission_id):
                response, _ = self._post(submission_id)
                self.assertEqual(response.status_code, 409)
                self.api.request_service_action.assert_not_called()

    def test_submission_id_is_bound_to_current_customer_and_user(self) -> None:
        submission_id, _ = self._open_form()
        self.session["user_id"] = 8
        response, _ = self._post(submission_id)
        self.assertEqual(response.status_code, 409)
        self.api.request_service_action.assert_not_called()

    def test_viewer_cannot_open_or_submit_form(self) -> None:
        for role in ("viewer",):
            self.session["user_memberships"][0]["role"] = role
            for method in ("get", "post"):
                with self.subTest(role=role, method=method):
                    response = service_request_action(self._request(method), service_id=55)
                    self.assertEqual(response.status_code, 403)
                    self.api.request_service_action.assert_not_called()

    def test_owner_billing_and_tech_can_request_active_and_suspended_services(self) -> None:
        for role in ("owner", "billing", "tech"):
            self.session["user_memberships"][0]["role"] = role
            for status in ("active", "suspended"):
                with self.subTest(role=role, status=status):
                    self.api.get_service_detail.return_value["status"] = status
                    self._open_form()

    def test_technical_members_only_see_and_submit_upgrade_or_downgrade(self) -> None:
        self.session["user_memberships"][0]["role"] = "tech"
        submission_id, html = self._open_form()
        for action in ("suspend_request", "cancel_request"):
            with self.subTest(action=action):
                self.assertNotIn(f'id="action_{action}"', html)
                response, _ = self._post(submission_id, action=action)
                self.assertEqual(response.status_code, 403)
                self.api.request_service_action.assert_not_called()
        for action in ("upgrade_request", "downgrade_request"):
            submission_id, html = self._open_form()
            self.assertIn(f'id="action_{action}"', html)
            response, _ = self._post(submission_id, action=action)
            self.assertEqual(response.status_code, 302)

    def test_billing_members_can_submit_suspension_and_cancellation(self) -> None:
        self.session["user_memberships"][0]["role"] = "billing"
        for action in ("suspend_request", "cancel_request"):
            submission_id, html = self._open_form()
            self.assertIn(f'id="action_{action}"', html)
            response, _ = self._post(submission_id, action=action)
            self.assertEqual(response.status_code, 302)

    def test_inactive_services_cannot_open_or_submit_form(self) -> None:
        for status in ("pending", "provisioning", "failed", "terminated", "expired"):
            self.api.get_service_detail.return_value["status"] = status
            for method in ("get", "post"):
                with self.subTest(status=status, method=method):
                    response = service_request_action(self._request(method), service_id=55)
                    self.assertEqual(response.status_code, 403)
                    self.api.request_service_action.assert_not_called()

    def test_missing_identity_redirects_before_calling_platform(self) -> None:
        self.session.pop("user_id")
        response = service_request_action(self._request(), service_id=55)
        self.assertEqual(response.url, "/login/")
        self.api.get_service_detail.assert_not_called()
        self.api.request_service_action.assert_not_called()

    def test_csrf_is_required_before_submitting_request(self) -> None:
        request = self._request("post")
        request._dont_enforce_csrf_checks = False
        response = service_request_action(request, service_id=55)
        self.assertEqual(response.status_code, 403)
        self.api.request_service_action.assert_not_called()

    def test_unsupported_methods_do_not_submit_requests(self) -> None:
        response = service_request_action(self._request("delete"), service_id=55)
        self.assertEqual(response.status_code, 405)
        self.api.request_service_action.assert_not_called()

    def test_detail_hides_all_action_links_for_restricted_role_or_status(self) -> None:
        cases = (
            ("owner", "active", True),
            ("tech", "suspended", True),
            ("viewer", "active", False),
            ("billing", "active", True),
            ("owner", "terminated", False),
        )
        for role, status, allowed in cases:
            with self.subTest(role=role, status=status):
                self.session["user_memberships"][0]["role"] = role
                self.api.get_service_detail.return_value["status"] = status
                response = service_detail(self._request(), service_id=55)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.path in response.content.decode(), allowed)

    def test_available_plans_are_informational_and_form_has_reason_limit(self) -> None:
        _, html = self._open_form()
        self.assertIn("Plus", html)
        self.assertIn("20,00 EUR", html)
        self.assertIn("Include your preferred plan in the reason", html)
        self.assertIn('maxlength="4000"', html)
        self.assertNotIn("hover:border-blue-500 transition-colors cursor-pointer", html)
        form_html = html.split('<form id="service-request-form"', 1)[1].split("</form>", 1)[0]
        self.assertNotIn("Approve", form_html)
        self.assertNotIn("Reject", form_html)
