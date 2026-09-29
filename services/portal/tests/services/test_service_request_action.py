"""Service action views retain user identity and link the resulting support ticket."""

import json
import time
from datetime import timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

from django.contrib.messages import get_messages
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.html import escape

from apps.services.services import ServicesAPIClient


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "service-action-view",
        },
    },
)
class ServiceRequestActionTests(SimpleTestCase):
    def setUp(self) -> None:
        self._session("owner")
        self.path = reverse("services:request_action", kwargs={"service_id": 5})
        self.receipt = {"request_id": str(uuid4()), "ticket_id": 42, "ticket_number": "TK-123"}
        api_patch = patch("apps.services.views.services_api")
        self.platform = api_patch.start()
        self.addCleanup(api_patch.stop)
        self.platform.get_service_detail.return_value = {
            "id": 5, "status": "active", "service_name": "Example Hosting", "monthly_price": "10.00",
        }
        self.platform.get_available_plans.return_value = []
        self.platform.request_service_action.return_value = self.receipt

    def _open_form(self) -> str:
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200)
        return response.context["submission_id"]

    def _session(self, role: str) -> None:
        now = timezone.now()
        session = self.client.session
        session.update({
            "user_id": 7,
            "customer_id": 1,
            "selected_customer_id": 1,
            "user_memberships": [{"customer_id": 1, "role": role}],
            "user_memberships_fetched_at": time.time(),
            "session_auth_hash": "test-session",
            "validated_at": now.isoformat(),
            "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
        })
        session.save()

    def test_owner_request_passes_user_id_and_links_ticket(self) -> None:
        submission_id = self._open_form()
        response = self.client.post(
            self.path,
            {"action": "cancel_request", "reason": "moving", "submission_id": submission_id},
        )
        self.assertEqual(self.platform.request_service_action.call_args.kwargs, {
            "customer_id": 1, "user_id": 7, "service_id": 5, "action": "cancel_request", "reason": "moving",
            "submission_id": submission_id,
        })
        self.assertRedirects(
            response, reverse("tickets:detail", kwargs={"ticket_id": 42}), fetch_redirect_response=False
        )
        message = " ".join(str(item) for item in get_messages(response.wsgi_request))
        self.assertIn("TK-123", message)
        self.assertNotIn("<a", message)

    def test_viewer_is_denied(self) -> None:
        self._session("viewer")
        with patch("apps.services.views.services_api"):
            response = self.client.post(
                reverse("services:request_action", kwargs={"service_id": 5}),
                {"action": "cancel_request", "reason": "moving"},
            )
        self.assertEqual(response.status_code, 403)

    def test_client_includes_user_in_signed_body(self) -> None:
        submission_id = str(uuid4())
        envelope = {"success": True, "data": self.receipt}
        upstream = Mock(status_code=201, headers={})
        upstream.json.return_value = envelope
        with patch("apps.api_client.services.portal_request", return_value=upstream) as transport:
            result = ServicesAPIClient().request_service_action(
                customer_id=1, user_id=7, service_id=5, action="cancel_request", reason="moving",
                submission_id=submission_id,
            )
        self.assertEqual(result, self.receipt)
        payload = json.loads(transport.call_args.kwargs["data"])
        self.assertEqual(payload["user_id"], 7)
        self.assertEqual(payload["customer_id"], 1)
        self.assertEqual(payload["action"], "cancel_request")
        self.assertEqual(payload["reason"], "moving")
        self.assertEqual(payload["submission_id"], submission_id)

    def test_success_message_escapes_ticket_number_when_rendered(self) -> None:
        submission_id = self._open_form()
        self.platform.request_service_action.return_value = self.receipt | {
            "ticket_number": "<script>alert(1)</script>",
        }
        response = self.client.post(
            self.path, {"action": "cancel_request", "reason": "moving", "submission_id": submission_id},
        )
        self.assertRedirects(
            response, reverse("tickets:detail", kwargs={"ticket_id": 42}), fetch_redirect_response=False,
        )
        rendered = self.client.get(self.path)
        self.assertContains(rendered, escape("<script>alert(1)</script>"))
        self.assertNotContains(rendered, "<script>alert(1)</script>")
