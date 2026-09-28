"""Service action views retain user identity and link the resulting support ticket."""

import json
import time
from datetime import timedelta
from unittest.mock import Mock, patch

from django.contrib.messages import get_messages
from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

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
        with patch("apps.services.views.services_api") as platform:
            platform.request_service_action.return_value = {
                "success": True,
                "data": {"request_id": "TK-123", "ticket_id": 42, "action": "cancel_request"},
            }
            response = self.client.post(
                reverse("services:request_action", kwargs={"service_id": 5}),
                {"action": "cancel_request", "reason": "moving"},
            )
        self.assertEqual(platform.request_service_action.call_args.kwargs, {
            "customer_id": 1, "user_id": 7, "service_id": 5, "action": "cancel_request", "reason": "moving",
        })
        self.assertRedirects(
            response, reverse("services:detail", kwargs={"service_id": 5}), fetch_redirect_response=False
        )
        message = " ".join(str(item) for item in get_messages(response.wsgi_request))
        self.assertIn("TK-123", message)
        self.assertIn(f'href="{reverse("tickets:detail", kwargs={"ticket_id": 42})}"', message)

    def test_viewer_is_denied(self) -> None:
        self._session("viewer")
        with patch("apps.services.views.services_api"):
            response = self.client.post(
                reverse("services:request_action", kwargs={"service_id": 5}),
                {"action": "cancel_request", "reason": "moving"},
            )
        self.assertEqual(response.status_code, 403)

    def test_client_includes_user_in_signed_body(self) -> None:
        envelope = {
            "success": True,
            "data": {"request_id": "TK-123", "ticket_id": 42, "action": "cancel_request"},
        }
        upstream = Mock(status_code=201, headers={})
        upstream.json.return_value = envelope
        with patch("apps.api_client.services.portal_request", return_value=upstream) as transport:
            result = ServicesAPIClient().request_service_action(
                customer_id=1, user_id=7, service_id=5, action="cancel_request", reason="moving"
            )
        self.assertEqual(result, envelope)
        payload = json.loads(transport.call_args.kwargs["data"])
        self.assertEqual(payload["user_id"], 7)
        self.assertEqual(payload["customer_id"], 1)
        self.assertEqual(payload["action"], "cancel_request")
        self.assertEqual(payload["reason"], "moving")

    def test_success_link_escapes_request_id(self) -> None:
        with patch("apps.services.views.services_api") as platform:
            platform.request_service_action.return_value = {
                "success": True, "data": {"request_id": "<script>alert(1)</script>", "ticket_id": 42},
            }
            response = self.client.post(
                reverse("services:request_action", kwargs={"service_id": 5}),
                {"action": "cancel_request", "reason": "moving"},
            )
        self.assertEqual(response.status_code, 302)
        message = " ".join(str(item) for item in get_messages(response.wsgi_request))
        self.assertIn("&lt;script&gt;", message)
        self.assertNotIn("<script>", message)
