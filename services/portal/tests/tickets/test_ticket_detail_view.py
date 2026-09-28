"""Ticket details render the related service returned by Platform."""

import time
from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "ticket-detail-service",
        },
    },
)
class TicketDetailViewTests(SimpleTestCase):
    def setUp(self) -> None:
        now = timezone.now()
        session = self.client.session
        session.update({
            "user_id": 7,
            "customer_id": 1,
            "selected_customer_id": 1,
            "user_memberships": [{"customer_id": 1, "role": "owner"}],
            "user_memberships_fetched_at": time.time(),
            "session_auth_hash": "test-session",
            "validated_at": now.isoformat(),
            "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
        })
        session.save()

    def test_related_service_link_is_rendered(self) -> None:
        with patch("apps.tickets.views.tickets_api.get_ticket_detail") as platform:
            platform.return_value = {
                "success": True,
                "data": {"ticket": {
                    "id": 12, "title": "Hosting question", "status": "open", "comments": [],
                    "related_service": 5, "related_service_name": "web.example.com - Acme",
                }},
            }
            response = self.client.get(reverse("tickets:detail", kwargs={"ticket_id": 12}))
        self.assertContains(response, reverse("services:detail", kwargs={"service_id": 5}))
        self.assertContains(response, "web.example.com - Acme")

    def test_absent_related_service_hides_link(self) -> None:
        with patch("apps.tickets.views.tickets_api.get_ticket_detail") as platform:
            platform.return_value = {
                "success": True,
                "data": {"ticket": {
                    "id": 12, "title": "Hosting question", "status": "open", "comments": [],
                    "related_service": None, "related_service_name": "web.example.com - Acme",
                }},
            }
            response = self.client.get(reverse("tickets:detail", kwargs={"ticket_id": 12}))
        self.assertNotContains(response, reverse("services:detail", kwargs={"service_id": 5}))
        self.assertNotContains(response, "web.example.com - Acme")
