"""An audit event with no object has no object: it is never filed under a user.

Object-less events used to be stored with the User content type and the actor's id, or "1" when
there was no actor. Anything that selects a person's events by object would then take every
actor-less event as user 1's, and a staff member's own object-less actions as events about them.
"""

from __future__ import annotations

import json

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import Client, TestCase
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.audit.services import AuditRetentionService, AuditService, SecurityAuditService
from apps.audit.siem import SIEMService
from apps.common.validators import log_security_event

User = get_user_model()


def _user_with_pk_one() -> object:
    """The first user of a fresh database, usually the founding administrator."""
    existing = User.objects.filter(pk=1).first()
    if existing is not None:
        return existing
    return User.objects.create_user(id=1, email="founder@example.com", password="x-pass-123")


class ObjectlessEventsHaveNoObjectTests(TestCase):
    def test_an_object_less_event_is_not_filed_under_a_user(self) -> None:
        actor = User.objects.create_user(email="actor@example.com", password="x-pass-123")

        with_actor = AuditService.log_simple_event("login_success", user=actor, description="signed in")
        without_actor = AuditService.log_simple_event("system_maintenance", description="nightly job")
        log_security_event("suspicious_activity", {"reason": "probe"}, request_ip="203.0.113.9")
        security = AuditEvent.objects.get(action="suspicious_activity")

        for event in (with_actor, without_actor, security):
            event.refresh_from_db()
            self.assertIsNone(event.content_type_id, event.action)
            self.assertEqual(event.object_id, "", event.action)
        self.assertEqual(with_actor.user, actor, "the actor is still recorded as the actor")

    def test_no_event_is_filed_under_user_one(self) -> None:
        founder = _user_with_pk_one()
        user_type = ContentType.objects.get_for_model(User)

        AuditService.log_simple_event("system_maintenance", description="no actor, no object")
        SecurityAuditService.log_rate_limit_event(
            {
                "endpoint": "/api/login",
                "ip_address": "198.51.100.4",
                "user_agent": "probe",
                "rate_limit_key": "ip:198.51.100.4",
                "rate_limit_rate": "5/min",
            }
        )
        about_founder = AuditService.log_simple_event(
            "profile_updated", content_object=founder, description="an event really about user 1"
        )

        filed_under_founder = AuditEvent.objects.filter(content_type=user_type, object_id=str(founder.pk))
        self.assertEqual(list(filed_under_founder), [about_founder])

    def test_the_readers_handle_an_object_less_event(self) -> None:
        admin = User.objects.create_user(
            email="admin@example.com", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        event = AuditService.log_simple_event("system_maintenance", description="no object at all")

        self.assertIn("system_maintenance", str(event))
        entry = SIEMService()._create_log_entry(event)
        self.assertIsNone(entry.target_type)
        self.assertFalse(AuditRetentionService._is_financial_record(event))
        self.assertEqual(AuditRetentionService._anonymize_events([event]), 1)

        client = Client()
        client.force_login(admin)
        exported = client.get(reverse("audit:export_logs"), {"format": "json"})
        self.assertEqual(exported.status_code, 200)
        rows = json.loads(b"".join(exported.streaming_content) if exported.streaming else exported.content)
        exported_event = next(row for row in rows["audit_events"] if row["action"] == "system_maintenance")
        self.assertEqual(exported_event["content_type"], {"app_label": None, "model": None})
        self.assertEqual(exported_event["object_id"], "")
        self.assertEqual(client.get(reverse("audit:export_logs"), {"format": "csv"}).status_code, 200)
        self.assertEqual(client.get(reverse("audit:logs_list")).status_code, 200)
        self.assertEqual(client.get(reverse("audit:event_detail", args=[event.pk])).status_code, 200)
