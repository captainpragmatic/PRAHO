"""Rejected commercial identities remain valid, classified audit obligations."""

from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.common.validators import log_security_event


@override_settings(AUDIT_CHAIN_ENABLED=False)
class PlanChangeSecurityActionTests(TestCase):
    def test_rejected_payment_binding_reaches_the_security_review_queue(self) -> None:
        log_security_event("plan_change_payment_binding_rejected", {"attempt_id": "synthetic-attempt"})
        event = AuditEvent.objects.get(action="plan_change_payment_binding_rejected")
        self.assertEqual((event.category, event.severity), ("security_event", "high"))
        self.assertTrue(event.requires_review)
        self.assertTrue(event.is_sensitive)

    def test_changed_submission_is_recorded_without_creating_an_urgent_review(self) -> None:
        log_security_event("plan_change_submission_conflict", {"submission_id": "synthetic-submission"})
        event = AuditEvent.objects.get(action="plan_change_submission_conflict")
        self.assertEqual((event.category, event.severity), ("security_event", "medium"))
        self.assertFalse(event.requires_review)
