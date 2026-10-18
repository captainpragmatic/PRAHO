"""One classifier for audit events (rows 39, 40, 50): the action classifies, metadata never does."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

from django.test import SimpleTestCase, TestCase

from apps.audit.actor_context import acting_as
from apps.audit.classification import ACTION_OVERRIDES, SEVERITIES, Classification, classify
from apps.audit.models import AuditEvent, CookieConsent, audit_mutation_allowed
from apps.audit.services import AuditContext, AuditEventData, AuditService, serialize_metadata
from apps.audit.signals import cookie_consent_updated
from apps.customers.models import Customer
from apps.promotions.signals import create_audit_event as create_promotion_audit_event
from apps.tickets.models import SupportCategory, Ticket
from apps.users.models import CustomerMembership, User

CLASSIFICATION_KEYS = ("category", "severity", "is_sensitive", "requires_review")

# What each action a model receiver writes was stored as before the receivers stopped writing a
# classification of their own into metadata: (category, severity, is_sensitive, requires_review).
# Severity and review never change.
RECEIVER_ACTIONS: dict[str, tuple[str, str, bool, bool]] = {
    "email_changed": ("account_management", "medium", True, False),
    "name_changed": ("account_management", "medium", True, False),
    "phone_updated": ("account_management", "medium", True, False),
    "staff_role_changed": ("authorization", "high", True, True),
    "2fa_enabled": ("authentication", "medium", True, False),
    "2fa_disabled": ("authentication", "high", True, True),
    "marketing_consent_granted": ("privacy", "high", True, False),
    "marketing_consent_withdrawn": ("privacy", "high", True, True),
    "language_preference_changed": ("business_operation", "low", False, False),
    "timezone_changed": ("business_operation", "low", False, False),
    "notification_settings_changed": ("business_operation", "low", False, False),
    "emergency_contact_updated": ("business_operation", "low", False, False),
    "profile_updated": ("account_management", "medium", True, False),
    "customer_membership_created": ("authorization", "medium", True, False),
    "customer_membership_updated": ("authorization", "medium", True, False),
    "customer_membership_deleted": ("authorization", "high", True, True),
    "customer_role_changed": ("authorization", "high", True, True),
    "primary_customer_changed": ("business_operation", "low", False, False),
    "cookie_consent_updated": ("privacy", "high", True, False),
}

# Severity and review flags writers used to pass in event metadata, where they overrode the
# classification: (severity, requires_review).
WRITER_FLAGS: dict[str, tuple[str, bool]] = {
    "coupon_reversal_failed_on_cancellation": ("high", True),
    "coupon_reversal_failed_on_refund": ("high", True),
    "gift_card_reversal_failed_on_cancellation": ("high", True),
    "gift_card_reversal_failed_on_refund": ("high", True),
    "promotion_release_blocked_anomalous_payments": ("high", True),
    "domain_operation_review_required": ("low", True),
    "virtualmin_chain_backup_alert": ("high", True),
    "virtualmin_chain_schedule_deferred": ("high", True),
    "virtualmin_pair_release_abandoned": ("high", True),
    "virtualmin_server_autofail_deferred": ("high", True),
    "virtualmin_server_health_alert": ("high", True),
    "virtualmin_migration_needs_review": ("low", True),
    "virtualmin_migration_started": ("low", False),
    "virtualmin_migration_completed": ("low", False),
    "node_drain_paused": ("high", True),
    "node_drain_started": ("low", False),
    "node_drain_finalized": ("low", False),
    "refund_reconciliation_gap": ("critical", False),
    "security_bnr_outbound_blocked": ("high", True),
    "2fa_admin_reset": ("high", True),
    "2fa_disabled": ("high", True),
    "2fa_verification_failed": ("medium", False),
    "2fa_backup_code_used": ("medium", False),
}


class EveryFlagIsPreservedTests(SimpleTestCase):
    def test_a_receiver_event_keeps_its_stored_classification(self) -> None:
        for action, expected in RECEIVER_ACTIONS.items():
            with self.subTest(action=action):
                self.assertEqual(_tuple(classify(action)), expected)

    def test_a_writer_keeps_the_severity_and_review_flag_it_used_to_pass_in_metadata(self) -> None:
        for action, (severity, review) in WRITER_FLAGS.items():
            with self.subTest(action=action):
                result = classify(action)
                self.assertEqual((result.severity, result.requires_review), (severity, review))

    def test_data_anonymization_completed_stays_a_privacy_event(self) -> None:
        self.assertEqual(classify("data_anonymization_completed").category, "privacy")

    def test_infrastructure_actions_are_system_admin_events(self) -> None:
        for action in ("node_deployment_failed", "drift_detected", "cloud_provider_created", "node_size_created"):
            with self.subTest(action=action):
                self.assertEqual(classify(action).category, "system_admin")
        self.assertNotEqual(classify("node_drain_started").category, "system_admin")

    def test_every_override_names_a_known_field_and_value(self) -> None:
        fields = {"category", "severity", "is_sensitive", "requires_review"}
        for action, override in ACTION_OVERRIDES.items():
            with self.subTest(action=action):
                self.assertLessEqual(set(override), fields)
                if "severity" in override:
                    self.assertIn(override["severity"], SEVERITIES)

    def test_explicit_event_facts_are_validated(self) -> None:
        self.assertEqual(classify("coupon_updated", severity="medium", is_sensitive=True).severity, "medium")
        with self.assertLogs("apps.audit.classification", level="ERROR"):
            self.assertEqual(classify("coupon_updated", severity="catastrophic").severity, "low")


def _tuple(result: Classification) -> tuple[str, str, bool, bool]:
    return (result.category, result.severity, result.is_sensitive, result.requires_review)


class MetadataNeverClassifiesTests(TestCase):
    def test_keys_in_metadata_do_not_override_the_classification(self) -> None:
        event = AuditService.log_simple_event(
            "login_success",
            metadata={
                "category": "system_admin",
                "severity": "critical",
                "requires_review": True,
                "is_sensitive": False,
            },
        )
        self.assertEqual(
            (event.category, event.severity, event.requires_review, event.is_sensitive),
            ("authentication", "medium", False, True),
        )

    def test_an_explicit_severity_and_sensitivity_travel_as_arguments(self) -> None:
        event = AuditService.log_simple_event("coupon_updated", severity="medium", is_sensitive=True)
        self.assertEqual((event.severity, event.is_sensitive), ("medium", True))
        event = AuditService.log_event(
            AuditEventData(event_type="coupon_updated"), AuditContext(metadata={"severity": "critical"})
        )
        self.assertEqual(event.severity, "low")

    def test_promotion_events_keep_their_own_severity_and_sensitivity(self) -> None:
        user = User.objects.create_user(email="promo-actor@example.com", password="pw", staff_role="admin")
        with acting_as(user):
            event = create_promotion_audit_event(
                action="coupon_updated", instance=user, severity="medium", is_sensitive=True
            )
        self.assertEqual((event.severity, event.is_sensitive, event.user), ("medium", True, user))
        self.assertFalse(any(key in event.metadata for key in ("severity", "is_sensitive", "category")))

    def test_cookie_consent_is_classified_as_privacy_on_every_path(self) -> None:
        consent = CookieConsent.objects.create(cookie_id="classification-cookie", status="accepted")
        cookie_consent_updated.send(sender=CookieConsent, consent=consent)
        from_signal = AuditEvent.objects.filter(action="cookie_consent_updated").latest("timestamp")
        from_service = AuditService.log_simple_event("cookie_consent_updated")

        for event in (from_signal, from_service):
            self.assertEqual(
                (event.category, event.severity, event.is_sensitive, event.requires_review),
                ("privacy", "high", True, False),
            )

    def test_ticket_metadata_names_its_category_ticket_category(self) -> None:
        customer = Customer.objects.create(name="Ticket Co", customer_type="individual", status="active")
        category = SupportCategory.objects.create(name="Billing questions", name_en="Billing questions")
        ticket = Ticket.objects.create(
            customer=customer, category=category, title="Help", description="x", contact_email="x@example.test"
        )

        event = AuditEvent.objects.get(action="support_ticket_created", object_id=str(ticket.pk))
        self.assertEqual(event.metadata["ticket_category"], "Billing questions")
        self.assertNotIn("category", event.metadata)
        self.assertEqual(event.category, "business_operation")


class ReceiverEventsStoreTheMappedClassificationTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_user(email="class-admin@example.com", password="pw", staff_role="admin")
        self.subject = User.objects.create_user(
            email="class-subject@example.com", password="pw", staff_role="support", first_name="A", last_name="B"
        )
        self.customer = Customer.objects.create(company_name="Class Co", customer_type="business", status="active")
        self.membership = CustomerMembership.objects.create(user=self.subject, customer=self.customer, role="viewer")
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.all().delete()

    def test_signal_events_store_the_classification_and_no_classification_keys(self) -> None:
        with acting_as(self.admin):
            self.subject.staff_role = "billing"
            self.subject.first_name = "C"
            self.subject.save()
            self.membership.role = "owner"
            self.membership.save()
            self.membership.delete()

        seen = {e.action: e for e in AuditEvent.objects.all()}
        for action in ("staff_role_changed", "name_changed", "customer_role_changed", "customer_membership_deleted"):
            with self.subTest(action=action):
                event = seen[action]
                self.assertEqual(
                    (event.category, event.severity, event.is_sensitive, event.requires_review),
                    RECEIVER_ACTIONS[action],
                )
                for key in CLASSIFICATION_KEYS:
                    self.assertNotIn(key, event.metadata)
                self.assertTrue(event.metadata["audit_signal"])


class OneBadValueTests(SimpleTestCase):
    def test_one_bad_value_keeps_the_rest_of_the_evidence(self) -> None:
        class Opaque:
            __slots__ = ()

            def __repr__(self) -> str:
                return "<Opaque handle>"

        result = serialize_metadata(
            {
                "customer_id": "42",
                "amount": Decimal("10.50"),
                "at": datetime(2026, 10, 18, tzinfo=UTC),
                "handle": Opaque(),
                "nested": {"ok": 1, "bad": Opaque()},
                "items": [1, Opaque(), 3],
            }
        )

        self.assertEqual(result["customer_id"], "42")
        self.assertEqual(result["amount"], "10.50")
        self.assertEqual(result["at"], "2026-10-18T00:00:00+00:00")
        self.assertIn("Opaque", result["handle"])
        self.assertEqual(result["nested"]["ok"], 1)
        self.assertIn("Opaque", result["nested"]["bad"])
        self.assertEqual([result["items"][0], result["items"][2]], [1, 3])
        self.assertEqual(sorted(result["unserializable_keys"]), ["handle", "items", "nested"])
        json.dumps(result)  # storable as it is

    def test_sets_are_stored_as_sorted_lists(self) -> None:
        result = serialize_metadata({"roles": {"viewer", "owner"}, "ids": frozenset({3, 1, 2})})
        self.assertEqual(result, {"roles": ["owner", "viewer"], "ids": [1, 2, 3]})

    def test_a_circular_value_does_not_cost_the_other_keys(self) -> None:
        loop: dict[str, object] = {}
        loop["self"] = loop
        result = serialize_metadata({"kept": "yes", "loop": loop})
        self.assertEqual(result["kept"], "yes")
        self.assertIn("loop", result["unserializable_keys"])
