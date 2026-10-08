"""Audit failures preserve user and membership changes."""

from unittest.mock import patch

from django.db import transaction
from django.test import override_settings

from apps.audit.models import AuditEvent
from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from tests.common._signal_isolation import SignalIsolationTestCase


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class AuditSignalIsolationTests(SignalIsolationTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="isolation@example.com", password="test")
        self.customer = Customer.objects.create(name="Isolation", primary_email="customer@example.com")

    def test_membership_creation_survives_failed_audit_write(self) -> None:
        membership = self.run_effect(
            "apps.audit.signals.AuditService.log_event",
            lambda: CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner"),
        )
        self.assertTrue(CustomerMembership.objects.filter(pk=membership.pk).exists())

    def test_user_change_survives_failed_audit_write(self) -> None:
        self.user.first_name = "Persisted"
        self.run_effect(
            "apps.audit.signals.AuditService.log_event",
            lambda: self.user.save(update_fields=["first_name"]),
        )
        self.assertEqual(User.objects.get(pk=self.user.pk).first_name, "Persisted")

    def test_failed_role_audit_preserves_primary_audit(self) -> None:
        membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="viewer")
        real_log = AuditService.log_event

        def fail_role(data: AuditEventData, context: AuditContext | None = None) -> AuditEvent | None:
            if data.event_type == "customer_role_changed":
                self.fail_write()
                return None
            return real_log(data, context)

        membership.role = "owner"
        membership.is_primary = True
        with patch.object(AuditService, "log_event", side_effect=fail_role), transaction.atomic():
            membership.save(update_fields=["role", "is_primary"])
        persisted = CustomerMembership.objects.get(pk=membership.pk)
        self.assertEqual(persisted.role, "owner")
        self.assertTrue(persisted.is_primary)
        self.assertTrue(
            AuditEvent.objects.filter(action="primary_customer_changed", object_id=str(membership.pk)).exists()
        )
