"""
End-to-end audit trail tests.

Verifies the full HTTP request → signal → AuditService → AuditEvent pipeline
for critical business flows using Django's test client.
"""

from __future__ import annotations

import json

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.settings.models import SystemSetting
from tests.factories.core_factories import create_staff_user


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestSettingsAPIAuditTrail(TestCase):
    """Full HTTP → settings model → signal → AuditEvent pipeline."""

    def setUp(self) -> None:
        self.staff = create_staff_user(username="audit_staff", staff_role="admin")
        self.client.force_login(self.staff)

        # Create a setting that can be updated via API
        self.setting = SystemSetting.objects.create(
            key="test.e2e_setting",
            name="E2E Test Setting",
            description="Setting for E2E audit test",
            data_type="string",
            value="initial",
            default_value="default",
        )
        # Clear events from setup
        AuditEvent.objects.all().delete()

    def test_update_setting_via_api_creates_audit_event(self) -> None:
        """POST /settings/api/ → SystemSetting.save() → AuditEvent."""
        response = self.client.post(
            "/settings/api/",
            data=json.dumps({
                "key": "test.e2e_setting",
                "value": "updated_via_api",
                "reason": "E2E audit test",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200, response.content)

        ct = ContentType.objects.get_for_model(SystemSetting)
        events = AuditEvent.objects.filter(
            content_type=ct,
            object_id=str(self.setting.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent after updating setting via API")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestModelSaveAuditTrail(TestCase):
    """Model save in a request-like context → AuditEvent pipeline."""

    def test_system_setting_create_produces_audit_event(self) -> None:
        """Direct model save → signal → AuditEvent (regression guard)."""
        AuditEvent.objects.all().delete()

        SystemSetting.objects.create(
            key="test.e2e_direct",
            name="E2E Direct Create",
            description="Direct create test",
            data_type="boolean",
            value=True,
            default_value=False,
        )

        ct = ContentType.objects.get_for_model(SystemSetting)
        events = AuditEvent.objects.filter(content_type=ct)
        self.assertTrue(events.exists(), "No AuditEvent for direct SystemSetting.create")

        event = events.first()
        self.assertIn("test.e2e_direct", event.metadata.get("setting_key", ""))

    def test_customer_create_produces_audit_event(self) -> None:
        """Customer creation → signal → AuditEvent."""
        from apps.customers.models import Customer

        AuditEvent.objects.all().delete()

        customer = Customer.objects.create(
            company_name="E2E Audit Test SRL",
            customer_type="business",
            status="active",
        )

        ct = ContentType.objects.get_for_model(Customer)
        events = AuditEvent.objects.filter(
            content_type=ct,
            object_id=str(customer.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent for Customer.create")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestInvoiceCreationAuditTrail(TestCase):
    """Invoice creation → signal → AuditEvent pipeline."""

    def test_invoice_create_produces_audit_event(self) -> None:
        """Creating an Invoice must produce at least one AuditEvent."""
        from apps.billing.models import Currency, Invoice
        from apps.customers.models import Customer

        AuditEvent.objects.all().delete()

        currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "L", "decimals": 2}
        )
        customer = Customer.objects.create(
            company_name="E2E Invoice Test SRL",
            customer_type="business",
            status="active",
        )
        invoice = Invoice.objects.create(
            customer=customer,
            currency=currency,
            number="INV-E2E-001",
            status="draft",
            total_cents=10000,
        )

        ct = ContentType.objects.get_for_model(Invoice)
        events = AuditEvent.objects.filter(
            content_type=ct,
            object_id=str(invoice.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent for Invoice creation")
