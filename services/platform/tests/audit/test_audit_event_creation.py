"""
Integration tests: signal → AuditService → AuditEvent pipeline.

Verifies that saving/deleting critical models actually creates AuditEvent
records in the database. This proves the full pipeline works end-to-end.
"""

from __future__ import annotations

import hashlib

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.billing.models import Currency, Invoice, Payment
from apps.common.validators import log_security_event
from apps.notifications.models import EmailPreference, EmailSuppression, EmailTemplate
from apps.settings.models import SystemSetting
from tests.factories.core_factories import CustomerCreationRequest, create_full_customer


def _get_ron() -> Currency:
    """Create or get the RON currency for tests."""
    currency, _ = Currency.objects.get_or_create(
        code="RON", defaults={"name": "Romanian Leu", "symbol": "L", "decimals": 2}
    )
    return currency


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestSystemSettingAuditEvent(TestCase):
    """SystemSetting save/delete → AuditEvent creation."""

    def test_create_system_setting_produces_audit_event(self) -> None:
        setting = SystemSetting.objects.create(
            key="test.audit_integration",
            name="Test Audit Integration",
            description="Integration test setting",
            data_type="string",
            value="test_value",
            default_value="default",
        )

        ct = ContentType.objects.get_for_model(SystemSetting)
        events = AuditEvent.objects.filter(
            content_type=ct,
            object_id=str(setting.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent created for SystemSetting.create")

    def test_update_system_setting_produces_audit_event(self) -> None:
        setting = SystemSetting.objects.create(
            key="test.update_audit",
            name="Test Update Audit",
            description="Update test",
            data_type="string",
            value="old_value",
            default_value="default",
        )

        # Clear events from creation
        ct = ContentType.objects.get_for_model(SystemSetting)
        AuditEvent.objects.filter(content_type=ct, object_id=str(setting.pk)).delete()

        # Update
        setting.value = "new_value"
        setting.save()

        events = AuditEvent.objects.filter(
            content_type=ct,
            object_id=str(setting.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent created for SystemSetting.update")

    def test_delete_system_setting_produces_audit_event(self) -> None:
        setting = SystemSetting.objects.create(
            key="test.delete_audit",
            name="Test Delete Audit",
            description="Delete test",
            data_type="string",
            value="value",
            default_value="default",
        )
        setting_pk = str(setting.pk)
        setting.delete()

        ct = ContentType.objects.get_for_model(SystemSetting)
        events = AuditEvent.objects.filter(
            content_type=ct,
            object_id=setting_pk,
            action="delete",
        )
        self.assertTrue(events.exists(), "No AuditEvent created for SystemSetting.delete")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestEmailSuppressionAuditEvent(TestCase):
    """EmailSuppression save → AuditEvent creation (data protection)."""

    def test_create_email_suppression_produces_audit_event(self) -> None:
        suppression = EmailSuppression.objects.create(
            email_hash=hashlib.sha256(b"test@example.com").hexdigest(),
            reason="hard_bounce",
        )

        events = AuditEvent.objects.filter(
            action="email_suppression_added",
            metadata__suppression_id=str(suppression.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent for EmailSuppression.create")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestEmailPreferenceAuditEvent(TestCase):
    """EmailPreference create → AuditEvent creation (GDPR consent tracking)."""

    def test_create_email_preference_produces_audit_event(self) -> None:
        customer = create_full_customer(
            CustomerCreationRequest(
                with_tax_profile=False,
                with_billing_profile=False,
            )
        )
        # Signal auto-creates EmailPreference on Customer create — check if it exists
        pref = EmailPreference.objects.filter(customer=customer).first()
        if pref is None:
            pref = EmailPreference.objects.create(
                customer=customer,
                marketing=True,
            )

        events = AuditEvent.objects.filter(
            action="notification_preference_created",
            metadata__preference_id=str(pref.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent for EmailPreference.create")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestEmailTemplateAuditEvent(TestCase):
    """EmailTemplate update/delete → AuditEvent creation."""

    def test_update_email_template_produces_audit_event(self) -> None:
        template = EmailTemplate.objects.create(
            key="test_audit_template",
            locale="en",
            subject="Test Subject",
            body_html="<p>Test</p>",
            body_text="Test",
            version=1,
        )

        # Update triggers audit (create does not for templates)
        template.subject = "Updated Subject"
        template.save()

        events = AuditEvent.objects.filter(
            action="email_template_updated",
            metadata__template_key=template.key,
            metadata__locale=template.locale,
        )
        self.assertTrue(events.exists(), "No AuditEvent for EmailTemplate.update")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestInvoiceAuditEvent(TestCase):
    """Invoice save → AuditEvent creation."""

    def test_create_invoice_produces_audit_event(self) -> None:
        customer = create_full_customer(
            CustomerCreationRequest(
                with_tax_profile=False,
                with_billing_profile=False,
            )
        )
        currency = _get_ron()
        invoice = Invoice.objects.create(
            customer=customer,
            currency=currency,
            number="INV-AUDIT-001",
            status="draft",
            total_cents=10000,
            tax_cents=1597,
            subtotal_cents=8403,
        )

        ct = ContentType.objects.get_for_model(Invoice)
        events = AuditEvent.objects.filter(
            content_type=ct,
            object_id=str(invoice.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent for Invoice.create")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestPaymentAuditEvent(TestCase):
    """Payment save → AuditEvent creation."""

    def test_create_payment_produces_audit_event(self) -> None:
        customer = create_full_customer(
            CustomerCreationRequest(
                with_tax_profile=False,
                with_billing_profile=False,
            )
        )
        currency = _get_ron()
        invoice = Invoice.objects.create(
            customer=customer,
            currency=currency,
            number="INV-AUDIT-PAY-001",
            status="draft",
            total_cents=10000,
        )
        payment = Payment.objects.create(
            customer=customer,
            invoice=invoice,
            currency=currency,
            amount_cents=10000,
            status="pending",
            payment_method="stripe",
        )

        ct = ContentType.objects.get_for_model(Payment)
        events = AuditEvent.objects.filter(
            content_type=ct,
            object_id=str(payment.pk),
        )
        self.assertTrue(events.exists(), "No AuditEvent for Payment.create")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestLogSecurityEvent(TestCase):
    """log_security_event() → AuditEvent creation via AuditService delegation."""

    def test_log_security_event_creates_audit_event(self) -> None:
        initial_count = AuditEvent.objects.count()

        log_security_event(
            event_type="suspicious_activity",
            details={"reason": "integration_test"},
            request_ip="127.0.0.1",
            user_email="test@example.com",
        )

        self.assertGreater(
            AuditEvent.objects.count(),
            initial_count,
            "log_security_event() did not create an AuditEvent",
        )

        event = AuditEvent.objects.order_by("-timestamp").first()
        self.assertIsNotNone(event)
        self.assertEqual(event.action, "suspicious_activity")
        self.assertEqual(event.ip_address, "127.0.0.1")
        self.assertEqual(event.metadata.get("user_email"), "test@example.com")
