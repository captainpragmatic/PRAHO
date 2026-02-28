"""
Comprehensive coverage tests for apps/audit/services.py.
Targets uncovered paths: GDPR services, integrity, retention, search,
security, integrations, tickets, products, domains, customers, provisioning.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta
from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import (
    AuditAlert,
    AuditEvent,
    AuditIntegrityCheck,
    AuditRetentionPolicy,
    ComplianceLog,
    CookieConsent,
    DataExport,
)
from apps.audit.services import (
    AccountEventData,
    AuditContext,
    AuditEventData,
    AuditIntegrityService,
    AuditJSONEncoder,
    AuditRetentionService,
    AuditSearchService,
    AuditService,
    AuthenticationAuditService,
    AuthenticationEventData,
    ComplianceEventRequest,
    CustomersAuditService,
    DomainsAuditService,
    GDPRConsentService,
    GDPRDeletionService,
    GDPRExportService,
    IntegrationsAuditService,
    LoginFailureEventData,
    LogoutEventData,
    ProductsAuditService,
    ProvisioningAuditService,
    SecurityAuditService,
    SessionRotationEventData,
    TicketsAuditService,
    TwoFactorAuditRequest,
    audit_service,
    serialize_metadata,
)

User = get_user_model()


def _make_mock_with_pk(user_pk, **attrs):
    """Create a Mock that Django's ContentType can resolve (pretends to be User).
    Sets _meta to match User so ContentType.objects.get_for_model works."""
    m = Mock()
    m.pk = user_pk
    m._meta = User._meta  # Required for ContentType resolution
    for k, v in attrs.items():
        setattr(m, k, v)
    return m


def _make_user(**kwargs):
    """Create a test user with defaults."""
    defaults = {
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "password": "testpass123",
        "first_name": "Test",
        "last_name": "User",
        "is_active": True,
    }
    defaults.update(kwargs)
    pwd = defaults.pop("password")
    u = User(**defaults)
    u.set_password(pwd)
    u.save()
    return u


class TestAuditJSONEncoder(TestCase):
    """Cover AuditJSONEncoder.default for all branches."""

    def test_encode_uuid(self):
        uid = uuid.uuid4()
        enc = AuditJSONEncoder()
        self.assertEqual(enc.default(uid), str(uid))

    def test_encode_datetime(self):
        dt = datetime(2025, 1, 1, 12, 0, 0)
        enc = AuditJSONEncoder()
        self.assertEqual(enc.default(dt), dt.isoformat())

    def test_encode_decimal(self):
        d = Decimal("123.45")
        enc = AuditJSONEncoder()
        self.assertEqual(enc.default(d), "123.45")

    def test_encode_model_instance(self):
        user = _make_user()
        enc = AuditJSONEncoder()
        result = enc.default(user)
        self.assertIn("pk=", result)

    def test_encode_generic_object_with_dict(self):
        class Obj:
            x = 1
        enc = AuditJSONEncoder()
        result = enc.default(Obj())
        self.assertIsInstance(result, str)

    def test_encode_unsupported_raises(self):
        enc = AuditJSONEncoder()
        with self.assertRaises(TypeError):
            enc.default(set())


class TestSerializeMetadata(TestCase):

    def test_empty_metadata(self):
        self.assertEqual(serialize_metadata({}), {})

    def test_none_metadata(self):
        self.assertEqual(serialize_metadata(None), {})

    def test_error_handling(self):
        """Cover the except branch for non-serializable objects."""
        result = serialize_metadata({"bad": object()})
        # Should have serialization_error key from fallback
        self.assertIn("serialization_error", result)


class TestAuditServiceLogEvent(TestCase):

    def test_log_event_no_context(self):
        user = _make_user()
        event_data = AuditEventData(event_type="test_event", content_object=user, description="test")
        event = AuditService.log_event(event_data)
        self.assertEqual(event.action, "test_event")

    def test_log_event_no_content_object_no_user(self):
        """Cover fallback content_type when no content_object and no user."""
        event_data = AuditEventData(event_type="system_event", description="system action")
        context = AuditContext()
        event = AuditService.log_event(event_data, context)
        self.assertEqual(event.object_id, "1")

    def test_log_event_no_content_object_with_user(self):
        user = _make_user()
        event_data = AuditEventData(event_type="user_action", description="action")
        context = AuditContext(user=user)
        event = AuditService.log_event(event_data, context)
        self.assertEqual(event.object_id, str(user.pk))

    def test_log_event_category_none_fallback(self):
        """Cover the category is None fallback."""
        user = _make_user()
        event_data = AuditEventData(event_type="totally_unknown_event", content_object=user)
        context = AuditContext(user=user, metadata={"category": None})
        event = AuditService.log_event(event_data, context)
        self.assertEqual(event.category, "business_operation")


class TestAuditServiceSimpleEvent(TestCase):

    def test_log_simple_event(self):
        user = _make_user()
        event = AuditService.log_simple_event(
            "test_simple",
            user=user,
            content_object=user,
            description="simple event",
            metadata={"key": "val"},
            ip_address="1.2.3.4",
        )
        self.assertEqual(event.action, "test_simple")


class TestAuditServiceCategorization(TestCase):

    def test_account_management_category(self):
        self.assertEqual(AuditService._get_action_category("profile_updated"), "account_management")
        self.assertEqual(AuditService._get_action_category("email_changed"), "account_management")

    def test_integration_category(self):
        self.assertEqual(AuditService._get_action_category("api_key_generated"), "integration")
        self.assertEqual(AuditService._get_action_category("webhook_sent"), "integration")

    def test_system_admin_category(self):
        self.assertEqual(AuditService._get_action_category("system_maintenance_started"), "system_admin")
        self.assertEqual(AuditService._get_action_category("user_impersonation"), "system_admin")

    def test_compliance_category(self):
        self.assertEqual(AuditService._get_action_category("vat_calculation_applied"), "compliance")
        self.assertEqual(AuditService._get_action_category("efactura_submitted"), "compliance")

    def test_default_category(self):
        self.assertEqual(AuditService._get_action_category("some_random_action"), "business_operation")

    def test_severity_critical(self):
        self.assertEqual(AuditService._get_action_severity("data_breach_detected"), "critical")
        self.assertEqual(AuditService._get_action_severity("security_incident_detected"), "critical")
        self.assertEqual(AuditService._get_action_severity("suspicious_login"), "critical")

    def test_severity_high(self):
        self.assertEqual(AuditService._get_action_severity("data_export_requested"), "high")
        self.assertEqual(AuditService._get_action_severity("gdpr_consent_withdrawn"), "high")
        self.assertEqual(AuditService._get_action_severity("privacy_settings_changed"), "high")
        self.assertEqual(AuditService._get_action_severity("role_assigned"), "high")
        self.assertEqual(AuditService._get_action_severity("payment_fraud_detected"), "high")

    def test_severity_medium(self):
        self.assertEqual(AuditService._get_action_severity("login_success"), "medium")
        self.assertEqual(AuditService._get_action_severity("password_changed"), "medium")
        self.assertEqual(AuditService._get_action_severity("order_created"), "medium")

    def test_severity_low(self):
        self.assertEqual(AuditService._get_action_severity("invoice_created"), "low")

    def test_is_sensitive_non_sensitive(self):
        self.assertFalse(AuditService._is_action_sensitive("invoice_created"))
        self.assertFalse(AuditService._is_action_sensitive("invoice_sent"))

    def test_is_sensitive_specific_actions(self):
        self.assertTrue(AuditService._is_action_sensitive("account_locked"))
        self.assertTrue(AuditService._is_action_sensitive("brute_force_attempt"))
        self.assertTrue(AuditService._is_action_sensitive("privilege_escalation_attempt"))

    def test_is_sensitive_patterns(self):
        self.assertTrue(AuditService._is_action_sensitive("login_success"))
        self.assertTrue(AuditService._is_action_sensitive("password_changed"))
        self.assertTrue(AuditService._is_action_sensitive("gdpr_export"))
        self.assertTrue(AuditService._is_action_sensitive("payment_succeeded"))

    def test_requires_review(self):
        self.assertTrue(AuditService._requires_review("account_locked"))
        self.assertTrue(AuditService._requires_review("security_incident_detected"))
        self.assertTrue(AuditService._requires_review("malicious_request_detected"))
        self.assertTrue(AuditService._requires_review("data_breach_confirmed"))
        self.assertFalse(AuditService._requires_review("invoice_created"))


class TestAuditServiceLegacy(TestCase):

    def test_log_event_legacy(self):
        user = _make_user()
        event = AuditService.log_event_legacy(
            "test_legacy", user=user, content_object=user, description="legacy test"
        )
        self.assertEqual(event.action, "test_legacy")

    def test_log_2fa_event_legacy(self):
        user = _make_user()
        user.two_factor_enabled = False
        user.backup_tokens = []
        user.save()
        event = AuditService.log_2fa_event_legacy(
            "2fa_enabled", user=user, ip_address="1.2.3.4", description="2FA enabled"
        )
        self.assertEqual(event.action, "2fa_enabled")

    def test_log_compliance_event_legacy(self):
        log = AuditService.log_compliance_event_legacy(
            "gdpr_consent", "ref_001", "Test compliance", status="success"
        )
        self.assertEqual(log.compliance_type, "gdpr_consent")


class TestAuditServiceProxy(TestCase):

    def test_proxy_log_event(self):
        user = _make_user()
        event = audit_service.log_event("test_proxy", user=user, content_object=user)
        self.assertEqual(event.action, "test_proxy")

    def test_proxy_log_2fa_event(self):
        user = _make_user()
        user.two_factor_enabled = False
        user.backup_tokens = []
        user.save()
        event = audit_service.log_2fa_event("2fa_enabled", user=user)
        self.assertEqual(event.action, "2fa_enabled")

    def test_proxy_log_compliance_event(self):
        log = audit_service.log_compliance_event("gdpr_consent", "ref_002", "Proxy test")
        self.assertIsInstance(log, ComplianceLog)


class TestLog2FAEvent(TestCase):

    def test_2fa_disabled_high_severity(self):
        user = _make_user()
        user.two_factor_enabled = False
        user.backup_tokens = []
        user.save()
        request = TwoFactorAuditRequest(event_type="2fa_disabled", user=user, description="Disabled 2FA")
        event = AuditService.log_2fa_event(request)
        self.assertEqual(event.metadata.get("severity"), "high")
        self.assertTrue(event.metadata.get("requires_review"))

    def test_2fa_enabled_medium_severity(self):
        user = _make_user()
        user.two_factor_enabled = True
        user.backup_tokens = ["token1", "token2"]
        user.save()
        request = TwoFactorAuditRequest(event_type="2fa_enabled", user=user)
        event = AuditService.log_2fa_event(request)
        self.assertEqual(event.metadata.get("severity"), "medium")


class TestLogComplianceEvent(TestCase):

    def test_success(self):
        user = _make_user()
        req = ComplianceEventRequest(
            compliance_type="gdpr_consent",
            reference_id="ref_003",
            description="Test",
            user=user,
            evidence={"key": "val"},
            metadata={"source": "test"},
        )
        log = AuditService.log_compliance_event(req)
        self.assertEqual(log.compliance_type, "gdpr_consent")
        self.assertEqual(log.evidence, {"key": "val"})


class TestGDPRExportService(TestCase):

    def test_create_data_export_request_default_scope(self):
        user = _make_user()
        result = GDPRExportService.create_data_export_request(user, request_ip="1.2.3.4")
        self.assertTrue(result.is_ok())
        export = result.unwrap()
        self.assertEqual(export.status, "pending")
        self.assertEqual(export.requested_by, user)

    def test_create_data_export_request_custom_scope(self):
        user = _make_user()
        scope = {"include_profile": True, "include_customers": False, "format": "json"}
        result = GDPRExportService.create_data_export_request(user, export_scope=scope)
        self.assertTrue(result.is_ok())

    @patch("apps.audit.services.default_storage")
    def test_process_data_export_success(self, mock_storage):
        mock_storage.save.return_value = "gdpr_exports/test.json"
        user = _make_user()
        export = DataExport.objects.create(
            requested_by=user,
            export_type="gdpr",
            scope={"include_profile": True, "include_customers": True, "include_tickets": True,
                   "include_audit_logs": True},
            status="pending",
            expires_at=timezone.now() + timedelta(days=7),
        )
        result = GDPRExportService.process_data_export(export)
        self.assertTrue(result.is_ok())
        export.refresh_from_db()
        self.assertEqual(export.status, "completed")

    @patch("apps.audit.services.default_storage")
    def test_process_data_export_failure(self, mock_storage):
        mock_storage.save.side_effect = Exception("Storage error")
        user = _make_user()
        export = DataExport.objects.create(
            requested_by=user,
            export_type="gdpr",
            scope={"include_profile": True},
            status="pending",
            expires_at=timezone.now() + timedelta(days=7),
        )
        result = GDPRExportService.process_data_export(export)
        self.assertTrue(result.is_err())
        export.refresh_from_db()
        self.assertEqual(export.status, "failed")

    def test_get_user_exports(self):
        user = _make_user()
        DataExport.objects.create(
            requested_by=user, export_type="gdpr", scope={}, status="completed",
            expires_at=timezone.now() + timedelta(days=7), completed_at=timezone.now(),
        )
        exports = GDPRExportService.get_user_exports(user)
        self.assertEqual(len(exports), 1)
        self.assertEqual(exports[0]["status"], "completed")

    def test_count_records(self):
        data = {
            "customers": [1, 2],
            "billing_data": [],
            "support_tickets": [1],
            "audit_summary": {"recent_activities": [1, 2, 3]},
        }
        count = GDPRExportService._count_records(data)
        self.assertEqual(count, 7)  # 1 + 2 + 0 + 1 + 3

    @patch("apps.audit.services.default_storage")
    def test_collect_user_data_with_memberships(self, mock_storage):
        """Cover _collect_user_data with customer memberships."""
        mock_storage.save.return_value = "gdpr_exports/test.json"
        user = _make_user()
        # Create customer membership
        from apps.customers.models import Customer  # noqa: PLC0415
        from apps.users.models import CustomerMembership  # noqa: PLC0415
        customer = Customer.objects.create(
            company_name="Test SRL", customer_type="business", status="active"
        )
        CustomerMembership.objects.create(customer=customer, user=user, role="owner", is_primary=True)

        export = DataExport.objects.create(
            requested_by=user,
            export_type="gdpr",
            scope={"include_profile": True, "include_customers": True, "include_tickets": True,
                   "include_audit_logs": True},
            status="pending",
            expires_at=timezone.now() + timedelta(days=7),
        )
        result = GDPRExportService.process_data_export(export)
        self.assertTrue(result.is_ok())

    @patch("apps.audit.services.default_storage")
    def test_collect_user_data_no_profile(self, mock_storage):
        """Cover scope with include_profile=False."""
        mock_storage.save.return_value = "gdpr_exports/test.json"
        user = _make_user()
        export = DataExport.objects.create(
            requested_by=user,
            export_type="gdpr",
            scope={"include_profile": False, "include_customers": False,
                   "include_tickets": False, "include_audit_logs": False},
            status="pending",
            expires_at=timezone.now() + timedelta(days=7),
        )
        result = GDPRExportService.process_data_export(export)
        self.assertTrue(result.is_ok())


class TestGDPRDeletionService(TestCase):

    def test_create_deletion_request_anonymize(self):
        user = _make_user()
        result = GDPRDeletionService.create_deletion_request(user, "anonymize", "1.2.3.4", "User request")
        self.assertTrue(result.is_ok())

    def test_create_deletion_request_invalid_type(self):
        user = _make_user()
        result = GDPRDeletionService.create_deletion_request(user, "invalid", "1.2.3.4")
        self.assertTrue(result.is_err())

    def test_create_deletion_request_delete_with_customer_forces_anonymize(self):
        user = _make_user()
        from apps.customers.models import Customer  # noqa: PLC0415
        from apps.users.models import CustomerMembership  # noqa: PLC0415
        customer = Customer.objects.create(company_name="SRL", customer_type="business", status="active")
        CustomerMembership.objects.create(customer=customer, user=user, role="owner", is_primary=True)
        result = GDPRDeletionService.create_deletion_request(user, "delete", "1.2.3.4")
        self.assertTrue(result.is_ok())
        # Should have been forced to anonymize
        log = result.unwrap()
        self.assertEqual(log.evidence["deletion_type"], "anonymize")

    def test_process_deletion_request_anonymize(self):
        user = _make_user()
        original_email = user.email
        log = ComplianceLog.objects.create(
            compliance_type="gdpr_deletion",
            reference_id="test_del",
            description="test",
            user=user,
            status="requested",
            evidence={"user_email": original_email, "deletion_type": "anonymize"},
        )
        result = GDPRDeletionService.process_deletion_request(log)
        self.assertTrue(result.is_ok())
        log.refresh_from_db()
        self.assertEqual(log.status, "completed")
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertNotEqual(user.email, original_email)

    def test_process_deletion_request_delete(self):
        """Delete path: covers _delete_user_data. We use a log with user=None
        so the FK issue doesn't arise when saving back."""
        user = _make_user()
        user_email = user.email
        # Create log without user FK to avoid save issues after deletion
        log = ComplianceLog.objects.create(
            compliance_type="gdpr_deletion",
            reference_id="test_del2",
            description="test",
            user=None,
            status="requested",
            evidence={"user_email": user_email, "deletion_type": "delete"},
        )
        # User is None => "already deleted" path
        result = GDPRDeletionService.process_deletion_request(log)
        self.assertTrue(result.is_ok())

    def test_delete_user_data_directly(self):
        """Cover _delete_user_data directly."""
        user = _make_user()
        user_email = user.email
        result = GDPRDeletionService._delete_user_data(user)
        self.assertTrue(result.is_ok())
        self.assertFalse(User.objects.filter(email=user_email).exists())

    def test_process_deletion_request_user_none(self):
        """Cover branch where user is None."""
        log = ComplianceLog.objects.create(
            compliance_type="gdpr_deletion",
            reference_id="test_del3",
            description="test",
            user=None,
            status="requested",
            evidence={"user_email": "gone@example.com", "deletion_type": "anonymize"},
        )
        result = GDPRDeletionService.process_deletion_request(log)
        self.assertTrue(result.is_ok())
        self.assertIn("already deleted", result.unwrap())

    def test_process_deletion_request_failure(self):
        user = _make_user()
        log = ComplianceLog.objects.create(
            compliance_type="gdpr_deletion",
            reference_id="test_del4",
            description="test",
            user=user,
            status="requested",
            evidence={"user_email": user.email, "deletion_type": "anonymize"},
        )
        with patch.object(GDPRDeletionService, "_anonymize_user_data", side_effect=Exception("fail")):
            result = GDPRDeletionService.process_deletion_request(log)
        self.assertTrue(result.is_err())

    def test_can_user_be_deleted_no_restrictions(self):
        user = _make_user()
        can_delete, reason = GDPRDeletionService._can_user_be_deleted(user)
        self.assertTrue(can_delete)
        self.assertIsNone(reason)

    @patch("apps.audit.services.GDPRDeletionService.ANONYMIZATION_MAP", {
        "email": lambda: "anonymized@example.com",
        "first_name": lambda: "Anonymized",
        "last_name": lambda: "User",
        "phone": lambda: "+40700000000",
        "ip_address": lambda: "0.0.0.0",
    })
    def test_anonymize_user_data_with_2fa(self):
        user = _make_user()
        user.two_factor_enabled = True
        user.backup_tokens = ["t1", "t2"]
        user.save(update_fields=["two_factor_enabled", "backup_tokens"])
        result = GDPRDeletionService._anonymize_user_data(user)
        self.assertTrue(result.is_ok())
        user.refresh_from_db()
        self.assertFalse(user.two_factor_enabled)


class TestGDPRConsentService(TestCase):

    def test_withdraw_marketing_consent(self):
        user = _make_user()
        user.accepts_marketing = True
        user.save()
        result = GDPRConsentService.withdraw_consent(user, ["marketing"], "1.2.3.4")
        self.assertTrue(result.is_ok())
        user.refresh_from_db()
        self.assertFalse(user.accepts_marketing)

    def test_withdraw_invalid_consent_type(self):
        user = _make_user()
        result = GDPRConsentService.withdraw_consent(user, ["invalid_type"], "1.2.3.4")
        self.assertTrue(result.is_err())

    def test_withdraw_data_processing_consent(self):
        user = _make_user()
        result = GDPRConsentService.withdraw_consent(user, ["data_processing"], "1.2.3.4")
        self.assertTrue(result.is_ok())

    def test_withdraw_no_changes(self):
        """Marketing not enabled, so no changes made."""
        user = _make_user()
        user.accepts_marketing = False
        user.save()
        result = GDPRConsentService.withdraw_consent(user, ["analytics"], "1.2.3.4")
        self.assertTrue(result.is_ok())

    def test_get_consent_history(self):
        user = _make_user()
        ComplianceLog.objects.create(
            compliance_type="gdpr_consent",
            reference_id="consent_test",
            description="Test consent",
            user=user,
            status="success",
            evidence={"test": True},
        )
        history = GDPRConsentService.get_consent_history(user)
        self.assertGreaterEqual(len(history), 1)
        self.assertIn("timestamp", history[0])

    def test_get_consent_history_empty(self):
        user = _make_user()
        history = GDPRConsentService.get_consent_history(user)
        self.assertEqual(len(history), 0)

    def test_record_cookie_consent_success(self):
        """Test record_cookie_consent happy path."""
        result = GDPRConsentService.record_cookie_consent(
            cookie_id="test_cookie_123",
            status="accepted_all",
            functional=True,
            analytics=True,
            marketing=True,
            ip_address="1.2.3.4",
            user_agent="TestAgent",
        )
        self.assertTrue(result.is_ok())

    def test_record_cookie_consent_anonymous(self):
        result = GDPRConsentService.record_cookie_consent(
            cookie_id="anon_cookie_456",
            status="accepted_essential",
            functional=False,
            analytics=False,
            marketing=False,
        )
        self.assertTrue(result.is_ok())

    def test_record_cookie_consent_with_user(self):
        user = _make_user()
        result = GDPRConsentService.record_cookie_consent(
            cookie_id="user_cookie_789",
            status="customized",
            functional=True,
            analytics=False,
            marketing=False,
            user_id=user.id,
        )
        self.assertTrue(result.is_ok())

    def test_record_cookie_consent_invalid_user_id(self):
        result = GDPRConsentService.record_cookie_consent(
            cookie_id="bad_user_cookie",
            status="accepted_all",
            user_id=999999,
        )
        self.assertTrue(result.is_ok())  # User lookup just fails silently

    def test_record_cookie_consent_unknown_status(self):
        result = GDPRConsentService.record_cookie_consent(
            cookie_id="unknown_status_cookie",
            status="unknown_status",
        )
        self.assertTrue(result.is_ok())

    def test_get_cookie_consent_history(self):
        user = _make_user()
        CookieConsent.objects.create(
            cookie_id="hist_cookie",
            user=user,
            status="accepted_all",
            essential_cookies=True,
            consent_version="1.0",
        )
        history = GDPRConsentService.get_cookie_consent_history(user)
        self.assertEqual(len(history), 1)

    def test_get_cookie_consent_history_empty(self):
        user = _make_user()
        history = GDPRConsentService.get_cookie_consent_history(user)
        self.assertEqual(len(history), 0)


class TestAuditIntegrityService(TestCase):

    def setUp(self):
        self.user = _make_user()
        self.ct = ContentType.objects.get_for_model(User)
        self.now = timezone.now()

    def _create_event(self, **kwargs):
        defaults = {
            "user": self.user,
            "action": "test_action",
            "category": "authentication",
            "severity": "low",
            "content_type": self.ct,
            "object_id": str(self.user.pk),
            "metadata": {},
        }
        defaults.update(kwargs)
        return AuditEvent.objects.create(**defaults)

    def test_verify_audit_integrity_hash_verification_healthy(self):
        self._create_event()
        result = AuditIntegrityService.verify_audit_integrity(
            self.now - timedelta(hours=1), self.now + timedelta(hours=1), "hash_verification"
        )
        self.assertTrue(result.is_ok())
        check = result.unwrap()
        self.assertEqual(check.status, "healthy")

    def test_verify_audit_integrity_hash_mismatch(self):
        self._create_event(metadata={"integrity_hash": "wrong_hash_value"})
        result = AuditIntegrityService.verify_audit_integrity(
            self.now - timedelta(hours=1), self.now + timedelta(hours=1), "hash_verification"
        )
        self.assertTrue(result.is_ok())
        check = result.unwrap()
        self.assertEqual(check.status, "compromised")
        self.assertGreater(check.issues_found, 0)

    def test_verify_audit_integrity_sequence_check(self):
        result = AuditIntegrityService.verify_audit_integrity(
            self.now - timedelta(hours=1), self.now + timedelta(hours=1), "sequence_check"
        )
        self.assertTrue(result.is_ok())

    def test_verify_audit_integrity_gdpr_compliance(self):
        self._create_event(category="privacy", ip_address=None, description="")
        result = AuditIntegrityService.verify_audit_integrity(
            self.now - timedelta(hours=1), self.now + timedelta(hours=1), "gdpr_compliance"
        )
        self.assertTrue(result.is_ok())
        check = result.unwrap()
        # Should find compliance issue for missing fields
        self.assertGreater(check.issues_found, 0)

    def test_sequence_gap_detection(self):
        """Create events with a gap to trigger sequence_gap detection."""
        e1 = self._create_event(session_key="sess1")
        # Update timestamp to 2 hours ago
        AuditEvent.objects.filter(pk=e1.pk).update(timestamp=self.now - timedelta(hours=3))
        e2 = self._create_event(session_key="sess1")
        AuditEvent.objects.filter(pk=e2.pk).update(timestamp=self.now - timedelta(hours=1))

        result = AuditIntegrityService.verify_audit_integrity(
            self.now - timedelta(hours=4), self.now, "sequence_check"
        )
        self.assertTrue(result.is_ok())

    def test_generate_hash_chain_empty(self):
        result = AuditIntegrityService._generate_hash_chain([])
        self.assertEqual(result, "")

    def test_should_have_activity_false(self):
        e1 = self._create_event(session_key="")
        e2 = self._create_event(session_key="")
        self.assertFalse(AuditIntegrityService._should_have_activity(e1, e2))

    def test_should_have_activity_true(self):
        e1 = self._create_event(session_key="sess1")
        e2 = self._create_event(session_key="sess1")
        self.assertTrue(AuditIntegrityService._should_have_activity(e1, e2))

    def test_create_integrity_alert(self):
        check = AuditIntegrityCheck.objects.create(
            check_type="hash_verification",
            period_start=self.now - timedelta(hours=1),
            period_end=self.now,
            status="compromised",
            records_checked=10,
            issues_found=1,
        )
        issues = [{"severity": "critical", "type": "hash_mismatch", "event_id": "123"}]
        AuditIntegrityService._create_integrity_alert(check, issues)
        self.assertTrue(AuditAlert.objects.filter(alert_type="data_integrity").exists())

    def test_create_integrity_alert_non_critical(self):
        check = AuditIntegrityCheck.objects.create(
            check_type="hash_verification",
            period_start=self.now - timedelta(hours=1),
            period_end=self.now,
            status="warning",
            records_checked=10,
            issues_found=1,
        )
        issues = [{"severity": "warning", "type": "sequence_gap"}]
        AuditIntegrityService._create_integrity_alert(check, issues)
        alert = AuditAlert.objects.filter(alert_type="data_integrity").last()
        self.assertEqual(alert.severity, "high")


class TestAuditRetentionService(TestCase):

    def setUp(self):
        self.user = _make_user()
        self.ct = ContentType.objects.get_for_model(User)

    def _create_old_event(self, days_ago=400, **kwargs):
        defaults = {
            "user": self.user,
            "action": "test_action",
            "category": "authentication",
            "severity": "low",
            "content_type": self.ct,
            "object_id": str(self.user.pk),
            "metadata": {},
        }
        defaults.update(kwargs)
        event = AuditEvent.objects.create(**defaults)
        AuditEvent.objects.filter(pk=event.pk).update(
            timestamp=timezone.now() - timedelta(days=days_ago)
        )
        return event

    def test_apply_retention_policies_archive(self):
        _policy = AuditRetentionPolicy.objects.create(
            name="archive_auth", category="authentication", retention_days=30, action="archive", is_active=True
        )
        self._create_old_event(days_ago=60)
        result = AuditRetentionService.apply_retention_policies()
        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["policies_applied"], 1)
        self.assertGreaterEqual(data["events_archived"], 1)

    def test_apply_retention_policies_delete_non_mandatory(self):
        _policy = AuditRetentionPolicy.objects.create(
            name="delete_auth", category="authentication", retention_days=30, action="delete",
            is_active=True, is_mandatory=False,
        )
        self._create_old_event(days_ago=60)
        result = AuditRetentionService.apply_retention_policies()
        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertGreaterEqual(data["events_deleted"], 1)

    def test_apply_retention_policies_delete_mandatory_blocked(self):
        _policy = AuditRetentionPolicy.objects.create(
            name="delete_mandatory", category="authentication", retention_days=30, action="delete",
            is_active=True, is_mandatory=True,
        )
        self._create_old_event(days_ago=60)
        result = AuditRetentionService.apply_retention_policies()
        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["events_deleted"], 0)

    def test_apply_retention_policies_anonymize(self):
        _policy = AuditRetentionPolicy.objects.create(
            name="anonymize_auth", category="authentication", retention_days=30, action="anonymize", is_active=True
        )
        event = self._create_old_event(days_ago=60, ip_address="1.2.3.4", user_agent="TestBrowser")
        result = AuditRetentionService.apply_retention_policies()
        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertGreaterEqual(data["events_anonymized"], 1)
        event.refresh_from_db()
        self.assertEqual(event.ip_address, "0.0.0.0")

    def test_apply_retention_policies_with_severity_filter(self):
        _policy = AuditRetentionPolicy.objects.create(
            name="archive_low", category="authentication", severity="low",
            retention_days=30, action="archive", is_active=True,
        )
        self._create_old_event(days_ago=60, severity="low")
        self._create_old_event(days_ago=60, severity="high")
        result = AuditRetentionService.apply_retention_policies()
        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["events_archived"], 1)

    def test_apply_retention_policies_no_events_to_process(self):
        AuditRetentionPolicy.objects.create(
            name="empty_policy", category="authentication", retention_days=30, action="archive", is_active=True,
        )
        result = AuditRetentionService.apply_retention_policies()
        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["events_processed"], 0)

    def test_delete_events_financial_records_blocked(self):
        """Financial records should be excluded from deletion."""
        _policy = AuditRetentionPolicy.objects.create(
            name="delete_biz", category="business_operation", retention_days=30, action="delete",
            is_active=True, is_mandatory=False,
        )
        self._create_old_event(days_ago=60, action="invoice_created", category="business_operation")
        result = AuditRetentionService.apply_retention_policies()
        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["events_deleted"], 0)

    def test_anonymize_events_with_sensitive_metadata(self):
        _policy = AuditRetentionPolicy.objects.create(
            name="anon_test", category="authentication", retention_days=30, action="anonymize", is_active=True,
        )
        event = self._create_old_event(
            days_ago=60,
            metadata={"user_email": "test@example.com", "phone": "123", "normal_key": "keep"},
        )
        result = AuditRetentionService.apply_retention_policies()
        self.assertTrue(result.is_ok())
        event.refresh_from_db()
        self.assertEqual(event.metadata["user_email"], "Anonymized")
        self.assertEqual(event.metadata["phone"], "Anonymized")
        self.assertTrue(event.metadata["anonymized"])

    def test_is_financial_record(self):
        ct = ContentType.objects.get_for_model(User)
        event = AuditEvent(action="invoice_paid", category="business_operation", content_type=ct, object_id="1")
        self.assertTrue(AuditRetentionService._is_financial_record(event))
        event2 = AuditEvent(action="login_success", category="authentication", content_type=ct, object_id="1")
        self.assertFalse(AuditRetentionService._is_financial_record(event2))
        event3 = AuditEvent(action="random_action", category="business_operation", content_type=ct, object_id="1")
        self.assertTrue(AuditRetentionService._is_financial_record(event3))


class TestAuditSearchService(TestCase):

    def setUp(self):
        self.user = _make_user(is_staff=True)
        self.ct = ContentType.objects.get_for_model(User)

    def _create_event(self, **kwargs):
        defaults = {
            "user": self.user,
            "action": "login_success",
            "category": "authentication",
            "severity": "medium",
            "content_type": self.ct,
            "object_id": str(self.user.pk),
            "metadata": {},
            "ip_address": "1.2.3.4",
            "description": "Test event",
        }
        defaults.update(kwargs)
        return AuditEvent.objects.create(**defaults)

    def test_build_advanced_query_basic_filters(self):
        self._create_event()
        qs, info = AuditSearchService.build_advanced_query(
            {"user_ids": [self.user.id], "actions": ["login_success"], "categories": ["authentication"],
             "severities": ["medium"]},
            self.user,
        )
        self.assertGreaterEqual(qs.count(), 1)
        self.assertIn("user_filter", info["filters_applied"])

    def test_build_advanced_query_date_filters_with_date_objects(self):
        self._create_event()
        today = date.today()
        _qs, info = AuditSearchService.build_advanced_query(
            {"start_date": today, "end_date": today},
            self.user,
        )
        self.assertIn("date_range_start", info["filters_applied"])

    def test_build_advanced_query_date_filters_with_datetime(self):
        self._create_event()
        now = timezone.now()
        _qs, info = AuditSearchService.build_advanced_query(
            {"start_date": now - timedelta(hours=1), "end_date": now + timedelta(hours=1)},
            self.user,
        )
        self.assertIn("date_range_start", info["filters_applied"])

    def test_build_advanced_query_technical_filters(self):
        self._create_event(ip_address="10.0.0.1", request_id="req-123", session_key="sess-abc")
        _qs, info = AuditSearchService.build_advanced_query(
            {"ip_addresses": ["10.0.0.1"], "request_ids": ["req-123"], "session_keys": ["sess-abc"]},
            self.user,
        )
        self.assertIn("ip_filter", info["filters_applied"])

    def test_build_advanced_query_technical_filters_single_value(self):
        """Cover the case where filter value is not a list."""
        self._create_event(ip_address="10.0.0.1")
        _qs, info = AuditSearchService.build_advanced_query(
            {"ip_addresses": "10.0.0.1"},
            self.user,
        )
        self.assertIn("ip_filter", info["filters_applied"])

    def test_build_advanced_query_content_type_filter(self):
        self._create_event()
        _qs, info = AuditSearchService.build_advanced_query(
            {"content_types": [self.ct.id]},
            self.user,
        )
        self.assertIn("content_type_filter", info["filters_applied"])

    def test_build_advanced_query_text_search(self):
        self._create_event(description="special_search_term")
        _qs, info = AuditSearchService.build_advanced_query(
            {"search_text": "special_search"},
            self.user,
        )
        self.assertIn("text_search", info["filters_applied"])
        self.assertEqual(info["estimated_cost"], "medium")

    def test_build_advanced_query_text_search_only_performance_hint(self):
        """Text search alone triggers performance hint."""
        self._create_event()
        _qs, info = AuditSearchService.build_advanced_query(
            {"search_text": "test"},
            self.user,
        )
        self.assertIn("Add date range or user filters", info["performance_hints"][0])

    def test_build_advanced_query_boolean_filters(self):
        self._create_event(is_sensitive=True, requires_review=True)
        _qs, info = AuditSearchService.build_advanced_query(
            {"is_sensitive": True, "requires_review": True},
            self.user,
        )
        self.assertIn("sensitivity_filter", info["filters_applied"])
        self.assertIn("review_filter", info["filters_applied"])

    def test_build_advanced_query_value_filters(self):
        self._create_event(old_values={"key": "val"}, new_values={})
        _qs, info = AuditSearchService.build_advanced_query(
            {"has_old_values": True, "has_new_values": False},
            self.user,
        )
        self.assertIn("old_values_filter", info["filters_applied"])
        self.assertIn("new_values_filter", info["filters_applied"])

    def test_build_advanced_query_high_complexity(self):
        """Many filters trigger high complexity warning."""
        self._create_event()
        _qs, info = AuditSearchService.build_advanced_query(
            {
                "user_ids": [self.user.id],
                "actions": ["login_success"],
                "categories": ["authentication"],
                "severities": ["medium"],
                "ip_addresses": ["1.2.3.4"],
                "is_sensitive": False,
                "requires_review": False,
            },
            self.user,
        )
        self.assertEqual(info["estimated_cost"], "high")

    def test_save_search_query_success(self):
        result = AuditSearchService.save_search_query(
            "my_query", {"actions": ["login_success"]}, self.user, description="Test query"
        )
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().name, "my_query")

    def test_save_search_query_duplicate(self):
        AuditSearchService.save_search_query("dup_query", {}, self.user)
        result = AuditSearchService.save_search_query("dup_query", {}, self.user)
        self.assertTrue(result.is_err())

    def test_get_search_suggestions_short_query(self):
        suggestions = AuditSearchService.get_search_suggestions("a", self.user)
        self.assertEqual(suggestions["actions"], [])

    def test_get_search_suggestions_actions(self):
        suggestions = AuditSearchService.get_search_suggestions("login", self.user)
        self.assertIsInstance(suggestions["actions"], list)

    def test_get_search_suggestions_staff_users(self):
        suggestions = AuditSearchService.get_search_suggestions("test", self.user)
        self.assertIsInstance(suggestions["users"], list)

    def test_get_search_suggestions_non_staff(self):
        non_staff = _make_user(is_staff=False)
        suggestions = AuditSearchService.get_search_suggestions("test", non_staff)
        self.assertEqual(suggestions["users"], [])

    def test_get_search_suggestions_ip_like(self):
        self._create_event(ip_address="192.168.1.1")
        suggestions = AuditSearchService.get_search_suggestions("192.168", self.user)
        self.assertIsInstance(suggestions["ip_addresses"], list)

    def test_is_ip_like(self):
        self.assertTrue(AuditSearchService._is_ip_like("192.168"))
        self.assertTrue(AuditSearchService._is_ip_like("10.0.0.1"))
        self.assertFalse(AuditSearchService._is_ip_like("hello"))
        self.assertFalse(AuditSearchService._is_ip_like(""))


class TestSecurityAuditService(TestCase):

    def test_log_rate_limit_event_authenticated(self):
        user = _make_user()
        event_data = {
            "endpoint": "/api/login",
            "ip_address": "1.2.3.4",
            "user_agent": "TestAgent",
            "rate_limit_key": "ip:1.2.3.4",
            "rate_limit_rate": "10/min",
        }
        event = SecurityAuditService.log_rate_limit_event(event_data, user=user)
        self.assertEqual(event.action, "rate_limit_exceeded")
        self.assertEqual(event.category, "security_event")
        self.assertIn("user_info", event.metadata)

    def test_log_rate_limit_event_anonymous(self):
        event_data = {
            "endpoint": "/api/login",
            "ip_address": "5.6.7.8",
            "user_agent": "Bot",
            "rate_limit_key": "ip:5.6.7.8",
            "rate_limit_rate": "5/min",
        }
        event = SecurityAuditService.log_rate_limit_event(event_data)
        self.assertEqual(event.object_id, "anonymous")
        self.assertNotIn("user_info", event.metadata)


class TestIntegrationsAuditService(TestCase):

    def setUp(self):
        self.user = _make_user()

    def _make_webhook_event(self, **kwargs):
        """Create a webhook mock that uses a real User as base for ContentType resolution."""
        # We need pk and __class__ to resolve ContentType properly
        # Use a simple namespace object that Django can introspect
        attrs = {
            "pk": self.user.pk,
            "id": uuid.uuid4(),
            "source": "stripe",
            "event_type": "payment_intent.succeeded",
            "event_id": "evt_123",
            "processing_duration": timedelta(seconds=1),
            "retry_count": 0,
            "ip_address": "1.2.3.4",
            "user_agent": "Stripe/1.0",
            "signature": "sig_abc",
            "payload": {"key": "val"},
            "processed_at": timezone.now(),
            "received_at": timezone.now() - timedelta(minutes=1),
            "error_message": "",
            "next_retry_at": None,
        }
        attrs.update(kwargs)

        # Use the real user as content_object but pass webhook attrs via context
        class WebhookProxy:
            """Proxy that looks like User for ContentType but has webhook attrs."""

        # Set __class__ to User so ContentType.objects.get_for_model works
        proxy = WebhookProxy()
        proxy.__class__ = User
        proxy.pk = self.user.pk
        for k, v in attrs.items():
            setattr(proxy, k, v)
        return proxy

    def test_log_webhook_success_fast(self):
        wh = self._make_webhook_event()
        user = _make_user()
        event = IntegrationsAuditService.log_webhook_success(wh, 500, 200, user=user)
        self.assertEqual(event.action, "webhook_delivery_success")

    def test_log_webhook_success_medium(self):
        wh = self._make_webhook_event()
        event = IntegrationsAuditService.log_webhook_success(wh, 2000, 200)
        self.assertIn("medium", event.metadata["service_health"]["reliability_score"])

    def test_log_webhook_success_slow(self):
        wh = self._make_webhook_event()
        event = IntegrationsAuditService.log_webhook_success(wh, 5000, 200)
        self.assertEqual(event.metadata["service_health"]["reliability_score"], "low")

    def test_log_webhook_success_no_processing_duration(self):
        wh = self._make_webhook_event(processing_duration=None)
        event = IntegrationsAuditService.log_webhook_success(wh, 100, 200)
        self.assertIsNone(event.metadata["performance_metrics"]["processing_duration"])

    def test_log_webhook_failure_basic(self):
        wh = self._make_webhook_event(error_message="Connection timeout")
        event = IntegrationsAuditService.log_webhook_failure(
            wh, {"error_type": "timeout", "category": "network_error"}
        )
        self.assertEqual(event.action, "webhook_delivery_failure")

    def test_log_webhook_failure_max_retries(self):
        wh = self._make_webhook_event(retry_count=5)
        event = IntegrationsAuditService.log_webhook_failure(wh, {"error_type": "server_error"})
        self.assertEqual(event.new_values["failure_severity"], "high")

    def test_log_webhook_failure_security_flags(self):
        wh = self._make_webhook_event(retry_count=1)
        event = IntegrationsAuditService.log_webhook_failure(
            wh, {"error_type": "auth_error"}, security_flags={"suspicious_ip": True}
        )
        self.assertEqual(event.new_values["failure_severity"], "critical")

    def test_log_webhook_retry_exhausted(self):
        wh = self._make_webhook_event(retry_count=5)
        event = IntegrationsAuditService.log_webhook_retry_exhausted(
            wh, 5, "Max retries reached", reliability_impact={"sla_breach": True, "customer_impact_level": "high", "customer_visible": True}
        )
        self.assertEqual(event.action, "webhook_retry_exhausted")

    def test_log_webhook_retry_exhausted_no_timeline(self):
        wh = self._make_webhook_event(received_at=None, processed_at=None)
        event = IntegrationsAuditService.log_webhook_retry_exhausted(wh, 3, "Error")
        self.assertIsNone(event.metadata["retry_analysis"]["timeline"])

    def test_log_webhook_retry_exhausted_no_reliability(self):
        wh = self._make_webhook_event(retry_count=6)
        event = IntegrationsAuditService.log_webhook_retry_exhausted(wh, 6, "Final error")
        self.assertFalse(event.metadata["service_reliability"]["sla_impact"])


class TestTicketsAuditService(TestCase):

    def setUp(self):
        self.user = _make_user()

    def _make_ticket(self, **kwargs):
        m = _make_mock_with_pk(self.user.pk)
        m.id = uuid.uuid4()
        m.ticket_number = "TKT-001"
        m.title = "Test Ticket"
        m.status = "open"
        m.priority = "normal"
        m.source = "email"
        m.contact_email = "customer@example.com"
        m.contact_person = "John"
        m.assigned_to = None
        m.related_service = None
        m.created_at = timezone.now()
        m.resolved_at = None
        m.satisfaction_rating = None
        m.satisfaction_comment = ""
        m.is_escalated = False
        m.requires_customer_response = False
        m.customer = Mock()
        m.customer.id = uuid.uuid4()
        m.customer.get_display_name.return_value = "Test Company"
        m.category = Mock()
        m.category.name = "Technical"
        for k, v in kwargs.items():
            setattr(m, k, v)
        return m

    def test_log_ticket_opened(self):
        ticket = self._make_ticket()
        event = TicketsAuditService.log_ticket_opened(
            ticket,
            sla_metadata={"deadline_hours": 24, "priority_level": "normal"},
            should_escalate=False,
        )
        self.assertEqual(event.action, "support_ticket_created")

    def test_log_ticket_opened_with_escalation(self):
        ticket = self._make_ticket()
        event = TicketsAuditService.log_ticket_opened(
            ticket,
            sla_metadata={"deadline_hours": 4},
            should_escalate=True,
            romanian_business_context={"is_business_customer": True},
            user=_make_user(),
        )
        self.assertTrue(event.metadata["auto_escalation_eligible"])

    def test_log_ticket_closed_with_resolution(self):
        ticket = self._make_ticket(
            resolved_at=timezone.now(),
            satisfaction_rating=5,
            satisfaction_comment="Great support",
            is_escalated=False,
            assigned_to=Mock(get_full_name=Mock(return_value="Agent Smith")),
        )
        event = TicketsAuditService.log_ticket_closed(
            ticket,
            old_status="open",
            new_status="resolved",
            sla_performance={"sla_grade": "A", "overall_compliance": True},
            service_metrics={"avg_response_time": 30},
            romanian_compliance={"compliant": True},
            user=_make_user(),
        )
        self.assertEqual(event.action, "support_ticket_closed")
        self.assertIn("resolution_duration", event.metadata)

    def test_log_ticket_closed_no_resolution(self):
        ticket = self._make_ticket(resolved_at=None)
        event = TicketsAuditService.log_ticket_closed(
            ticket,
            old_status="open",
            new_status="closed",
            sla_performance={"sla_grade": "C", "overall_compliance": False},
            service_metrics={},
        )
        self.assertIsNone(event.metadata["resolution_duration"])


class TestProductsAuditService(TestCase):

    def setUp(self):
        self._user = _make_user()

    def _make_product(self, **kwargs):
        m = _make_mock_with_pk(self._user.pk)
        m.id = uuid.uuid4()
        m.slug = "hosting-basic"
        m.name = "Basic Hosting"
        m.product_type = "hosting"
        m.module = "hosting"
        m.is_active = True
        m.is_public = True
        m.is_featured = False
        m.includes_vat = True
        m.requires_domain = True
        m.sort_order = 1
        m.tags = ["hosting"]
        m.created_at = timezone.now()
        m.get_product_type_display.return_value = "Hosting"
        for k, v in kwargs.items():
            setattr(m, k, v)
        return m

    def test_log_product_created(self):
        product = self._make_product()
        event = ProductsAuditService.log_product_created(product, user=_make_user())
        self.assertEqual(event.action, "product_created")

    def test_log_product_created_with_romanian_context(self):
        product = self._make_product()
        event = ProductsAuditService.log_product_created(
            product, romanian_business_context={"vat_rate": 19}
        )
        self.assertIn("romanian_context", event.metadata)

    def test_log_product_availability_changed(self):
        product = self._make_product()
        changes = {
            "is_active": {"from": True, "to": False},
            "customer_impact_level": "high",
        }
        event = ProductsAuditService.log_product_availability_changed(product, changes)
        self.assertEqual(event.action, "product_availability_changed")

    def test_log_product_pricing_changed_created(self):
        product = self._make_product()
        price = _make_mock_with_pk(self._user.pk)
        price.id = uuid.uuid4()
        price.product = product
        price.currency = Mock(code="RON")
        price.billing_period = "monthly"
        price.amount_cents = 5000
        price.amount = Decimal("50.00")
        price.setup_cents = 0
        price.setup_fee = Decimal("0.00")
        price.is_active = True
        price.promo_price_cents = None
        price.discount_percent = Decimal("0.00")

        event = ProductsAuditService.log_product_pricing_changed(
            price, "price_created", {}
        )
        self.assertEqual(event.action, "product_pricing_changed")
        self.assertIn("New pricing created", event.description)

    def test_log_product_pricing_changed_updated(self):
        product = self._make_product()
        price = _make_mock_with_pk(self._user.pk)
        price.id = uuid.uuid4()
        price.product = product
        price.currency = Mock(code="RON")
        price.billing_period = "monthly"
        price.amount_cents = 6000
        price.amount = Decimal("60.00")
        price.setup_cents = 0
        price.setup_fee = Decimal("0.00")
        price.is_active = True
        price.promo_price_cents = None
        price.discount_percent = Decimal("0.00")

        changes = {
            "price_changed": {
                "from_amount": 50, "to_amount": 60, "percent_change": 20.0,
                "price_increased": True, "significant": True,
            }
        }
        event = ProductsAuditService.log_product_pricing_changed(price, "price_updated", changes)
        self.assertIn("Pricing updated", event.description)

    def test_log_product_pricing_changed_updated_no_price_change(self):
        product = self._make_product()
        price = _make_mock_with_pk(self._user.pk)
        price.id = uuid.uuid4()
        price.product = product
        price.currency = Mock(code="RON")
        price.billing_period = "monthly"
        price.amount_cents = 5000
        price.amount = Decimal("50.00")
        price.setup_cents = 0
        price.setup_fee = Decimal("0.00")
        price.is_active = True
        price.promo_price_cents = None
        price.discount_percent = Decimal("0.00")

        changes = {"status_changed": {"from": "active", "to": "inactive"}}
        event = ProductsAuditService.log_product_pricing_changed(price, "price_updated", changes)
        self.assertIn("Pricing updated", event.description)


class TestDomainsAuditService(TestCase):

    def setUp(self):
        self._user = _make_user()

    def _make_domain(self, **kwargs):
        m = _make_mock_with_pk(self._user.pk)
        m.id = uuid.uuid4()
        m.name = "example.ro"
        m.status = "active"
        m.registrar = Mock(name="ROTLD")
        m.registrar.name = "ROTLD"
        m.tld = Mock(extension="ro")
        m.registered_at = timezone.now()
        m.expires_at = timezone.now() + timedelta(days=365)
        m.auto_renew_enabled = True
        m.whois_privacy_enabled = False
        m.is_locked = True
        m.customer = Mock(id=uuid.uuid4())
        m.nameservers = Mock()
        m.nameservers.all.return_value = []
        for k, v in kwargs.items():
            setattr(m, k, v)
        return m

    def test_log_domain_event(self):
        domain = self._make_domain()
        event = DomainsAuditService.log_domain_event("domain_registered", domain, user=_make_user())
        self.assertEqual(event.action, "domain_registered")

    def test_log_domain_event_no_description(self):
        domain = self._make_domain()
        event = DomainsAuditService.log_domain_event("domain_renewed", domain)
        self.assertIn("domain renewed", event.description.lower())

    def test_log_tld_event(self):
        tld = _make_mock_with_pk(self._user.pk)
        tld.id = uuid.uuid4()
        tld.extension = "ro"
        tld.description = "Romanian TLD"
        tld.registration_price_cents = 5000
        tld.renewal_price_cents = 5000
        tld.transfer_price_cents = 3000
        tld.is_active = True
        event = DomainsAuditService.log_tld_event("tld_created", tld)
        self.assertEqual(event.action, "tld_created")

    def test_log_registrar_event(self):
        registrar = _make_mock_with_pk(self._user.pk)
        registrar.id = uuid.uuid4()
        registrar.name = "ROTLD"
        registrar.api_url = "https://api.rotld.ro"
        registrar.is_active = True
        registrar.supported_tlds = Mock()
        registrar.supported_tlds.all.return_value = []
        event = DomainsAuditService.log_registrar_event("registrar_created", registrar)
        self.assertEqual(event.action, "registrar_created")

    def test_log_registrar_event_security_sensitive(self):
        registrar = _make_mock_with_pk(self._user.pk)
        registrar.id = uuid.uuid4()
        registrar.name = "ROTLD"
        registrar.api_url = "https://api.rotld.ro"
        registrar.is_active = True
        registrar.supported_tlds = Mock()
        registrar.supported_tlds.all.return_value = []
        event = DomainsAuditService.log_registrar_event(
            "api_credentials_updated", registrar, security_sensitive=True
        )
        self.assertIn("[SECURITY]", event.description)
        self.assertEqual(event.metadata["api_url"], "[REDACTED]")

    def test_log_domain_order_event(self):
        order_item = _make_mock_with_pk(self._user.pk)
        order_item.id = uuid.uuid4()
        order_item.order = Mock(id=uuid.uuid4(), customer=Mock(id=uuid.uuid4()))
        order_item.domain_name = "test.ro"
        order_item.operation_type = "register"
        order_item.registrar = Mock(name="ROTLD")
        order_item.registrar.name = "ROTLD"
        order_item.tld = Mock(extension="ro")
        order_item.price_cents = 5000
        event = DomainsAuditService.log_domain_order_event("domain_order_created", order_item)
        self.assertEqual(event.action, "domain_order_created")

    def test_log_domain_security_event(self):
        domain = self._make_domain()
        event = DomainsAuditService.log_domain_security_event(
            "epp_code_generated", domain, "epp_code_generation"
        )
        self.assertEqual(event.action, "epp_code_generated")


class TestCustomersAuditService(TestCase):

    def setUp(self):
        self._user = _make_user()

    def _make_customer_mock(self, **kwargs):
        m = _make_mock_with_pk(self._user.pk)
        m.id = uuid.uuid4()
        m.name = "Test Company"
        m.customer_type = "business"
        m.status = "active"
        m.company_name = "Test Company SRL"
        m.primary_email = "info@test.com"
        m.primary_phone = "+40700000000"
        m.industry = "IT"
        m.website = "https://test.com"
        m.assigned_account_manager = None
        m.data_processing_consent = True
        m.marketing_consent = True
        m.gdpr_consent_date = timezone.now()
        m.created_at = timezone.now()
        m.updated_at = timezone.now()
        m.created_by = None
        m.is_deleted = False
        m.deleted_at = None
        m.deleted_by = None
        m.addresses = Mock()
        m.addresses.exists.return_value = True
        m.get_display_name.return_value = "Test Company SRL"
        for k, v in kwargs.items():
            setattr(m, k, v)
        return m

    def test_log_customer_event(self):
        customer = self._make_customer_mock()
        event = CustomersAuditService.log_customer_event("customer_created", customer)
        self.assertEqual(event.action, "customer_created")

    def test_log_customer_event_with_context(self):
        customer = self._make_customer_mock()
        user = _make_user()
        event = CustomersAuditService.log_customer_event(
            "customer_updated", customer, user=user,
            old_values={"status": "pending"}, new_values={"status": "active"},
            description="Customer activated",
        )
        self.assertEqual(event.old_values, {"status": "pending"})

    def test_log_tax_profile_event(self):
        tax_profile = _make_mock_with_pk(self._user.pk)
        tax_profile.customer = self._make_customer_mock()
        tax_profile.cui = "RO12345678"
        tax_profile.registration_number = "J40/123/2020"
        tax_profile.is_vat_payer = True
        tax_profile.vat_number = "RO12345678"
        tax_profile.vat_rate = Decimal("19.00")
        tax_profile.reverse_charge_eligible = False
        tax_profile.validate_cui.return_value = True
        tax_profile.created_at = timezone.now()
        tax_profile.updated_at = timezone.now()
        event = CustomersAuditService.log_tax_profile_event("tax_profile_updated", tax_profile)
        self.assertEqual(event.action, "tax_profile_updated")

    def test_log_billing_profile_event(self):
        billing_profile = _make_mock_with_pk(self._user.pk)
        billing_profile.customer = self._make_customer_mock()
        billing_profile.payment_terms = "net30"
        billing_profile.credit_limit = Decimal("1000.00")
        billing_profile.preferred_currency = "RON"
        billing_profile.invoice_delivery_method = "email"
        billing_profile.auto_payment_enabled = True
        billing_profile.get_account_balance.return_value = Decimal("500.00")
        billing_profile.created_at = timezone.now()
        billing_profile.updated_at = timezone.now()
        event = CustomersAuditService.log_billing_profile_event("billing_profile_updated", billing_profile)
        self.assertEqual(event.action, "billing_profile_updated")

    def test_log_address_event(self):
        address = _make_mock_with_pk(self._user.pk)
        address.customer = self._make_customer_mock()
        address.address_type = "legal"
        address.address_line1 = "Str. Test 1"
        address.address_line2 = ""
        address.city = "Bucharest"
        address.county = "Bucharest"
        address.postal_code = "010101"
        address.country = "România"
        address.is_current = True
        address.version = 1
        address.is_validated = True
        address.validated_at = timezone.now()
        address.get_full_address.return_value = "Str. Test 1, Bucharest, 010101"
        address.created_at = timezone.now()
        address.updated_at = timezone.now()
        event = CustomersAuditService.log_address_event("address_created", address)
        self.assertEqual(event.action, "address_created")
        self.assertTrue(event.metadata["is_romanian_address"])

    def test_log_payment_method_event(self):
        pm = _make_mock_with_pk(self._user.pk)
        pm.customer = self._make_customer_mock()
        pm.method_type = "stripe_card"
        pm.display_name = "Visa ending 4242"
        pm.last_four = "4242"
        pm.is_default = True
        pm.is_active = True
        pm.stripe_payment_method_id = "pm_123"
        pm.bank_details = None
        pm.created_at = timezone.now()
        pm.updated_at = timezone.now()
        event = CustomersAuditService.log_payment_method_event("payment_method_added", pm)
        self.assertEqual(event.action, "payment_method_added")
        self.assertTrue(event.metadata["pci_compliance_required"])

    def test_log_note_event(self):
        note = _make_mock_with_pk(self._user.pk)
        note.customer = self._make_customer_mock()
        note.note_type = "complaint"
        note.title = "Service Issue"
        note.is_important = True
        note.is_private = False
        note.created_by = None
        note.created_at = timezone.now()
        note.content = "Customer reported an issue with their hosting service."
        event = CustomersAuditService.log_note_event("note_created", note)
        self.assertEqual(event.action, "note_created")
        self.assertTrue(event.metadata["is_feedback"])


class TestProvisioningAuditService(TestCase):

    def setUp(self):
        self._user = _make_user()

    def test_log_service_plan_event(self):
        plan = _make_mock_with_pk(self._user.pk)
        plan.id = uuid.uuid4()
        plan.name = "Basic Plan"
        plan.plan_type = "shared"
        plan.price_monthly = Decimal("50.00")
        plan.price_quarterly = Decimal("135.00")
        plan.price_annual = Decimal("480.00")
        plan.setup_fee = Decimal("0.00")
        plan.includes_vat = True
        plan.is_active = True
        plan.is_public = True
        plan.auto_provision = True
        plan.sort_order = 1
        plan.disk_space_gb = 10
        plan.bandwidth_gb = 100
        plan.email_accounts = 10
        plan.databases = 5
        plan.cpu_cores = 1
        plan.ram_gb = 1
        plan.created_at = timezone.now()
        plan.updated_at = timezone.now()
        event = ProvisioningAuditService.log_service_plan_event("service_plan_created", plan)
        self.assertEqual(event.action, "service_plan_created")

    def test_log_server_event(self):
        server = _make_mock_with_pk(self._user.pk)
        server.id = uuid.uuid4()
        server.name = "web-01"
        server.hostname = "web-01.pragmatichost.com"
        server.server_type = "shared"
        server.status = "active"
        server.primary_ip = "10.0.0.1"
        server.secondary_ips = []
        server.location = "Bucharest"
        server.datacenter = "M247"
        server.cpu_model = "Xeon E5"
        server.cpu_cores = 8
        server.ram_gb = 32
        server.disk_type = "ssd"
        server.disk_capacity_gb = 500
        server.os_type = "linux"
        server.control_panel = "virtualmin"
        server.provider = "m247"
        server.provider_instance_id = "inst-123"
        server.monthly_cost = Decimal("100.00")
        server.max_services = 50
        server.active_services_count = 10
        server.is_active = True
        server.cpu_usage_percent = Decimal("30.0")
        server.ram_usage_percent = Decimal("50.0")
        server.disk_usage_percent = Decimal("40.0")
        server.resource_usage_average = 40.0
        server.last_maintenance = None
        server.next_maintenance = None
        server.created_at = timezone.now()
        server.updated_at = timezone.now()
        event = ProvisioningAuditService.log_server_event("server_created", server)
        self.assertEqual(event.action, "server_created")

    def test_log_service_event(self):
        customer = Mock()
        customer.id = uuid.uuid4()
        customer.get_display_name.return_value = "Test SRL"
        customer.customer_type = "company"
        tax_profile = Mock()
        tax_profile.cui = "RO12345678"
        customer.get_tax_profile.return_value = tax_profile

        service = _make_mock_with_pk(self._user.pk)
        service.id = uuid.uuid4()
        service.service_name = "test-hosting"
        service.domain = "test.ro"
        service.username = "testuser"
        service.customer = customer
        service.service_plan = Mock(id=uuid.uuid4(), name="Basic", plan_type="shared")
        service.server = Mock(id=uuid.uuid4(), name="web-01")
        service.status = "active"
        service.billing_cycle = "monthly"
        service.price = Decimal("50.00")
        service.setup_fee_paid = True
        service.auto_renew = True
        service.disk_usage_mb = 100
        service.bandwidth_usage_mb = 500
        service.email_accounts_used = 2
        service.databases_used = 1
        service.created_at = timezone.now()
        service.activated_at = timezone.now()
        service.suspended_at = None
        service.expires_at = timezone.now() + timedelta(days=30)
        service.updated_at = timezone.now()
        service.is_overdue = False
        service.days_until_expiry = 30
        service.get_next_billing_date.return_value = timezone.now() + timedelta(days=30)
        service.suspension_reason = None
        service.admin_notes = None
        service.last_provisioning_attempt = None
        service.provisioning_errors = None

        event = ProvisioningAuditService.log_service_event("service_activated", service)
        self.assertEqual(event.action, "service_activated")

    def test_log_service_relationship_event(self):
        rel = _make_mock_with_pk(self._user.pk)
        rel.id = uuid.uuid4()
        rel.parent_service = Mock(id=uuid.uuid4(), service_name="parent-svc")
        rel.child_service = Mock(id=uuid.uuid4(), service_name="child-svc")
        rel.relationship_type = "addon"
        rel.billing_impact = "included"
        rel.is_required = True
        rel.auto_provision = True
        rel.cascade_suspend = True
        rel.cascade_terminate = False
        rel.discount_percentage = Decimal("0")
        rel.fixed_discount_cents = 0
        rel.is_active = True
        rel.notes = "Test relationship"
        rel.created_at = timezone.now()
        rel.updated_at = timezone.now()
        event = ProvisioningAuditService.log_service_relationship_event("relationship_created", rel)
        self.assertEqual(event.action, "relationship_created")

    def test_log_service_group_event(self):
        group = _make_mock_with_pk(self._user.pk)
        group.id = uuid.uuid4()
        group.name = "Test Group"
        group.description = "Test description"
        group.group_type = "package"
        group.customer = Mock(id=uuid.uuid4())
        group.customer.get_display_name.return_value = "Test SRL"
        group.status = "active"
        group.billing_cycle = "monthly"
        group.auto_provision = True
        group.coordinated_billing = True
        group.total_services = 3
        group.active_services = 3
        group.notes = "Group notes"
        group.created_at = timezone.now()
        group.updated_at = timezone.now()
        event = ProvisioningAuditService.log_service_group_event("service_group_created", group)
        self.assertEqual(event.action, "service_group_created")

    def test_log_provisioning_task_event(self):
        task = _make_mock_with_pk(self._user.pk)
        task.id = uuid.uuid4()
        task.task_type = "create_service"
        task.status = "completed"
        task.service = Mock(
            id=uuid.uuid4(),
            service_name="test-svc",
            customer=Mock(id=uuid.uuid4()),
        )
        task.service.customer.get_display_name.return_value = "Test SRL"
        task.retry_count = 0
        task.max_retries = 3
        task.can_retry = False
        task.duration_seconds = 120
        task.parameters = {"plan": "basic"}
        task.result = {"success": True}
        task.error_message = None
        task.created_at = timezone.now()
        task.started_at = timezone.now()
        task.completed_at = timezone.now()
        task.next_retry_at = None
        task.updated_at = timezone.now()
        task.get_task_type_display.return_value = "Create Service"
        event = ProvisioningAuditService.log_provisioning_task_event("task_completed", task)
        self.assertEqual(event.action, "task_completed")

    def test_log_service_domain_event(self):
        sd = _make_mock_with_pk(self._user.pk)
        sd.id = uuid.uuid4()
        sd.service = Mock(id=uuid.uuid4(), service_name="test-svc")
        sd.domain = Mock(id=uuid.uuid4(), name="example.ro")
        sd.full_domain_name = "www.example.ro"
        sd.domain_type = "primary"
        sd.subdomain = "www"
        sd.dns_management = True
        sd.ssl_enabled = True
        sd.ssl_type = "lets_encrypt"
        sd.email_routing = True
        sd.catch_all_email = ""
        sd.redirect_url = ""
        sd.redirect_type = ""
        sd.is_active = True
        sd.notes = None
        sd.created_at = timezone.now()
        sd.updated_at = timezone.now()
        event = ProvisioningAuditService.log_service_domain_event("domain_bound", sd)
        self.assertEqual(event.action, "domain_bound")


class TestSettingsServiceHelpers(TestCase):
    """Cover the get_*_threshold helper functions."""

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=10)
    def test_get_high_complexity_filter_threshold(self, mock_get):
        from apps.audit.services import get_high_complexity_filter_threshold  # noqa: PLC0415
        result = get_high_complexity_filter_threshold()
        self.assertEqual(result, 10)

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=300)
    def test_get_webhook_healthy_response_threshold(self, mock_get):
        from apps.audit.services import get_webhook_healthy_response_threshold  # noqa: PLC0415
        result = get_webhook_healthy_response_threshold()
        self.assertEqual(result, 300)

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=5)
    def test_get_webhook_max_retry_threshold(self, mock_get):
        from apps.audit.services import get_webhook_max_retry_threshold  # noqa: PLC0415
        result = get_webhook_max_retry_threshold()
        self.assertEqual(result, 5)

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=3)
    def test_get_webhook_suspicious_retry_threshold(self, mock_get):
        from apps.audit.services import get_webhook_suspicious_retry_threshold  # noqa: PLC0415
        result = get_webhook_suspicious_retry_threshold()
        self.assertEqual(result, 3)


class TestAuthenticationAuditServiceAdditional(TestCase):
    """Cover additional branches in AuthenticationAuditService."""

    def test_log_login_success_with_request(self):
        user = _make_user()
        request = Mock()
        request.META = {"HTTP_USER_AGENT": "TestBrowser/1.0"}
        request.session = Mock(session_key="sess_123")
        with patch("apps.audit.services.get_safe_client_ip", return_value="10.0.0.1"):
            event = AuthenticationAuditService.log_login_success(
                AuthenticationEventData(user=user, request=request)
            )
        self.assertEqual(event.action, "login_success")
        self.assertIn("user_agent_info", event.metadata)

    def test_log_login_failed_with_request_no_user(self):
        request = Mock()
        request.META = {"HTTP_USER_AGENT": "BadBot/1.0"}
        with patch("apps.audit.services.get_safe_client_ip", return_value="10.0.0.2"):
            event = AuthenticationAuditService.log_login_failed(
                LoginFailureEventData(
                    email="nouser@example.com",
                    request=request,
                    failure_reason="user_not_found",
                )
            )
        self.assertEqual(event.action, "login_failed_user_not_found")
        self.assertFalse(event.metadata["user_exists"])

    def test_log_login_failed_invalid_email(self):
        """Cover attempted_email_format_valid branch with no @ sign."""
        event = AuthenticationAuditService.log_login_failed(
            LoginFailureEventData(email="not-an-email", failure_reason="user_not_found")
        )
        self.assertFalse(event.metadata["attempted_email_format_valid"])

    def test_log_login_failed_no_email(self):
        event = AuthenticationAuditService.log_login_failed(
            LoginFailureEventData(email=None, failure_reason="unknown")
        )
        self.assertEqual(event.action, "login_failed")

    def test_log_logout_with_request(self):
        user = _make_user()
        request = Mock()
        request.META = {"HTTP_USER_AGENT": "Browser/1.0"}
        request.session = Mock(session_key="sess_456")
        with patch("apps.audit.services.get_safe_client_ip", return_value="10.0.0.3"):
            event = AuthenticationAuditService.log_logout(
                LogoutEventData(user=user, request=request, logout_reason="security_event")
            )
        self.assertEqual(event.action, "logout_security_event")

    def test_log_logout_session_expired(self):
        user = _make_user()
        event = AuthenticationAuditService.log_logout(
            LogoutEventData(user=user, logout_reason="session_expired")
        )
        self.assertEqual(event.action, "logout_session_expired")

    def test_log_logout_concurrent_session(self):
        user = _make_user()
        event = AuthenticationAuditService.log_logout(
            LogoutEventData(user=user, logout_reason="concurrent_session")
        )
        self.assertEqual(event.action, "logout_concurrent_session")

    def test_log_logout_with_last_login(self):
        user = _make_user()
        user.last_login = timezone.now() - timedelta(hours=2)
        user.save()
        event = AuthenticationAuditService.log_logout(
            LogoutEventData(user=user, logout_reason="manual")
        )
        self.assertIn("duration_seconds", event.metadata["session_info"])

    def test_log_account_locked_with_request(self):
        user = _make_user()
        request = Mock()
        with patch("apps.audit.services.get_safe_client_ip", return_value="10.0.0.4"):
            event = AuthenticationAuditService.log_account_locked(
                AccountEventData(user=user, trigger_reason="too_many_attempts", request=request, failed_attempts=5)
            )
        self.assertEqual(event.action, "account_locked")

    def test_log_session_rotation_with_request(self):
        user = _make_user()
        request = Mock()
        with patch("apps.audit.services.get_safe_client_ip", return_value="10.0.0.5"):
            event = AuthenticationAuditService.log_session_rotation(
                SessionRotationEventData(
                    user=user, reason="security_upgrade", request=request,
                    old_session_key="old_sess", new_session_key="new_sess",
                )
            )
        self.assertEqual(event.action, "session_rotation")
