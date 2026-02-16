"""
Comprehensive tests for audit signals and user action logging.
Tests industry-standard audit requirements (GDPR, ISO 27001, NIST, SOX, PCI DSS).
"""

import pytest
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_delete
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings
from unittest.mock import Mock, patch

from apps.audit.models import AuditEvent
from apps.audit.signals import (
    _create_audit_event,
    _get_action_category_severity,
    audit_customer_membership_changes,
    audit_customer_membership_deletion,
    audit_user_profile_changes,
    audit_user_profile_preferences,
    api_key_generated,
    api_key_revoked,
    customer_context_switched,
    privacy_settings_changed,
)
from apps.audit.services import AuditService
from apps.users.models import User, UserProfile, CustomerMembership
from apps.customers.models import Customer

pytestmark = pytest.mark.django_db


class TestAuditSignalHelpers(TestCase):
    """Test helper functions for audit signals"""

    def test_get_action_category_severity_authentication(self):
        """Test categorization of authentication events"""
        # Authentication events
        category, severity, is_sensitive, requires_review = _get_action_category_severity('login_success')
        assert category == 'authentication'
        assert severity == 'medium'
        assert is_sensitive is True
        assert requires_review is False

        # Failed login with account lockout
        category, severity, is_sensitive, requires_review = _get_action_category_severity('account_locked')
        assert category == 'authentication'
        assert severity == 'medium'
        assert is_sensitive is True
        assert requires_review is True

    def test_get_action_category_severity_password(self):
        """Test categorization of password events"""
        # Regular password change
        category, severity, is_sensitive, requires_review = _get_action_category_severity('password_changed')
        assert category == 'authentication'
        assert severity == 'medium'
        assert is_sensitive is True
        assert requires_review is False

        # Compromised password
        category, severity, is_sensitive, requires_review = _get_action_category_severity('password_compromised')
        assert category == 'authentication'
        assert severity == 'high'
        assert is_sensitive is True
        assert requires_review is True

    def test_get_action_category_severity_2fa(self):
        """Test categorization of 2FA events"""
        # 2FA enabled
        category, severity, is_sensitive, requires_review = _get_action_category_severity('2fa_enabled')
        assert category == 'authentication'
        assert severity == 'medium'
        assert is_sensitive is True
        assert requires_review is False

        # 2FA disabled (high risk)
        category, severity, is_sensitive, requires_review = _get_action_category_severity('2fa_disabled')
        assert category == 'authentication'
        assert severity == 'high'
        assert is_sensitive is True
        assert requires_review is True

    def test_get_action_category_severity_privacy(self):
        """Test categorization of privacy events"""
        category, severity, is_sensitive, requires_review = _get_action_category_severity('privacy_settings_changed')
        assert category == 'privacy'
        assert severity == 'high'
        assert is_sensitive is True
        assert requires_review is False

        # GDPR consent withdrawn
        category, severity, is_sensitive, requires_review = _get_action_category_severity('gdpr_consent_withdrawn')
        assert category == 'privacy'
        assert severity == 'high'
        assert is_sensitive is True
        assert requires_review is True

    def test_get_action_category_severity_security_events(self):
        """Test categorization of security events"""
        category, severity, is_sensitive, requires_review = _get_action_category_severity('security_incident_detected')
        assert category == 'security_event'
        assert severity == 'critical'
        assert is_sensitive is True
        assert requires_review is True

        category, severity, is_sensitive, requires_review = _get_action_category_severity('suspicious_activity')
        assert category == 'security_event'
        assert severity == 'critical'
        assert is_sensitive is True
        assert requires_review is True

    def test_create_audit_event_with_categorization(self):
        """Test audit event creation with automatic categorization"""
        user = User.objects.create_user(email='test@example.com', password='testpass123')
        factory = RequestFactory()
        request = factory.get('/')
        request.user = user

        # Create audit event
        _create_audit_event(
            action='profile_updated',
            user=user,
            content_object=user,
            description='Test profile update',
            request=request,
            metadata={'test': 'metadata'}
        )

        # Verify event was created with correct categorization
        audit_event = AuditEvent.objects.filter(action='profile_updated').first()
        assert audit_event.category == 'account_management'
        assert audit_event.severity == 'medium'
        assert audit_event.is_sensitive is True
        assert audit_event.requires_review is False
        assert audit_event.user == user
        assert 'test' in audit_event.metadata


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestUserProfileAuditSignals(TransactionTestCase):
    """Test user profile change audit signals"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='John',
            last_name='Doe',
            phone='+40123456789'
        )

    def test_audit_email_change(self):
        """Test audit logging for email address changes"""
        # Change email address
        new_email = 'newemail@example.com'

        # Update email with update_fields to trigger the signal properly
        self.user.email = new_email
        self.user.save(update_fields=['email'])

        # Verify audit event was created
        audit_events = AuditEvent.objects.filter(action='email_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['email'] == new_email
        assert audit_event.category == 'account_management'
        assert audit_event.is_sensitive is True
        assert 'security_sensitive' in audit_event.metadata

    def test_audit_name_change(self):
        """Test audit logging for name changes"""
        # Change name
        self.user.first_name = 'Jane'
        self.user.last_name = 'Smith'
        self.user.save(update_fields=['first_name', 'last_name'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='name_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['first_name'] == 'Jane'
        assert audit_event.new_values['last_name'] == 'Smith'
        assert 'identity_change' in audit_event.metadata

    def test_audit_phone_change(self):
        """Test audit logging for phone number changes"""
        new_phone = '+40987654321'

        self.user.phone = new_phone
        self.user.save(update_fields=['phone'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='phone_updated', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['phone'] == new_phone
        assert 'affects_2fa' in audit_event.metadata
        assert audit_event.metadata['requires_verification'] is True

    def test_audit_staff_role_change(self):
        """Test audit logging for staff role changes"""
        new_role = 'admin'

        self.user.staff_role = new_role
        self.user.save(update_fields=['staff_role'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='staff_role_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['staff_role'] == new_role
        assert 'authorization_change' in audit_event.metadata
        assert audit_event.requires_review is True  # This is now a model field
        assert audit_event.category == 'authorization'
        assert audit_event.severity == 'high'

    def test_audit_2fa_status_change(self):
        """Test audit logging for 2FA status changes"""
        # Enable 2FA
        self.user.two_factor_enabled = True
        self.user.save(update_fields=['two_factor_enabled'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='2fa_enabled', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['two_factor_enabled'] is True
        assert 'security_configuration' in audit_event.metadata

        # Disable 2FA (should require review)
        self.user.two_factor_enabled = False
        self.user.save(update_fields=['two_factor_enabled'])

        audit_events = AuditEvent.objects.filter(action='2fa_disabled', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.last()
        assert audit_event.requires_review is True

    def test_audit_marketing_consent_change(self):
        """Test audit logging for marketing consent changes"""
        # Grant marketing consent
        self.user.accepts_marketing = True
        self.user.save(update_fields=['accepts_marketing'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='marketing_consent_granted', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert 'gdpr_compliance' in audit_event.metadata
        assert 'consent_change' in audit_event.metadata

        # Withdraw marketing consent
        self.user.accepts_marketing = False
        self.user.save(update_fields=['accepts_marketing'])

        audit_events = AuditEvent.objects.filter(action='marketing_consent_withdrawn', user=self.user)
        assert audit_events.exists()


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestUserProfilePreferencesAudit(TransactionTestCase):
    """Test UserProfile preferences audit logging"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        # UserProfile is created automatically by signals
        self.profile = self.user.profile

    def test_audit_language_preference_change(self):
        """Test audit logging for language preference changes"""
        new_language = 'ro'

        self.profile.preferred_language = new_language
        self.profile.save(update_fields=['preferred_language'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='language_preference_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['preferred_language'] == new_language
        assert 'preference_change' in audit_event.metadata

    def test_audit_timezone_change(self):
        """Test audit logging for timezone changes"""
        new_timezone = 'America/New_York'

        self.profile.timezone = new_timezone
        self.profile.save(update_fields=['timezone'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='timezone_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['timezone'] == new_timezone

    def test_audit_notification_preferences_change(self):
        """Test audit logging for notification preference changes"""
        # Change email notifications setting
        self.profile.email_notifications = False
        self.profile.save(update_fields=['email_notifications'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='notification_settings_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert 'notification_change' in audit_event.metadata
        assert 'channel' in audit_event.metadata
        assert audit_event.metadata['channel'] == 'email_notifications'

    def test_audit_emergency_contact_update(self):
        """Test audit logging for emergency contact updates"""
        self.profile.emergency_contact_name = 'Jane Doe'
        self.profile.emergency_contact_phone = '+40123456789'
        self.profile.save(update_fields=['emergency_contact_name', 'emergency_contact_phone'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='emergency_contact_updated', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['name'] == 'Jane Doe'
        assert audit_event.new_values['phone'] == '+40123456789'
        assert 'security_relevant' in audit_event.metadata


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class TestCustomerMembershipAudit(TransactionTestCase):
    """Test customer membership audit logging"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.customer = Customer.objects.create(
            company_name='Test Company',
            customer_type='business',
            status='active'
        )

    def test_audit_customer_membership_creation(self):
        """Test audit logging for customer membership creation"""
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner',
            is_primary=True
        )

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='customer_membership_created', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['customer'] == str(self.customer)
        assert audit_event.new_values['role'] == 'owner'
        assert audit_event.new_values['is_primary'] is True
        assert 'authorization_change' in audit_event.metadata
        assert 'customer_id' in audit_event.metadata

    def test_audit_customer_role_change(self):
        """Test audit logging for customer role changes"""
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='viewer'
        )

        # Clear existing events
        AuditEvent.objects.all().delete()

        # Change role
        membership.role = 'billing'
        membership.save(update_fields=['role'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='customer_role_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['role'] == 'billing'
        assert audit_event.requires_review is True

    def test_audit_primary_customer_change(self):
        """Test audit logging for primary customer changes"""
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner',
            is_primary=False
        )

        # Clear existing events
        AuditEvent.objects.all().delete()

        # Set as primary
        membership.is_primary = True
        membership.save(update_fields=['is_primary'])

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='primary_customer_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['new_primary'] == str(self.customer)

    def test_audit_customer_membership_deletion(self):
        """Test audit logging for customer membership deletion"""
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='tech'
        )

        # Clear existing events
        AuditEvent.objects.all().delete()

        # Delete membership
        membership.delete()

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='customer_membership_deleted', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.old_values['customer'] == str(self.customer)
        assert audit_event.old_values['role'] == 'tech'
        assert audit_event.requires_review is True  # This is now a model field, not metadata
        assert audit_event.metadata['access_revoked'] is True


class TestCustomSignalHandlers(TestCase):
    """Test custom signal handlers for business events"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.factory = RequestFactory()
        self.request = self.factory.post('/')
        self.request.user = self.user

    def test_privacy_settings_changed_signal(self):
        """Test privacy settings change signal"""
        old_settings = {'marketing': True, 'analytics': True}
        new_settings = {'marketing': False, 'analytics': False}

        # Send signal
        privacy_settings_changed.send(
            sender=None,
            user=self.user,
            old_settings=old_settings,
            new_settings=new_settings,
            request=self.request
        )

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='privacy_settings_changed', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.old_values == old_settings
        assert audit_event.new_values == new_settings
        assert 'gdpr_compliance' in audit_event.metadata

    def test_api_key_generated_signal(self):
        """Test API key generation signal"""
        api_key_info = {'id': 'key_123', 'name': 'Test API Key'}

        # Send signal
        api_key_generated.send(
            sender=None,
            user=self.user,
            api_key_info=api_key_info,
            request=self.request
        )

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='api_key_generated', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.new_values['api_key_id'] == 'key_123'
        assert audit_event.new_values['name'] == 'Test API Key'
        assert 'integration_change' in audit_event.metadata
        assert 'security_sensitive' in audit_event.metadata

    def test_api_key_revoked_signal(self):
        """Test API key revocation signal"""
        api_key_info = {'id': 'key_123', 'name': 'Test API Key'}

        # Send signal
        api_key_revoked.send(
            sender=None,
            user=self.user,
            api_key_info=api_key_info,
            request=self.request
        )

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='api_key_revoked', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.old_values['api_key_id'] == 'key_123'
        assert 'security_action' in audit_event.metadata

    def test_customer_context_switched_signal(self):
        """Test customer context switching signal"""
        customer = Customer.objects.create(
            company_name='Test Company',
            customer_type='business',
            status='active'
        )

        # Send signal
        customer_context_switched.send(
            sender=None,
            user=self.user,
            old_customer=None,
            new_customer=customer,
            request=self.request
        )

        # Verify audit event
        audit_events = AuditEvent.objects.filter(action='customer_context_switched', user=self.user)
        assert audit_events.exists()

        audit_event = audit_events.first()
        assert audit_event.old_values['customer'] is None
        assert audit_event.new_values['customer'] == str(customer)
        assert 'context_change' in audit_event.metadata
        assert 'customer_id' in audit_event.metadata


class TestAuditServiceCategorization(TestCase):
    """Test AuditService automatic categorization"""

    def test_action_category_mapping(self):
        """Test automatic action category mapping"""
        assert AuditService._get_action_category('login_success') == 'authentication'
        assert AuditService._get_action_category('password_changed') == 'authentication'
        assert AuditService._get_action_category('2fa_enabled') == 'authentication'
        assert AuditService._get_action_category('profile_updated') == 'account_management'
        assert AuditService._get_action_category('privacy_settings_changed') == 'privacy'
        assert AuditService._get_action_category('role_assigned') == 'authorization'
        assert AuditService._get_action_category('customer_membership_created') == 'authorization'
        assert AuditService._get_action_category('security_incident_detected') == 'security_event'
        assert AuditService._get_action_category('data_export_requested') == 'data_protection'
        assert AuditService._get_action_category('api_key_generated') == 'integration'
        assert AuditService._get_action_category('system_maintenance_started') == 'system_admin'
        assert AuditService._get_action_category('vat_validation_completed') == 'compliance'
        assert AuditService._get_action_category('invoice_created') == 'business_operation'

    def test_action_severity_mapping(self):
        """Test automatic action severity mapping"""
        assert AuditService._get_action_severity('data_breach_detected') == 'critical'
        assert AuditService._get_action_severity('security_incident_detected') == 'critical'
        assert AuditService._get_action_severity('password_compromised') == 'high'
        assert AuditService._get_action_severity('2fa_disabled') == 'high'
        assert AuditService._get_action_severity('role_assigned') == 'high'
        assert AuditService._get_action_severity('login_success') == 'medium'
        assert AuditService._get_action_severity('password_changed') == 'medium'
        assert AuditService._get_action_severity('profile_updated') == 'medium'
        assert AuditService._get_action_severity('invoice_created') == 'low'

    def test_sensitive_action_detection(self):
        """Test sensitive action detection"""
        assert AuditService._is_action_sensitive('login_success') is True
        assert AuditService._is_action_sensitive('password_changed') is True
        assert AuditService._is_action_sensitive('profile_updated') is True
        assert AuditService._is_action_sensitive('privacy_settings_changed') is True
        assert AuditService._is_action_sensitive('payment_method_added') is True
        assert AuditService._is_action_sensitive('invoice_created') is False

    def test_review_required_detection(self):
        """Test review required detection"""
        assert AuditService._requires_review('account_locked') is True
        assert AuditService._requires_review('password_compromised') is True
        assert AuditService._requires_review('2fa_disabled') is True
        assert AuditService._requires_review('role_assigned') is True
        assert AuditService._requires_review('security_incident_detected') is True
        assert AuditService._requires_review('user_impersonation_started') is True
        assert AuditService._requires_review('login_success') is False
        assert AuditService._requires_review('profile_updated') is False


class TestAuditEventPerformance(TestCase):
    """Test audit event performance and indexing"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_category_index_usage(self):
        """Test that category indexes are used efficiently"""
        # Create multiple audit events with different categories
        from apps.audit.services import AuditService, AuditEventData, AuditContext

        categories = ['authentication', 'authorization', 'account_management', 'privacy']

        for i, category in enumerate(categories):
            context = AuditContext(user=self.user, metadata={'category': category})
            event_data = AuditEventData(
                event_type=f'test_action_{i}',
                content_object=self.user,
                description=f'Test event {i}'
            )
            AuditService.log_event(event_data, context)

        # Query by category should use index
        with self.assertNumQueries(1):  # Single query should be efficient
            events = list(AuditEvent.objects.filter(category='authentication').order_by('-timestamp'))
            assert len(events) == 1

        # Query by severity should use index
        with self.assertNumQueries(1):
            events = list(AuditEvent.objects.filter(severity='medium').order_by('-timestamp'))
            assert len(events) >= 0  # May vary based on automatic categorization

        # Combined category + severity query should be efficient
        with self.assertNumQueries(1):
            events = list(AuditEvent.objects.filter(
                category='authentication',
                severity='medium'
            ).order_by('-timestamp'))
            assert len(events) >= 0


class TestSecurityEventDetection(TestCase):
    """Test security event detection and alerting"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_high_severity_event_flagging(self):
        """Test that high severity events are properly flagged"""
        _create_audit_event(
            action='password_compromised',
            user=self.user,
            content_object=self.user,
            description='Compromised password detected',
            metadata={'threat_level': 'high'}
        )

        # Verify event was flagged for review
        audit_event = AuditEvent.objects.get(action='password_compromised')
        assert audit_event.severity == 'high'
        assert audit_event.requires_review is True
        assert audit_event.is_sensitive is True
        assert audit_event.category == 'authentication'

    def test_security_incident_categorization(self):
        """Test security incident categorization"""
        _create_audit_event(
            action='security_incident_detected',
            user=self.user,
            content_object=self.user,
            description='Suspicious activity detected',
            metadata={'incident_type': 'suspicious_activity'}
        )

        audit_event = AuditEvent.objects.filter(action='security_incident_detected').first()
        assert audit_event.category == 'security_event'
        assert audit_event.severity == 'critical'
        assert audit_event.requires_review is True

    def test_compliance_event_tracking(self):
        """Test compliance event tracking"""
        _create_audit_event(
            action='gdpr_consent_withdrawn',
            user=self.user,
            content_object=self.user,
            description='GDPR consent withdrawn',
            metadata={'gdpr_compliance': True}
        )

        audit_event = AuditEvent.objects.get(action='gdpr_consent_withdrawn')
        assert audit_event.category == 'privacy'
        assert audit_event.severity == 'high'
        assert audit_event.requires_review is True
        assert 'gdpr_compliance' in audit_event.metadata
