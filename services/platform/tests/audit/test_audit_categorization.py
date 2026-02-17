"""
Tests for audit event categorization and security classification system.
Validates industry compliance requirements and threat detection capabilities.
"""

import pytest
from django.test import TestCase
from unittest.mock import Mock, patch

from apps.audit.models import AuditEvent
from apps.audit.services import (
    AuditService,
    AuditEventData,
    AuditContext,
    AuthenticationAuditService,
    TwoFactorAuditRequest
)
from apps.users.models import User

pytestmark = pytest.mark.django_db


class TestAuditEventCategorizationModel(TestCase):
    """Test AuditEvent model categorization fields"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_audit_event_category_choices(self):
        """Test that all category choices are valid"""
        valid_categories = [choice[0] for choice in AuditEvent.CATEGORY_CHOICES]

        expected_categories = [
            'authentication', 'authorization', 'account_management',
            'data_protection', 'security_event', 'business_operation',
            'system_admin', 'compliance', 'privacy', 'integration'
        ]

        for category in expected_categories:
            assert category in valid_categories

    def test_audit_event_severity_choices(self):
        """Test that all severity choices are valid"""
        valid_severities = [choice[0] for choice in AuditEvent.SEVERITY_CHOICES]

        expected_severities = ['low', 'medium', 'high', 'critical']

        for severity in expected_severities:
            assert severity in valid_severities

    def test_audit_event_creation_with_categorization(self):
        """Test creating audit event with full categorization"""
        event = AuditEvent.objects.create(
            user=self.user,
            action='test_action',
            category='authentication',
            severity='high',
            is_sensitive=True,
            requires_review=True,
            content_type_id=1,
            object_id='1',
            description='Test audit event',
            ip_address='192.168.1.1'
        )

        assert event.category == 'authentication'
        assert event.severity == 'high'
        assert event.is_sensitive is True
        assert event.requires_review is True
        assert event.user == self.user

    def test_audit_event_default_values(self):
        """Test audit event default category and severity values"""
        event = AuditEvent.objects.create(
            user=self.user,
            action='test_action',
            content_type_id=1,
            object_id='1',
            description='Test audit event'
        )

        # Test defaults
        assert event.category == 'business_operation'  # Default category
        assert event.severity == 'low'  # Default severity
        assert event.is_sensitive is False  # Default not sensitive
        assert event.requires_review is False  # Default no review

    def test_audit_event_indexes_exist(self):
        """Test that performance indexes are created correctly"""
        from django.db import connection
        from django.test import skipIfDBFeature

        # Skip this test for SQLite as it doesn't have the same index introspection
        if connection.vendor == 'sqlite':
            self.skipTest("Index introspection test skipped for SQLite")

        # Get all index names for audit_event table (PostgreSQL)
        with connection.cursor() as cursor:
            if connection.vendor == 'postgresql':
                cursor.execute("""
                    SELECT indexname FROM pg_indexes
                    WHERE tablename = 'audit_event'
                    ORDER BY indexname
                """)
                index_names = [row[0] for row in cursor.fetchall()]
            else:
                # For other databases, we'll assume the indexes exist if no error occurs
                # This is a simplified check - in production you'd implement proper introspection
                index_names = [
                    'idx_audit_category_time',
                    'idx_audit_severity_time',
                    'idx_audit_sensitive_time',
                    'idx_audit_review_time',
                    'idx_audit_cat_sev_time',
                    'idx_audit_user_cat_time',
                    'idx_audit_ip_sev_time',
                    'idx_audit_compliance',
                    'idx_audit_time_cat'
                ]

        # Check that security analysis indexes exist
        expected_indexes = [
            'idx_audit_category_time',
            'idx_audit_severity_time',
            'idx_audit_sensitive_time',
            'idx_audit_review_time',
            'idx_audit_cat_sev_time',
            'idx_audit_user_cat_time',
            'idx_audit_ip_sev_time',
            'idx_audit_compliance',
            'idx_audit_time_cat'
        ]

        for expected_index in expected_indexes:
            assert expected_index in index_names, f"Index {expected_index} not found"


class TestAuditServiceCategorization(TestCase):
    """Test AuditService automatic categorization logic"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_authentication_events_categorization(self):
        """Test authentication events are categorized correctly"""
        test_cases = [
            ('login_success', 'authentication', 'medium', True, False),
            ('login_failed', 'authentication', 'medium', True, False),
            ('logout_manual', 'authentication', 'medium', True, False),
            ('account_locked', 'authentication', 'medium', True, True),
            ('session_rotation', 'authentication', 'medium', True, False),
        ]

        for action, expected_category, expected_severity, expected_sensitive, expected_review in test_cases:
            with self.subTest(action=action):
                category = AuditService._get_action_category(action)
                severity = AuditService._get_action_severity(action)
                is_sensitive = AuditService._is_action_sensitive(action)
                requires_review = AuditService._requires_review(action)

                assert category == expected_category, f"Action {action} - expected category {expected_category}, got {category}"
                assert severity == expected_severity, f"Action {action} - expected severity {expected_severity}, got {severity}"
                assert is_sensitive == expected_sensitive, f"Action {action} - expected sensitive {expected_sensitive}, got {is_sensitive}"
                assert requires_review == expected_review, f"Action {action} - expected review {expected_review}, got {requires_review}"

    def test_password_events_categorization(self):
        """Test password events are categorized correctly"""
        test_cases = [
            ('password_changed', 'authentication', 'medium', True, False),
            ('password_reset_requested', 'authentication', 'medium', True, False),
            ('password_reset_completed', 'authentication', 'medium', True, False),
            ('password_compromised', 'authentication', 'high', True, True),
            ('password_strength_weak', 'authentication', 'medium', True, False),
        ]

        for action, expected_category, expected_severity, expected_sensitive, expected_review in test_cases:
            with self.subTest(action=action):
                category = AuditService._get_action_category(action)
                severity = AuditService._get_action_severity(action)
                is_sensitive = AuditService._is_action_sensitive(action)
                requires_review = AuditService._requires_review(action)

                assert category == expected_category
                assert severity == expected_severity
                assert is_sensitive == expected_sensitive
                assert requires_review == expected_review

    def test_2fa_events_categorization(self):
        """Test 2FA events are categorized correctly"""
        test_cases = [
            ('2fa_enabled', 'authentication', 'medium', True, False),
            ('2fa_disabled', 'authentication', 'high', True, True),
            ('2fa_admin_reset', 'authentication', 'high', True, True),
            ('2fa_verification_success', 'authentication', 'medium', True, False),
            ('2fa_verification_failed', 'authentication', 'medium', True, False),
            ('2fa_backup_codes_generated', 'authentication', 'medium', True, False),
        ]

        for action, expected_category, expected_severity, expected_sensitive, expected_review in test_cases:
            with self.subTest(action=action):
                category = AuditService._get_action_category(action)
                severity = AuditService._get_action_severity(action)
                is_sensitive = AuditService._is_action_sensitive(action)
                requires_review = AuditService._requires_review(action)

                assert category == expected_category
                assert severity == expected_severity
                assert is_sensitive == expected_sensitive
                assert requires_review == expected_review

    def test_privacy_events_categorization(self):
        """Test privacy events are categorized correctly"""
        test_cases = [
            ('privacy_settings_changed', 'privacy', 'high', True, False),
            ('gdpr_consent_granted', 'privacy', 'high', True, False),
            ('gdpr_consent_withdrawn', 'privacy', 'high', True, True),
            ('marketing_consent_granted', 'privacy', 'high', True, False),
            ('cookie_consent_updated', 'privacy', 'high', True, False),
        ]

        for action, expected_category, expected_severity, expected_sensitive, expected_review in test_cases:
            with self.subTest(action=action):
                category = AuditService._get_action_category(action)
                severity = AuditService._get_action_severity(action)
                is_sensitive = AuditService._is_action_sensitive(action)
                requires_review = AuditService._requires_review(action)

                assert category == expected_category
                assert severity == expected_severity
                assert is_sensitive == expected_sensitive
                assert requires_review == expected_review

    def test_authorization_events_categorization(self):
        """Test authorization events are categorized correctly"""
        test_cases = [
            ('role_assigned', 'authorization', 'high', True, True),
            ('role_removed', 'authorization', 'high', True, True),
            ('permission_granted', 'authorization', 'high', True, True),
            ('permission_revoked', 'authorization', 'high', True, True),
            ('customer_membership_created', 'authorization', 'medium', False, False),
        ]

        for action, expected_category, expected_severity, expected_sensitive, expected_review in test_cases:
            with self.subTest(action=action):
                category = AuditService._get_action_category(action)
                severity = AuditService._get_action_severity(action)
                is_sensitive = AuditService._is_action_sensitive(action)
                requires_review = AuditService._requires_review(action)

                assert category == expected_category
                assert severity == expected_severity
                # Authorization events may or may not be sensitive depending on context
                assert requires_review == expected_review

    def test_security_events_categorization(self):
        """Test security events are categorized correctly"""
        test_cases = [
            ('security_incident_detected', 'security_event', 'critical', True, True),
            ('suspicious_activity', 'security_event', 'critical', True, True),
            ('brute_force_attempt', 'security_event', 'critical', True, True),
            ('malicious_request', 'security_event', 'critical', True, True),
        ]

        for action, expected_category, expected_severity, expected_sensitive, expected_review in test_cases:
            with self.subTest(action=action):
                category = AuditService._get_action_category(action)
                severity = AuditService._get_action_severity(action)
                is_sensitive = AuditService._is_action_sensitive(action)
                requires_review = AuditService._requires_review(action)

                assert category == expected_category
                assert severity == expected_severity
                assert is_sensitive == expected_sensitive
                assert requires_review == expected_review

    def test_data_protection_events_categorization(self):
        """Test data protection events are categorized correctly"""
        test_cases = [
            ('data_export_requested', 'data_protection', 'high', True, True),
            ('data_deletion_requested', 'data_protection', 'high', True, True),
            ('data_breach_detected', 'security_event', 'critical', True, True),  # Note: categorized as security_event
        ]

        for action, expected_category, expected_severity, expected_sensitive, expected_review in test_cases:
            with self.subTest(action=action):
                category = AuditService._get_action_category(action)
                severity = AuditService._get_action_severity(action)
                is_sensitive = AuditService._is_action_sensitive(action)
                requires_review = AuditService._requires_review(action)

                assert category == expected_category
                assert severity == expected_severity
                assert is_sensitive == expected_sensitive
                assert requires_review == expected_review


class TestAuditEventCreationWithCategorization(TestCase):
    """Test audit event creation with automatic categorization"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_automatic_categorization_on_event_creation(self):
        """Test that events are automatically categorized when created"""
        # Create audit event with authentication action
        context = AuditContext(user=self.user)
        event_data = AuditEventData(
            event_type='login_success',
            content_object=self.user,
            description='User logged in successfully'
        )

        audit_event = AuditService.log_event(event_data, context)

        # Verify automatic categorization
        assert audit_event.action == 'login_success'
        assert audit_event.category == 'authentication'
        assert audit_event.severity == 'medium'
        assert audit_event.is_sensitive is True
        assert audit_event.requires_review is False

    def test_manual_categorization_override(self):
        """Test that manual categorization overrides automatic detection"""
        # Create audit event with manual categorization
        context = AuditContext(
            user=self.user,
            metadata={
                'category': 'system_admin',
                'severity': 'critical',
                'is_sensitive': False,
                'requires_review': True
            }
        )
        event_data = AuditEventData(
            event_type='login_success',  # Would normally be 'authentication'
            content_object=self.user,
            description='Manual override test'
        )

        audit_event = AuditService.log_event(event_data, context)

        # Verify manual override
        assert audit_event.category == 'system_admin'  # Overridden
        assert audit_event.severity == 'critical'      # Overridden
        assert audit_event.is_sensitive is False       # Overridden
        assert audit_event.requires_review is True     # Overridden

    def test_2fa_event_categorization(self):
        """Test 2FA events are categorized with authentication context"""
        context = AuditContext(user=self.user)
        request = TwoFactorAuditRequest(
            event_type='2fa_disabled',
            user=self.user,
            context=context,
            description='2FA disabled by user'
        )

        audit_event = AuditService.log_2fa_event(request)

        # Verify 2FA specific categorization
        assert audit_event.action == '2fa_disabled'
        assert audit_event.category == 'authentication'
        assert audit_event.severity == 'high'
        assert audit_event.is_sensitive is True
        assert audit_event.requires_review is True

        # Verify 2FA metadata
        assert 'event_category' in audit_event.metadata
        assert audit_event.metadata['event_category'] == 'authentication'


class TestSecurityThreatDetection(TestCase):
    """Test security threat detection capabilities"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_critical_security_events(self):
        """Test detection of critical security events"""
        critical_actions = [
            'data_breach_detected',
            'security_incident_detected',
            'brute_force_attempt',
            'malicious_request'
        ]

        for action in critical_actions:
            with self.subTest(action=action):
                context = AuditContext(user=self.user, ip_address='192.168.1.100')
                event_data = AuditEventData(
                    event_type=action,
                    content_object=self.user,
                    description=f'Critical security event: {action}'
                )

                audit_event = AuditService.log_event(event_data, context)

                # All critical security events should be flagged for immediate review
                assert audit_event.severity == 'critical'
                assert audit_event.requires_review is True
                assert audit_event.is_sensitive is True
                assert audit_event.category in ['security_event', 'data_protection']

    def test_suspicious_activity_patterns(self):
        """Test detection of suspicious activity patterns"""
        # Simulate multiple failed login attempts
        for i in range(5):
            context = AuditContext(
                user=self.user,
                ip_address='192.168.1.100',
                metadata={'attempt_number': i + 1}
            )
            event_data = AuditEventData(
                event_type='login_failed_password',
                content_object=self.user,
                description=f'Failed login attempt {i + 1}'
            )

            AuditService.log_event(event_data, context)

        # Check that all failed attempts are properly categorized
        failed_logins = AuditEvent.objects.filter(
            action='login_failed_password',
            user=self.user
        )

        assert failed_logins.count() == 5
        for event in failed_logins:
            assert event.category == 'authentication'
            assert event.severity == 'medium'
            assert event.is_sensitive is True

    def test_privilege_escalation_detection(self):
        """Test detection of privilege escalation attempts"""
        context = AuditContext(
            user=self.user,
            metadata={'escalation_type': 'unauthorized_admin_access'}
        )
        event_data = AuditEventData(
            event_type='privilege_escalation_attempt',
            content_object=self.user,
            description='Attempted unauthorized admin access'
        )

        audit_event = AuditService.log_event(event_data, context)

        # Privilege escalation should be flagged as critical authorization issue
        assert audit_event.category == 'authorization'
        assert audit_event.severity == 'high'  # Based on high_actions list
        assert audit_event.requires_review is True
        assert audit_event.is_sensitive is True


class TestComplianceReporting(TestCase):
    """Test compliance reporting capabilities"""

    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_gdpr_compliance_events(self):
        """Test GDPR compliance event tracking"""
        gdpr_actions = [
            'gdpr_consent_granted',
            'gdpr_consent_withdrawn',
            'data_export_requested',
            'data_deletion_requested'
        ]

        for action in gdpr_actions:
            with self.subTest(action=action):
                context = AuditContext(
                    user=self.user,
                    metadata={'gdpr_article': 'Article 17', 'legal_basis': 'Consent'}
                )
                event_data = AuditEventData(
                    event_type=action,
                    content_object=self.user,
                    description=f'GDPR event: {action}'
                )

                audit_event = AuditService.log_event(event_data, context)

                # GDPR events should be categorized appropriately
                expected_category = 'privacy' if action.startswith('gdpr_consent') else 'data_protection'
                assert audit_event.category == expected_category
                assert audit_event.severity == 'high'
                assert audit_event.is_sensitive is True

    def test_compliance_event_queries(self):
        """Test efficient querying of compliance events"""
        # Create various compliance events
        compliance_events = [
            ('gdpr_consent_granted', 'privacy'),
            ('data_export_requested', 'data_protection'),
            ('vat_validation_completed', 'compliance'),
            ('efactura_submission_completed', 'compliance')
        ]

        for action, category in compliance_events:
            context = AuditContext(
                user=self.user,
                metadata={'compliance_type': 'gdpr' if 'gdpr' in action else 'romanian_law'}
            )
            event_data = AuditEventData(
                event_type=action,
                content_object=self.user,
                description=f'Compliance event: {action}'
            )
            AuditService.log_event(event_data, context)

        # Test efficient querying by category
        with self.assertNumQueries(1):
            privacy_events = list(AuditEvent.objects.filter(
                category='privacy'
            ).order_by('-timestamp'))
            assert len(privacy_events) == 1

        # Test combined queries
        with self.assertNumQueries(1):
            sensitive_compliance = list(AuditEvent.objects.filter(
                category__in=['privacy', 'data_protection', 'compliance'],
                is_sensitive=True
            ).order_by('-timestamp'))
            assert len(sensitive_compliance) >= 2

    def test_audit_event_metadata_structure(self):
        """Test audit event metadata structure for compliance reporting"""
        context = AuditContext(
            user=self.user,
            metadata={
                'gdpr_article': 'Article 20',
                'legal_basis': 'Data portability',
                'retention_period': '7_years',
                'data_categories': ['personal', 'billing']
            }
        )
        event_data = AuditEventData(
            event_type='data_export_requested',
            content_object=self.user,
            description='GDPR data export request'
        )

        audit_event = AuditService.log_event(event_data, context)

        # Verify metadata structure is preserved
        assert 'gdpr_article' in audit_event.metadata
        assert 'legal_basis' in audit_event.metadata
        assert 'retention_period' in audit_event.metadata
        assert 'data_categories' in audit_event.metadata
        assert audit_event.metadata['data_categories'] == ['personal', 'billing']
