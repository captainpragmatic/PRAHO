"""
===============================================================================
GDPR BASIC FUNCTIONALITY TESTS 🛡️
===============================================================================

Basic tests for GDPR compliance functionality covering core features:
- Service instantiation and basic operations
- Data export request creation
- Consent management basics
- Romanian Law 190/2018 compliance validation
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import ComplianceLog, DataExport
from apps.audit.services import (
    audit_service,
    gdpr_consent_service,
    gdpr_deletion_service,
    gdpr_export_service,
)

User = get_user_model()


class GDPRExportBasicTestCase(TestCase):
    """🛡️ Test basic GDPR export functionality"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@praho.com',
            password='testpass123',
            first_name='Maria',
            last_name='Popescu'
        )
        self.user.gdpr_consent_date = timezone.now() - timedelta(days=30)
        self.user.save()

    def test_export_service_exists(self):
        """Test that GDPR export service is available"""
        self.assertTrue(hasattr(gdpr_export_service, 'create_data_export_request'))
        self.assertTrue(hasattr(gdpr_export_service, 'process_data_export'))

    def test_create_basic_export_request(self):
        """Test creating a basic GDPR export request"""
        export_scope = {
            'include_profile': True,
            'format': 'json'
        }

        result = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope=export_scope
        )

        # Should succeed
        self.assertTrue(result.is_ok())
        export_request = result.value

        # Verify basic properties
        self.assertEqual(export_request.requested_by, self.user)
        self.assertEqual(export_request.status, 'pending')
        self.assertEqual(export_request.scope, export_scope)
        self.assertIsNotNone(export_request.expires_at)

    def test_export_request_has_expiration(self):
        """Test that export requests have proper expiration dates"""
        result = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope={'include_profile': True}
        )

        export_request = result.value

        # Should expire in approximately 7 days
        expected_expiry = timezone.now() + timedelta(days=7)
        time_diff = abs(
            (export_request.expires_at - expected_expiry).total_seconds()
        )

        # Allow 1 minute difference
        self.assertLess(time_diff, 60)


class GDPRConsentBasicTestCase(TestCase):
    """🛡️ Test basic GDPR consent functionality"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='consent@praho.com',
            password='testpass123'
        )
        self.user.gdpr_consent_date = timezone.now() - timedelta(days=10)
        self.user.accepts_marketing = True
        self.user.save()

    def test_consent_service_exists(self):
        """Test that GDPR consent service is available"""
        self.assertTrue(hasattr(gdpr_consent_service, 'withdraw_consent'))
        self.assertTrue(hasattr(gdpr_consent_service, 'get_consent_history'))

    def test_marketing_consent_withdrawal(self):
        """Test withdrawing marketing consent"""
        # Verify initial state
        self.assertTrue(self.user.accepts_marketing)

        result = gdpr_consent_service.withdraw_consent(
            user=self.user,
            consent_types=['marketing']
        )

        # Should succeed
        self.assertTrue(result.is_ok())

        # Verify marketing consent was withdrawn
        self.user.refresh_from_db()
        self.assertFalse(self.user.accepts_marketing)

    def test_consent_history_retrieval(self):
        """Test retrieving consent history"""
        # Create a consent event first
        audit_service.log_compliance_event(
            compliance_type='gdpr_consent',
            reference_id='test_consent_history',
            description='Test consent granted',
            user=self.user,
            status='success'
        )

        history = gdpr_consent_service.get_consent_history(self.user)

        # Should return a list
        self.assertIsInstance(history, list)
        # Should have at least one entry
        self.assertGreater(len(history), 0)


class GDPRDeletionBasicTestCase(TestCase):
    """🛡️ Test basic GDPR deletion functionality"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='delete@praho.com',
            password='testpass123',
            first_name='Ion',
            last_name='Ionescu'
        )

    def test_deletion_service_exists(self):
        """Test that GDPR deletion service is available"""
        self.assertTrue(hasattr(gdpr_deletion_service, 'create_deletion_request'))
        self.assertTrue(hasattr(gdpr_deletion_service, 'process_deletion_request'))

    def test_create_anonymization_request(self):
        """Test creating a data anonymization request"""
        result = gdpr_deletion_service.create_deletion_request(
            user=self.user,
            deletion_type='anonymize',
            reason='User requested anonymization'
        )

        # Should succeed
        self.assertTrue(result.is_ok())

        # Should create a compliance log entry
        log_entries = ComplianceLog.objects.filter(
            compliance_type='gdpr_deletion',
            user=self.user
        )
        self.assertGreater(len(log_entries), 0)

        log_entry = log_entries.first()
        self.assertEqual(log_entry.status, 'requested')  # Updated to match service implementation
        self.assertIn('anonymize', log_entry.description.lower())


class GDPRViewsBasicTestCase(TestCase):
    """🛡️ Test basic GDPR views functionality"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='views@praho.com',
            password='testpass123'
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_gdpr_dashboard_accessible(self):
        """Test that GDPR dashboard is accessible to authenticated users"""
        url = reverse('audit:gdpr_dashboard')
        response = self.client.get(url)

        # Should load successfully
        self.assertEqual(response.status_code, 200)

        # Should contain expected content
        self.assertContains(response, 'Privacy')
        self.assertContains(response, 'Data Protection')

    def test_consent_history_accessible(self):
        """Test that GDPR dashboard shows consent history information"""
        url = reverse('audit:gdpr_dashboard')
        response = self.client.get(url)

        # Should load successfully
        self.assertEqual(response.status_code, 200)

        # Should contain expected content
        self.assertContains(response, 'Recent Consent Changes')

    def test_unauthenticated_access_redirects(self):
        """Test that unauthenticated users are redirected to login"""
        self.client.logout()

        urls_to_test = [
            reverse('audit:gdpr_dashboard'),
        ]

        for url in urls_to_test:
            response = self.client.get(url)
            # Should redirect (302) to login
            self.assertEqual(response.status_code, 302)
            # Should redirect to auth/login
            self.assertIn('/users/login/', response.url)


class GDPRComplianceBasicTestCase(TestCase):
    """🛡️ Test basic GDPR compliance and Romanian law requirements"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='compliance@praho.com',
            password='testpass123'
        )

    def test_audit_service_logging(self):
        """Test that audit service can log compliance events"""
        # Log a test compliance event
        result = audit_service.log_compliance_event(
            compliance_type='gdpr_consent',
            reference_id='test_compliance_log',
            description='Test Romanian GDPR compliance logging',
            user=self.user,
            status='success',
            evidence={'test': 'data'},
            metadata={'legal_basis': 'Romanian Law 190/2018'}
        )

        # Should succeed (assuming audit service returns success indicator)
        self.assertIsNotNone(result)

        # Verify log entry was created
        log_entry = ComplianceLog.objects.filter(
            compliance_type='gdpr_consent',
            reference_id='test_compliance_log'
        ).first()

        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.user, self.user)
        self.assertEqual(log_entry.status, 'success')
        self.assertEqual(log_entry.evidence, {'test': 'data'})

    def test_data_export_model_creation(self):
        """Test that DataExport model can be created properly"""
        export_request = DataExport.objects.create(
            requested_by=self.user,
            export_type='gdpr',
            scope={'include_profile': True},
            expires_at=timezone.now() + timedelta(days=7)
        )

        # Should create successfully
        self.assertIsNotNone(export_request.id)
        self.assertEqual(export_request.requested_by, self.user)
        self.assertEqual(export_request.status, 'pending')  # Default status
        self.assertEqual(export_request.scope, {'include_profile': True})
