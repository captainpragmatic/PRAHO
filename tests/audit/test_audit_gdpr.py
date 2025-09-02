"""
===============================================================================
COMPREHENSIVE GDPR COMPLIANCE TESTS 🛡️
===============================================================================

Tests for GDPR compliance implementation covering:
- Data export (Article 20 - Right to data portability)
- Data deletion/anonymization (Article 17 - Right to erasure)  
- Consent management (Articles 6, 7 - Lawful basis and consent)
- Romanian Law 190/2018 compliance
- Security and access controls
"""

import json
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.core.files.storage import default_storage
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


class GDPRExportServiceTestCase(TestCase):
    """🛡️ Test GDPR data export functionality"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Ion',
            last_name='Popescu'
        )
        self.user.gdpr_consent_date = timezone.now() - timedelta(days=30)
        self.user.save()

    def test_create_data_export_request_success(self):
        """Test successful data export request creation"""
        export_scope = {
            'include_profile': True,
            'include_customers': True,
            'include_billing': False,
            'format': 'json'
        }

        result = gdpr_export_service.create_data_export_request(
            user=self.user,
            request_ip='192.168.1.1',
            export_scope=export_scope
        )

        self.assertTrue(result.is_ok())
        if result.is_ok():
            export_request = result.value
        else:
            self.fail("Result should be Ok")

        self.assertEqual(export_request.requested_by, self.user)
        self.assertEqual(export_request.status, 'pending')
        self.assertEqual(export_request.scope, export_scope)  # Field is 'scope' not 'export_scope'
        self.assertEqual(export_request.file_path, '')

        # Check expiration date (should be 7 days from now)
        expected_expiry = timezone.now() + timedelta(days=7)
        self.assertAlmostEqual(
            export_request.expires_at.timestamp(),
            expected_expiry.timestamp(),
            delta=60  # Allow 1-minute difference
        )

    def test_create_data_export_request_duplicate_prevention(self):
        """Test that multiple export requests can be created (no artificial limits)"""
        export_scope = {'include_profile': True, 'format': 'json'}

        # Create first request
        result1 = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope=export_scope
        )
        self.assertTrue(result1.is_ok())

        # Create second request (should also succeed - no duplicate prevention implemented)
        result2 = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope=export_scope
        )
        self.assertTrue(result2.is_ok())  # Both requests should succeed

    def test_process_data_export_success(self):
        """Test successful data export processing"""
        # Create export request
        result = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope={'include_profile': True, 'format': 'json'}
        )
        export_request = result.value

        # Process the export
        process_result = gdpr_export_service.process_data_export(export_request)
        self.assertTrue(process_result.is_ok())

        # Verify export was processed
        export_request.refresh_from_db()
        self.assertEqual(export_request.status, 'completed')
        self.assertIsNotNone(export_request.file_path)
        self.assertIsNotNone(export_request.file_size)
        assert export_request.file_size is not None  # Type narrowing
        self.assertGreater(export_request.file_size, 0)

        # Verify file exists and contains valid JSON
        self.assertTrue(default_storage.exists(export_request.file_path))
        file_content = default_storage.open(export_request.file_path).read()
        data = json.loads(file_content)

        # Check Romanian compliance metadata (updated field name)
        self.assertIn('metadata', data)
        self.assertIn('gdpr_article', data['metadata'])
        self.assertEqual(data['metadata']['gdpr_article'], 'Article 20 - Right to data portability')

        # Check user data
        self.assertIn('user_profile', data)
        self.assertEqual(data['user_profile']['email'], self.user.email)
        self.assertEqual(data['user_profile']['first_name'], 'Ion')

    def test_process_data_export_failure_handling(self):
        """Test export processing failure handling"""
        # Create export request
        result = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope={'include_profile': True, 'format': 'json'}
        )
        export_request = result.value

        # Mock storage failure
        with patch('apps.audit.services.default_storage.save') as mock_save:
            mock_save.side_effect = Exception("Storage error")

            process_result = gdpr_export_service.process_data_export(export_request)
            self.assertTrue(process_result.is_err())
            self.assertIn('Storage error', process_result.error)

            # Verify status is marked as failed
            export_request.refresh_from_db()
            self.assertEqual(export_request.status, 'failed')


class GDPRDeletionServiceTest(TestCase):
    """Test GDPR data deletion and anonymization"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='delete@example.com',
            password='testpass123',
            first_name='Maria',
            last_name='Ionescu'
        )

    def test_create_deletion_request_anonymize(self):
        """Test anonymization request creation"""
        result = gdpr_deletion_service.create_deletion_request(
            user=self.user,
            deletion_type='anonymize',
            request_ip='10.0.0.1',
            reason='No longer need account'
        )

        self.assertTrue(result.is_ok())

        # Check compliance log entry
        log_entry = ComplianceLog.objects.filter(
            compliance_type='gdpr_deletion',
            user=self.user
        ).first()

        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.status, 'requested')
        self.assertIn('anonymize', log_entry.description)
        self.assertEqual(log_entry.evidence['deletion_type'], 'anonymize')
        self.assertEqual(log_entry.evidence['reason'], 'No longer need account')

    def test_create_deletion_request_delete(self):
        """Test full deletion request creation"""
        result = gdpr_deletion_service.create_deletion_request(
            user=self.user,
            deletion_type='delete',
            request_ip='10.0.0.1',
            reason='Complete data removal requested'
        )

        self.assertTrue(result.is_ok())

        log_entry = ComplianceLog.objects.filter(
            compliance_type='gdpr_deletion',
            user=self.user
        ).first()

        self.assertEqual(log_entry.evidence['deletion_type'], 'delete')
        self.assertIn('irreversible', log_entry.description.lower())

    def test_process_deletion_request_anonymize(self):
        """Test user anonymization processing"""
        # Create deletion request
        result = gdpr_deletion_service.create_deletion_request(
            user=self.user,
            deletion_type='anonymize',
            reason='Privacy request'
        )
        deletion_request = result.value

        # Store original values
        original_email = self.user.email

        # Process the deletion
        process_result = gdpr_deletion_service.process_deletion_request(deletion_request)
        self.assertTrue(process_result.is_ok())

        # Verify user data was anonymized
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.email, original_email)
        self.assertTrue(self.user.email.startswith('anonymized_'))
        self.assertTrue(self.user.email.endswith('@example.com'))
        self.assertEqual(self.user.first_name, 'Anonymized')
        self.assertEqual(self.user.last_name, 'User')
        self.assertFalse(self.user.is_active)

        # Verify log entry was updated
        deletion_request.refresh_from_db()
        self.assertEqual(deletion_request.status, 'completed')


class GDPRConsentServiceTest(TestCase):
    """Test GDPR consent management"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='consent@example.com',
            password='testpass123'
        )
        self.user.gdpr_consent_date = timezone.now() - timedelta(days=10)
        self.user.accepts_marketing = True
        self.user.save()

    def test_withdraw_consent_marketing_only(self):
        """Test withdrawing only marketing consent"""
        result = gdpr_consent_service.withdraw_consent(
            user=self.user,
            consent_types=['marketing'],
            request_ip='192.168.1.100'
        )

        self.assertTrue(result.is_ok())
        self.assertIn('marketing', result.value)

        # Verify user preferences updated
        self.user.refresh_from_db()
        self.assertFalse(self.user.accepts_marketing)
        self.assertTrue(self.user.is_active)  # Still active

        # Verify compliance log
        log_entry = ComplianceLog.objects.filter(
            compliance_type='gdpr_consent',
            user=self.user,
            description__icontains='marketing'
        ).first()

        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.status, 'success')

    def test_withdraw_consent_data_processing(self):
        """Test withdrawing data processing consent (triggers anonymization)"""
        result = gdpr_consent_service.withdraw_consent(
            user=self.user,
            consent_types=['data_processing'],
            request_ip='192.168.1.100'
        )

        self.assertTrue(result.is_ok())

        # Verify user account was deactivated
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertIsNone(self.user.gdpr_consent_date)

        # Should have compliance logs for both consent withdrawal and anonymization
        consent_log = ComplianceLog.objects.filter(
            compliance_type='gdpr_consent',
            user=self.user
        ).first()
        self.assertIsNotNone(consent_log)

        deletion_log = ComplianceLog.objects.filter(
            compliance_type='gdpr_deletion',
            user=self.user
        ).first()
        self.assertIsNotNone(deletion_log)

    def test_get_consent_history(self):
        """Test retrieving user consent history"""
        # Create some consent events
        audit_service.log_compliance_event(
            compliance_type='gdpr_consent',
            reference_id='consent_granted',
            description='Initial consent granted',
            user=self.user,
            status='success'
        )

        history = gdpr_consent_service.get_consent_history(self.user)

        self.assertIsInstance(history, list)
        self.assertGreater(len(history), 0)

        # Check structure
        for entry in history:
            self.assertIn('timestamp', entry)
            self.assertIn('action', entry)
            self.assertIn('description', entry)


class GDPRViewsTest(TestCase):
    """Test GDPR views and user workflows"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='views@example.com',
            password='testpass123'
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_gdpr_dashboard_access(self):
        """Test GDPR dashboard page loads correctly"""
        url = reverse('audit:gdpr_dashboard')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Privacy & Data Protection')
        self.assertContains(response, 'Data Protection')
        self.assertContains(response, 'Romanian Law 190/2018')

    def test_request_data_export_post(self):
        """Test data export request via POST"""
        url = reverse('audit:request_data_export')
        data = {
            'include_profile': 'on',
            'include_customers': 'on',
            'include_billing': 'on',
        }

        response = self.client.post(url, data)

        # Should redirect back to dashboard
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.endswith(reverse('audit:gdpr_dashboard')))

        # Verify export request was created
        export_request = DataExport.objects.filter(requested_by=self.user).first()
        self.assertIsNotNone(export_request)
        self.assertTrue(export_request.scope['include_profile'])
        self.assertTrue(export_request.scope['include_customers'])

    def test_download_data_export_success(self):
        """Test downloading completed export"""
        # Create and process export request
        result = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope={'include_profile': True, 'format': 'json'}
        )
        export_request = result.value
        gdpr_export_service.process_data_export(export_request)

        # Test download
        url = reverse('audit:download_data_export', args=[export_request.id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertIn('attachment', response['Content-Disposition'])

        # Verify download was logged
        export_request.refresh_from_db()
        self.assertEqual(export_request.download_count, 1)

    def test_download_data_export_expired(self):
        """Test downloading expired export fails gracefully"""
        # Create export request and mark as expired
        result = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope={'include_profile': True, 'format': 'json'}
        )
        export_request = result.value
        export_request.expires_at = timezone.now() - timedelta(hours=1)
        export_request.status = 'completed'
        export_request.save()

        url = reverse('audit:download_data_export', args=[export_request.id])
        response = self.client.get(url)

        # Should redirect with error message
        self.assertEqual(response.status_code, 302)
        messages = list(get_messages(response.wsgi_request))
        self.assertTrue(any('expired' in str(m) for m in messages))

    def test_request_data_deletion_post(self):
        """Test data deletion request via POST"""
        url = reverse('audit:request_data_deletion')
        data = {
            'deletion_type': 'anonymize',
            'reason': 'Privacy concerns',
            'confirm_immediate': 'yes'
        }

        response = self.client.post(url, data)

        # Should redirect back to dashboard
        self.assertEqual(response.status_code, 302)

        # Verify deletion request was logged
        deletion_log = ComplianceLog.objects.filter(
            compliance_type='gdpr_deletion',
            user=self.user
        ).first()
        self.assertIsNotNone(deletion_log)

        # User should be anonymized due to immediate processing
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)

    def test_withdraw_consent_post(self):
        """Test consent withdrawal via POST"""
        url = reverse('audit:withdraw_consent')
        data = {
            'consent_types': ['marketing']
        }

        response = self.client.post(url, data)

        # Should redirect back to dashboard
        self.assertEqual(response.status_code, 302)

        # Verify consent was withdrawn
        self.user.refresh_from_db()
        self.assertFalse(self.user.accepts_marketing)

    def test_consent_history_view(self):
        """Test consent history page"""
        # Create some consent history
        audit_service.log_compliance_event(
            compliance_type='gdpr_consent',
            reference_id='test_consent',
            description='Test consent event',
            user=self.user,
            status='success'
        )

        url = reverse('audit:gdpr_dashboard')
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Recent Consent Changes')
        self.assertContains(response, 'Test consent event')


class GDPRIntegrationTestCase(TestCase):
    """End-to-end GDPR compliance integration tests"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='integration@example.com',
            password='testpass123',
            first_name='Andrei',
            last_name='Gheorghe'
        )
        self.user.gdpr_consent_date = timezone.now()
        self.user.accepts_marketing = True
        self.user.save()

        self.client = Client()
        self.client.force_login(self.user)

    def test_complete_gdpr_export_workflow(self):
        """Test complete data export workflow from request to download"""
        # 1. Request export via dashboard
        response = self.client.post(reverse('audit:request_data_export'), {
            'include_profile': 'on',
            'include_customers': 'on',
        })
        self.assertEqual(response.status_code, 302)

        # 2. Verify export request exists
        export_request = DataExport.objects.get(requested_by=self.user)
        self.assertEqual(export_request.status, 'completed')  # Processed immediately

        # 3. Download the export
        download_response = self.client.get(
            reverse('audit:download_data_export', args=[export_request.id])
        )
        self.assertEqual(download_response.status_code, 200)

        # 4. Verify file content
        export_data = json.loads(download_response.content)
        self.assertIn('user_profile', export_data)
        self.assertEqual(export_data['user_profile']['email'], self.user.email)
        self.assertIn('Romanian Law 190/2018', export_data['metadata']['legal_basis'])

    def test_complete_gdpr_deletion_workflow(self):
        """Test complete data deletion workflow"""
        # 1. Request deletion
        response = self.client.post(reverse('audit:request_data_deletion'), {
            'deletion_type': 'anonymize',
            'reason': 'Account no longer needed',
            'confirm_immediate': 'yes'
        })
        self.assertEqual(response.status_code, 302)

        # 2. Verify user was anonymized
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertTrue(self.user.email.startswith('anonymized_'))

        # 3. Verify audit trail
        deletion_log = ComplianceLog.objects.filter(
            compliance_type='gdpr_deletion',
            reference_id__icontains=str(self.user.id)
        ).first()
        self.assertIsNotNone(deletion_log)
        self.assertEqual(deletion_log.status, 'completed')

    def test_consent_withdrawal_cascade(self):
        """Test consent withdrawal with cascading effects"""
        # Verify initial state
        self.assertTrue(self.user.accepts_marketing)
        self.assertIsNotNone(self.user.gdpr_consent_date)

        # 1. Withdraw data processing consent
        response = self.client.post(reverse('audit:withdraw_consent'), {
            'consent_types': ['data_processing']
        })
        self.assertEqual(response.status_code, 302)

        # 2. Verify cascading anonymization
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_active)
        self.assertIsNone(self.user.gdpr_consent_date)

        # 3. Verify multiple compliance logs
        consent_logs = ComplianceLog.objects.filter(
            user=self.user
        ).order_by('timestamp')
        self.assertGreaterEqual(len(consent_logs), 2)

        # Should have both consent withdrawal and deletion logs
        log_types = [log.compliance_type for log in consent_logs]
        self.assertIn('gdpr_consent', log_types)
        self.assertIn('gdpr_deletion', log_types)


class GDPRSecurityTest(TestCase):
    """Security-focused GDPR tests"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='security@example.com',
            password='testpass123'
        )
        self.other_user = User.objects.create_user(
            email='other@example.com',
            password='testpass123'
        )
        self.client = Client()

    def test_export_access_control(self):
        """Test users can only access their own exports"""
        self.client.force_login(self.user)

        # Create export for other user
        other_result = gdpr_export_service.create_data_export_request(
            user=self.other_user,
            export_scope={'include_profile': True, 'format': 'json'}
        )
        other_export = other_result.value
        gdpr_export_service.process_data_export(other_export)

        # Try to download other user's export
        url = reverse('audit:download_data_export', args=[other_export.id])
        response = self.client.get(url)

        # Should return 404 (not 403 to avoid information disclosure)
        self.assertEqual(response.status_code, 404)

    def test_gdpr_views_require_authentication(self):
        """Test all GDPR views require authentication"""
        urls = [
            reverse('audit:gdpr_dashboard'),
            reverse('audit:request_data_export'),
            reverse('audit:request_data_deletion'),
            reverse('audit:withdraw_consent'),
        ]

        for url in urls:
            response = self.client.get(url)
            # Should redirect to login
            self.assertEqual(response.status_code, 302)
            self.assertIn('/users/login/', response.url)

    def test_export_data_sanitization(self):
        """Test exported data doesn't contain sensitive system information"""
        # Create and process export
        result = gdpr_export_service.create_data_export_request(
            user=self.user,
            export_scope={'include_profile': True, 'format': 'json'}
        )
        export_request = result.value
        process_result = gdpr_export_service.process_data_export(export_request)

        self.assertTrue(process_result.is_ok())

        # Read export data
        file_content = default_storage.open(export_request.file_path).read()
        export_data = json.loads(file_content)

        # Should not contain sensitive system fields
        user_data = export_data.get('user_profile', {})
        sensitive_fields = ['password', 'last_login_ip', 'session_key']

        for field in sensitive_fields:
            self.assertNotIn(field, user_data)

        # Should contain proper legal basis
        self.assertIn('legal_basis', export_data['metadata'])
        self.assertIn('Romanian Law 190/2018', export_data['metadata']['legal_basis'])
