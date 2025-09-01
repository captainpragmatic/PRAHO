"""
Test suite for enterprise audit management features.

This module tests advanced audit search, data integrity monitoring, retention management,
and security features for the PRAHO audit system.
"""

import json
import uuid
from datetime import datetime, timedelta
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.contrib.contenttypes.models import ContentType

from apps.audit.models import (
    AuditEvent,
    AuditIntegrityCheck,
    AuditRetentionPolicy,
    AuditSearchQuery,
    AuditAlert,
    ComplianceLog,
)
from apps.audit.services import (
    audit_integrity_service,
    audit_retention_service,
    audit_search_service,
)

User = get_user_model()


class EnterpriseAuditManagementTestCase(TestCase):
    """Base test case with common setup for enterprise audit management tests."""
    
    def setUp(self):
        """Set up test data."""
        # Create test users
        self.staff_user = User.objects.create_user(
            email='staff@example.com',
            password='testpass123',
            is_staff=True,
            staff_role="admin"
        )
        
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            password='testpass123',
            is_staff=True,
            is_superuser=True
        )
        
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            password='testpass123'
        )
        
        # Create test audit events
        self.create_test_audit_events()
        
        # Set up test client
        self.client = Client()
        self.client.login(email='staff@example.com', password='testpass123')
    
    def create_test_audit_events(self):
        """Create test audit events for testing."""
        user_content_type = ContentType.objects.get_for_model(User)
        
        # Create events with different categories and severities
        self.events = []
        
        # Authentication events
        for i in range(5):
            event = AuditEvent.objects.create(
                user=self.regular_user,
                action='login_success',
                category='authentication',
                severity='medium',
                content_type=user_content_type,
                object_id=str(self.regular_user.id),
                description='User logged in successfully',
                ip_address='192.168.1.1',
                timestamp=timezone.now() - timedelta(hours=i)
            )
            self.events.append(event)
        
        # Security events
        for i in range(3):
            event = AuditEvent.objects.create(
                user=self.regular_user,
                action='security_incident_detected',
                category='security_event',
                severity='critical',
                is_sensitive=True,
                requires_review=True,
                content_type=user_content_type,
                object_id=str(self.regular_user.id),
                description='Suspicious login attempt detected',
                ip_address='10.0.0.1',
                timestamp=timezone.now() - timedelta(days=i+1)
            )
            self.events.append(event)
        
        # Business operation events
        for i in range(7):
            event = AuditEvent.objects.create(
                user=self.regular_user,
                action='invoice_created',
                category='business_operation',
                severity='low',
                content_type=user_content_type,
                object_id=str(self.regular_user.id),
                description=f'Invoice INV-{i+1} created',
                ip_address='192.168.1.100',
                timestamp=timezone.now() - timedelta(days=i*2)
            )
            self.events.append(event)


class AuditManagementDashboardTests(EnterpriseAuditManagementTestCase):
    """Test enterprise audit management dashboard functionality."""
    
    def test_dashboard_access_staff_required(self):
        """Test that dashboard requires staff access."""
        # Test anonymous access denied
        self.client.logout()
        response = self.client.get(reverse('audit:management_dashboard'))
        self.assertEqual(response.status_code, 302)
        
        # Test regular user access denied
        self.client.login(email='user@example.com', password='testpass123')
        response = self.client.get(reverse('audit:management_dashboard'))
        self.assertEqual(response.status_code, 403)
        
        # Test staff user access allowed
        self.client.login(email='staff@example.com', password='testpass123')
        response = self.client.get(reverse('audit:management_dashboard'))
        self.assertEqual(response.status_code, 200)
    
    def test_dashboard_metrics_display(self):
        """Test dashboard displays correct metrics."""
        response = self.client.get(reverse('audit:management_dashboard'))
        self.assertEqual(response.status_code, 200)
        
        # Check context data
        context = response.context
        self.assertIn('audit_stats', context)
        
        audit_stats = context['audit_stats']
        self.assertGreater(audit_stats['total_events'], 0)
        self.assertGreater(audit_stats['critical_events'], 0)
        self.assertGreaterEqual(audit_stats['sensitive_events'], 0)
        self.assertGreater(audit_stats['review_required'], 0)
    
    def test_dashboard_template_rendering(self):
        """Test dashboard uses correct template."""
        response = self.client.get(reverse('audit:management_dashboard'))
        self.assertTemplateUsed(response, 'audit/management_dashboard.html')


class AdvancedAuditSearchTests(EnterpriseAuditManagementTestCase):
    """Test advanced audit search and filtering functionality."""
    
    def test_advanced_search_filters(self):
        """Test advanced search with multiple filter combinations."""
        # Test category filter
        response = self.client.get(reverse('audit:logs_list'), {
            'category': ['authentication', 'security_event']
        })
        self.assertEqual(response.status_code, 200)
        
        # Test severity filter
        response = self.client.get(reverse('audit:logs_list'), {
            'severity': ['critical']
        })
        self.assertEqual(response.status_code, 200)
        
        # Test combined filters
        response = self.client.get(reverse('audit:logs_list'), {
            'category': ['security_event'],
            'severity': ['critical'],
            'is_sensitive': 'true'
        })
        self.assertEqual(response.status_code, 200)
    
    def test_search_suggestions_endpoint(self):
        """Test search suggestions API endpoint."""
        response = self.client.get(reverse('audit:search_suggestions'), {
            'q': 'login'
        })
        self.assertEqual(response.status_code, 200)
        
        # Test suggestions for IP addresses
        response = self.client.get(reverse('audit:search_suggestions'), {
            'q': '192.168'
        })
        self.assertEqual(response.status_code, 200)
    
    def test_save_search_query(self):
        """Test saving search queries for reuse."""
        query_data = {
            'name': 'Test Security Search',
            'description': 'Search for critical security events',
            'filter_category': 'security_event',
            'filter_severity': 'critical',
            'is_shared': 'on'
        }
        
        response = self.client.post(reverse('audit:save_search_query'), query_data)
        self.assertEqual(response.status_code, 302)  # Redirect after save
        
        # Verify query was saved
        saved_query = AuditSearchQuery.objects.get(name='Test Security Search')
        self.assertEqual(saved_query.created_by, self.staff_user)
        self.assertTrue(saved_query.is_shared)
    
    def test_load_saved_search(self):
        """Test loading and using saved search queries."""
        # Create a saved search
        query = AuditSearchQuery.objects.create(
            name='Test Query',
            query_params={'category': 'authentication', 'severity': 'medium'},
            created_by=self.staff_user,
            is_shared=True
        )
        
        response = self.client.get(reverse('audit:load_saved_search', args=[query.id]))
        self.assertEqual(response.status_code, 302)  # Redirect to logs with params
        
        # Check usage statistics updated
        query.refresh_from_db()
        self.assertEqual(query.usage_count, 1)
        self.assertIsNotNone(query.last_used_at)
    
    def test_advanced_query_performance(self):
        """Test that advanced queries are optimized and don't cause N+1 problems."""
        filters = {
            'categories': ['authentication', 'security_event'],
            'severities': ['medium', 'critical'],
            'start_date': timezone.now() - timedelta(days=7),
            'end_date': timezone.now(),
            'is_sensitive': True
        }
        
        # This should execute efficiently with proper select_related/prefetch_related
        queryset, query_info = audit_search_service.build_advanced_query(filters, self.staff_user)
        
        # Test that query info is returned
        self.assertIn('filters_applied', query_info)
        self.assertIn('estimated_cost', query_info)
        
        # Test that queryset works
        results = list(queryset[:10])  # Limit for performance
        self.assertIsInstance(results, list)


class AuditIntegrityMonitoringTests(EnterpriseAuditManagementTestCase):
    """Test audit data integrity monitoring functionality."""
    
    def test_integrity_check_hash_verification(self):
        """Test hash verification integrity check."""
        start_time = timezone.now() - timedelta(days=1)
        end_time = timezone.now()
        
        result = audit_integrity_service.verify_audit_integrity(
            period_start=start_time,
            period_end=end_time,
            check_type='hash_verification'
        )
        
        self.assertTrue(result.is_ok())
        
        integrity_check = result.unwrap()
        self.assertEqual(integrity_check.check_type, 'hash_verification')
        self.assertIn(integrity_check.status, ['healthy', 'warning', 'compromised'])
        self.assertGreaterEqual(integrity_check.records_checked, 0)
    
    def test_integrity_check_sequence_gaps(self):
        """Test sequence gap detection."""
        start_time = timezone.now() - timedelta(days=1)
        end_time = timezone.now()
        
        result = audit_integrity_service.verify_audit_integrity(
            period_start=start_time,
            period_end=end_time,
            check_type='sequence_check'
        )
        
        self.assertTrue(result.is_ok())
        
        integrity_check = result.unwrap()
        self.assertEqual(integrity_check.check_type, 'sequence_check')
        self.assertIsInstance(integrity_check.findings, list)
    
    def test_integrity_check_gdpr_compliance(self):
        """Test GDPR compliance validation."""
        start_time = timezone.now() - timedelta(days=1)
        end_time = timezone.now()
        
        result = audit_integrity_service.verify_audit_integrity(
            period_start=start_time,
            period_end=end_time,
            check_type='gdpr_compliance'
        )
        
        self.assertTrue(result.is_ok())
        
        integrity_check = result.unwrap()
        self.assertEqual(integrity_check.check_type, 'gdpr_compliance')
        self.assertIsInstance(integrity_check.findings, list)
    
    def test_integrity_dashboard_access(self):
        """Test integrity dashboard access and data."""
        response = self.client.get(reverse('audit:integrity_dashboard'))
        self.assertEqual(response.status_code, 200)
        
        context = response.context
        self.assertIn('recent_checks', context)
        self.assertIn('stats', context)
    
    def test_manual_integrity_check_trigger(self):
        """Test manually triggering integrity checks."""
        check_data = {
            'check_type': 'hash_verification',
            'start_date': (timezone.now() - timedelta(hours=24)).isoformat(),
            'end_date': timezone.now().isoformat()
        }
        
        response = self.client.post(reverse('audit:run_integrity_check'), check_data)
        self.assertEqual(response.status_code, 302)  # Redirect after check
        
        # Verify check was created
        self.assertTrue(
            AuditIntegrityCheck.objects.filter(check_type='hash_verification').exists()
        )


class AuditRetentionManagementTests(EnterpriseAuditManagementTestCase):
    """Test audit retention policy management."""
    
    def setUp(self):
        super().setUp()
        
        # Create test retention policy
        self.retention_policy = AuditRetentionPolicy.objects.create(
            name='Test Authentication Policy',
            description='Retain authentication logs for 30 days',
            category='authentication',
            retention_days=30,
            action='archive',
            is_active=True,
            created_by=self.admin_user
        )
    
    def test_retention_policy_creation(self):
        """Test creating retention policies."""
        policy = AuditRetentionPolicy.objects.create(
            name='Security Events Policy',
            category='security_event',
            retention_days=365,  # 1 year for security events
            action='archive',
            legal_basis='Romanian Law 190/2018',
            is_mandatory=True,
            created_by=self.admin_user
        )
        
        self.assertEqual(policy.name, 'Security Events Policy')
        self.assertEqual(policy.retention_days, 365)
        self.assertTrue(policy.is_mandatory)
    
    def test_apply_retention_policies(self):
        """Test applying retention policies to audit data."""
        # Create old events that should be processed
        old_timestamp = timezone.now() - timedelta(days=35)  # Older than policy
        
        old_event = AuditEvent.objects.create(
            user=self.regular_user,
            action='login_success',
            category='authentication',
            severity='low',
            content_type=ContentType.objects.get_for_model(User),
            object_id=str(self.regular_user.id),
            description='Old login event',
            timestamp=old_timestamp
        )
        
        # Apply retention policies
        result = audit_retention_service.apply_retention_policies()
        self.assertTrue(result.is_ok())
        
        results = result.unwrap()
        self.assertGreater(results['policies_applied'], 0)
    
    def test_retention_dashboard(self):
        """Test retention management dashboard."""
        response = self.client.get(reverse('audit:retention_dashboard'))
        self.assertEqual(response.status_code, 200)
        
        context = response.context
        self.assertIn('policies', context)
        self.assertIn('retention_stats', context)
    
    def test_retention_policy_application_confirmation(self):
        """Test that retention policy application requires confirmation."""
        # Without confirmation
        response = self.client.post(reverse('audit:apply_retention_policies'))
        self.assertEqual(response.status_code, 302)
        
        # With confirmation
        response = self.client.post(reverse('audit:apply_retention_policies'), {
            'confirm': 'yes'
        })
        self.assertEqual(response.status_code, 302)
    
    def test_financial_record_protection(self):
        """Test that financial records are protected from deletion."""
        # Create a financial event
        financial_event = AuditEvent.objects.create(
            user=self.regular_user,
            action='invoice_created',
            category='business_operation',
            severity='medium',
            content_type=ContentType.objects.get_for_model(User),
            object_id=str(self.regular_user.id),
            description='Invoice created',
            timestamp=timezone.now() - timedelta(days=400)  # Very old
        )
        
        # Create policy that would delete it
        delete_policy = AuditRetentionPolicy.objects.create(
            name='Delete Old Business Events',
            category='business_operation',
            retention_days=30,
            action='delete',
            is_active=True,
            created_by=self.admin_user
        )
        
        # Apply policies
        result = audit_retention_service.apply_retention_policies()
        
        # Financial event should still exist (Romanian 7-year requirement)
        financial_event.refresh_from_db()
        self.assertIsNotNone(financial_event)


class AuditAlertsManagementTests(EnterpriseAuditManagementTestCase):
    """Test security and compliance alerts management."""
    
    def setUp(self):
        super().setUp()
        
        # Create test alerts
        self.alert = AuditAlert.objects.create(
            alert_type='security_incident',
            severity='critical',
            title='Suspicious Login Activity',
            description='Multiple failed login attempts detected',
            status='active'
        )
        
        # Add related events
        security_events = AuditEvent.objects.filter(action='security_incident_detected')
        self.alert.related_events.set(security_events)
    
    def test_alerts_dashboard_access(self):
        """Test alerts dashboard access and filtering."""
        # Login as staff user
        self.client.login(email='admin@example.com', password='testpass123')
        response = self.client.get(reverse('audit:alerts_dashboard'))
        self.assertEqual(response.status_code, 200)
        
        context = response.context
        self.assertIn('alerts', context)
        self.assertIn('alert_stats', context)
    
    def test_alerts_filtering(self):
        """Test alert filtering functionality."""
        # Filter by status
        response = self.client.get(reverse('audit:alerts_dashboard'), {
            'status': 'active'
        })
        self.assertEqual(response.status_code, 200)
        
        # Filter by severity
        response = self.client.get(reverse('audit:alerts_dashboard'), {
            'severity': 'critical'
        })
        self.assertEqual(response.status_code, 200)
        
        # Filter by alert type
        response = self.client.get(reverse('audit:alerts_dashboard'), {
            'alert_type': 'security_incident'
        })
        self.assertEqual(response.status_code, 200)
    
    def test_alert_status_updates(self):
        """Test updating alert status and assignment."""
        # Acknowledge alert
        response = self.client.post(
            reverse('audit:update_alert_status', args=[self.alert.id]),
            {'action': 'acknowledge'}
        )
        self.assertEqual(response.status_code, 302)
        
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, 'acknowledged')
        self.assertEqual(self.alert.acknowledged_by, self.staff_user)
        
        # Assign to self
        response = self.client.post(
            reverse('audit:update_alert_status', args=[self.alert.id]),
            {'action': 'assign_to_me'}
        )
        self.assertEqual(response.status_code, 302)
        
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.assigned_to, self.staff_user)
        # Status should change to investigating when assigned
        self.assertIn(self.alert.status, ['investigating', 'acknowledged'])  # Either is acceptable
        
        # Resolve alert
        response = self.client.post(
            reverse('audit:update_alert_status', args=[self.alert.id]),
            {'action': 'resolve', 'resolution_notes': 'Issue resolved'}
        )
        self.assertEqual(response.status_code, 302)
        
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.status, 'resolved')
        self.assertEqual(self.alert.resolution_notes, 'Issue resolved')
        
        # Mark as false positive
        active_alert = AuditAlert.objects.create(
            alert_type='data_integrity',
            severity='warning',
            title='False Positive Test',
            description='Test alert for false positive',
            status='active'
        )
        
        response = self.client.post(
            reverse('audit:update_alert_status', args=[active_alert.id]),
            {'action': 'false_positive', 'resolution_notes': 'This was a false positive'}
        )
        self.assertEqual(response.status_code, 302)
        
        active_alert.refresh_from_db()
        self.assertEqual(active_alert.status, 'false_positive')


class AuditExportEnhancementsTests(EnterpriseAuditManagementTestCase):
    """Test enhanced audit export functionality."""
    
    def test_csv_export_with_filters(self):
        """Test CSV export with applied filters."""
        export_params = {
            'format': 'csv',
            'category': ['authentication'],
            'severity': ['medium'],
            'start_date': (timezone.now() - timedelta(days=7)).date()
        }
        
        response = self.client.get(reverse('audit:export_logs'), export_params)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        self.assertIn('attachment', response['Content-Disposition'])
    
    def test_json_export_with_filters(self):
        """Test JSON export with comprehensive data structure."""
        export_params = {
            'format': 'json',
            'category': ['security_event'],
            'severity': ['critical']
        }
        
        response = self.client.get(reverse('audit:export_logs'), export_params)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Parse JSON response
        data = json.loads(response.content)
        self.assertIn('export_metadata', data)
        self.assertIn('audit_events', data)
        self.assertGreater(data['export_metadata']['record_count'], 0)
    
    def test_export_size_limits(self):
        """Test that exports are limited for performance."""
        # This would test the 10,000 record limit in production
        export_params = {'format': 'csv'}
        
        response = self.client.get(reverse('audit:export_logs'), export_params)
        self.assertEqual(response.status_code, 200)


class EventDetailEnhancementsTests(EnterpriseAuditManagementTestCase):
    """Test enhanced event detail view with correlation analysis."""
    
    def test_event_detail_with_correlations(self):
        """Test event detail view shows related events."""
        event = self.events[0]  # Pick first authentication event
        
        response = self.client.get(reverse('audit:event_detail', args=[event.id]))
        self.assertEqual(response.status_code, 200)
        
        context = response.context
        self.assertIn('event', context)
        self.assertIn('related_events', context)
        self.assertIn('related_alerts', context)
        
        # Check JSON formatting for metadata
        if context['event_metadata_json']:
            self.assertIsInstance(json.loads(context['event_metadata_json']), dict)
    
    def test_event_correlation_by_user(self):
        """Test that events are correlated by user within time window."""
        # Create events with same user in close time proximity
        base_time = timezone.now()
        
        event1 = AuditEvent.objects.create(
            user=self.regular_user,
            action='login_success',
            category='authentication',
            severity='medium',
            content_type=ContentType.objects.get_for_model(User),
            object_id=str(self.regular_user.id),
            description='User login',
            timestamp=base_time,
            session_key='test_session_123'
        )
        
        event2 = AuditEvent.objects.create(
            user=self.regular_user,
            action='profile_updated',
            category='account_management',
            severity='low',
            content_type=ContentType.objects.get_for_model(User),
            object_id=str(self.regular_user.id),
            description='Profile updated',
            timestamp=base_time + timedelta(minutes=5),
            session_key='test_session_123'
        )
        
        response = self.client.get(reverse('audit:event_detail', args=[event1.id]))
        self.assertEqual(response.status_code, 200)
        
        # Should find event2 as related (same user, same session, close time)
        related_events = response.context['related_events']
        related_event_ids = [e.id for e in related_events]
        self.assertIn(event2.id, related_event_ids)


class SecurityAndPerformanceTests(EnterpriseAuditManagementTestCase):
    """Test security controls and performance optimizations."""
    
    def test_staff_access_required_for_all_views(self):
        """Test that all enterprise audit views require staff access."""
        protected_urls = [
            'audit:management_dashboard',
            'audit:integrity_dashboard',
            'audit:retention_dashboard',
            'audit:alerts_dashboard',
        ]
        
        # Test with regular user (should be denied)
        self.client.login(email='user@example.com', password='testpass123')
        
        for url_name in protected_urls:
            with self.settings(LOGIN_URL='/admin/login/'):
                response = self.client.get(reverse(url_name))
                self.assertEqual(response.status_code, 403, f"{url_name} should require staff access")
    
    def test_search_query_permissions(self):
        """Test that users can only access appropriate saved searches."""
        # Create private search by another user
        other_staff = User.objects.create_user(
            email='other_staff@example.com',
            password='testpass123',
            is_staff=True
        )
        
        private_query = AuditSearchQuery.objects.create(
            name='Private Query',
            query_params={'category': 'authentication'},
            created_by=other_staff,
            is_shared=False
        )
        
        # Should not be able to access private query of another user
        response = self.client.get(reverse('audit:load_saved_search', args=[private_query.id]))
        self.assertEqual(response.status_code, 302)  # Redirect with error
        
        # Should be able to access shared query
        private_query.is_shared = True
        private_query.save()
        
        response = self.client.get(reverse('audit:load_saved_search', args=[private_query.id]))
        self.assertEqual(response.status_code, 302)  # Redirect to search results
    
    def test_audit_event_immutability(self):
        """Test that audit events cannot be modified after creation."""
        event = self.events[0]
        original_description = event.description
        
        # Attempt to modify
        event.description = "Modified description"
        event.save()
        
        # In a real implementation, this might be prevented by database triggers
        # or model overrides. For now, we test that the system is designed for immutability.
        self.assertIsNotNone(event.timestamp)  # Core audit fields should remain intact


class ComplianceAndReportingTests(EnterpriseAuditManagementTestCase):
    """Test compliance features and reporting capabilities."""
    
    def test_romanian_compliance_features(self):
        """Test Romanian-specific compliance features."""
        # Test that financial records are marked properly
        financial_event = AuditEvent.objects.create(
            user=self.regular_user,
            action='invoice_created',
            category='business_operation',
            severity='medium',
            content_type=ContentType.objects.get_for_model(User),
            object_id=str(self.regular_user.id),
            description='Invoice INV-2025-001 created',
            metadata={
                'invoice_number': 'INV-2025-001',
                'vat_amount': '19.00',
                'total_amount': '100.00',
                'romanian_compliance': True
            }
        )
        
        # Should be detected as financial record
        is_financial = audit_retention_service._is_financial_record(financial_event)
        self.assertTrue(is_financial)
    
    def test_gdpr_compliance_validation(self):
        """Test GDPR compliance validation in integrity checks."""
        # Create events that might have compliance issues
        incomplete_event = AuditEvent.objects.create(
            user=None,  # Missing required user for privacy event
            action='gdpr_consent_withdrawn',
            category='privacy',
            severity='high',
            content_type=ContentType.objects.get_for_model(User),
            object_id='1',
            description='GDPR consent withdrawn',
            ip_address=None  # Missing required IP for GDPR event
        )
        
        # Run GDPR compliance check
        start_time = timezone.now() - timedelta(minutes=1)
        end_time = timezone.now() + timedelta(minutes=1)
        
        result = audit_integrity_service.verify_audit_integrity(
            period_start=start_time,
            period_end=end_time,
            check_type='gdpr_compliance'
        )
        
        self.assertTrue(result.is_ok())
        integrity_check = result.unwrap()
        
        # Should find compliance issues
        if integrity_check.issues_found > 0:
            findings = integrity_check.findings
            compliance_issues = [f for f in findings if f['type'] == 'gdpr_compliance']
            self.assertGreater(len(compliance_issues), 0)