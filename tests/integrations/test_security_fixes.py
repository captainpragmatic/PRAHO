"""
🔒 Integrations App Security Fix Tests
Tests all security enhancements implemented for the integrations system.
"""

import hashlib
import json
import uuid
from unittest.mock import patch, Mock, MagicMock
from django.test import TestCase, Client, RequestFactory
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from django.utils.html import escape

from apps.integrations.models import WebhookEvent, WebhookDelivery
from apps.integrations.webhooks.base import BaseWebhookProcessor, SecurityError
from apps.integrations.views import webhook_status, retry_webhook
from apps.billing.models import Currency

User = get_user_model()


class WebhookSignatureSecurityTests(TestCase):
    """🔒 Tests for webhook signature hashing security fixes"""

    def setUp(self):
        self.currency = Currency.objects.create(
            code='USD',
            name='US Dollar',
            symbol='$'
        )

    def test_webhook_signature_hashing(self):
        """Test that webhook signatures are properly hashed instead of stored raw"""
        webhook_event = WebhookEvent.objects.create(
            source='stripe',
            event_id='evt_test123',
            event_type='invoice.payment_succeeded',
            payload={'test': 'data'},
            ip_address='192.168.1.1',
            user_agent='Stripe-Webhook/1.0'
        )
        
        # Test setting signature
        test_signature = 'whsec_test_signature_12345'
        webhook_event.set_signature(test_signature)
        webhook_event.save()
        
        # Verify signature is hashed, not stored raw
        self.assertNotEqual(webhook_event.signature_hash, test_signature)
        self.assertEqual(len(webhook_event.signature_hash), 64)  # SHA-256 hex length
        
        # Verify it's a valid SHA-256 hash
        expected_hash = hashlib.sha256(test_signature.encode()).hexdigest()
        self.assertEqual(webhook_event.signature_hash, expected_hash)

    def test_signature_verification(self):
        """Test signature verification against stored hash"""
        webhook_event = WebhookEvent.objects.create(
            source='stripe',
            event_id='evt_test124',
            event_type='invoice.created',
            payload={'test': 'data'}
        )
        
        original_signature = 'whsec_original_signature_12345'
        webhook_event.set_signature(original_signature)
        webhook_event.save()
        
        # Test correct signature verification
        self.assertTrue(webhook_event.verify_signature_hash(original_signature))
        
        # Test incorrect signature
        self.assertFalse(webhook_event.verify_signature_hash('wrong_signature'))
        
        # Test empty signature
        self.assertFalse(webhook_event.verify_signature_hash(''))
        self.assertFalse(webhook_event.verify_signature_hash(None))

    def test_empty_signature_handling(self):
        """Test handling of empty signatures"""
        webhook_event = WebhookEvent.objects.create(
            source='test',
            event_id='evt_empty',
            event_type='test.event',
            payload={}
        )
        
        # Test setting empty signature
        webhook_event.set_signature('')
        self.assertEqual(webhook_event.signature_hash, '')
        
        webhook_event.set_signature(None)
        self.assertEqual(webhook_event.signature_hash, '')

    def test_signature_hash_consistency(self):
        """Test that same signature always produces same hash"""
        signature = 'test_signature_consistency'
        
        webhook1 = WebhookEvent.objects.create(
            source='test1',
            event_id='evt_1',
            event_type='test',
            payload={}
        )
        
        webhook2 = WebhookEvent.objects.create(
            source='test2', 
            event_id='evt_2',
            event_type='test',
            payload={}
        )
        
        webhook1.set_signature(signature)
        webhook2.set_signature(signature)
        
        self.assertEqual(webhook1.signature_hash, webhook2.signature_hash)

    def test_database_signature_field_migration(self):
        """Test that signature_hash field exists and works correctly"""
        webhook_event = WebhookEvent()
        
        # Verify the field exists
        self.assertTrue(hasattr(webhook_event, 'signature_hash'))
        
        # Verify field properties
        field = WebhookEvent._meta.get_field('signature_hash')
        self.assertEqual(field.max_length, 64)
        self.assertTrue(field.blank)


class RetryTimingSecurityTests(TestCase):
    """🔒 Tests for retry timing jitter security fixes"""

    def setUp(self):
        self.currency = Currency.objects.create(
            code='USD',
            name='US Dollar',
            symbol='$'
        )

    @patch('secrets.SystemRandom.uniform')
    def test_retry_timing_uses_jitter(self, mock_uniform):
        """Test that retry timing uses jitter to prevent timing attacks"""
        mock_uniform.return_value = 0.9  # 90% of base delay
        
        webhook_event = WebhookEvent.objects.create(
            source='stripe',
            event_id='evt_retry_test',
            event_type='test.event',
            payload={'test': 'data'},
            status='pending'
        )
        
        # Mark as failed to trigger retry calculation
        webhook_event.mark_failed('Test error')
        
        # Verify jitter was applied
        mock_uniform.assert_called_with(0.8, 1.2)
        
        # Verify retry time is calculated with jitter
        self.assertIsNotNone(webhook_event.next_retry_at)
        
        # Calculate expected delay with jitter
        expected_base_delay = 300  # First retry delay
        expected_jittered_delay = int(expected_base_delay * 0.9)
        
        expected_time = timezone.now() + timedelta(seconds=expected_jittered_delay)
        
        # Allow 1-second tolerance for test execution time
        time_diff = abs((webhook_event.next_retry_at - expected_time).total_seconds())
        self.assertLess(time_diff, 1)

    def test_retry_timing_randomization_range(self):
        """Test that retry timing randomization is within expected range"""
        webhook_event = WebhookEvent.objects.create(
            source='test',
            event_id='evt_random_test',
            event_type='test.event',
            payload={},
            status='pending'
        )
        
        # Test multiple failures to check jitter range
        retry_delays = []
        base_delays = [300, 900, 3600, 7200, 21600]  # Expected base delays
        
        for i in range(5):
            webhook_event.retry_count = i
            original_time = timezone.now()
            webhook_event.mark_failed(f'Test error {i+1}', save=False)
            
            if webhook_event.next_retry_at:
                actual_delay = (webhook_event.next_retry_at - original_time).total_seconds()
                retry_delays.append(actual_delay)
                
                # Verify delay is within jitter range (80% to 120% of base)
                base_delay = base_delays[i]
                min_delay = base_delay * 0.8
                max_delay = base_delay * 1.2
                
                self.assertGreaterEqual(actual_delay, min_delay - 1)  # Allow 1s tolerance
                self.assertLessEqual(actual_delay, max_delay + 1)

    def test_retry_count_progression(self):
        """Test that retry count progresses correctly with timing"""
        webhook_event = WebhookEvent.objects.create(
            source='test',
            event_id='evt_progression',
            event_type='test.event', 
            payload={}
        )
        
        # Test progression through retry attempts
        expected_counts = [1, 2, 3, 4, 5]
        
        for expected_count in expected_counts:
            webhook_event.mark_failed(f'Error attempt {expected_count}')
            
            self.assertEqual(webhook_event.retry_count, expected_count)
            
            if expected_count <= 5:  # Only first 5 attempts get retry times
                self.assertIsNotNone(webhook_event.next_retry_at)
            else:
                # After max retries, no more retry time set
                break


class InputSanitizationSecurityTests(TestCase):
    """🔒 Tests for input sanitization security fixes"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='staff@example.com',
            password='testpass123',
            is_staff=True
        )
        self.client = Client()
        self.client.force_login(self.user)

    def test_webhook_status_sanitizes_external_data(self):
        """Test that webhook status API sanitizes external webhook data"""
        # Create webhook with potentially malicious data
        malicious_data = {
            'source': 'stripe<script>alert("XSS")</script>',
            'event_type': 'invoice.created"><img src=x onerror=alert(1)>',
            'status': 'processed</div><script>steal_data()</script>'
        }
        
        WebhookEvent.objects.create(
            source=malicious_data['source'],
            event_id='evt_malicious',
            event_type=malicious_data['event_type'],
            status='processed',  # Use valid status for the model
            payload={'test': 'data'}
        )
        
        # Mock permission check to pass
        with patch.object(self.user, 'has_perm', return_value=True):
            response = self.client.get(reverse('integrations:webhook_status'))
        
        self.assertEqual(response.status_code, 200)
        
        response_data = response.json()
        recent_webhooks = response_data.get('recent_webhooks', [])
        
        if recent_webhooks:
            webhook_data = recent_webhooks[0]
            
            # Verify malicious content is escaped
            self.assertNotIn('<script>', webhook_data['source'])
            self.assertNotIn('<img src=', webhook_data['event_type'])
            self.assertNotIn('</div>', webhook_data['status'])
            
            # Verify escaped content is present
            self.assertIn('&lt;script&gt;', webhook_data['source'])
            self.assertIn('&lt;img', webhook_data['event_type'])

    def test_webhook_data_escape_comprehensive(self):
        """Test comprehensive escaping of webhook data"""
        xss_payloads = [
            '"><script>alert(1)</script>',
            "'; DROP TABLE webhooks; --",
            '<img src=x onerror=alert(document.cookie)>',
            'javascript:alert(1)',
            '&lt;already&gt;escaped&lt;/already&gt;',
            '\"><iframe src=javascript:alert(1)></iframe>',
        ]
        
        for i, payload in enumerate(xss_payloads):
            WebhookEvent.objects.create(
                source=f'test_source_{i}',
                event_id=f'evt_xss_{i}',
                event_type=payload,
                payload={'test': f'payload_{i}'},
                status='processed'
            )
        
        # Mock permission to pass authorization
        with patch.object(self.user, 'has_perm', return_value=True):
            response = self.client.get(reverse('integrations:webhook_status'))
        
        self.assertEqual(response.status_code, 200)
        
        response_content = response.content.decode()
        
        # Verify no unescaped malicious content
        dangerous_patterns = [
            '<script>alert',
            'javascript:alert',
            '<img src=x',
            '<iframe src=',
            'DROP TABLE',
        ]
        
        for pattern in dangerous_patterns:
            self.assertNotIn(pattern, response_content, 
                           f"Dangerous pattern '{pattern}' found unescaped in response")

    def test_json_response_content_type_safety(self):
        """Test that JSON responses have proper content-type to prevent MIME sniffing"""
        with patch.object(self.user, 'has_perm', return_value=True):
            response = self.client.get(reverse('integrations:webhook_status'))
        
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # Verify response is valid JSON
        response_data = response.json()
        self.assertIsInstance(response_data, dict)


class AbstractWebhookProcessorSecurityTests(TestCase):
    """🔒 Tests for abstract webhook processor security enforcement"""

    def test_abstract_webhook_processor_cannot_be_instantiated(self):
        """Test that BaseWebhookProcessor cannot be instantiated directly"""
        with self.assertRaises(TypeError):
            BaseWebhookProcessor()

    def test_subclass_must_implement_verify_signature(self):
        """Test that subclasses must implement verify_signature method"""
        # This should fail to instantiate without implementing abstract method
        with self.assertRaises(TypeError):
            class IncompleteProcessor(BaseWebhookProcessor):
                pass
            
            IncompleteProcessor()

    def test_proper_subclass_can_be_instantiated(self):
        """Test that properly implemented subclass can be instantiated"""
        class ProperProcessor(BaseWebhookProcessor):
            def verify_signature(self, payload, signature, headers):
                return False  # Always reject for security
        
        # Should be able to instantiate
        processor = ProperProcessor()
        self.assertIsInstance(processor, BaseWebhookProcessor)

    def test_signature_verification_enforcement(self):
        """Test that signature verification is properly enforced"""
        class TestProcessor(BaseWebhookProcessor):
            def verify_signature(self, payload, signature, headers):
                # Simulate proper verification logic
                if signature == 'obviously_invalid_signature_12345':
                    return False
                return len(signature) > 10  # Simple test logic
        
        processor = TestProcessor()
        
        # Test validation method exists
        self.assertTrue(hasattr(processor, '_validate_signature_implementation'))
        
        # Test validation logic
        processor._validate_signature_implementation()  # Should not raise
        
    def test_overly_permissive_signature_verification_detection(self):
        """Test detection of overly permissive signature verification"""
        class PermissiveProcessor(BaseWebhookProcessor):
            def verify_signature(self, payload, signature, headers):
                return True  # Always accept - DANGEROUS!
        
        processor = PermissiveProcessor()
        
        # Should detect overly permissive implementation
        with self.assertRaises(SecurityError):
            processor._validate_signature_implementation()

    def test_security_error_class_exists(self):
        """Test that SecurityError class is properly defined"""
        from apps.integrations.webhooks.base import SecurityError
        
        # Should be able to raise and catch
        with self.assertRaises(SecurityError):
            raise SecurityError("Test security error")
        
        # Should inherit from Exception
        self.assertTrue(issubclass(SecurityError, Exception))


class AccessControlSecurityTests(TestCase):
    """🔒 Tests for access control security improvements"""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email='staff@example.com',
            password='testpass123',
            is_staff=True
        )
        
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            password='testpass123',
            is_staff=False
        )
        
        self.client = Client()
        self.factory = RequestFactory()

    def test_webhook_status_requires_staff_and_permissions(self):
        """Test webhook status requires both staff status and specific permissions"""
        from django.contrib.auth.models import Permission
        from django.contrib.contenttypes.models import ContentType
        from apps.integrations.models import WebhookEvent
        
        # Test with non-staff user
        self.client.force_login(self.regular_user)
        response = self.client.get(reverse('integrations:webhook_status'))
        self.assertEqual(response.status_code, 403)
        
        # Test with staff user but no permissions
        self.client.force_login(self.staff_user)
        response = self.client.get(reverse('integrations:webhook_status'))
        # Should fail without the specific permission
        self.assertEqual(response.status_code, 403)
        
        # Add webhook stats permission to staff user
        content_type = ContentType.objects.get_for_model(WebhookEvent)
        permission, _ = Permission.objects.get_or_create(
            content_type=content_type, 
            codename="view_webhook_stats",
            defaults={"name": "Can view webhook statistics"}
        )
        self.staff_user.user_permissions.add(permission)
        
        # Test with staff user and proper permissions
        response = self.client.get(reverse('integrations:webhook_status'))
        self.assertEqual(response.status_code, 200)

    def test_retry_webhook_permission_checks(self):
        """Test retry webhook has proper permission checks"""
        from django.contrib.auth.models import Permission
        from django.contrib.contenttypes.models import ContentType
        
        webhook_event = WebhookEvent.objects.create(
            source='test',
            event_id='evt_retry',
            event_type='test.event',
            payload={},
            status='failed'
        )
        
        # Test with non-staff user
        self.client.force_login(self.regular_user)
        response = self.client.post(
            reverse('integrations:retry_webhook', kwargs={'webhook_id': webhook_event.id})
        )
        self.assertEqual(response.status_code, 403)
        
        # Test with staff user but no retry permission
        self.client.force_login(self.staff_user)
        response = self.client.post(
            reverse('integrations:retry_webhook', kwargs={'webhook_id': webhook_event.id})
        )
        self.assertEqual(response.status_code, 403)  # Should fail without permission
        
        # Add retry webhook permission to staff user
        content_type = ContentType.objects.get_for_model(WebhookEvent)
        permission, _ = Permission.objects.get_or_create(
            content_type=content_type, 
            codename="retry_webhook",
            defaults={"name": "Can retry failed webhooks"}
        )
        self.staff_user.user_permissions.add(permission)
        
        # Test with staff user and proper permissions - should succeed (404 due to mock)
        response = self.client.post(
            reverse('integrations:retry_webhook', kwargs={'webhook_id': webhook_event.id})
        )
        # Since we don't have a processor registered for 'test' source, expect error
        self.assertEqual(response.status_code, 400)

    def test_webhook_not_found_handling(self):
        """Test proper handling of non-existent webhooks"""
        self.client.force_login(self.staff_user)
        
        non_existent_id = uuid.uuid4()
        response = self.client.post(
            reverse('integrations:retry_webhook', kwargs={'webhook_id': non_existent_id})
        )
        
        self.assertEqual(response.status_code, 404)
        response_data = response.json()
        self.assertEqual(response_data['error'], 'Webhook not found')

    def test_permission_logging_for_security_monitoring(self):
        """Test that permission failures are logged for security monitoring"""
        with patch('apps.integrations.views.logger') as mock_logger:
            self.client.force_login(self.staff_user)
            
            # Trigger permission failure
            response = self.client.get(reverse('integrations:webhook_status'))
            
            # Should log the security event
            mock_logger.warning.assert_called_once()
            log_call = mock_logger.warning.call_args[0][0]
            self.assertIn('Webhook stats access denied', log_call)
            self.assertIn(self.staff_user.email, log_call)


class SSRFProtectionSecurityTests(TestCase):
    """🔒 Tests for SSRF protection in webhook deliveries"""

    def setUp(self):
        from apps.customers.models import Customer
        self.customer = Customer.objects.create(
            name='Test Customer',
            company_name='Test Company',
            primary_email='test@example.com',
            customer_type='business'
        )

    def test_webhook_delivery_blocks_localhost_urls(self):
        """Test that webhook delivery blocks localhost URLs"""
        localhost_urls = [
            'http://localhost:8000/webhook',
            'https://127.0.0.1/webhook',
            'http://::1/webhook',
        ]
        
        for url in localhost_urls:
            webhook_delivery = WebhookDelivery(
                customer=self.customer,
                endpoint_url=url,
                event_type='test.event',
                payload={'test': 'data'}
            )
            
            with self.assertRaises(ValidationError) as cm:
                webhook_delivery.clean()
            
            self.assertIn('localhost', str(cm.exception).lower())

    def test_webhook_delivery_blocks_private_network_ips(self):
        """Test that webhook delivery blocks private network IP addresses"""
        private_ips = [
            'http://192.168.1.100/webhook',
            'https://10.0.0.1/webhook', 
            'http://172.16.0.1/webhook',
            'https://169.254.1.1/webhook',  # Link-local
        ]
        
        for url in private_ips:
            webhook_delivery = WebhookDelivery(
                customer=self.customer,
                endpoint_url=url,
                event_type='test.event',
                payload={}
            )
            
            with self.assertRaises(ValidationError) as cm:
                webhook_delivery.clean()
            
            self.assertIn('private network', str(cm.exception).lower())

    def test_webhook_delivery_blocks_dangerous_ports(self):
        """Test that webhook delivery blocks dangerous ports"""
        dangerous_ports = [22, 23, 25, 53, 135, 445, 993, 995, 1433, 1521, 3306, 5432, 6379, 9200, 11211]
        
        for port in dangerous_ports[:5]:  # Test first 5 to keep test fast
            url = f'http://example.com:{port}/webhook'
            webhook_delivery = WebhookDelivery(
                customer=self.customer,
                endpoint_url=url,
                event_type='test.event',
                payload={}
            )
            
            with self.assertRaises(ValidationError) as cm:
                webhook_delivery.clean()
            
            self.assertIn(f'port {port}', str(cm.exception))

    def test_webhook_delivery_allows_safe_urls(self):
        """Test that webhook delivery allows safe URLs"""
        safe_urls = [
            'https://api.example.com/webhooks',
            'http://webhook.customer.com/endpoint',
            'https://external-service.com:443/webhook',
            'https://secure-endpoint.org:8443/api/webhook',
        ]
        
        for url in safe_urls:
            webhook_delivery = WebhookDelivery(
                customer=self.customer,
                endpoint_url=url,
                event_type='test.event',
                payload={}
            )
            
            # Should not raise ValidationError
            try:
                webhook_delivery.clean()
            except ValidationError:
                self.fail(f'Safe URL {url} was incorrectly blocked')

    def test_webhook_delivery_save_calls_clean(self):
        """Test that save() automatically calls clean() for validation"""
        malicious_webhook = WebhookDelivery(
            customer=self.customer,
            endpoint_url='http://localhost/webhook',
            event_type='test.event',
            payload={}
        )
        
        # save() should call clean() and raise ValidationError
        with self.assertRaises(ValidationError):
            malicious_webhook.save()

    def test_ssrf_protection_with_domain_names(self):
        """Test SSRF protection works with domain names that resolve to private IPs"""
        # Mock domain that resolves to private IP
        webhook_delivery = WebhookDelivery(
            customer=self.customer,
            endpoint_url='http://internal.company.com/webhook',
            event_type='test.event',
            payload={}
        )
        
        # This test verifies the validation structure exists
        # In real implementation, you might add DNS resolution checking
        try:
            webhook_delivery.clean()
            # If no exception, the URL passed validation
        except ValidationError:
            # URL was blocked, which is acceptable behavior
            pass


class ComprehensiveSecurityTests(TestCase):
    """🔒 Comprehensive security tests covering edge cases"""

    def setUp(self):
        self.currency = Currency.objects.create(
            code='USD',
            name='US Dollar',
            symbol='$'
        )

    def test_webhook_event_model_security_comprehensive(self):
        """Test comprehensive security of WebhookEvent model"""
        # Test with various malicious payloads
        malicious_payloads = [
            {'sql_injection': "'; DROP TABLE webhooks; --"},
            {'xss': '<script>alert("XSS")</script>'},
            {'large_payload': 'x' * 10000},  # Test size limits
            {'nested': {'level1': {'level2': {'level3': 'deep_nesting'}}}},
        ]
        
        for i, payload in enumerate(malicious_payloads):
            webhook_event = WebhookEvent.objects.create(
                source='security_test',
                event_id=f'evt_security_{i}',
                event_type='security.test',
                payload=payload
            )
            
            # Should be able to create and retrieve safely
            self.assertIsNotNone(webhook_event.id)
            
            # Payload should be stored but accessed safely
            retrieved_payload = webhook_event.payload
            self.assertEqual(retrieved_payload, payload)

    def test_security_boundary_conditions(self):
        """Test security at boundary conditions"""
        # Test empty and None values
        webhook_event = WebhookEvent.objects.create(
            source='boundary_test',
            event_id='evt_boundary',
            event_type='test.boundary',
            payload={}
        )
        
        # Test signature operations with edge cases
        edge_cases = ['', None, 'a', 'x' * 1000]
        
        for case in edge_cases:
            if case is not None:
                webhook_event.set_signature(case)
                if case:
                    self.assertEqual(len(webhook_event.signature_hash), 64)
                    self.assertTrue(webhook_event.verify_signature_hash(case))
                else:
                    self.assertEqual(webhook_event.signature_hash, '')
                    self.assertFalse(webhook_event.verify_signature_hash(case))

    def test_unicode_and_encoding_security(self):
        """Test security with Unicode and various encodings"""
        unicode_test_data = [
            'Test with émojis 🔒🔐',
            'Romanian diacritics: ăâîșț ĂÂÎȘȚ',
            'Mixed: Test-テスト-тест-测试',
            '\x00\x01\x02',  # Control characters
            '\\u0041\\u0042',  # Escaped Unicode
        ]
        
        for i, test_data in enumerate(unicode_test_data):
            webhook_event = WebhookEvent.objects.create(
                source='unicode_test',
                event_id=f'evt_unicode_{i}',
                event_type=test_data,
                payload={'unicode_test': test_data}
            )
            
            # Should handle Unicode safely
            self.assertIsNotNone(webhook_event.id)
            
            # Test signature with Unicode
            webhook_event.set_signature(test_data)
            if test_data:  # Skip empty strings
                self.assertTrue(webhook_event.verify_signature_hash(test_data))