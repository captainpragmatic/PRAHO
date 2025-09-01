"""
🔒 Security Tests for Notifications App - OWASP Top 10 Compliance

Tests for template injection prevention, access control, input validation,
data encryption, and security logging implementations.
"""

import json
from unittest.mock import patch, MagicMock

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from apps.notifications.models import (
    EmailTemplate, EmailLog, EmailCampaign,
    validate_template_content, validate_json_field, validate_email_subject,
    encrypt_sensitive_content, decrypt_sensitive_content
)
from apps.notifications.services import (
    EmailService, validate_template_context, render_template_safely
)

User = get_user_model()


class TemplateInjectionSecurityTests(TestCase):
    """🔒 Tests for template injection prevention (A03 - Injection)"""
    
    def setUp(self):
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True,
            is_superuser=True
        )
        
    def test_dangerous_template_patterns_blocked(self):
        """🔒 Test that dangerous template patterns are blocked"""
        dangerous_templates = [
            "{% debug %}",
            "{% load ssi %}{% ssi '/etc/passwd' %}",
            "{% load admin_tags %}",
            "{{ request.user.password }}",
            "{{ user.email }}",
            "{% load cache %}{% cache 1000000000 evil %}",
        ]
        
        for dangerous_template in dangerous_templates:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {dangerous_template}"):
                validate_template_content(dangerous_template)
    
    def test_allowed_template_tags_pass(self):
        """✅ Test that safe template patterns are allowed"""
        safe_templates = [
            "Hello {{ customer_name }}!",
            "{% if invoice_number %}Invoice: {{ invoice_number }}{% endif %}",
            "{% for item in items %}{{ item }}{% endfor %}",
            "{% load static %}{% static 'css/email.css' %}",
            "{% trans 'Hello' %}",
            "{% blocktrans %}Welcome {{ name }}{% endblocktrans %}",
        ]
        
        for safe_template in safe_templates:
            try:
                validate_template_content(safe_template)
            except ValidationError:
                self.fail(f"Safe template was blocked: {safe_template}")
    
    def test_template_size_limit_enforced(self):
        """🔒 Test that template size limits are enforced"""
        # Create template larger than 100KB limit
        large_template = "x" * 100001
        
        with self.assertRaises(ValidationError) as cm:
            validate_template_content(large_template)
        
        self.assertIn("Template content too large", str(cm.exception))
    
    def test_disallowed_template_tags_blocked(self):
        """🔒 Test that disallowed template tags are blocked"""
        disallowed_template = "{% csrf_token %}{% autoescape off %}{{ evil_content }}{% endautoescape %}"
        
        with self.assertRaises(ValidationError) as cm:
            validate_template_content(disallowed_template)
        
        self.assertIn("disallowed tags", str(cm.exception))
    
    def test_email_template_model_validation(self):
        """🔒 Test EmailTemplate model validates content on save"""
        with self.assertRaises(ValidationError):
            template = EmailTemplate(
                key="test.dangerous",
                locale="en",
                subject="Test Subject",
                body_html="{% debug %}{{ dangerous_content }}",
                body_text="Safe text",
                category="security"
            )
            template.full_clean()  # This should trigger validation


class InputValidationSecurityTests(TestCase):
    """🔒 Tests for input validation and sanitization (A06 - Vulnerable Components)"""
    
    def test_json_size_limit_enforced(self):
        """🔒 Test that JSON size limits prevent DoS attacks"""
        # Create JSON larger than 10KB limit
        large_json = {"data": "x" * 10001}
        
        with self.assertRaises(ValidationError) as cm:
            validate_json_field(large_json)
        
        self.assertIn("JSON content too large", str(cm.exception))
    
    def test_json_depth_limit_enforced(self):
        """🔒 Test that JSON depth limits prevent stack overflow"""
        # Create deeply nested JSON (>10 levels)
        nested_json = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "level5": {
                                "level6": {
                                    "level7": {
                                        "level8": {
                                            "level9": {
                                                "level10": {
                                                    "level11": "too deep"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        with self.assertRaises(ValidationError) as cm:
            validate_json_field(nested_json)
        
        self.assertIn("JSON nesting too deep", str(cm.exception))
    
    def test_email_subject_header_injection_prevention(self):
        """🔒 Test that email subject prevents header injection"""
        malicious_subjects = [
            "Subject\nBcc: attacker@evil.com",
            "Subject\rCc: attacker@evil.com", 
            "Subject\0\nX-Malicious: header",
        ]
        
        for malicious_subject in malicious_subjects:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {repr(malicious_subject)}"):
                validate_email_subject(malicious_subject)
    
    def test_email_subject_length_limit(self):
        """🔒 Test that email subject length is limited"""
        long_subject = "x" * 256  # Over 255 char limit
        
        with self.assertRaises(ValidationError) as cm:
            validate_email_subject(long_subject)
        
        self.assertIn("Subject too long", str(cm.exception))
    
    def test_template_context_sanitization(self):
        """🔒 Test that template context is sanitized"""
        dangerous_context = {
            "password": "secret123",
            "api_key": "key123",
            "user_token": "token123",
            "private_data": "sensitive",
        }
        
        with self.assertRaises(ValidationError) as cm:
            validate_template_context(dangerous_context)
        
        self.assertIn("sensitive information", str(cm.exception))
    
    def test_template_context_xss_prevention(self):
        """🔒 Test that template context prevents XSS"""
        xss_context = {
            "customer_name": "<script>alert('xss')</script>John Doe",
            "message": "<img src=x onerror=alert('xss')>Hello",
        }
        
        sanitized = validate_template_context(xss_context)
        
        # Should strip HTML tags
        self.assertNotIn("<script>", sanitized["customer_name"])
        self.assertNotIn("onerror", sanitized["message"])
        self.assertEqual(sanitized["customer_name"], "John Doe")


class DataEncryptionSecurityTests(TestCase):
    """🔒 Tests for data encryption at rest (A04 - Insecure Design)"""
    
    def setUp(self):
        self.customer = User.objects.create_user(
            email="customer@test.com",
            password="testpass123"
        )
    
    @patch('apps.notifications.models.ENCRYPTION_AVAILABLE', True)
    @patch('apps.notifications.models.settings_encryption')
    def test_email_content_encryption_on_save(self, mock_encryption):
        """🔒 Test that email content is encrypted when saved"""
        mock_encryption.is_encrypted.return_value = False
        mock_encryption.encrypt_value.return_value = "enc:v1:encrypted_content"
        
        email_log = EmailLog.objects.create(
            to_addr="test@example.com",
            subject="Test Email",
            body_html="<p>Sensitive email content</p>",
            body_text="Sensitive email content",
            template_key="test.template",
            status="sent"
        )
        
        # Should have called encryption for both HTML and text
        self.assertEqual(mock_encryption.encrypt_value.call_count, 2)
        mock_encryption.encrypt_value.assert_any_call("<p>Sensitive email content</p>")
        mock_encryption.encrypt_value.assert_any_call("Sensitive email content")
    
    @patch('apps.notifications.models.ENCRYPTION_AVAILABLE', True)
    @patch('apps.notifications.models.settings_encryption')
    def test_email_content_decryption_on_access(self, mock_encryption):
        """🔓 Test that email content is decrypted when accessed"""
        mock_encryption.decrypt_if_needed.return_value = "Decrypted content"
        
        email_log = EmailLog(
            to_addr="test@example.com",
            subject="Test Email", 
            body_html="enc:v1:encrypted_content",
            body_text="enc:v1:encrypted_content",
            template_key="test.template",
            status="sent"
        )
        
        # Test decryption methods
        decrypted_html = email_log.get_decrypted_body_html()
        decrypted_text = email_log.get_decrypted_body_text()
        
        self.assertEqual(decrypted_html, "Decrypted content")
        self.assertEqual(decrypted_text, "Decrypted content")
        mock_encryption.decrypt_if_needed.assert_called()
    
    @patch('apps.notifications.models.ENCRYPTION_AVAILABLE', False)
    def test_encryption_graceful_fallback(self):
        """✅ Test graceful fallback when encryption is unavailable"""
        original_content = "Unencrypted content"
        
        # Should return content unchanged when encryption unavailable
        result = encrypt_sensitive_content(original_content)
        self.assertEqual(result, original_content)
        
        result = decrypt_sensitive_content(original_content) 
        self.assertEqual(result, original_content)
    
    def test_email_address_privacy_in_logs(self):
        """🔒 Test that email addresses are masked in logs"""
        email_log = EmailLog(
            to_addr="sensitive@customer.com",
            subject="Test Email",
            template_key="test.template",
            status="sent"
        )
        
        preview = email_log.get_safe_content_preview()
        # Should not expose full email address in any preview
        self.assertNotIn("sensitive@customer.com", preview)


class AccessControlSecurityTests(TestCase):
    """🔒 Tests for access control implementation (A01 - Broken Access Control)"""
    
    def setUp(self):
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True,
            is_superuser=True
        )
        
        self.staff_user = User.objects.create_user(
            email="staff@test.com",
            password="testpass123",
            is_staff=True
        )
        
        self.regular_user = User.objects.create_user(
            email="user@test.com",
            password="testpass123"
        )
        
        self.template = EmailTemplate.objects.create(
            key="test.template",
            locale="en",
            subject="Test Template",
            body_html="<p>Test content</p>",
            body_text="Test content",
            category="system"
        )
        
        self.client = Client()
    
    def test_template_list_requires_admin(self):
        """🔒 Test that template listing requires admin access"""
        url = reverse('notifications:template_list')
        
        # Unauthorized access
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)  # Redirect to login
        
        # Regular user access (should be denied)
        self.client.force_login(self.regular_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)  # Forbidden
        
        # Staff user access (should be denied - admin required)
        self.client.force_login(self.staff_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)  # Forbidden
        
        # Admin user access (should work)
        self.client.force_login(self.admin_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
    
    def test_email_logs_require_staff(self):
        """🔒 Test that email logs require staff access"""
        url = reverse('notifications:email_log_list')
        
        # Unauthorized access
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)  # Redirect to login
        
        # Regular user access (should be denied)
        self.client.force_login(self.regular_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)  # Forbidden
        
        # Staff user access (should work)
        self.client.force_login(self.staff_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        # Admin user access (should work)
        self.client.force_login(self.admin_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
    
    def test_template_api_requires_admin_and_rate_limiting(self):
        """🔒 Test that template API requires admin access and has rate limiting"""
        url = reverse('notifications:template_api')
        
        # Test unauthorized access
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)  # Redirect to login
        
        # Test with admin user
        self.client.force_login(self.admin_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('templates', data)
        self.assertIn('count', data)
    
    def test_security_monitoring_api_admin_only(self):
        """🔒 Test that security monitoring API requires admin access"""
        url = reverse('notifications:security_monitoring')
        
        # Test unauthorized access
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        
        # Test staff user (should be denied)
        self.client.force_login(self.staff_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)
        
        # Test admin user (should work)
        self.client.force_login(self.admin_user)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('security_stats', data)


class SecurityLoggingTests(TestCase):
    """🔒 Tests for security logging and monitoring (A09 - Security Logging Failures)"""
    
    def setUp(self):
        self.admin_user = User.objects.create_user(
            email="admin@test.com",
            password="testpass123",
            is_staff=True,
            is_superuser=True
        )
        
    @patch('apps.common.validators.log_security_event')
    def test_template_access_logging(self, mock_log_event):
        """🔒 Test that template access is logged for security monitoring"""
        from apps.notifications.views import EmailTemplateListView
        
        # Simulate template access
        request = MagicMock()
        request.user.email = "admin@test.com"
        request.META = {'REMOTE_ADDR': '127.0.0.1'}
        
        view = EmailTemplateListView()
        view.request = request
        
        # This should trigger security logging
        view.get_queryset()
        
        # Verify security event was logged
        mock_log_event.assert_called_with(
            event_type='template_access',
            details={'action': 'list_templates', 'user': 'admin@test.com'},
            request_ip='127.0.0.1'
        )
    
    @patch('apps.common.validators.log_security_event')
    def test_email_service_logging(self, mock_log_event):
        """🔒 Test that email service operations are logged"""
        # Test template email logging
        result = EmailService.send_template_email(
            template_key="test.template",
            recipient="test@example.com",
            context={"name": "Test User"},
            request_ip="127.0.0.1"
        )
        
        self.assertTrue(result)
        
        # Verify security event was logged
        mock_log_event.assert_called_with(
            event_type='template_email_send',
            details={
                'template_key': 'test.template',
                'recipient_domain': 'example.com',
                'context_keys': ['name']
            },
            request_ip='127.0.0.1'
        )
    
    @patch('apps.notifications.models.logger')
    def test_template_modification_logging(self, mock_logger):
        """🔒 Test that template modifications are logged"""
        template = EmailTemplate(
            key="test.modified",
            locale="en",
            subject="Modified Template",
            body_html="<p>Modified content</p>",
            body_text="Modified content",
            category="system"
        )
        
        # This should trigger logging in clean() method
        template.clean()
        
        # Verify template modification was logged
        mock_logger.info.assert_called()
        call_args = mock_logger.info.call_args[0][0]
        self.assertIn("Template modified", call_args)
    
    def test_gdpr_compliance_monitoring(self):
        """🔒 Test GDPR compliance monitoring for campaigns"""
        # Create non-compliant marketing campaign
        campaign = EmailCampaign(
            name="Non-Compliant Marketing",
            template=EmailTemplate.objects.create(
                key="marketing.template",
                locale="en", 
                subject="Marketing Email",
                body_html="<p>Marketing content</p>",
                category="marketing"
            ),
            audience="all_customers",
            is_transactional=False,
            requires_consent=False  # This should trigger warning
        )
        
        with patch('apps.notifications.models.logger') as mock_logger:
            campaign.clean()
            
            # Should log GDPR compliance warning
            mock_logger.warning.assert_called()
            call_args = mock_logger.warning.call_args[0][0]
            self.assertIn("GDPR", call_args)
            self.assertIn("Marketing campaign without consent", call_args)


class SafeTemplateRenderingTests(TestCase):
    """🔒 Tests for safe template rendering with security controls"""
    
    def test_safe_template_rendering_with_valid_context(self):
        """✅ Test that safe template rendering works with valid context"""
        template_content = "Hello {{ customer_name }}, your invoice {{ invoice_number }} is ready!"
        context = {
            "customer_name": "John Doe",
            "invoice_number": "INV-001"
        }
        
        result = render_template_safely(template_content, context)
        
        self.assertIn("Hello John Doe", result)
        self.assertIn("INV-001", result)
    
    def test_safe_template_rendering_blocks_dangerous_context(self):
        """🔒 Test that safe template rendering blocks dangerous context"""
        template_content = "Hello {{ customer_name }}"
        dangerous_context = {
            "customer_name": "John Doe",
            "password": "secret123"  # Should be blocked
        }
        
        with self.assertRaises(ValidationError) as cm:
            render_template_safely(template_content, dangerous_context)
        
        self.assertIn("sensitive information", str(cm.exception))
    
    def test_safe_template_rendering_xss_protection(self):
        """🔒 Test that safe template rendering prevents XSS"""
        template_content = "Hello {{ customer_name }}"
        xss_context = {
            "customer_name": "<script>alert('xss')</script>John"
        }
        
        result = render_template_safely(template_content, xss_context)
        
        # Should strip HTML tags
        self.assertNotIn("<script>", result)
        self.assertIn("John", result)
    
    def test_safe_template_rendering_size_limit(self):
        """🔒 Test that safe template rendering enforces size limits"""
        # Create template content that will exceed size limit
        large_content = "x" * 600000  # 600KB content, over 500KB limit
        template_content = "{{ large_content }}"
        context = {
            "large_content": large_content
        }
        
        result = render_template_safely(template_content, context)
        
        # Should be truncated to 500KB limit
        self.assertLess(len(result), 500001)
        self.assertIn("[truncated]", result)
    
    def test_email_preview_generation_security(self):
        """🔒 Test that email preview generation is secure"""
        template_content = "Hello {{ customer_name }}, this is a test email with sensitive {{ data }}."
        context = {
            "customer_name": "John Doe",
            "data": "information" * 100  # Make it long
        }
        
        preview = EmailService.get_safe_email_preview(template_content, context)
        
        # Should be truncated for preview
        self.assertLessEqual(len(preview), 500 + len("...[preview truncated]"))
        if len(preview) > 500:
            self.assertIn("[preview truncated]", preview)