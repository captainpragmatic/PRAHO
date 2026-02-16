"""
🔒 Core Security Function Tests for Notifications App
Tests the fundamental security validation functions without complex Django setup.
"""

from django.test import TestCase
from django.core.exceptions import ValidationError

from apps.notifications.models import (
    validate_template_content, validate_json_field, validate_email_subject,
)
from apps.notifications.services import validate_template_context


class CoreSecurityValidationTests(TestCase):
    """🔒 Tests for core security validation functions"""

    def test_template_dangerous_patterns_blocked(self):
        """🔒 Test that dangerous template patterns are blocked"""
        dangerous_patterns = [
            "{% debug %}",
            "{% load ssi %}",
            "{{ request.user }}",
            "{% load admin_tags %}",
        ]

        for pattern in dangerous_patterns:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {pattern}"):
                validate_template_content(pattern)

    def test_template_size_limits(self):
        """🔒 Test template size limits are enforced"""
        large_template = "x" * 100001  # Over 100KB limit

        with self.assertRaises(ValidationError) as cm:
            validate_template_content(large_template)

        self.assertIn("too large", str(cm.exception))

    def test_json_size_limits(self):
        """🔒 Test JSON size limits prevent DoS"""
        large_json = {"data": "x" * 10001}  # Over 10KB limit

        with self.assertRaises(ValidationError) as cm:
            validate_json_field(large_json)

        self.assertIn("too large", str(cm.exception))

    def test_json_depth_limits(self):
        """🔒 Test JSON depth limits prevent stack overflow"""
        # 12 levels deep (over 10 limit)
        deep_json = {}
        current = deep_json
        for i in range(12):
            current[f"level{i}"] = {}
            current = current[f"level{i}"]

        with self.assertRaises(ValidationError) as cm:
            validate_json_field(deep_json)

        self.assertIn("too deep", str(cm.exception))

    def test_email_subject_header_injection(self):
        """🔒 Test email subject blocks header injection"""
        malicious_subjects = [
            "Subject\nBcc: evil@test.com",
            "Subject\rCc: evil@test.com",
            "Subject\0X-Malicious: header",
        ]

        for subject in malicious_subjects:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {repr(subject)}"):
                validate_email_subject(subject)

    def test_email_subject_length_limits(self):
        """🔒 Test email subject length limits"""
        long_subject = "x" * 256  # Over 255 limit

        with self.assertRaises(ValidationError) as cm:
            validate_email_subject(long_subject)

        self.assertIn("too long", str(cm.exception))

    def test_template_context_dangerous_keys(self):
        """🔒 Test template context blocks dangerous keys"""
        dangerous_contexts = [
            {"password": "secret"},
            {"api_key": "key123"},
            {"token": "token123"},
            {"private_data": "sensitive"},
        ]

        for context in dangerous_contexts:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {context}"):
                validate_template_context(context)

    def test_template_context_xss_prevention(self):
        """🔒 Test template context strips XSS"""
        xss_context = {
            "name": "<script>alert('xss')</script>John",
            "message": "<img onerror=alert(1)>Test",
        }

        sanitized = validate_template_context(xss_context)

        # Should strip HTML tags
        self.assertNotIn("<script>", sanitized["name"])
        self.assertNotIn("onerror", sanitized["message"])
        self.assertIn("John", sanitized["name"])
        self.assertIn("Test", sanitized["message"])

    def test_template_context_size_limits(self):
        """🔒 Test template context enforces size limits on values"""
        large_context = {
            "data": "x" * 2000  # Over 1KB limit per value
        }

        sanitized = validate_template_context(large_context)

        # Should be truncated to 1000 chars
        self.assertEqual(len(sanitized["data"]), 1000)

    def test_safe_template_content_passes(self):
        """✅ Test that safe template content passes validation"""
        safe_templates = [
            "Hello {{ customer_name }}!",
            "{% if condition %}Content{% endif %}",
            "{% for item in items %}{{ item }}{% endfor %}",
            "{% load static %}",
            "{% trans 'Hello' %}",
        ]

        for template in safe_templates:
            try:
                validate_template_content(template)
            except ValidationError as e:
                self.fail(f"Safe template was blocked: {template}, error: {e}")

    def test_safe_json_content_passes(self):
        """✅ Test that safe JSON content passes validation"""
        safe_json = {
            "customer_name": "John Doe",
            "invoice_number": "INV-001",
            "amount": 100.00,
            "items": ["item1", "item2"],
            "nested": {"data": "value"}
        }

        try:
            validate_json_field(safe_json)
        except ValidationError as e:
            self.fail(f"Safe JSON was blocked: {e}")

    def test_safe_email_subjects_pass(self):
        """✅ Test that safe email subjects pass validation"""
        safe_subjects = [
            "Invoice INV-001 is ready",
            "Payment reminder for your account",
            "Welcome to PRAHO Platform!",
            "Service provisioned successfully",
        ]

        for subject in safe_subjects:
            try:
                validate_email_subject(subject)
            except ValidationError as e:
                self.fail(f"Safe subject was blocked: {subject}, error: {e}")

    def test_safe_template_context_passes(self):
        """✅ Test that safe template context passes validation"""
        safe_context = {
            "customer_name": "John Doe",
            "invoice_number": "INV-001",
            "amount": "100.00",
            "due_date": "2024-12-31",
            "company_name": "Test Company",
        }

        try:
            result = validate_template_context(safe_context)
            self.assertEqual(len(result), len(safe_context))
        except ValidationError as e:
            self.fail(f"Safe context was blocked: {e}")
