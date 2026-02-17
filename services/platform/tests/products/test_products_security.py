"""
🔒 Core Security Function Tests for Products App
Tests the fundamental security validation functions without complex Django setup.
"""

from django.test import TestCase
from django.core.exceptions import ValidationError

from apps.products.models import (
    validate_json_field, validate_product_config, validate_text_field_length,
    _get_json_depth, _check_json_security
)


class CoreSecurityValidationTests(TestCase):
    """🔒 Tests for core security validation functions"""

    def test_json_size_limits_enforced(self):
        """🔒 Test that JSON size limits prevent DoS attacks"""
        large_data = {"data": "x" * 12000}  # Over 10KB limit

        with self.assertRaises(ValidationError) as cm:
            validate_json_field(large_data)

        self.assertIn("too large", str(cm.exception))

    def test_json_depth_limits_enforced(self):
        """🔒 Test that JSON depth limits prevent stack overflow"""
        # Create 12 levels deep (over 10 limit)
        deep_data = {}
        current = deep_data
        for i in range(12):
            current[f"level{i}"] = {}
            current = current[f"level{i}"]

        with self.assertRaises(ValidationError) as cm:
            validate_json_field(deep_data)

        self.assertIn("too deep", str(cm.exception))

    def test_json_dangerous_patterns_blocked(self):
        """🔒 Test that dangerous patterns in JSON are blocked"""
        dangerous_data = {
            "script": "<script>alert('xss')</script>",
            "eval": "eval('malicious code')",
            "import": "__import__('os').system('rm -rf /')",
            "subprocess": "subprocess.call(['rm', '-rf', '/'])"
        }

        for key, value in dangerous_data.items():
            data = {key: value}
            with self.assertRaises(ValidationError, msg=f"Failed to block: {data}"):
                validate_json_field(data)

    def test_config_sensitive_keys_blocked(self):
        """🔒 Test that sensitive keys in config are blocked"""
        sensitive_configs = [
            {"password": "secret123"},
            {"api_key": "key123"},
            {"private_token": "token123"},
            {"admin_pass": "admin123"},
            {"mysql_password": "dbpass"},
            {"secret_key": "secret"},
            {"auth_token": "token"},
            {"credential": "cred"}
        ]

        for config in sensitive_configs:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {config}"):
                validate_product_config(config)

    def test_config_dangerous_patterns_blocked(self):
        """🔒 Test that dangerous patterns in config values are blocked"""
        dangerous_configs = [
            {"command": "eval('malicious')"},
            {"script": "exec('dangerous')"},
            {"shell": "os.system('rm -rf /')"},
            {"import": "__import__('subprocess')"},
            {"html": "<script>alert(1)</script>"},
            {"js": "javascript:void(0)"},
            {"data": "data:text/html,<script>alert(1)</script>"}
        ]

        for config in dangerous_configs:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {config}"):
                validate_product_config(config)

    def test_text_field_length_limits(self):
        """🔒 Test that text fields enforce length limits"""
        long_text = "x" * 15000  # Over default 10KB limit

        with self.assertRaises(ValidationError) as cm:
            validate_text_field_length(long_text, "test field")

        self.assertIn("too long", str(cm.exception))

    def test_text_field_custom_length_limit(self):
        """🔒 Test that custom length limits work"""
        text = "x" * 600  # Over custom 500 limit

        with self.assertRaises(ValidationError) as cm:
            validate_text_field_length(text, "test field", max_length=500)

        self.assertIn("too long", str(cm.exception))

    def test_json_depth_calculation(self):
        """🔒 Test that JSON depth is calculated correctly"""
        # Test simple data
        simple_data = {"key": "value"}
        self.assertEqual(_get_json_depth(simple_data), 1)

        # Test nested data
        nested_data = {"level1": {"level2": {"level3": "value"}}}
        self.assertEqual(_get_json_depth(nested_data), 3)

        # Test array data
        array_data = [{"nested": {"deep": "value"}}]
        self.assertEqual(_get_json_depth(array_data), 3)

        # Test empty data
        self.assertEqual(_get_json_depth({}), 0)
        self.assertEqual(_get_json_depth([]), 0)

    def test_json_security_check_recursive(self):
        """🔒 Test that security checks work recursively"""
        nested_dangerous = {
            "safe": "value",
            "nested": {
                "also_safe": "value",
                "dangerous": "eval('malicious')"
            },
            "array": [
                {"safe": "value"},
                {"dangerous": "<script>alert(1)</script>"}
            ]
        }

        with self.assertRaises(ValidationError):
            _check_json_security(nested_dangerous, "test field")

    def test_safe_json_passes_validation(self):
        """✅ Test that safe JSON data passes all validations"""
        safe_data = {
            "product_name": "VPS Hosting",
            "features": ["SSD Storage", "24/7 Support", "99.9% Uptime"],
            "pricing": {
                "monthly": 29.99,
                "annual": 299.99
            },
            "specifications": {
                "cpu": "2 cores",
                "ram": "4GB",
                "storage": "80GB SSD",
                "bandwidth": "unlimited"
            },
            "metadata": {
                "category": "hosting",
                "popularity": 4.5,
                "recommended": True
            }
        }

        try:
            validate_json_field(safe_data)
        except ValidationError as e:
            self.fail(f"Safe JSON failed validation: {e}")

    def test_safe_config_passes_validation(self):
        """✅ Test that safe configuration passes all validations"""
        safe_config = {
            "panel": "cpanel",
            "php_version": "8.1",
            "mysql_version": "8.0",
            "features": ["email", "mysql", "php", "ssl"],
            "limits": {
                "disk_space": "10GB",
                "bandwidth": "unlimited",
                "databases": 10,
                "email_accounts": 100
            },
            "backup": {
                "enabled": True,
                "frequency": "daily",
                "retention": "30 days"
            }
        }

        try:
            validate_product_config(safe_config)
        except ValidationError as e:
            self.fail(f"Safe config failed validation: {e}")

    def test_safe_text_passes_validation(self):
        """✅ Test that safe text passes length validation"""
        safe_texts = [
            "Short description",
            "This is a medium length product description with some details.",
            "Lorem ipsum " * 50,  # About 650 chars - well under limit
            ""  # Empty text should be allowed
        ]

        for text in safe_texts:
            try:
                validate_text_field_length(text, "test field")
            except ValidationError as e:
                self.fail(f"Safe text failed validation: '{text[:50]}...', error: {e}")

    def test_empty_data_handling(self):
        """✅ Test that empty/None data is handled correctly"""
        # Empty data should not raise errors
        try:
            validate_json_field(None)
            validate_json_field({})
            validate_json_field([])
            validate_product_config(None)
            validate_product_config({})
            validate_text_field_length("", "test field")
        except ValidationError as e:
            self.fail(f"Empty data should be valid: {e}")

    def test_edge_case_data_types(self):
        """🔒 Test validation with edge case data types"""
        # Test with various data types
        mixed_data = {
            "string": "text",
            "number": 123,
            "float": 45.67,
            "boolean": True,
            "null": None,
            "array": [1, 2, 3],
            "nested": {"key": "value"}
        }

        try:
            validate_json_field(mixed_data)
        except ValidationError as e:
            self.fail(f"Mixed data types should be valid: {e}")

    def test_unicode_text_handling(self):
        """✅ Test that unicode text is handled correctly"""
        unicode_texts = [
            "Produs de găzduire în România",
            "产品描述",
            "Описание продукта",
            "🚀 Awesome hosting with emojis 🎉",
            "Mixed unicode: café, naïve, résumé"
        ]

        for text in unicode_texts:
            try:
                validate_text_field_length(text, "unicode field")
            except ValidationError as e:
                self.fail(f"Unicode text failed validation: '{text}', error: {e}")

    def test_performance_with_large_safe_data(self):
        """⚡ Test that validation performs reasonably with large safe data"""
        # Create large but safe data structure
        large_safe_data = {
            f"item_{i}": {
                "name": f"Product {i}",
                "description": f"Description for product {i}" * 10,
                "features": [f"feature_{j}" for j in range(10)],
                "pricing": {"monthly": 29.99 + i, "annual": 299.99 + i * 10}
            }
            for i in range(20)  # 20 products with nested data
        }

        # This should complete without raising ValidationError
        # and should complete in reasonable time (< 1 second)
        import time
        start_time = time.time()

        try:
            validate_json_field(large_safe_data)
            validate_product_config(large_safe_data)
        except ValidationError as e:
            self.fail(f"Large safe data failed validation: {e}")

        elapsed_time = time.time() - start_time
        self.assertLess(elapsed_time, 1.0, "Validation took too long for large safe data")
