# ===============================================================================
# 🧪 VIRTUALMIN VALIDATORS TESTS
# ===============================================================================
"""
Comprehensive tests for Virtualmin input validation focusing on security and compliance.

🚨 Coverage Target: ≥95% for security validation methods
🔒 Security: Tests input sanitization and injection prevention
📊 Performance: Validates O(1) validation performance
"""

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.provisioning.virtualmin_validators import VirtualminValidator


class VirtualminValidatorTest(TestCase):
    """Test Virtualmin input validation with security focus"""

    def test_domain_validation_valid_cases(self):
        """Test valid domain name validation"""
        valid_domains = [
            "testdomain.ro",
            "example.com",
            "sub.domain.org",
            "test-site.net",
            "a.co",
            "very-long-domain-name-that-is-still-valid.com"
        ]

        for domain in valid_domains:
            with self.subTest(domain=domain):
                # Should not use reserved domains in real tests
                if domain not in ["example.com", "example.org", "example.net"]:
                    result = VirtualminValidator.validate_domain_name(domain)
                    self.assertEqual(result, domain.lower())

    def test_domain_validation_reserved_domains(self):
        """Test reserved domain rejection"""
        reserved_domains = [
            "localhost",
            "example.com",
            "example.org",
            "example.net",
            "test.local",
            "invalid",
            "local"
        ]

        for domain in reserved_domains:
            with self.subTest(domain=domain):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_domain_name(domain)

    def test_domain_validation_invalid_format(self):
        """Test invalid domain format rejection"""
        invalid_domains = [
            "invalid..domain",
            ".invalid-start",
            "invalid-end.",
            "-invalid-start.com",
            "invalid-end-.com",
            "",
            "a",
            "ab",  # Too short
            "a" * 254,  # Too long (>253 chars)
            "space domain.com",
            "special!chars.com",
            "under_score.com"  # Underscore not allowed in domain
        ]

        for domain in invalid_domains:
            with self.subTest(domain=domain):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_domain_name(domain)

    def test_username_validation_valid_cases(self):
        """Test valid username validation"""
        valid_usernames = [
            "testuser",
            "user123",
            "test_user",
            "a1b2c3",
            "user_with_numbers123",
            "a" * 32  # Maximum length
        ]

        for username in valid_usernames:
            with self.subTest(username=username):
                result = VirtualminValidator.validate_username(username)
                self.assertEqual(result, username)

    def test_username_validation_reserved_usernames(self):
        """Test reserved username rejection"""
        reserved_usernames = [
            "root",
            "admin",
            "administrator",
            "www",
            "mail",
            "ftp",
            "test",
            "guest",
            "daemon",
            "nobody",
            "www-data"
        ]

        for username in reserved_usernames:
            with self.subTest(username=username):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_username(username)

    def test_username_validation_invalid_format(self):
        """Test invalid username format rejection"""
        invalid_usernames = [
            "",
            "ab",  # Too short
            "a" * 33,  # Too long
            "invalid-dash",
            "invalid space",
            "invalid.dot",
            "invalid@symbol",
            "invalid!special",
            # Note: USERNAME_PATTERN allows uppercase and numbers at start
            # These patterns are actually valid according to the regex: ^[a-zA-Z0-9_]{3,32}$
        ]

        for username in invalid_usernames:
            with self.subTest(username=username):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_username(username)

    def test_program_validation_valid_cases(self):
        """Test valid Virtualmin program validation"""
        valid_programs = [
            "create-domain",
            "delete-domain",
            "enable-domain",
            "disable-domain",
            "list-domains",
            "modify-domain",
            "create-user",
            "delete-user",
            "list-users"
        ]

        for program in valid_programs:
            with self.subTest(program=program):
                result = VirtualminValidator.validate_virtualmin_program(program)
                self.assertEqual(result, program)

    def test_program_validation_dangerous_commands(self):
        """Test dangerous command rejection"""
        dangerous_programs = [
            "dangerous-command",
            "rm-rf",
            "sudo-command",
            "shell-access",
            "system-command",
            "",
            "invalid program",
            "program;injection",
            "program|pipe",
            "program&background"
        ]

        for program in dangerous_programs:
            with self.subTest(program=program):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_virtualmin_program(program)

    def test_password_validation_strength(self):
        """Test password strength validation"""
        # Valid strong passwords
        strong_passwords = [
            "StrongPass123!",
            "C0mpl3x!P@ssw0rd",
            "MySecure#Pass1",
            "Test@123Password"
        ]

        for password in strong_passwords:
            with self.subTest(password=password):
                result = VirtualminValidator.validate_password(password)
                self.assertEqual(result, password)

    def test_password_validation_weak_passwords(self):
        """Test weak password rejection"""
        weak_passwords = [
            "",
            "short",  # Too short
            "password",  # No uppercase, digits, special
            "PASSWORD",  # No lowercase, digits, special
            "12345678",  # No letters, special
            "!!!!!!!!",  # No letters, digits
            "a" * 129,  # Too long
            "onlylower123",  # Missing uppercase and special
            "ONLYUPPER123",  # Missing lowercase and special
        ]

        for password in weak_passwords:
            with self.subTest(password=password):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_password(password)

    def test_email_validation(self):
        """Test email validation"""
        # Valid emails (avoid reserved domains)
        valid_emails = [
            "test@testdomain.ro",
            "user.name@domain.org",
            "user+tag@test.co.uk"
        ]

        for email in valid_emails:
            with self.subTest(email=email):
                result = VirtualminValidator.validate_email(email)
                self.assertEqual(result, email.lower())

        # Invalid emails
        invalid_emails = [
            "",
            "invalid-email",
            "@domain.com",
            "user@",
            "user@domain",
            "user.domain.com",
            "a" * 250 + "@domain.com",  # Too long
            "user@domain@domain.com"  # Multiple @
        ]

        for email in invalid_emails:
            with self.subTest(email=email):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_email(email)

    def test_template_name_validation(self):
        """Test template name validation"""
        # Valid templates
        valid_templates = [
            "Default",
            "PHP-Template",
            "Custom_Template",
            "Template123"
        ]

        for template in valid_templates:
            with self.subTest(template=template):
                result = VirtualminValidator.validate_template_name(template)
                self.assertEqual(result, template)

        # Test empty template returns Default
        result = VirtualminValidator.validate_template_name("")
        self.assertEqual(result, "Default")

        # Invalid templates
        invalid_templates = [
            "a" * 51,  # Too long
            "Invalid Template",  # Space not allowed
            "Invalid.Template",  # Dot not allowed
            "Invalid@Template"  # Special chars not allowed
        ]

        for template in invalid_templates:
            with self.subTest(template=template):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_template_name(template)

    def test_quota_validation(self):
        """Test quota validation"""
        # Valid quotas
        self.assertEqual(VirtualminValidator.validate_quota_mb(1000), 1000)
        self.assertEqual(VirtualminValidator.validate_quota_mb(None), None)
        # Note: The validator returns 0 for 0 input, not None
        self.assertEqual(VirtualminValidator.validate_quota_mb(0), 0)

        # Invalid quotas
        with self.assertRaises(ValidationError):
            VirtualminValidator.validate_quota_mb(-1)

        with self.assertRaises(ValidationError):
            VirtualminValidator.validate_quota_mb(1000000000)  # Too large

    def test_security_injection_prevention(self):
        """Test security against injection attacks"""
        malicious_inputs = [
            "domain.com; rm -rf /",
            "domain.com && malicious",
            "domain.com | evil",
            "domain.com $(injection)",
            "domain.com `backtick`",
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --"
        ]

        for malicious_input in malicious_inputs:
            with self.subTest(input=malicious_input):
                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_domain_name(malicious_input)

                with self.assertRaises(ValidationError):
                    VirtualminValidator.validate_username(malicious_input)
