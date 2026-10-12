# ===============================================================================
# COMPREHENSIVE UNIT TESTS FOR COMMON VALIDATORS
# ===============================================================================
"""
Unit tests for the enhanced input validation framework in PRAHO Platform.
Tests cover security validations, Romanian compliance, and edge cases.
"""

import pytest
from django.core.exceptions import ValidationError

from apps.common.validators import (
    MAX_EMAIL_LENGTH,
    MAX_NAME_LENGTH,
    MAX_URL_LENGTH,
    SUSPICIOUS_PATTERNS,
    SecureInputValidator,
)


@pytest.mark.django_db
class TestSecureInputValidatorEmail:
    """Test email validation security and functionality"""

    def test_valid_email_accepted(self):
        """Valid email addresses should be accepted"""
        valid_emails = [
            'test@example.com',
            'user.name@domain.ro',
            'user+tag@company.com',
            'firstname.lastname@pragmatichost.com',
        ]
        for email in valid_emails:
            result = SecureInputValidator.validate_email_secure(email)
            assert result == email.lower()

    def test_email_normalized_to_lowercase(self):
        """Email addresses should be normalized to lowercase"""
        email = 'Test.User@EXAMPLE.COM'
        result = SecureInputValidator.validate_email_secure(email)
        assert result == 'test.user@example.com'

    def test_email_trimmed(self):
        """Whitespace should be trimmed from email"""
        email = '  test@example.com  '
        result = SecureInputValidator.validate_email_secure(email)
        assert result == 'test@example.com'

    def test_empty_email_rejected(self):
        """Empty email should be rejected"""
        with pytest.raises(ValidationError):
            SecureInputValidator.validate_email_secure('')

    def test_none_email_rejected(self):
        """None email should be rejected"""
        with pytest.raises(ValidationError):
            SecureInputValidator.validate_email_secure(None)

    def test_email_too_long_rejected(self):
        """Email exceeding maximum length should be rejected"""
        long_email = 'a' * (MAX_EMAIL_LENGTH + 1) + '@example.com'
        with pytest.raises(ValidationError):
            SecureInputValidator.validate_email_secure(long_email)

    def test_invalid_email_format_rejected(self):
        """Invalid email formats should be rejected"""
        invalid_emails = [
            'notanemail',
            '@nodomain.com',
            'no@',
            'spaces in@email.com',
            'email@.com',
        ]
        for email in invalid_emails:
            with pytest.raises(ValidationError):
                SecureInputValidator.validate_email_secure(email)

    def test_xss_in_email_rejected(self):
        """XSS attempts in email should be rejected"""
        xss_emails = [
            '<script>alert("xss")</script>@example.com',
            'user@example.com<script>',
            'javascript:alert(1)@example.com',
        ]
        for email in xss_emails:
            with pytest.raises(ValidationError):
                SecureInputValidator.validate_email_secure(email)

    def test_sql_injection_in_email_rejected(self):
        """SQL injection attempts in email should be rejected"""
        sql_emails = [
            "user'; DROP TABLE users; --@example.com",
            "user@example.com' OR '1'='1",
            "UNION SELECT * FROM users@example.com",
        ]
        for email in sql_emails:
            with pytest.raises(ValidationError):
                SecureInputValidator.validate_email_secure(email)


@pytest.mark.django_db
class TestSecureInputValidatorMaliciousPatterns:
    """Test malicious pattern detection"""

    def test_xss_script_tag_detected(self):
        """Script tags should be detected as malicious"""
        malicious = '<script>alert("xss")</script>'
        with pytest.raises(ValidationError):
            SecureInputValidator._check_malicious_patterns(malicious)

    def test_javascript_protocol_detected(self):
        """JavaScript protocol should be detected as malicious"""
        malicious = 'javascript:alert(1)'
        with pytest.raises(ValidationError):
            SecureInputValidator._check_malicious_patterns(malicious)

    def test_event_handlers_detected(self):
        """Event handlers should be detected as malicious"""
        malicious_patterns = [
            'onclick=alert(1)',
            'onmouseover = test()',
            'onerror=hack()',
        ]
        for pattern in malicious_patterns:
            with pytest.raises(ValidationError):
                SecureInputValidator._check_malicious_patterns(pattern)

    def test_sql_injection_keywords_detected(self):
        """SQL injection keywords should be detected"""
        sql_patterns = [
            "SELECT * FROM users",
            "DROP TABLE customers",
            "UNION SELECT password",
            "INSERT INTO admin",
            "DELETE FROM orders",
        ]
        for pattern in sql_patterns:
            with pytest.raises(ValidationError):
                SecureInputValidator._check_malicious_patterns(pattern)

    def test_code_execution_attempts_detected(self):
        """Code execution attempts should be detected"""
        code_exec = [
            'eval(code)',
            'exec(command)',
        ]
        for pattern in code_exec:
            with pytest.raises(ValidationError):
                SecureInputValidator._check_malicious_patterns(pattern)

    def test_sql_comments_detected(self):
        """SQL comments should be detected"""
        sql_comments = [
            'password -- this is a comment',
            '/* comment */ data',
        ]
        for pattern in sql_comments:
            with pytest.raises(ValidationError):
                SecureInputValidator._check_malicious_patterns(pattern)

    def test_safe_text_accepted(self):
        """Normal text without malicious patterns should be accepted"""
        safe_texts = [
            'This is a normal company description',
            'SC Test Company SRL',
            'Contact: +40721234567',
            'Romanian compliance documentation',
            'Order placed successfully',
        ]
        for text in safe_texts:
            # Should not raise exception
            SecureInputValidator._check_malicious_patterns(text)




class TestInputLengthValidation:
    """Test input length validation constants"""

    def test_email_max_length(self):
        """Email max length should be RFC-compliant"""
        assert MAX_EMAIL_LENGTH == 254

    def test_name_max_length(self):
        """Name max length should be reasonable"""
        assert MAX_NAME_LENGTH == 100


    def test_url_max_length(self):
        """URL max length should be standard"""
        assert MAX_URL_LENGTH == 2048


class TestSuspiciousPatterns:
    """Test that suspicious patterns are properly defined"""

    def test_suspicious_patterns_not_empty(self):
        """Suspicious patterns list should not be empty"""
        assert len(SUSPICIOUS_PATTERNS) > 0

    def test_xss_patterns_included(self):
        """XSS patterns should be included"""
        import re
        xss_test = '<script>alert(1)</script>'
        found = any(re.search(pattern, xss_test, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS)
        assert found, "XSS script tag pattern should be detected"

    def test_sql_injection_patterns_included(self):
        """SQL injection patterns should be included"""
        import re
        sql_test = "SELECT * FROM users"
        found = any(re.search(pattern, sql_test, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS)
        assert found, "SQL SELECT pattern should be detected"

    def test_javascript_pattern_included(self):
        """JavaScript protocol pattern should be included"""
        import re
        js_test = 'javascript:alert(1)'
        found = any(re.search(pattern, js_test, re.IGNORECASE) for pattern in SUSPICIOUS_PATTERNS)
        assert found, "JavaScript protocol should be detected"
