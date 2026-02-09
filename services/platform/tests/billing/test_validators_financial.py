# ===============================================================================
# UNIT TESTS FOR BILLING VALIDATORS
# ===============================================================================
"""
Comprehensive tests for financial validation in PRAHO Platform billing.
Tests cover security validations, amount limits, and Romanian compliance.
"""

import pytest
from django.core.exceptions import ValidationError

from apps.billing.validators import (
    DANGEROUS_FINANCIAL_PATTERNS,
    MAX_FINANCIAL_AMOUNT_CENTS,
    MAX_JSON_DEPTH,
    MAX_JSON_SIZE_BYTES,
    MIN_FINANCIAL_AMOUNT_CENTS,
    SENSITIVE_FINANCIAL_KEYS,
    validate_financial_amount,
    validate_financial_json,
    validate_financial_text_field,
)


class TestValidateFinancialAmount:
    """Test financial amount validation"""

    def test_valid_amount_accepted(self):
        """Valid amounts should be accepted"""
        valid_amounts = [
            0,
            100,
            10000,
            100000,
            MAX_FINANCIAL_AMOUNT_CENTS,
        ]
        for amount in valid_amounts:
            # Should not raise exception
            validate_financial_amount(amount)

    def test_none_amount_accepted(self):
        """None amount should be accepted (optional field)"""
        validate_financial_amount(None)

    def test_negative_amounts_for_refunds(self):
        """Negative amounts should be allowed for refunds/credits"""
        negative_amounts = [
            -100,
            -10000,
            MIN_FINANCIAL_AMOUNT_CENTS,
        ]
        for amount in negative_amounts:
            validate_financial_amount(amount)

    def test_amount_too_large_rejected(self):
        """Amounts exceeding maximum should be rejected"""
        with pytest.raises(ValidationError) as exc:
            validate_financial_amount(MAX_FINANCIAL_AMOUNT_CENTS + 1)
        assert 'too large' in str(exc.value).lower()

    def test_amount_too_small_rejected(self):
        """Amounts below minimum should be rejected"""
        with pytest.raises(ValidationError) as exc:
            validate_financial_amount(MIN_FINANCIAL_AMOUNT_CENTS - 1)
        assert 'too small' in str(exc.value).lower()

    def test_max_amount_is_reasonable(self):
        """Maximum amount should be a reasonable business limit"""
        # 100 million in major currency units
        assert MAX_FINANCIAL_AMOUNT_CENTS == 10000000000

    def test_min_amount_allows_refunds(self):
        """Minimum amount should allow reasonable refunds"""
        # -100 million (mirror of max)
        assert MIN_FINANCIAL_AMOUNT_CENTS == -10000000000

    def test_custom_field_name_in_error(self):
        """Custom field name should appear in error message"""
        with pytest.raises(ValidationError) as exc:
            validate_financial_amount(MAX_FINANCIAL_AMOUNT_CENTS + 1, field_name="Invoice Total")
        assert 'Invoice Total' in str(exc.value)


class TestValidateFinancialJson:
    """Test JSON validation for financial data"""

    def test_empty_data_accepted(self):
        """Empty data should be accepted"""
        validate_financial_json(None)
        validate_financial_json({})
        validate_financial_json([])

    def test_valid_json_accepted(self):
        """Valid JSON structures should be accepted"""
        valid_data = [
            {'invoice_type': 'standard'},
            {'items': [{'name': 'hosting', 'price': 100}]},
            {'customer': {'name': 'Test', 'city': 'Bucharest'}},
        ]
        for data in valid_data:
            validate_financial_json(data)

    def test_json_size_limit_enforced(self):
        """JSON exceeding size limit should be rejected"""
        # Create data larger than 5KB
        large_data = {'data': 'x' * (MAX_JSON_SIZE_BYTES + 100)}
        with pytest.raises(ValidationError) as exc:
            validate_financial_json(large_data)
        assert 'too large' in str(exc.value).lower()

    def test_json_depth_limit_enforced(self):
        """JSON exceeding depth limit should be rejected"""
        # Create deeply nested structure
        deep_data = {'level1': {'level2': {'level3': {'level4': {'level5': {'level6': 'too deep'}}}}}}
        with pytest.raises(ValidationError) as exc:
            validate_financial_json(deep_data)
        assert 'too deep' in str(exc.value).lower()

    def test_sensitive_keys_rejected(self):
        """JSON with sensitive keys should be rejected"""
        for key in SENSITIVE_FINANCIAL_KEYS[:5]:  # Test first 5
            data = {key: 'secret_value'}
            with pytest.raises(ValidationError) as exc:
                validate_financial_json(data)
            assert 'sensitive' in str(exc.value).lower()

    def test_password_key_rejected(self):
        """Password in JSON should be rejected"""
        data = {'user_password': 'secret123'}
        with pytest.raises(ValidationError):
            validate_financial_json(data)

    def test_credit_card_key_rejected(self):
        """Credit card data in JSON should be rejected"""
        data = {'card_number': '4111111111111111'}
        with pytest.raises(ValidationError):
            validate_financial_json(data)

    def test_dangerous_patterns_in_values_rejected(self):
        """Dangerous patterns in values should be rejected"""
        dangerous_data = [
            {'description': '<script>alert("xss")</script>'},
            {'notes': 'eval(code)'},
            {'metadata': 'javascript:void(0)'},
        ]
        for data in dangerous_data:
            with pytest.raises(ValidationError):
                validate_financial_json(data)

    def test_template_injection_rejected(self):
        """Template injection patterns should be rejected"""
        injection_data = [
            {'template': '${malicious}'},
            {'data': '<%=evil%>'},
        ]
        for data in injection_data:
            with pytest.raises(ValidationError):
                validate_financial_json(data)

    def test_nested_sensitive_keys_detected(self):
        """Sensitive keys in nested structures should be detected"""
        nested_data = {
            'billing': {
                'customer': {
                    'api_key': 'sk_test_123'
                }
            }
        }
        with pytest.raises(ValidationError):
            validate_financial_json(nested_data)

    def test_list_items_validated(self):
        """Items in lists should be validated"""
        list_data = {
            'items': [
                {'name': 'good'},
                {'password': 'bad'},
            ]
        }
        with pytest.raises(ValidationError):
            validate_financial_json(list_data)


class TestValidateFinancialTextField:
    """Test text field validation for financial documents"""

    def test_empty_text_accepted(self):
        """Empty text should be accepted"""
        validate_financial_text_field('', 'description')
        validate_financial_text_field(None, 'notes')

    def test_valid_text_accepted(self):
        """Valid text should be accepted"""
        valid_texts = [
            'Invoice for web hosting services',
            'Monthly subscription - Standard plan',
            'Romanian VAT 19% included',
            'Plata pentru servicii hosting - SC Test SRL',
        ]
        for text in valid_texts:
            validate_financial_text_field(text, 'description')

    def test_text_too_long_rejected(self):
        """Text exceeding max length should be rejected"""
        long_text = 'x' * 1001
        with pytest.raises(ValidationError) as exc:
            validate_financial_text_field(long_text, 'description')
        assert 'too long' in str(exc.value).lower()

    def test_custom_max_length_enforced(self):
        """Custom max length should be enforced"""
        text = 'x' * 51
        with pytest.raises(ValidationError):
            validate_financial_text_field(text, 'short_field', max_length=50)

    def test_dangerous_patterns_rejected(self):
        """Dangerous patterns in text should be rejected"""
        for pattern in DANGEROUS_FINANCIAL_PATTERNS[:3]:
            # Create text that matches pattern
            if 'eval' in pattern:
                text = 'eval(code)'
            elif 'script' in pattern:
                text = '<script>alert(1)</script>'
            else:
                continue
            with pytest.raises(ValidationError):
                validate_financial_text_field(text, 'notes')

    def test_script_tags_rejected(self):
        """Script tags in financial text should be rejected"""
        text = 'Invoice notes: <script>alert("xss")</script>'
        with pytest.raises(ValidationError):
            validate_financial_text_field(text, 'notes')

    def test_field_name_in_error(self):
        """Field name should appear in error message"""
        long_text = 'x' * 1001
        with pytest.raises(ValidationError) as exc:
            validate_financial_text_field(long_text, 'Invoice Description')
        assert 'Invoice Description' in str(exc.value)


class TestDangerousPatterns:
    """Test dangerous pattern definitions"""

    def test_patterns_defined(self):
        """Dangerous patterns should be defined"""
        assert len(DANGEROUS_FINANCIAL_PATTERNS) > 0

    def test_code_execution_patterns(self):
        """Code execution patterns should be included"""
        patterns_found = False
        for pattern in DANGEROUS_FINANCIAL_PATTERNS:
            if 'eval' in pattern or 'exec' in pattern:
                patterns_found = True
                break
        assert patterns_found, "Code execution patterns should be defined"

    def test_script_pattern_included(self):
        """Script injection pattern should be included"""
        import re
        test_string = '<script>alert(1)</script>'
        detected = any(
            re.search(pattern, test_string, re.IGNORECASE)
            for pattern in DANGEROUS_FINANCIAL_PATTERNS
        )
        assert detected, "Script pattern should be detected"


class TestSensitiveKeys:
    """Test sensitive key definitions"""

    def test_sensitive_keys_defined(self):
        """Sensitive keys should be defined"""
        assert len(SENSITIVE_FINANCIAL_KEYS) > 0

    def test_password_in_sensitive_keys(self):
        """Password should be a sensitive key"""
        assert 'password' in SENSITIVE_FINANCIAL_KEYS

    def test_token_in_sensitive_keys(self):
        """Token should be a sensitive key"""
        assert 'token' in SENSITIVE_FINANCIAL_KEYS

    def test_card_number_in_sensitive_keys(self):
        """Card number should be a sensitive key"""
        assert 'card_number' in SENSITIVE_FINANCIAL_KEYS

    def test_api_key_in_sensitive_keys(self):
        """API key should be a sensitive key"""
        assert 'api_key' in SENSITIVE_FINANCIAL_KEYS


class TestJsonLimits:
    """Test JSON validation limits"""

    def test_json_size_limit(self):
        """JSON size limit should be defined"""
        assert MAX_JSON_SIZE_BYTES == 5120  # 5KB

    def test_json_depth_limit(self):
        """JSON depth limit should be defined"""
        assert MAX_JSON_DEPTH == 5
