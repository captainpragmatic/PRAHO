"""
Tests for Romanian phone number validation improvements
"""

import pytest
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.users.models import User
from apps.customers.forms import CustomerCreationForm
from apps.users.forms import UserRegistrationForm, UserProfileForm, CustomerOnboardingRegistrationForm
from apps.common.types import validate_romanian_phone


class TestRomanianPhoneValidation(TestCase):
    """Test comprehensive Romanian phone number validation"""
    
    def test_valid_romanian_phone_formats(self):
        """Test all valid Romanian phone formats"""
        valid_phones = [
            '+40721234567',
            '+40 721 123 456',
            '0721123456',
            '+40 21 123 4567',
            '0211234567',
            '+40.21.123.4567',
            '0721 123 456',
        ]
        
        for phone in valid_phones:
            result = validate_romanian_phone(phone)
            assert result.is_ok(), f"Valid phone {phone} should pass: {result.error}"
    
    def test_invalid_romanian_phone_formats(self):
        """Test invalid Romanian phone formats"""
        invalid_phones = [
            '1234567890',  # No country code
            '+44 721 123 456',  # Wrong country code
            '+40 123 456',  # Too short
            '+40 721 123456789',  # Too long
            'invalid',  # Text
            '+40 721 12 34 56 78',  # Too many digits
        ]
        
        for phone in invalid_phones:
            result = validate_romanian_phone(phone)
            assert result.is_err(), f"Invalid phone {phone} should fail"
    
    def test_user_model_phone_validation(self):
        """Test phone validation in User model"""
        user = User(email='test@example.com', phone='+40721123456')
        user.set_password('ComplexPassword123!')
        
        # Should pass with valid phone
        user.full_clean()
        
        # Should raise ValidationError with invalid phone
        user.phone = 'invalid'
        with self.assertRaises(ValidationError):
            user.full_clean()
    
    def test_user_registration_form_phone_validation(self):
        """Test phone validation in UserRegistrationForm"""
        form_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password1': 'ComplexPassword123!',
            'password2': 'ComplexPassword123!',
            'phone': '+40 721 123 456',
            'gdpr_consent': True,
        }
        
        form = UserRegistrationForm(data=form_data)
        self.assertTrue(form.is_valid())
        
        # Test with invalid phone
        form_data['phone'] = 'invalid'
        form = UserRegistrationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('phone', form.errors)
    
    def test_customer_creation_form_phone_validation(self):
        """Test phone validation in CustomerCreationForm"""
        form_data = {
            'user_action': 'create',
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'phone': '+40 721 123 456',
            'customer_type': 'individual',
            'address_line1': 'Test Street 1',
            'city': 'Bucharest',
            'county': 'Sector 1',
            'postal_code': '010101',
            'data_processing_consent': True,
            'payment_terms': 30,
            'credit_limit': 0,
            'preferred_currency': 'RON',
        }
        
        form = CustomerCreationForm(data=form_data)
        self.assertTrue(form.is_valid())
        
        # Test with invalid phone
        form_data['phone'] = 'invalid'
        form = CustomerCreationForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('phone', form.errors)
    
    def test_phone_normalization(self):
        """Test phone number normalization"""
        test_cases = [
            ('0721123456', '+40721123456'),
            ('+40 721 123 456', '+40721123456'),
            ('0211234567', '+40211234567'),
            ('+40 21 123 4567', '+40211234567'),
        ]
        
        for input_phone, expected in test_cases:
            result = validate_romanian_phone(input_phone)
            assert result.is_ok(), f"Normalization failed for {input_phone}"
            assert result.unwrap() == expected, f"Expected {expected}, got {result.unwrap()}"
    
    def test_empty_phone_is_valid(self):
        """Test that empty phone is valid (optional field)"""
        result = validate_romanian_phone('')
        assert result.is_err(), "Empty phone should fail validation"
        
        # But forms should handle empty optional phone
        form_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User',
            'password1': 'ComplexPassword123!',
            'password2': 'ComplexPassword123!',
            'phone': '',  # Empty phone
            'gdpr_consent': True,
        }
        
        form = UserRegistrationForm(data=form_data)
        self.assertTrue(form.is_valid())
    
    def test_consistent_validation_across_platform(self):
        """Test that all forms use the same validation logic"""
        test_phone = '+40721123456'
        
        # Test centralized validation
        result = validate_romanian_phone(test_phone)
        self.assertTrue(result.is_ok())
        
        # Test User model
        user = User(email='test@example.com', phone=test_phone)
        user.set_password('ComplexPassword123!')
        try:
            user.full_clean()
        except ValidationError as e:
            if 'phone' in e.message_dict:
                self.fail("User model should accept valid phone")
        
        # Test forms
        forms_to_test = [
            UserRegistrationForm,
            CustomerCreationForm,
        ]
        
        for form_class in forms_to_test:
            if form_class == UserRegistrationForm:
                form_data = {
                    'email': 'test@example.com',
                    'first_name': 'Test',
                    'last_name': 'User',
                    'password1': 'ComplexPassword123!',
                    'password2': 'ComplexPassword123!',
                    'phone': test_phone,
                    'gdpr_consent': True,
                }
            else:
                form_data = {
                    'user_action': 'create',
                    'first_name': 'Test',
                    'last_name': 'User',
                    'email': 'test@example.com',
                    'phone': test_phone,
                    'customer_type': 'individual',
                    'address_line1': 'Test Street 1',
                    'city': 'Bucharest',
                    'county': 'Sector 1',
                    'postal_code': '010101',
                    'data_processing_consent': True,
                    'payment_terms': 30,
                    'credit_limit': 0,
                    'preferred_currency': 'RON',
                }
            
            form = form_class(data=form_data)
            self.assertTrue(form.is_valid(), f"{form_class.__name__} should accept valid phone")