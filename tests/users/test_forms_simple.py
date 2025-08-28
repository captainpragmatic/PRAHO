"""
Simple working test for users forms
"""

from django.test import TestCase


class SimpleFormsTest(TestCase):
    """Simple forms test"""
    
    def test_forms_import(self) -> None:
        """Test that forms module can be imported"""
        try:
            from apps.users import forms
            self.assertIsNotNone(forms)
        except Exception as e:
            self.fail(f"Failed to import forms: {e}")
    
    def test_login_form_creation(self) -> None:
        """Test LoginForm can be created"""
        from apps.users.forms import LoginForm
        
        form = LoginForm()
        self.assertIsNotNone(form)
        
        # Test form fields exist
        self.assertIn('email', form.fields)
        self.assertIn('password', form.fields)
    
    def test_login_form_validation(self) -> None:
        """Test LoginForm validation"""
        from apps.users.forms import LoginForm
        
        # Valid data
        form = LoginForm(data={
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertTrue(form.is_valid())
        
        # Invalid email
        form = LoginForm(data={
            'email': 'invalid-email',
            'password': 'testpass123'
        })
        self.assertFalse(form.is_valid())
    
    def test_user_registration_form(self) -> None:
        """Test UserRegistrationForm"""
        from apps.users.forms import UserRegistrationForm
        
        form = UserRegistrationForm()
        self.assertIsNotNone(form)
        
        # Check required fields
        self.assertIn('email', form.fields)
        self.assertIn('password1', form.fields)
        self.assertIn('password2', form.fields)
