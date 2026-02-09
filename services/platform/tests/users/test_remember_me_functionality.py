"""
Test Remember Me functionality in login view
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.conf import settings

User = get_user_model()


class RememberMeFunctionalityTest(TestCase):
    """Test Remember Me checkbox functionality"""

    def setUp(self) -> None:
        """Set up test user"""
        self.client = Client()
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            is_staff=True,
            staff_role="support",
        )
        self.login_url = reverse("users:login")

    def test_successful_login_with_remember_me_true(self) -> None:
        """Test login with remember_me checked sets session correctly"""
        response = self.client.post(self.login_url, {
            "email": "test@example.com",
            "password": "testpass123",
            "remember_me": True
        })
        
        # Should redirect on success
        self.assertEqual(response.status_code, 302)
        
        # Check session has remember_me flag
        self.assertTrue(self.client.session.get("remember_me", False))
        
        # Check session timeout was updated (7 days = 604800 seconds)
        expected_timeout = 86400 * 7  # 7 days in seconds
        actual_timeout = self.client.session.get_expiry_age()
        self.assertEqual(actual_timeout, expected_timeout)

    def test_successful_login_with_remember_me_false(self) -> None:
        """Test login without remember_me uses standard timeout"""
        response = self.client.post(self.login_url, {
            "email": "test@example.com",
            "password": "testpass123",
            "remember_me": False
        })
        
        # Should redirect on success
        self.assertEqual(response.status_code, 302)
        
        # Check session does NOT have remember_me flag
        self.assertFalse(self.client.session.get("remember_me", False))
        
        # Check session timeout is standard (not 7 days)
        actual_timeout = self.client.session.get_expiry_age()
        self.assertNotEqual(actual_timeout, 86400 * 7)

    def test_successful_login_without_remember_me_field(self) -> None:
        """Test login without remember_me field (unchecked checkbox)"""
        response = self.client.post(self.login_url, {
            "email": "test@example.com",
            "password": "testpass123"
            # No remember_me field - simulates unchecked checkbox
        })
        
        # Should redirect on success
        self.assertEqual(response.status_code, 302)
        
        # Check session does NOT have remember_me flag
        self.assertFalse(self.client.session.get("remember_me", False))

    def test_remember_me_field_in_form(self) -> None:
        """Test that remember_me field is properly rendered in form"""
        response = self.client.get(self.login_url)
        self.assertEqual(response.status_code, 200)
        
        # The template should render the checkbox with the correct name
        self.assertContains(response, 'name="remember_me"')
        self.assertContains(response, 'Keep me logged in')

    def test_remember_me_with_invalid_credentials(self) -> None:
        """Test remember_me field doesn't interfere with failed login"""
        response = self.client.post(self.login_url, {
            "email": "test@example.com",
            "password": "wrongpassword",
            "remember_me": True
        })
        
        # Should return login form with error (not redirect)
        self.assertEqual(response.status_code, 200)
        
        # Session should not be created for failed login
        self.assertFalse(self.client.session.get("remember_me", False))
        
        # User should not be authenticated
        self.assertFalse(response.wsgi_request.user.is_authenticated)