"""
Tests for enhanced email enumeration protection features.

This test module covers the latest security enhancements including:
- Uniform logging with correlation IDs
- Neutral registration flow
- Registration submitted page
- Enhanced audit trailing
"""

import json
from unittest.mock import patch
from uuid import UUID

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

User = get_user_model()


class UniformLoggingTestCase(TestCase):
    """Test uniform logging with correlation IDs for registration paths."""

    def setUp(self):
        """Set up test data."""
        self.existing_user = User.objects.create_user(
            email="existing@example.com",
            first_name="Existing",
            last_name="User", 
            password="SuperSecure123!",
            gdpr_consent_date=timezone.now()
        )
        
        self.registration_url = reverse("users:register")
        self.valid_registration_data = {
            "email": "new@example.com",
            "first_name": "New",
            "last_name": "User",
            "phone": "+40.21.123.4567",
            "password1": "SuperSecure123!",
            "password2": "SuperSecure123!",
            "customer_type": "pfa",
            "company_name": "Test Company SRL",
            "vat_number": "RO12345678",
            "address_line1": "Str. Test Nr. 123",
            "city": "București",
            "county": "București", 
            "postal_code": "010001",
            "data_processing_consent": True,
            "marketing_consent": False,
            "terms_accepted": True,
        }

    @patch("apps.users.views.log_security_event")
    def test_correlation_id_generated_for_new_user(self, mock_log_security_event):
        """Test correlation ID is generated and used for new user registration."""
        response = self.client.post(self.registration_url, self.valid_registration_data)
        
        # Should redirect to success page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse("users:registration_submitted"))
        
        # Should have audit log entry
        mock_log_security_event.assert_called_once()
        
        # Check audit log details
        call_args = mock_log_security_event.call_args
        details = call_args[1]["details"]
        
        # Should have correlation ID
        self.assertIn("correlation_id", details)
        correlation_id = details["correlation_id"]
        
        # Should be valid UUID
        UUID(correlation_id)  # Will raise ValueError if invalid
        
        # Should have other required fields
        self.assertEqual(details["result_type"], "new_user")
        self.assertIn("email_hash", details)
        self.assertIn("session_key", details)
        self.assertIn("timestamp", details)

    @patch("apps.users.views.log_security_event")
    def test_correlation_id_maintained_for_existing_user(self, mock_log_security_event):
        """Test same correlation ID is maintained for existing user flow."""
        existing_email_data = self.valid_registration_data.copy()
        existing_email_data["email"] = "existing@example.com"
        
        response = self.client.post(self.registration_url, existing_email_data)
        
        # Should redirect to success page (same as new user)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse("users:registration_submitted"))
        
        # Should have audit log entry
        mock_log_security_event.assert_called_once()
        
        # Check audit log details
        call_args = mock_log_security_event.call_args
        details = call_args[1]["details"]
        
        # Should have correlation ID
        self.assertIn("correlation_id", details)
        correlation_id = details["correlation_id"]
        
        # Should be valid UUID
        UUID(correlation_id)  # Will raise ValueError if invalid
        
        # Should indicate existing user
        self.assertEqual(details["result_type"], "existing_user")

    @patch("apps.users.views.log_security_event")
    def test_correlation_id_for_validation_errors(self, mock_log_security_event):
        """Test correlation ID is generated even for form validation errors."""
        invalid_data = self.valid_registration_data.copy()
        invalid_data["email"] = "invalid-email-format"  # Invalid email
        
        response = self.client.post(self.registration_url, invalid_data)
        
        # Should render form with errors (not redirect)
        self.assertEqual(response.status_code, 200)
        
        # Should have audit log entry
        mock_log_security_event.assert_called_once()
        
        # Check audit log details
        call_args = mock_log_security_event.call_args
        details = call_args[1]["details"]
        
        # Should have correlation ID
        self.assertIn("correlation_id", details)
        correlation_id = details["correlation_id"]
        
        # Should be valid UUID
        UUID(correlation_id)  # Will raise ValueError if invalid
        
        # Should indicate form validation error
        self.assertEqual(details["result_type"], "form_validation_error")

    @patch("apps.users.views.log_security_event")
    def test_correlation_ids_are_unique(self, mock_log_security_event):
        """Test that different registration attempts get unique correlation IDs."""
        # First attempt
        self.client.post(self.registration_url, self.valid_registration_data)
        
        # Second attempt with different email
        second_data = self.valid_registration_data.copy()
        second_data["email"] = "second@example.com"
        self.client.post(self.registration_url, second_data)
        
        # Should have two audit log entries
        self.assertEqual(mock_log_security_event.call_count, 2)
        
        # Get correlation IDs from both calls
        first_call_details = mock_log_security_event.call_args_list[0][1]["details"]
        second_call_details = mock_log_security_event.call_args_list[1][1]["details"]
        
        first_correlation_id = first_call_details["correlation_id"]
        second_correlation_id = second_call_details["correlation_id"]
        
        # Should be different
        self.assertNotEqual(first_correlation_id, second_correlation_id)

    @patch("apps.users.views.log_security_event")
    def test_session_key_included_in_audit_logs(self, mock_log_security_event):
        """Test session key is included in audit logs for correlation."""
        # Set up session
        session = self.client.session
        session["test_key"] = "test_value"
        session.save()
        
        self.client.post(self.registration_url, self.valid_registration_data)
        
        # Should have audit log entry
        mock_log_security_event.assert_called_once()
        
        # Check session key is included
        call_args = mock_log_security_event.call_args
        details = call_args[1]["details"]
        
        self.assertIn("session_key", details)
        self.assertEqual(details["session_key"], session.session_key)


class NeutralRegistrationFlowTestCase(TestCase):
    """Test neutral registration flow and registration submitted page."""

    def setUp(self):
        """Set up test data."""
        self.existing_user = User.objects.create_user(
            email="existing@example.com",
            first_name="Existing",
            last_name="User", 
            password="SuperSecure123!",
            gdpr_consent_date=timezone.now()
        )
        
        self.registration_url = reverse("users:register")
        self.submitted_url = reverse("users:registration_submitted")
        
        self.valid_registration_data = {
            "email": "new@example.com",
            "first_name": "New",
            "last_name": "User",
            "phone": "+40.21.123.4567",
            "password1": "SuperSecure123!",
            "password2": "SuperSecure123!",
            "customer_type": "pfa",
            "company_name": "Test Company SRL",
            "vat_number": "RO12345678",
            "address_line1": "Str. Test Nr. 123",
            "city": "București",
            "county": "București", 
            "postal_code": "010001",
            "data_processing_consent": True,
            "marketing_consent": False,
            "terms_accepted": True,
        }

    def test_new_user_redirects_to_submitted_page(self):
        """Test new user registration redirects to neutral submitted page."""
        response = self.client.post(self.registration_url, self.valid_registration_data)
        
        # Should redirect to submitted page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.submitted_url)
        
        # User should be created
        self.assertTrue(User.objects.filter(email="new@example.com").exists())

    def test_existing_user_redirects_to_same_page(self):
        """Test existing user registration redirects to same submitted page."""
        existing_email_data = self.valid_registration_data.copy()
        existing_email_data["email"] = "existing@example.com"
        
        response = self.client.post(self.registration_url, existing_email_data)
        
        # Should redirect to same submitted page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.submitted_url)
        
        # No new user should be created
        user_count = User.objects.filter(email="existing@example.com").count()
        self.assertEqual(user_count, 1)  # Only the original user

    def test_registration_submitted_page_renders(self):
        """Test registration submitted page renders correctly."""
        response = self.client.get(self.submitted_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Check Your Email")
        self.assertContains(response, "Registration submitted successfully")
        self.assertContains(response, "check your email inbox")

    def test_registration_submitted_page_content(self):
        """Test registration submitted page contains expected content."""
        response = self.client.get(self.submitted_url)
        
        # Should contain helpful information without revealing anything
        self.assertContains(response, "We've received your registration")
        self.assertContains(response, "already have an account")
        self.assertContains(response, "What happens next")
        
        # Should have links to useful pages
        self.assertContains(response, 'href="/auth/login/"')
        self.assertContains(response, 'href="/app/"')  # Dashboard/home
        
        # Should have support options
        self.assertContains(response, "contact support")
        self.assertContains(response, "Try again")

    def test_no_messages_on_submitted_page(self):
        """Test registration submitted page doesn't rely on Django messages."""
        # Submit registration
        self.client.post(self.registration_url, self.valid_registration_data)
        
        # Follow redirect to submitted page
        response = self.client.get(self.submitted_url)
        
        # Page should work without relying on messages framework
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Registration submitted successfully")

    def test_uniform_response_timing_with_neutral_flow(self):
        """Test uniform response timing is maintained with neutral flow."""
        import time
        
        # Test new user timing
        start_time = time.perf_counter()
        response1 = self.client.post(self.registration_url, self.valid_registration_data)
        time1 = time.perf_counter() - start_time
        
        # Test existing user timing
        existing_email_data = self.valid_registration_data.copy()
        existing_email_data["email"] = "existing@example.com"
        
        start_time = time.perf_counter()
        response2 = self.client.post(self.registration_url, existing_email_data)
        time2 = time.perf_counter() - start_time
        
        # Both should redirect to same page
        self.assertEqual(response1.status_code, 302)
        self.assertEqual(response2.status_code, 302)
        self.assertEqual(response1.url, response2.url)
        
        # Timing should be similar (within test environment variance)
        time_diff = abs(time1 - time2)
        self.assertLess(time_diff, 0.5, f"Timing difference too large: {time_diff:.3f}s")


class AdvancedSecurityTestCase(TestCase):
    """Test advanced security features and edge cases."""

    def setUp(self):
        """Set up test data."""
        self.registration_url = reverse("users:register")
        self.valid_registration_data = {
            "email": "test@example.com",
            "first_name": "Test",
            "last_name": "User",
            "phone": "+40.21.123.4567",
            "password1": "SuperSecure123!",
            "password2": "SuperSecure123!",
            "customer_type": "pfa",
            "company_name": "Test Company SRL",
            "address_line1": "Str. Test Nr. 123",
            "city": "București",
            "county": "București", 
            "postal_code": "010001",
            "data_processing_consent": True,
            "terms_accepted": True,
        }

    @patch("apps.users.views.log_security_event")
    def test_email_hash_privacy_protection(self, mock_log_security_event):
        """Test email addresses are properly hashed in audit logs."""
        test_email = "sensitive@example.com"
        data = self.valid_registration_data.copy()
        data["email"] = test_email
        
        self.client.post(self.registration_url, data)
        
        # Should have audit log entry
        mock_log_security_event.assert_called_once()
        
        # Check audit log details
        call_args = mock_log_security_event.call_args
        details = call_args[1]["details"]
        
        # Email should be hashed, not plaintext
        self.assertIn("email_hash", details)
        email_hash = details["email_hash"]
        
        # Hash should not contain original email
        self.assertNotIn(test_email, email_hash)
        self.assertNotIn("sensitive", email_hash)
        
        # Hash should be consistent length (16 chars from SHA256)
        self.assertEqual(len(email_hash), 16)
        
        # Hash should be deterministic
        import hashlib
        expected_hash = hashlib.sha256(test_email.encode()).hexdigest()[:16]
        self.assertEqual(email_hash, expected_hash)

    @patch("apps.users.views._sleep_uniform")
    def test_timing_delay_always_applied(self, mock_sleep):
        """Test timing delay is applied for all valid registration attempts."""
        # Test new user
        self.client.post(self.registration_url, self.valid_registration_data)
        
        # Test existing user
        User.objects.create_user(
            email="existing@example.com",
            first_name="Existing",
            last_name="User",
            password="SuperSecure123!",
            gdpr_consent_date=timezone.now()
        )
        
        existing_data = self.valid_registration_data.copy()
        existing_data["email"] = "existing@example.com"
        self.client.post(self.registration_url, existing_data)
        
        # _sleep_uniform should be called for both attempts
        self.assertEqual(mock_sleep.call_count, 2)

    def test_no_information_leakage_in_response_content(self):
        """Test no information is leaked in response content or headers."""
        # Create existing user
        User.objects.create_user(
            email="existing@example.com",
            first_name="Existing",
            last_name="User",
            password="SuperSecure123!",
            gdpr_consent_date=timezone.now()
        )
        
        # Test new user response
        response1 = self.client.post(self.registration_url, self.valid_registration_data, follow=True)
        
        # Test existing user response
        existing_data = self.valid_registration_data.copy()
        existing_data["email"] = "existing@example.com"
        response2 = self.client.post(self.registration_url, existing_data, follow=True)
        
        # Both should end up on same page
        self.assertEqual(response1.status_code, 200)
        self.assertEqual(response2.status_code, 200)
        
        # Content should be identical (ignoring dynamic elements like CSRF tokens)
        content1 = response1.content.decode()
        content2 = response2.content.decode()
        
        # Remove CSRF tokens for comparison
        import re
        csrf_pattern = r'name="csrfmiddlewaretoken" value="[^"]*"'
        content1_clean = re.sub(csrf_pattern, 'name="csrfmiddlewaretoken" value="TOKEN"', content1)
        content2_clean = re.sub(csrf_pattern, 'name="csrfmiddlewaretoken" value="TOKEN"', content2)
        
        # Content should be identical
        self.assertEqual(content1_clean, content2_clean)
        
        # Should not contain any indication of email existence
        forbidden_terms = [
            "already exists",
            "account exists",
            "user exists",
            "email exists",
            "taken",
            "registered",
            "duplicate",
        ]
        
        for term in forbidden_terms:
            self.assertNotIn(term.lower(), content1.lower())
            self.assertNotIn(term.lower(), content2.lower())

    @patch("apps.users.views.log_security_event")
    def test_race_condition_handling_with_correlation_id(self, mock_log_security_event):
        """Test race condition handling maintains correlation ID."""
        # Create user that will be "deleted" in race condition simulation
        existing_user = User.objects.create_user(
            email="race@example.com",
            first_name="Race",
            last_name="User",
            password="SuperSecure123!",
            gdpr_consent_date=timezone.now()
        )
        
        # Simulate race condition by mocking User.objects.get to raise DoesNotExist
        with patch("apps.users.models.User.objects.get") as mock_get:
            mock_get.side_effect = User.DoesNotExist()
            
            race_data = self.valid_registration_data.copy()
            race_data["email"] = "race@example.com"
            
            response = self.client.post(self.registration_url, race_data)
        
        # Should still redirect to success page
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse("users:registration_submitted"))
        
        # Should have audit log entry
        mock_log_security_event.assert_called_once()
        
        # Check race condition was logged with correlation ID
        call_args = mock_log_security_event.call_args
        details = call_args[1]["details"]
        
        self.assertIn("correlation_id", details)
        self.assertEqual(details["result_type"], "existing_user")  # IntegrityError indicates existing user


class SecurityRegressionTestCase(TestCase):
    """Test for security regressions and comprehensive protection verification."""

    def test_no_django_messages_enumeration(self):
        """Test Django messages don't reveal email enumeration information."""
        # Create existing user
        User.objects.create_user(
            email="existing@example.com",
            first_name="Existing",
            last_name="User",
            password="SuperSecure123!",
            gdpr_consent_date=timezone.now()
        )
        
        registration_url = reverse("users:register")
        
        valid_data = {
            "email": "existing@example.com",
            "first_name": "Test",
            "last_name": "User",
            "phone": "+40.21.123.4567",
            "password1": "SuperSecure123!",
            "password2": "SuperSecure123!",
            "customer_type": "pfa",
            "company_name": "Test Company SRL",
            "address_line1": "Str. Test Nr. 123",
            "city": "București",
            "county": "București",
            "postal_code": "010001",
            "data_processing_consent": True,
            "terms_accepted": True,
        }
        
        response = self.client.post(registration_url, valid_data, follow=True)
        
        # Check no enumeration information in messages
        messages = list(response.context.get("messages", []))
        
        for message in messages:
            message_text = str(message).lower()
            
            # Should not contain enumeration indicators
            enumeration_terms = [
                "already exists",
                "account exists", 
                "user exists",
                "email exists",
                "taken",
                "registered",
                "in use",
            ]
            
            for term in enumeration_terms:
                self.assertNotIn(term, message_text)

    def test_comprehensive_neutral_flow(self):
        """Test comprehensive neutral flow covers all registration paths."""
        registration_url = reverse("users:register")
        submitted_url = reverse("users:registration_submitted")
        
        test_scenarios = [
            # New user
            {
                "email": "new1@example.com",
                "description": "new_user",
                "setup": lambda: None,
            },
            # Existing user  
            {
                "email": "existing1@example.com",
                "description": "existing_user",
                "setup": lambda: User.objects.create_user(
                    email="existing1@example.com",
                    first_name="Existing",
                    last_name="User",
                    password="SuperSecure123!",
                    gdpr_consent_date=timezone.now()
                ),
            },
        ]
        
        valid_base_data = {
            "first_name": "Test",
            "last_name": "User",
            "phone": "+40.21.123.4567",
            "password1": "SuperSecure123!",
            "password2": "SuperSecure123!",
            "customer_type": "pfa",
            "company_name": "Test Company SRL",
            "address_line1": "Str. Test Nr. 123",
            "city": "București",
            "county": "București",
            "postal_code": "010001",
            "data_processing_consent": True,
            "terms_accepted": True,
        }
        
        responses = []
        
        for scenario in test_scenarios:
            # Setup scenario
            scenario["setup"]()
            
            # Prepare data
            data = valid_base_data.copy()
            data["email"] = scenario["email"]
            
            # Submit registration
            response = self.client.post(registration_url, data)
            responses.append((scenario["description"], response))
        
        # All scenarios should redirect to same page
        for description, response in responses:
            with self.subTest(scenario=description):
                self.assertEqual(response.status_code, 302)
                self.assertRedirects(response, submitted_url)
        
        # All scenarios should result in identical response patterns
        redirect_urls = [response.url for _, response in responses]
        self.assertTrue(all(url == submitted_url for url in redirect_urls))