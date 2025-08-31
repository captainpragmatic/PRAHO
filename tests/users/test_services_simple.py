"""
Simple working test for users services
"""

from django.test import RequestFactory, TestCase

from apps.common.request_ip import get_safe_client_ip

from apps.users.models import User
from apps.users.services import SessionSecurityService


class SimpleServicesTest(TestCase):
    """Simple services test"""
    
    def setUp(self) -> None:
        """Set up test data"""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email='services@example.com',
            password='testpass123'
        )
    
    def test_services_import(self) -> None:
        """Test that services module can be imported"""
        try:
            from apps.users import services
            self.assertIsNotNone(services)
        except Exception as e:
            self.fail(f"Failed to import services: {e}")
    
    def test_session_security_service(self) -> None:
        """Test SessionSecurityService basic functionality"""
        from django.contrib.sessions.backends.db import SessionStore
        
        request = self.factory.get('/')
        request.user = self.user
        request.session = SessionStore()
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Test that methods can be called without errors
        try:
            # Test get_client_ip method (using the actual function from common module)
            from apps.common.request_ip import get_safe_client_ip
            ip = get_safe_client_ip(request)
            self.assertIsNotNone(ip)
            
            # Test get_appropriate_timeout
            timeout = SessionSecurityService.get_appropriate_timeout(request)
            self.assertIsInstance(timeout, int)
            self.assertGreater(timeout, 0)
            
            # Test log_session_activity
            SessionSecurityService.log_session_activity(request, 'test_activity')
            
        except Exception as e:
            self.fail(f"SessionSecurityService methods failed: {e}")
    
    def test_user_registration_service_import(self) -> None:
        """Test UserRegistrationService can be imported"""
        try:
            from apps.users.services import SecureUserRegistrationService
            self.assertIsNotNone(SecureUserRegistrationService)
        except Exception as e:
            self.fail(f"Failed to import SecureUserRegistrationService: {e}")
    
    def test_customer_user_service_import(self) -> None:
        """Test SecureCustomerUserService can be imported"""
        try:
            from apps.users.services import SecureCustomerUserService
            self.assertIsNotNone(SecureCustomerUserService)
        except Exception as e:
            self.fail(f"Failed to import SecureCustomerUserService: {e}")
