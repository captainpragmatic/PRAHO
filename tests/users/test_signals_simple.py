"""
Simple working test for users signals
"""

from django.test import RequestFactory, TestCase

from apps.users.models import User
from apps.users.signals import _get_client_ip


class SimpleSignalsTest(TestCase):
    """Simple signals test"""
    
    def setUp(self) -> None:
        """Set up test data"""
        self.factory = RequestFactory()
    
    def test_signals_import(self) -> None:
        """Test that signals module can be imported"""
        try:
            from apps.users import signals
            self.assertIsNotNone(signals)
        except Exception as e:
            self.fail(f"Failed to import signals: {e}")
    
    def test_get_client_ip_function(self) -> None:
        """Test _get_client_ip utility function"""
        request = self.factory.get('/')
        
        # Test with REMOTE_ADDR
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        ip = _get_client_ip(request)
        self.assertEqual(ip, '192.168.1.1')
        
        # Test with X-Forwarded-For
        request.META['HTTP_X_FORWARDED_FOR'] = '10.0.0.1, 192.168.1.1'
        ip = _get_client_ip(request)
        self.assertEqual(ip, '10.0.0.1')  # Should return first IP
        
        # Test with no IP
        del request.META['REMOTE_ADDR']
        del request.META['HTTP_X_FORWARDED_FOR']
        ip = _get_client_ip(request)
        self.assertEqual(ip, '127.0.0.1')  # Should return default
    
    def test_user_profile_auto_creation(self) -> None:
        """Test that user profile is auto-created via signals"""
        user = User.objects.create_user(
            email='signal@example.com',
            password='testpass123'
        )
        
        # Profile should be auto-created by signal
        self.assertTrue(hasattr(user, 'profile'))
        self.assertIsNotNone(user.profile)
