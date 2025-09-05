"""
Basic functionality test to verify test infrastructure works.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()


class BasicFunctionalityTestCase(TestCase):
    """Test basic functionality to verify infrastructure."""
    
    def test_user_creation(self):
        """Test that we can create users."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.assertIsNotNone(user.id)
        self.assertEqual(user.email, 'test@example.com')
    
    def test_timezone_now_works(self):
        """Test that timezone.now() works properly."""
        now = timezone.now()
        self.assertIsNotNone(now)
    
    def test_basic_database_operations(self):
        """Test that basic database operations work."""
        initial_count = User.objects.count()
        
        User.objects.create_user(
            email='test2@example.com',
            password='testpass123'
        )
        
        self.assertEqual(User.objects.count(), initial_count + 1)
    
    def test_message_framework(self):
        """Test that Django messages framework works in tests."""
        from django.contrib import messages
        from django.test import RequestFactory
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.contrib.messages.middleware import MessageMiddleware
        from django.http import HttpResponse
        
        # Create a request with proper middleware
        factory = RequestFactory()
        request = factory.get('/')
        
        # Add session middleware
        session_middleware = SessionMiddleware(lambda req: HttpResponse())
        session_middleware.process_request(request)
        request.session.save()
        
        # Add message middleware
        message_middleware = MessageMiddleware(lambda req: HttpResponse())
        message_middleware.process_request(request)
        
        # Try adding a message
        messages.success(request, 'Test message')
        
        # This should not raise an error
        self.assertEqual(len(messages.get_messages(request)), 1)