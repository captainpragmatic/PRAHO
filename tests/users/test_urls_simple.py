"""
Simple working test for users URLs
"""

from django.test import TestCase


class SimpleURLTest(TestCase):
    """Simple URL import test"""
    
    def test_urls_import(self) -> None:
        """Test that urls module can be imported"""
        try:
            from apps.users import urls
            self.assertIsNotNone(urls)
        except Exception as e:
            self.fail(f"Failed to import urls: {e}")
    
    def test_urlpatterns_exist(self) -> None:
        """Test that urlpatterns exist"""
        from apps.users.urls import urlpatterns
        self.assertIsNotNone(urlpatterns)
        self.assertGreater(len(urlpatterns), 0)
    
    def test_app_name_exists(self) -> None:
        """Test that app_name is defined"""
        from apps.users.urls import app_name
        self.assertEqual(app_name, 'users')
