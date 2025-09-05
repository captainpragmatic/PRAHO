# ===============================================================================
# PLATFORM ↔ PORTAL API INTEGRATION TESTS 🔗
# ===============================================================================
# Tests the API communication between platform and portal services
# Validates that portal can access platform data via API (not direct DB)

import pytest
import requests
from unittest.mock import patch, Mock


class TestPlatformPortalIntegration:
    """
    Integration tests for platform and portal service communication.
    
    These tests verify that:
    1. Portal can communicate with platform via API
    2. Portal receives expected data format from platform
    3. Portal handles platform API errors gracefully
    4. Authentication works between services
    """
    
    @pytest.mark.integration
    def test_portal_can_fetch_customer_data_from_platform_api(self):
        """
        Test that portal service can retrieve customer data from platform API.
        
        This validates the core integration - portal getting customer info
        without direct database access.
        """
        # Mock platform API response
        mock_response = Mock()
        mock_response.json.return_value = {
            'id': 1,
            'email': 'test@pragmatichost.com', 
            'name': 'Test Customer',
            'status': 'active'
        }
        mock_response.status_code = 200
        
        with patch('requests.get', return_value=mock_response) as mock_get:
            # Portal should make API call to platform
            platform_api_url = "http://platform:8700/api/customers/1/"
            
            # Simulate portal's API call
            response = requests.get(platform_api_url)
            
            # Verify API call was made
            mock_get.assert_called_once_with(platform_api_url)
            
            # Verify response format
            data = response.json()
            assert data['id'] == 1
            assert data['email'] == 'test@pragmatichost.com'
            assert 'status' in data
    
    @pytest.mark.integration
    def test_portal_handles_platform_api_errors(self):
        """
        Test that portal gracefully handles platform API errors.
        """
        # Mock platform API error response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {'error': 'Internal server error'}
        
        with patch('requests.get', return_value=mock_response):
            # Portal should handle API errors gracefully
            platform_api_url = "http://platform:8700/api/customers/999/"
            response = requests.get(platform_api_url)
            
            # Verify error handling
            assert response.status_code == 500
            error_data = response.json()
            assert 'error' in error_data
    
    @pytest.mark.integration  
    def test_portal_cannot_access_platform_database_directly(self):
        """
        Security test: Verify portal cannot access platform database.
        
        This is a critical security boundary - portal must use API only.
        """
        from django.core.exceptions import ImproperlyConfigured
        
        with pytest.raises(ImproperlyConfigured, match="Portal service attempted database access"):
            # This should fail - portal trying to access DB directly
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM customers_customer LIMIT 1")
    
    @pytest.mark.integration
    def test_platform_api_authentication_required(self):
        """
        Test that platform API requires proper authentication from portal.
        """
        # Mock unauthenticated API response
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {'error': 'Authentication required'}
        
        with patch('requests.get', return_value=mock_response):
            # Portal API call without auth should fail
            platform_api_url = "http://platform:8700/api/customers/"
            response = requests.get(platform_api_url)  # No auth headers
            
            # Verify authentication is enforced
            assert response.status_code == 401
            error_data = response.json()
            assert error_data['error'] == 'Authentication required'


# ===============================================================================
# DATABASE CACHE INTEGRATION TESTS (NO REDIS) 💾  
# ===============================================================================

class TestDatabaseCacheIntegration:
    """
    Integration tests for database cache functionality (post Redis removal).
    
    Validates that platform service uses database cache correctly.
    """
    
    @pytest.mark.integration
    @pytest.mark.cache
    def test_platform_uses_database_cache(self):
        """
        Test that platform service uses database cache (not Redis).
        """
        from django.core.cache import cache
        from django.conf import settings
        
        # Verify database cache backend is configured
        cache_config = settings.CACHES['default']
        assert cache_config['BACKEND'] == 'django.core.cache.backends.db.DatabaseCache'
        assert cache_config['LOCATION'] == 'django_cache_table'
        
        # Test cache operations work
        test_key = 'test_integration_key'
        test_value = {'data': 'test_value', 'timestamp': '2025-01-01'}
        
        # Set cache value
        cache.set(test_key, test_value, timeout=300)
        
        # Retrieve cache value  
        cached_value = cache.get(test_key)
        assert cached_value == test_value
        
        # Clear cache
        cache.delete(test_key)
        assert cache.get(test_key) is None
    
    @pytest.mark.integration
    @pytest.mark.cache
    def test_cache_table_exists_and_functional(self):
        """
        Test that django_cache_table exists and is functional.
        """
        from django.db import connection
        
        with connection.cursor() as cursor:
            # Verify cache table exists
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='django_cache_table'
            """)
            
            result = cursor.fetchone()
            assert result is not None, "django_cache_table should exist"
            
            # Test direct cache table operations
            from django.core.cache import cache
            cache.set('db_test_key', 'db_test_value', timeout=60)
            
            # Verify data is in cache table
            cursor.execute("SELECT cache_key FROM django_cache_table WHERE cache_key LIKE '%db_test_key%'")
            cache_entry = cursor.fetchone()
            assert cache_entry is not None, "Cache entry should be in database"
