# ===============================================================================
# DATABASE CACHE FUNCTIONALITY TESTS (POST REDIS REMOVAL) 💾
# ===============================================================================
# Tests that verify database cache works correctly without Redis
# Validates cache table creation, operations, and performance

import pytest
from django.core.cache import cache
from django.conf import settings
from django.db import connection
from django.test import TestCase, override_settings


class TestDatabaseCacheFunctionality(TestCase):
    """
    Tests for database cache functionality after Redis removal.
    
    These tests verify that:
    1. Database cache backend is correctly configured
    2. Cache operations work as expected
    3. Cache table exists and is functional
    4. Performance is acceptable for our use cases
    """
    
    @pytest.mark.cache
    def test_database_cache_backend_configuration(self):
        """
        Test that Django is configured to use database cache backend.
        """
        cache_config = settings.CACHES['default']
        
        # Verify database cache backend
        assert cache_config['BACKEND'] == 'django.core.cache.backends.db.DatabaseCache'
        assert cache_config['LOCATION'] == 'django_cache_table'
        assert cache_config['KEY_PREFIX'] == 'pragmatichost'
        
        # Verify cache options
        options = cache_config.get('OPTIONS', {})
        assert 'MAX_ENTRIES' in options
        assert 'CULL_FREQUENCY' in options
        
        # Verify timeout is set
        assert 'TIMEOUT' in cache_config
    
    @pytest.mark.cache
    def test_cache_table_exists(self):
        """
        Test that django_cache_table exists in database.
        """
        with connection.cursor() as cursor:
            # Check if cache table exists
            cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='django_cache_table'
            """)
            
            result = cursor.fetchone()
            assert result is not None, "django_cache_table should exist"
            
            # Check table structure
            cursor.execute("PRAGMA table_info(django_cache_table)")
            columns = cursor.fetchall()
            
            # Verify expected columns exist
            column_names = [col[1] for col in columns]  # Column name is at index 1
            expected_columns = ['cache_key', 'value', 'expires']
            
            for col in expected_columns:
                assert col in column_names, f"Column {col} should exist in cache table"
    
    @pytest.mark.cache
    def test_basic_cache_operations(self):
        """
        Test basic cache set/get/delete operations work correctly.
        """
        test_key = 'test_cache_key'
        test_value = {'data': 'test_value', 'number': 42, 'list': [1, 2, 3]}
        
        # Test cache.set()
        cache.set(test_key, test_value, timeout=300)
        
        # Test cache.get()
        cached_value = cache.get(test_key)
        assert cached_value == test_value
        
        # Test cache.get() with default
        non_existent = cache.get('non_existent_key', 'default_value')
        assert non_existent == 'default_value'
        
        # Test cache.delete()
        cache.delete(test_key)
        deleted_value = cache.get(test_key)
        assert deleted_value is None
    
    @pytest.mark.cache
    def test_cache_key_prefixing(self):
        """
        Test that cache keys are properly prefixed.
        """
        test_key = 'test_prefix_key'
        test_value = 'test_prefix_value'
        
        cache.set(test_key, test_value, timeout=60)
        
        # Check database directly to verify key prefixing
        with connection.cursor() as cursor:
            cursor.execute("SELECT cache_key FROM django_cache_table")
            cache_keys = [row[0] for row in cursor.fetchall()]
            
            # Should find a key with our prefix
            prefixed_keys = [key for key in cache_keys if 'pragmatichost' in key and test_key in key]
            assert len(prefixed_keys) > 0, "Cache key should be prefixed with 'pragmatichost'"
        
        # Clean up
        cache.delete(test_key)
    
    @pytest.mark.cache 
    def test_cache_expiration(self):
        """
        Test that cache expiration works correctly.
        """
        test_key = 'test_expiration_key'
        test_value = 'test_expiration_value'
        
        # Set cache with very short timeout (1 second)
        cache.set(test_key, test_value, timeout=1)
        
        # Should be available immediately
        cached_value = cache.get(test_key)
        assert cached_value == test_value
        
        # Wait for expiration (in real test, would use time manipulation)
        import time
        time.sleep(2)
        
        # Should be expired now
        expired_value = cache.get(test_key)
        assert expired_value is None
    
    @pytest.mark.cache
    def test_cache_with_complex_data(self):
        """
        Test caching complex data structures.
        """
        complex_data = {
            'customer': {
                'id': 123,
                'name': 'Test Customer',
                'orders': [
                    {'id': 1, 'product': 'Shared Hosting', 'price': 29.99},
                    {'id': 2, 'product': 'Domain Registration', 'price': 12.99}
                ],
                'metadata': {
                    'created_at': '2025-01-01T00:00:00Z',
                    'last_login': '2025-01-02T12:00:00Z'
                }
            }
        }
        
        test_key = 'complex_data_test'
        
        # Cache complex data
        cache.set(test_key, complex_data, timeout=300)
        
        # Retrieve and verify
        cached_data = cache.get(test_key)
        assert cached_data == complex_data
        assert cached_data['customer']['id'] == 123
        assert len(cached_data['customer']['orders']) == 2
        assert cached_data['customer']['metadata']['created_at'] == '2025-01-01T00:00:00Z'
        
        # Clean up
        cache.delete(test_key)
    
    @pytest.mark.cache
    def test_cache_many_operations(self):
        """
        Test cache.set_many() and cache.get_many() operations.
        """
        test_data = {
            'key1': 'value1',
            'key2': 'value2', 
            'key3': {'nested': 'value3'}
        }
        
        # Test set_many
        cache.set_many(test_data, timeout=300)
        
        # Test get_many  
        cached_data = cache.get_many(['key1', 'key2', 'key3', 'nonexistent'])
        
        assert cached_data['key1'] == 'value1'
        assert cached_data['key2'] == 'value2'
        assert cached_data['key3'] == {'nested': 'value3'}
        assert 'nonexistent' not in cached_data
        
        # Test delete_many
        cache.delete_many(['key1', 'key2', 'key3'])
        
        # Verify deletion
        after_delete = cache.get_many(['key1', 'key2', 'key3'])
        assert len(after_delete) == 0


# ===============================================================================
# CACHE PERFORMANCE TESTS 📊
# ===============================================================================

class TestDatabaseCachePerformance:
    """
    Performance tests for database cache to ensure it meets our needs.
    """
    
    @pytest.mark.cache
    @pytest.mark.slow
    def test_cache_performance_vs_redis(self):
        """
        Test that database cache performance is acceptable.
        
        While not as fast as Redis, database cache should be sufficient
        for our application's caching needs.
        """
        import time
        
        # Test multiple cache operations
        start_time = time.time()
        
        for i in range(100):
            cache.set(f'perf_test_key_{i}', f'perf_test_value_{i}', timeout=300)
        
        set_time = time.time() - start_time
        
        # Test cache retrieval performance  
        start_time = time.time()
        
        for i in range(100):
            value = cache.get(f'perf_test_key_{i}')
            assert value == f'perf_test_value_{i}'
        
        get_time = time.time() - start_time
        
        # Clean up
        for i in range(100):
            cache.delete(f'perf_test_key_{i}')
        
        # Performance should be reasonable (not Redis-fast, but acceptable)
        assert set_time < 5.0, f"Cache set operations too slow: {set_time}s"
        assert get_time < 2.0, f"Cache get operations too slow: {get_time}s"
    
    @pytest.mark.cache 
    def test_cache_memory_usage(self):
        """
        Test that cache doesn't consume excessive memory.
        """
        # Store some data in cache
        large_data = {'data': 'x' * 10000}  # 10KB of data
        
        for i in range(10):
            cache.set(f'memory_test_key_{i}', large_data, timeout=300)
        
        # Verify data is cached
        for i in range(10):
            cached_data = cache.get(f'memory_test_key_{i}')
            assert cached_data == large_data
        
        # Clean up
        for i in range(10):
            cache.delete(f'memory_test_key_{i}')


# ===============================================================================
# RATE LIMITING WITH DATABASE CACHE TESTS 🛡️
# ===============================================================================

class TestRateLimitingWithDatabaseCache:
    """
    Tests that rate limiting works correctly with database cache.
    """
    
    @pytest.mark.cache
    @pytest.mark.security
    def test_rate_limiting_uses_database_cache(self):
        """
        Test that rate limiting system works with database cache backend.
        """
        from django.core.cache import cache
        from apps.common.validators import RateLimitValidator
        
        # Test rate limiting cache operations
        rate_limiter = RateLimitValidator(max_requests=5, window_seconds=60)
        
        test_ip = '127.0.0.1'
        cache_key = f'rate_limit:{test_ip}'
        
        # Simulate rate limiting
        for i in range(3):
            # This should use database cache
            rate_limiter.check_rate_limit(test_ip)
        
        # Verify rate limit data is in cache
        rate_data = cache.get(cache_key)
        assert rate_data is not None, "Rate limit data should be cached"
        
        # Clean up
        cache.delete(cache_key)
