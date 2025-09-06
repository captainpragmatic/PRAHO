# Portal Test Suite

This directory contains unit tests for the Portal service.

## Structure

- `users/` - User authentication and API client tests
- `api_client/` - Platform API integration tests  
- `integration/` - Cross-app integration tests

## Running Tests

```bash
# From portal service directory
python manage.py test

# Run specific test module
python manage.py test tests.users.test_api_client_hmac

# Run with coverage
coverage run --source='.' manage.py test
coverage report
```

## Test Philosophy

Portal tests focus on:
- ✅ API client functionality (HMAC authentication)
- ✅ Session management
- ✅ Platform API integration
- ✅ Error handling and edge cases

Portal does NOT test business logic (that's in Platform).
