"""
E2E Test Constants — URLs, credentials, and configuration.

All URL and credential constants used across E2E tests.
"""

import os

# Portal (customer-facing) at :8701
BASE_URL = os.environ.get("PORTAL_BASE_URL", "http://localhost:8701")

# Auth URL paths for Portal service
LOGIN_URL = "/login/"
LOGOUT_URL = "/logout/"
REGISTER_URL = "/register/"

# Platform (staff backend) at :8700
PLATFORM_BASE_URL = os.environ.get("PLATFORM_BASE_URL", "http://localhost:8700")
PLATFORM_LOGIN_URL = "/auth/login/"
PLATFORM_LOGOUT_URL = "/auth/logout/"

# Test user credentials - using dedicated E2E users
SUPERUSER_EMAIL = "e2e-admin@test.local"
SUPERUSER_PASSWORD = "test123"
CUSTOMER_EMAIL = "e2e-customer@test.local"
CUSTOMER_PASSWORD = "test123"

# Legacy credentials (keep for compatibility)
LEGACY_SUPERUSER_EMAIL = "admin@pragmatichost.com"
LEGACY_SUPERUSER_PASSWORD = "admin123"
LEGACY_CUSTOMER_EMAIL = "customer@pragmatichost.com"
LEGACY_CUSTOMER_PASSWORD = "admin123"
CUSTOMER2_EMAIL = "customer2@pragmatichost.com"
CUSTOMER2_PASSWORD = "admin123"

# Staff credentials for platform (reuse E2E admin)
STAFF_EMAIL = SUPERUSER_EMAIL
STAFF_PASSWORD = SUPERUSER_PASSWORD


def is_login_url(url: str) -> bool:
    """Check if URL is a login page"""
    return "/login/" in url and "/logout/" not in url


def is_logged_in_url(url: str) -> bool:
    """Check if URL indicates successful login (user is in authenticated area)"""
    return any(path in url for path in ["/app/", "/dashboard/", "/customers/", "/billing/", "/tickets/", "/infrastructure/"])
