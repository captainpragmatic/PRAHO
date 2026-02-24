"""
E2E Dynamic Test User Management — create/cleanup test users and organizations.

Thread-safe user creation with guaranteed cleanup via context managers and atexit.
"""

import atexit
import os
import secrets
import string
import threading
from contextlib import contextmanager
from typing import Any, ClassVar

import django
from django.contrib.auth import get_user_model
from django.db import transaction
from playwright.sync_api import Page

from tests.e2e.helpers.auth import login_user


class E2EUserManager:
    """
    Comprehensive test user management system for PRAHO's E2E tests.

    Features:
    - Dynamic user creation with random credentials
    - Customer organization creation and relationships
    - Guaranteed cleanup using context managers and atexit handlers
    - Thread-safe operations
    - Proper error handling and logging
    - Integration with existing login utilities

    Usage:
        with TestUserManager() as user_mgr:
            admin = user_mgr.create_admin_user()
            customer_user, customer_org = user_mgr.create_customer_with_org()
            # Test logic here...
            # Automatic cleanup on context exit
    """

    __test__ = False

    _created_users: ClassVar[set[str]] = set()
    _created_customers: ClassVar[set[int]] = set()
    _cleanup_registered = False
    _lock = threading.Lock()

    def __init__(self):
        self._session_users: list[str] = []
        self._session_customers: list[int] = []
        self._django_initialized = False

        # Register global cleanup on first instance
        with self._lock:
            if not E2EUserManager._cleanup_registered:
                atexit.register(self._global_cleanup)
                E2EUserManager._cleanup_registered = True

    def _ensure_django_setup(self) -> None:
        """Ensure Django is properly configured"""
        if self._django_initialized:
            return

        try:
            # Set Django settings module for tests
            os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')
            django.setup()
            self._django_initialized = True
            print("✅ Django initialized for test user management")
        except Exception as e:
            print(f"❌ Failed to initialize Django: {e}")
            raise

    def _generate_random_email(self, prefix: str = "test") -> str:
        """Generate a random test email address"""
        random_suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        return f"{prefix}_{random_suffix}@test.praho.local"

    def _generate_random_password(self, length: int = 12) -> str:
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def _generate_random_company_name(self) -> str:
        """Generate a random Romanian company name"""
        prefixes = ["Tech", "Web", "Digital", "Smart", "Pro", "Expert", "Prima", "Nova"]
        suffixes = ["Solutions", "Systems", "Services", "Consulting", "Tech", "Software"]
        random_prefix = secrets.choice(prefixes)
        random_suffix = secrets.choice(suffixes)
        random_num = secrets.randbelow(999) + 1
        return f"{random_prefix} {random_suffix} {random_num} SRL"

    def create_admin_user(self, email: str | None = None, password: str | None = None) -> dict[str, str]:
        """
        Create a random admin/superuser.

        Args:
            email: Optional email (random if not provided)
            password: Optional password (random if not provided)

        Returns:
            dict: User credentials with email, password, and type

        Example:
            admin = user_mgr.create_admin_user()
            assert login_user(page, admin['email'], admin['password'])
        """
        self._ensure_django_setup()

        email = email or self._generate_random_email("admin")
        password = password or self._generate_random_password()

        try:
            with transaction.atomic():
                User = get_user_model()  # noqa: N806

                # Check if user already exists
                if User.objects.filter(email=email).exists():
                    raise ValueError(f"User with email {email} already exists")

                user = User.objects.create_superuser(
                    email=email,
                    password=password,
                    first_name="Test",
                    last_name="Admin",
                    is_active=True,
                    staff_role="admin"
                )

                # Track created user
                with self._lock:
                    E2EUserManager._created_users.add(email)
                    self._session_users.append(email)

                print(f"✅ Created admin user: {email}")
                return {
                    'email': email,
                    'password': password,
                    'type': 'admin',
                    'user_id': user.id
                }

        except Exception as e:
            print(f"❌ Failed to create admin user: {e}")
            raise

    def create_customer_with_org(self,
                               email: str | None = None,
                               password: str | None = None,
                               company_name: str | None = None) -> tuple[dict[str, str], dict[str, Any]]:
        """
        Create a customer user with associated organization.

        Args:
            email: Optional email (random if not provided)
            password: Optional password (random if not provided)
            company_name: Optional company name (random if not provided)

        Returns:
            tuple: (user_credentials_dict, customer_org_dict)

        Example:
            customer_user, customer_org = user_mgr.create_customer_with_org()
            assert login_user(page, customer_user['email'], customer_user['password'])
        """
        self._ensure_django_setup()

        email = email or self._generate_random_email("customer")
        password = password or self._generate_random_password()
        company_name = company_name or self._generate_random_company_name()

        try:
            with transaction.atomic():
                User = get_user_model()  # noqa: N806
                from apps.customers.models import Customer  # noqa: PLC0415
                from apps.users.models import CustomerMembership  # noqa: PLC0415

                # Check if user already exists
                if User.objects.filter(email=email).exists():
                    raise ValueError(f"User with email {email} already exists")

                # Create customer user
                user = User.objects.create_user(
                    email=email,
                    password=password,
                    first_name="Test",
                    last_name="Customer",
                    is_active=True
                )

                # Create customer organization
                customer = Customer.objects.create(
                    name=f"Test Customer {company_name[:20]}",
                    customer_type='company',
                    company_name=company_name,
                    status='active',
                    primary_email=email,
                    primary_phone='+40712345678',
                    industry='Technology',
                    data_processing_consent=True,
                    marketing_consent=False
                )

                # Create membership relationship
                CustomerMembership.objects.create(
                    user=user,
                    customer=customer,
                    role='owner',
                    is_primary=True,
                    created_by=user
                )

                # Track created resources
                with self._lock:
                    E2EUserManager._created_users.add(email)
                    E2EUserManager._created_customers.add(customer.id)
                    self._session_users.append(email)
                    self._session_customers.append(customer.id)

                print(f"✅ Created customer user: {email} with organization: {company_name}")

                return {
                    'email': email,
                    'password': password,
                    'type': 'customer',
                    'user_id': user.id
                }, {
                    'id': customer.id,
                    'name': customer.name,
                    'company_name': company_name,
                    'email': email,
                    'phone': customer.primary_phone
                }

        except Exception as e:
            print(f"❌ Failed to create customer with organization: {e}")
            raise

    def create_staff_user(self,
                         role: str = 'support',
                         email: str | None = None,
                         password: str | None = None) -> dict[str, str]:
        """
        Create a staff user with specific role.

        Args:
            role: Staff role ('admin', 'support', 'billing', 'manager')
            email: Optional email (random if not provided)
            password: Optional password (random if not provided)

        Returns:
            dict: User credentials with email, password, type, and role
        """
        self._ensure_django_setup()

        valid_roles = ['admin', 'support', 'billing', 'manager']
        if role not in valid_roles:
            raise ValueError(f"Invalid staff role: {role}. Must be one of {valid_roles}")

        email = email or self._generate_random_email(f"staff_{role}")
        password = password or self._generate_random_password()

        try:
            with transaction.atomic():
                User = get_user_model()  # noqa: N806

                # Check if user already exists
                if User.objects.filter(email=email).exists():
                    raise ValueError(f"User with email {email} already exists")

                user = User.objects.create_user(
                    email=email,
                    password=password,
                    first_name="Test",
                    last_name=role.title(),
                    is_active=True,
                    is_staff=True,
                    staff_role=role
                )

                # Track created user
                with self._lock:
                    E2EUserManager._created_users.add(email)
                    self._session_users.append(email)

                print(f"✅ Created staff user ({role}): {email}")
                return {
                    'email': email,
                    'password': password,
                    'type': 'staff',
                    'role': role,
                    'user_id': user.id
                }

        except Exception as e:
            print(f"❌ Failed to create staff user: {e}")
            raise

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """
        Get user information by email.

        Args:
            email: User email to look up

        Returns:
            dict: User information or None if not found
        """
        self._ensure_django_setup()

        try:
            User = get_user_model()  # noqa: N806
            user = User.objects.filter(email=email).first()

            if not user:
                return None

            return {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
                'staff_role': getattr(user, 'staff_role', ''),
                'is_active': user.is_active
            }

        except Exception as e:
            print(f"❌ Failed to get user by email {email}: {e}")
            return None

    def cleanup_session_users(self) -> None:
        """Clean up users and customers created in this session"""
        if not self._django_initialized:
            return

        print(f"🧹 Cleaning up {len(self._session_users)} session users and {len(self._session_customers)} organizations...")

        try:
            with transaction.atomic():
                User = get_user_model()  # noqa: N806
                from apps.customers.models import Customer  # noqa: PLC0415

                # Clean up customers first (due to foreign key constraints)
                for customer_id in self._session_customers:
                    try:
                        customer = Customer.objects.filter(id=customer_id).first()
                        if customer:
                            customer.delete()  # Hard delete for tests
                            print(f"  🗑️ Deleted customer: {customer_id}")
                    except Exception as e:
                        print(f"  ⚠️ Failed to delete customer {customer_id}: {e}")

                # Clean up users
                for email in self._session_users:
                    try:
                        user = User.objects.filter(email=email).first()
                        if user:
                            user.delete()  # Hard delete for tests
                            print(f"  🗑️ Deleted user: {email}")
                    except Exception as e:
                        print(f"  ⚠️ Failed to delete user {email}: {e}")

                # Remove from global tracking before clearing session lists
                with self._lock:
                    for email in self._session_users:
                        E2EUserManager._created_users.discard(email)
                    for customer_id in self._session_customers:
                        E2EUserManager._created_customers.discard(customer_id)

                # Clear session tracking
                self._session_users.clear()
                self._session_customers.clear()

                print("✅ Session cleanup completed")

        except Exception as e:
            print(f"❌ Session cleanup failed: {e}")

    @classmethod
    def _global_cleanup(cls) -> None:
        """Global cleanup called by atexit handler"""
        if not cls._created_users and not cls._created_customers:
            return

        print(f"🧹 Global cleanup: {len(cls._created_users)} users, {len(cls._created_customers)} customers")

        try:
            # Set Django settings if not already done
            os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')
            django.setup()

            with transaction.atomic():
                User = get_user_model()  # noqa: N806
                from apps.customers.models import Customer  # noqa: PLC0415

                # Clean up customers first
                for customer_id in list(cls._created_customers):
                    try:
                        customer = Customer.objects.filter(id=customer_id).first()
                        if customer:
                            customer.delete()
                    except Exception:  # noqa: S110
                        pass  # Silent cleanup

                # Clean up users
                for email in list(cls._created_users):
                    try:
                        user = User.objects.filter(email=email).first()
                        if user:
                            user.delete()
                    except Exception:  # noqa: S110
                        pass  # Silent cleanup

            print("✅ Global cleanup completed")

        except Exception as e:
            print(f"❌ Global cleanup failed: {e}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with guaranteed cleanup"""
        self.cleanup_session_users()


TestUserManager = E2EUserManager
TestUserManager.__test__ = False


@contextmanager
def test_users(*user_specs):
    """
    Convenient context manager for creating multiple test users.

    Args:
        *user_specs: Tuples of (user_type, **kwargs) where user_type is 'admin', 'customer', or 'staff'

    Yields:
        list: Created user credentials

    Example:
        with test_users(('admin',), ('customer',), ('staff', {'role': 'billing'})) as (admin, customer, staff):
            assert login_user(page, admin['email'], admin['password'])
            # Test logic...
            # Automatic cleanup
    """
    with E2EUserManager() as user_mgr:
        created_users = []

        for spec in user_specs:
            if isinstance(spec, str):
                user_type = spec
                kwargs = {}
            else:
                user_type = spec[0]
                kwargs = spec[1] if len(spec) > 1 else {}

            if user_type == 'admin':
                user = user_mgr.create_admin_user(**kwargs)
                created_users.append(user)
            elif user_type == 'customer':
                user, org = user_mgr.create_customer_with_org(**kwargs)
                created_users.append((user, org))
            elif user_type == 'staff':
                user = user_mgr.create_staff_user(**kwargs)
                created_users.append(user)
            else:
                raise ValueError(f"Unknown user type: {user_type}")

        yield created_users


# ===============================================================================
# ENHANCED LOGIN UTILITIES WITH TEST USER INTEGRATION
# ===============================================================================

def login_test_user(page: Page, user_credentials: dict[str, str]) -> bool:
    """
    Login using test user credentials from TestUserManager.

    Args:
        page: Playwright page object
        user_credentials: User credentials dict from TestUserManager

    Returns:
        bool: True if login successful

    Example:
        with TestUserManager() as user_mgr:
            admin = user_mgr.create_admin_user()
            assert login_test_user(page, admin)
    """
    return login_user(page, user_credentials['email'], user_credentials['password'])


def create_and_login_admin(page: Page, user_mgr: E2EUserManager) -> dict[str, str]:
    """
    Create admin user and login in one step.

    Args:
        page: Playwright page object
        user_mgr: TestUserManager instance

    Returns:
        dict: Admin user credentials

    Example:
        with TestUserManager() as user_mgr:
            admin = create_and_login_admin(page, user_mgr)
            # Admin is now logged in
    """
    admin = user_mgr.create_admin_user()

    if not login_test_user(page, admin):
        raise Exception(f"Failed to login admin user: {admin['email']}")

    print(f"✅ Created and logged in admin: {admin['email']}")
    return admin


def create_and_login_customer(page: Page, user_mgr: E2EUserManager) -> tuple[dict[str, str], dict[str, Any]]:
    """
    Create customer user with organization and login in one step.

    Args:
        page: Playwright page object
        user_mgr: TestUserManager instance

    Returns:
        tuple: (customer_credentials, customer_org)

    Example:
        with TestUserManager() as user_mgr:
            customer_user, customer_org = create_and_login_customer(page, user_mgr)
            # Customer is now logged in with access to their organization
    """
    customer_user, customer_org = user_mgr.create_customer_with_org()

    if not login_test_user(page, customer_user):
        raise Exception(f"Failed to login customer user: {customer_user['email']}")

    print(f"✅ Created and logged in customer: {customer_user['email']} for org: {customer_org['company_name']}")
    return customer_user, customer_org
