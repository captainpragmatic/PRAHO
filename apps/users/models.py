"""
User models for PRAHO Platform
Romanian hosting provider authentication with multi-customer support.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, ClassVar

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.db.models import QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

# Cross-app imports for core functionality
from apps.common.encryption import (  # Core encryption needed for user model
    decrypt_sensitive_data,
    encrypt_sensitive_data,
    generate_backup_codes,
    hash_backup_code,
    verify_backup_code,
)
from apps.customers.models import Customer  # Cross-app relationship


class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication"""

    def create_user(self, email: str, password: str | None = None, **extra_fields: Any) -> User:
        """Create and return a regular user with email and password"""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: str | None = None, **extra_fields: Any) -> User:
        """Create and return a superuser with email and password"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Extended user model for Romanian hosting provider.
    Supports both system users (staff) and customer users with hybrid approach.
    """

    # Staff roles for internal staff (nullable for customer users)
    STAFF_ROLE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('admin', _('System Administrator')),
        ('support', _('Support Agent')),
        ('billing', _('Billing Staff')),
        ('manager', _('Manager')),
    )

    # Basic information
    username = None  # Remove username field, using email instead
    email = models.EmailField(_('email address'), unique=True)
    phone = models.CharField(
        max_length=20,
        blank=True,
        help_text=_('Romanian phone number format: +40 721 123 456')
    )

    # Staff role for internal staff users (null for customer users)
    staff_role = models.CharField(
        max_length=20,
        choices=STAFF_ROLE_CHOICES,
        blank=True,
        default='',
        help_text=_('Staff role for internal staff. Leave empty for customer users.')
    )

    # Two-factor authentication
    two_factor_enabled = models.BooleanField(default=False)
    _two_factor_secret = models.CharField(max_length=256, blank=True)  # Encrypted storage
    backup_tokens = models.JSONField(default=list, blank=True)  # Stores hashed backup codes

    # Customer relationships (replaces primary_customer + additional_customers)
    customers = models.ManyToManyField(
        'customers.Customer',
        through='CustomerMembership',
        through_fields=('user', 'customer'),
        related_name='members',
        blank=True
    )

    # Romanian compliance
    accepts_marketing = models.BooleanField(default=False)
    gdpr_consent_date = models.DateTimeField(null=True, blank=True)
    last_privacy_policy_accepted = models.DateTimeField(null=True, blank=True)

    # Login tracking
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_users'
    )

    # Custom manager
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    class Meta:
        db_table = 'users'
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['email']),
            models.Index(fields=['staff_role']),
            models.Index(fields=['is_staff']),
            # 2FA performance indexes with consistent naming
            models.Index(fields=['two_factor_enabled'], name='idx_users_2fa_enabled'),
            models.Index(fields=['two_factor_enabled', 'is_staff'], name='idx_users_2fa_enabled_staff'),
        )

    def __str__(self) -> str:
        return f"{self.get_full_name()} ({self.email})"

    def get_full_name(self) -> str:
        """Get user's full name or email if name not available"""
        full_name = super().get_full_name()
        return full_name if full_name.strip() else self.email

    @property
    def is_staff_user(self) -> bool:
        """Check if user is internal staff"""
        return bool(self.staff_role)

    @property
    def is_customer_user(self) -> bool:
        """Check if user belongs to customer organizations

        🚀 Performance: Uses prefetched customer_memberships if available,
        falls back to database query if not prefetched.
        """
        # Try to use prefetched data first (O(1) if prefetched)
        prefetched_cache = getattr(self, '_prefetched_objects_cache', {})
        if 'customer_memberships' in prefetched_cache:
            return len(prefetched_cache['customer_memberships']) > 0

        # Fallback to database query (O(1) due to exists())
        return CustomerMembership.objects.filter(user=self).exists()

    @property
    def primary_customer(self) -> Customer | None:
        """Get user's primary customer organization

        🚀 Performance: Uses prefetched customer_memberships if available,
        falls back to optimized database query if not prefetched.
        """
        # Try to use prefetched data first (O(N) where N = user's memberships, typically small)
        prefetched_cache = getattr(self, '_prefetched_objects_cache', {})
        if 'customer_memberships' in prefetched_cache:
            for membership in prefetched_cache['customer_memberships']:
                if membership.is_primary:
                    return membership.customer
            return None

        # Fallback to optimized database query (O(1) due to index + select_related)
        membership = CustomerMembership.objects.filter(
            user=self,
            is_primary=True
        ).select_related('customer').first()
        return membership.customer if membership else None


    def get_accessible_customers(self) -> QuerySet[Customer] | list[Customer]:
        """Get all customers this user can access

        🚀 Performance: Uses prefetched customer_memberships if available,
        falls back to optimized database query if not prefetched.
        """
        # Staff can see all customers
        if self.is_staff or self.staff_role:
            return Customer.objects.all()

        # Try to use prefetched data first (O(N) where N = user's memberships)
        prefetched_cache = getattr(self, '_prefetched_objects_cache', {})
        if 'customer_memberships' in prefetched_cache:
            return [membership.customer for membership in prefetched_cache['customer_memberships']]

        # Fallback to optimized database query (O(M) where M = user's customers)
        return Customer.objects.filter(
            memberships__user=self
        ).distinct()

    def can_access_customer(self, customer: Customer) -> bool:
        """Check if user can access specific customer"""
        if self.is_staff or self.staff_role:
            return True

        return CustomerMembership.objects.filter(user=self, customer=customer).exists()

    def get_role_for_customer(self, customer: Customer) -> str | None:
        """Get user's role within specific customer organization"""
        membership = CustomerMembership.objects.filter(user=self, customer=customer).first()
        return membership.role if membership else None

    def is_account_locked(self) -> bool:
        """Check if account is currently locked"""
        if not self.account_locked_until:
            return False

        return timezone.now() < self.account_locked_until

    def increment_failed_login_attempts(self) -> None:
        """Increment failed login attempts and apply progressive lockout"""

        self.failed_login_attempts += 1

        # Progressive lockout delays: 5min → 15min → 30min → 1hr → 2hr → 4hr
        lockout_delays = [5, 15, 30, 60, 120, 240]  # minutes

        if self.failed_login_attempts >= len(lockout_delays):
            # Cap at maximum lockout (4 hours)
            lockout_minutes = lockout_delays[-1]
        else:
            lockout_minutes = lockout_delays[self.failed_login_attempts - 1]

        self.account_locked_until = timezone.now() + timedelta(minutes=lockout_minutes)
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])

    def reset_failed_login_attempts(self) -> None:
        """Reset failed login attempts and unlock account"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save(update_fields=['failed_login_attempts', 'account_locked_until'])

    def get_lockout_remaining_time(self) -> int:
        """Get remaining lockout time in minutes, 0 if not locked"""
        if not self.is_account_locked() or not self.account_locked_until:
            return 0

        remaining = self.account_locked_until - timezone.now()
        return max(0, int(remaining.total_seconds() / 60))

    def clean(self) -> None:
        """Validate user data"""
        super().clean()

    def get_staff_role_display(self) -> str:
        """Get display name for staff role"""
        if not self.staff_role:
            return _('Customer User')

        role_map = {
            'admin': _('System Administrator'),
            'support': _('Support Agent'),
            'billing': _('Billing Staff'),
            'manager': _('Manager'),
        }

        return role_map.get(self.staff_role, self.staff_role)

    # Two-factor authentication properties
    @property
    def two_factor_secret(self) -> str:
        """Get decrypted 2FA secret"""
        if not self._two_factor_secret:
            return ''

        return decrypt_sensitive_data(self._two_factor_secret)

    @two_factor_secret.setter
    def two_factor_secret(self, value: str) -> None:
        """Set encrypted 2FA secret"""
        if value:
            self._two_factor_secret = encrypt_sensitive_data(value)
        else:
            self._two_factor_secret = ''  # nosec B105

    def generate_backup_codes(self) -> list[str]:
        """Generate new backup codes and store hashed versions"""
        # Generate plain text codes
        codes = generate_backup_codes(count=8)

        # Store hashed versions
        hashed_codes = [hash_backup_code(code) for code in codes]
        self.backup_tokens = hashed_codes
        self.save(update_fields=['backup_tokens'])

        # Return plain text codes for user to save (only time they see them)
        return codes

    def verify_backup_code(self, code: str) -> bool:
        """Verify and consume a backup code"""
        for i, hashed_code in enumerate(self.backup_tokens):
            if verify_backup_code(code, hashed_code):
                # Remove used backup code
                self.backup_tokens.pop(i)
                self.save(update_fields=['backup_tokens'])
                return True

        return False

    def has_backup_codes(self) -> bool:
        """Check if user has unused backup codes"""
        return len(self.backup_tokens) > 0


class CustomerMembership(models.Model):
    """
    Junction table for user-customer relationships with roles.
    Aligns with PostgreSQL customer_membership table.
    """

    # PostgreSQL-aligned role choices
    CUSTOMER_ROLE_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('owner', _('Owner')),         # Full control of customer organization
        ('billing', _('Billing')),     # Invoices, payments, billing info
        ('tech', _('Technical')),      # Service management, support tickets
        ('viewer', _('Viewer')),       # Read-only access
    )

    customer = models.ForeignKey(
        'customers.Customer',
        on_delete=models.CASCADE,
        related_name='memberships'
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='customer_memberships'  # Use consistent related name
    )

    # Role within this customer organization
    role = models.CharField(
        max_length=20,
        choices=CUSTOMER_ROLE_CHOICES,
        help_text=_('User role within this customer organization')
    )

    # Primary customer flag (replaces User.primary_customer)
    is_primary = models.BooleanField(
        default=False,
        help_text=_('Primary customer for this user (used for default context)')
    )

    # ===============================================================================
    # NOTIFICATION PREFERENCES (Enhanced CustomerMembership)
    # ===============================================================================

    # Email Notifications
    email_billing = models.BooleanField(
        default=True,
        verbose_name=_('Email billing notifications')
    )
    email_technical = models.BooleanField(
        default=True,
        verbose_name=_('Email technical notifications')
    )
    email_marketing = models.BooleanField(
        default=False,
        verbose_name=_('Email marketing notifications')
    )

    # Notification Language
    notification_language = models.CharField(
        max_length=5,
        choices=[('ro', 'Română'), ('en', 'English')],
        default='ro',
        verbose_name=_('Notification language')
    )

    # Contact preferences
    preferred_contact_method = models.CharField(
        max_length=20,
        choices=[
            ('email', _('Email')),
            ('phone', _('Phone')),
            ('both', _('Email and phone')),
        ],
        default='email',
        verbose_name=_('Preferred contact method')
    )

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='granted_memberships'
    )

    class Meta:
        db_table = 'customer_membership'  # Match PostgreSQL schema
        unique_together: ClassVar[tuple[tuple[str, ...], ...]] = (('customer', 'user'),)
        verbose_name = _('Customer Membership')
        verbose_name_plural = _('Customer Memberships')
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['user', 'is_primary']),      # Fast primary lookup
            models.Index(fields=['customer', 'role']),        # Role-based queries
            models.Index(fields=['user', 'created_at']),      # User history
        )

    def __str__(self) -> str:
        primary_flag = " (Primary)" if self.is_primary else ""
        return f"{self.user.email} → {self.customer.name} ({self.get_role_display()}){primary_flag}"

    def get_role_display(self) -> str:
        """Get role display"""
        role_map = {
            'owner': _('Owner'),
            'billing': _('Billing'),
            'tech': _('Technical'),
            'viewer': _('Viewer'),
        }
        return role_map.get(self.role, self.role)


# Remove the old UserCustomerAccess model - will be handled by migration
# This will be replaced by CustomerMembership above


class UserProfile(models.Model):
    """Extended user profile information"""

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )

    # Language specific
    preferred_language = models.CharField(
        max_length=5,
        choices=[('en', _('English')), ('ro', _('Romanian'))],
        default='en'
    )

    # Preferences
    timezone = models.CharField(max_length=50, default='Europe/Bucharest')
    date_format = models.CharField(
        max_length=20,
        choices=[
            ('%d.%m.%Y', 'DD.MM.YYYY'),
            ('%Y-%m-%d', 'YYYY-MM-DD'),
        ],
        default='%d.%m.%Y'
    )

    # Notifications
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=False)
    marketing_emails = models.BooleanField(default=False)

    # Emergency contact
    emergency_contact_name = models.CharField(max_length=100, blank=True)
    emergency_contact_phone = models.CharField(max_length=20, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_profiles'
        verbose_name = _('User Profile')
        verbose_name_plural = _('User Profiles')

    def __str__(self) -> str:
        return f"Profile for {self.user.email}"


class UserLoginLog(models.Model):
    """Track user login attempts for security"""

    LOGIN_STATUS_CHOICES: ClassVar[tuple[tuple[str, str], ...]] = (
        ('success', _('Success')),
        ('failed_password', _('Failed Password')),
        ('failed_2fa', _('Failed 2FA')),
        ('failed_user_not_found', _('Failed User Not Found')),
        ('account_locked', _('Account Locked')),
        ('account_disabled', _('Account Disabled')),
        ('password_reset_completed', _('Password Reset Completed')),
        ('account_lockout_reset', _('Account Lockout Reset')),
        ('password_reset_failed', _('Password Reset Failed')),
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='login_logs',
        null=True # Allow null for failed logins of non-existent users
    )

    # Login details
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    status = models.CharField(max_length=30, choices=LOGIN_STATUS_CHOICES)

    # Geographic info (optional)
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)

    class Meta:
        db_table = 'user_login_logs'
        verbose_name = _('User Login Log')
        verbose_name_plural = _('User Login Logs')
        indexes: ClassVar[tuple[models.Index, ...]] = (
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['status', 'timestamp']),
        )

    def __str__(self) -> str:
        user_display = self.user.email if self.user else "Unknown User"
        return f"{user_display} - {self.status} at {self.timestamp}"


# Import MFA models to ensure they're recognized by Django
