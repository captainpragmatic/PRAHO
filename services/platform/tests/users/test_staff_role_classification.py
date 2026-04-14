"""
Tests for staff role classification fixes (#150).

Covers:
- is_staff_user property for all user types
- create_superuser defaults staff_role="admin"
- create_user rejects invalid staff_role values
- _determine_comment_type for superusers
- _validate_internal_note_permission for superusers
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.db import SessionStore
from django.test import RequestFactory, TestCase, override_settings

from apps.tickets.views import _determine_comment_type, _validate_internal_note_permission

User = get_user_model()


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class IsStaffUserPropertyTests(TestCase):
    """Test the is_staff_user property correctly identifies all staff types."""

    def test_user_with_staff_role_is_staff_user(self):
        user = User.objects.create_user(email="support@test.com", password="test123", staff_role="support")
        self.assertTrue(user.is_staff_user)

    def test_user_with_admin_role_is_staff_user(self):
        user = User.objects.create_user(email="admin@test.com", password="test123", staff_role="admin")
        self.assertTrue(user.is_staff_user)

    def test_superuser_with_empty_role_is_staff_user(self):
        """Superusers must be recognized as staff even without a staff_role."""
        user = User.objects.create_user(
            email="super@test.com", password="test123", is_superuser=True, is_staff=True
        )
        # Override the default staff_role="admin" that create_superuser sets —
        # test the property directly with empty role
        user.staff_role = ""
        user.save()
        self.assertTrue(user.is_staff_user)

    def test_django_is_staff_flag_makes_staff_user(self):
        """Users with is_staff=True but no staff_role should still be staff."""
        user = User.objects.create_user(email="djstaff@test.com", password="test123")
        user.is_staff = True
        user.save()
        self.assertTrue(user.is_staff_user)

    def test_customer_user_is_not_staff_user(self):
        user = User.objects.create_user(email="customer@test.com", password="test123")
        self.assertFalse(user.is_staff_user)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertEqual(user.staff_role, "")


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class CreateSuperuserTests(TestCase):
    """Test create_superuser defaults and behavior."""

    def test_create_superuser_defaults_staff_role_admin(self):
        user = User.objects.create_superuser(email="super@test.com", password="test123")
        self.assertEqual(user.staff_role, "admin")
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff_user)

    def test_create_superuser_respects_explicit_staff_role(self):
        user = User.objects.create_superuser(
            email="super2@test.com", password="test123", staff_role="manager"
        )
        self.assertEqual(user.staff_role, "manager")


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class CreateUserValidationTests(TestCase):
    """Test create_user rejects invalid staff_role values."""

    def test_reject_staff_role_customer(self):
        with self.assertRaises(ValueError) as ctx:
            User.objects.create_user(
                email="bad@test.com", password="test123", staff_role="customer"
            )
        self.assertIn("Invalid staff_role", str(ctx.exception))
        self.assertIn("customer", str(ctx.exception))

    def test_reject_arbitrary_staff_role(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(
                email="bad2@test.com", password="test123", staff_role="hacker"
            )

    def test_accept_valid_staff_roles(self):
        for role in ("admin", "support", "billing", "manager"):
            user = User.objects.create_user(
                email=f"{role}@test.com", password="test123", staff_role=role
            )
            self.assertEqual(user.staff_role, role)

    def test_accept_empty_staff_role(self):
        user = User.objects.create_user(email="empty@test.com", password="test123", staff_role="")
        self.assertEqual(user.staff_role, "")

    def test_accept_none_staff_role_defaults_to_empty(self):
        user = User.objects.create_user(email="none@test.com", password="test123")
        self.assertEqual(user.staff_role, "")


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class DetermineCommentTypeTests(TestCase):
    """Test _determine_comment_type handles superusers correctly."""

    def test_superuser_gets_support_comment_type(self):
        user = User.objects.create_superuser(email="super@test.com", password="test123")
        self.assertEqual(_determine_comment_type(user, is_internal=False), "support")

    def test_superuser_gets_internal_comment_type(self):
        user = User.objects.create_superuser(email="super@test.com", password="test123")
        self.assertEqual(_determine_comment_type(user, is_internal=True), "internal")

    def test_customer_gets_customer_comment_type(self):
        user = User.objects.create_user(email="cust@test.com", password="test123")
        self.assertEqual(_determine_comment_type(user, is_internal=False), "customer")

    def test_support_agent_gets_support_comment_type(self):
        user = User.objects.create_user(email="agent@test.com", password="test123", staff_role="support")
        self.assertEqual(_determine_comment_type(user, is_internal=False), "support")


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class ValidateInternalNotePermissionTests(TestCase):
    """Test _validate_internal_note_permission allows superusers."""

    def test_superuser_can_create_internal_notes(self):
        user = User.objects.create_superuser(email="super@test.com", password="test123")
        request = RequestFactory().post("/")
        request.user = user
        result = _validate_internal_note_permission(request, user, is_internal=True, ticket_pk=1)
        self.assertIsNone(result)

    def test_customer_cannot_create_internal_notes(self):
        user = User.objects.create_user(email="cust@test.com", password="test123")
        request = RequestFactory().post("/")
        request.user = user
        request.session = SessionStore()
        request._messages = FallbackStorage(request)
        result = _validate_internal_note_permission(request, user, is_internal=True, ticket_pk=1)
        self.assertIsNotNone(result)
