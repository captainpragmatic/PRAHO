# ===============================================================================
# INFRASTRUCTURE PERMISSIONS TESTS
# ===============================================================================
"""
Tests for Infrastructure app permissions and access control.

Covers:
- Permission check functions
- Permission decorators
- Role-based access control
"""

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.test import RequestFactory, TestCase

from apps.infrastructure.permissions import (
    PERM_DEPLOY_NODES,
    PERM_DESTROY_NODES,
    PERM_MANAGE_DEPLOYMENTS,
    PERM_MANAGE_PROVIDERS,
    PERM_VIEW_INFRASTRUCTURE,
    can_deploy_nodes,
    can_destroy_nodes,
    can_manage_deployments,
    can_manage_providers,
    can_manage_regions,
    can_manage_sizes,
    can_view_infrastructure,
    require_deploy_permission,
    require_deployment_management,
    require_destroy_permission,
    require_infrastructure_view,
)

User = get_user_model()


class PermissionCheckTests(TestCase):
    """Tests for permission check functions"""

    def setUp(self):
        self.regular_user = User.objects.create_user(
            email="regular@test.com",
            password="testpass123",
        )
        self.staff_user = User.objects.create_user(
            email="staff@test.com",
            password="testpass123",
            is_staff=True,
        )
        self.superuser = User.objects.create_superuser(
            email="super@test.com",
            password="testpass123",
        )

    # =========================================================================
    # can_view_infrastructure tests
    # =========================================================================

    def test_view_infrastructure_superuser(self):
        """Superuser can view infrastructure"""
        self.assertTrue(can_view_infrastructure(self.superuser))

    def test_view_infrastructure_staff(self):
        """Staff can view infrastructure"""
        self.assertTrue(can_view_infrastructure(self.staff_user))

    def test_view_infrastructure_regular_user(self):
        """Regular user cannot view infrastructure by default"""
        self.assertFalse(can_view_infrastructure(self.regular_user))

    def test_view_infrastructure_anonymous(self):
        """Anonymous user cannot view infrastructure"""
        from django.contrib.auth.models import AnonymousUser

        anon = AnonymousUser()
        self.assertFalse(can_view_infrastructure(anon))

    # =========================================================================
    # can_manage_deployments tests
    # =========================================================================

    def test_manage_deployments_superuser(self):
        """Superuser can manage deployments"""
        self.assertTrue(can_manage_deployments(self.superuser))

    def test_manage_deployments_staff(self):
        """Staff can manage deployments"""
        self.assertTrue(can_manage_deployments(self.staff_user))

    def test_manage_deployments_regular_user(self):
        """Regular user cannot manage deployments by default"""
        self.assertFalse(can_manage_deployments(self.regular_user))

    # =========================================================================
    # can_deploy_nodes tests
    # =========================================================================

    def test_deploy_nodes_superuser(self):
        """Superuser can deploy nodes"""
        self.assertTrue(can_deploy_nodes(self.superuser))

    def test_deploy_nodes_staff_without_perm(self):
        """Staff without permission cannot deploy nodes"""
        self.assertFalse(can_deploy_nodes(self.staff_user))

    def test_deploy_nodes_regular_user(self):
        """Regular user cannot deploy nodes"""
        self.assertFalse(can_deploy_nodes(self.regular_user))

    # =========================================================================
    # can_destroy_nodes tests
    # =========================================================================

    def test_destroy_nodes_superuser(self):
        """Superuser can destroy nodes"""
        self.assertTrue(can_destroy_nodes(self.superuser))

    def test_destroy_nodes_staff_without_perm(self):
        """Staff without permission cannot destroy nodes"""
        self.assertFalse(can_destroy_nodes(self.staff_user))

    def test_destroy_nodes_regular_user(self):
        """Regular user cannot destroy nodes"""
        self.assertFalse(can_destroy_nodes(self.regular_user))

    # =========================================================================
    # can_manage_providers tests
    # =========================================================================

    def test_manage_providers_superuser(self):
        """Superuser can manage providers"""
        self.assertTrue(can_manage_providers(self.superuser))

    def test_manage_providers_staff_without_perm(self):
        """Staff without permission cannot manage providers"""
        self.assertFalse(can_manage_providers(self.staff_user))

    def test_manage_providers_regular_user(self):
        """Regular user cannot manage providers"""
        self.assertFalse(can_manage_providers(self.regular_user))

    # =========================================================================
    # can_manage_sizes tests
    # =========================================================================

    def test_manage_sizes_superuser(self):
        """Superuser can manage sizes"""
        self.assertTrue(can_manage_sizes(self.superuser))

    def test_manage_sizes_staff_without_perm(self):
        """Staff without permission cannot manage sizes"""
        self.assertFalse(can_manage_sizes(self.staff_user))

    # =========================================================================
    # can_manage_regions tests
    # =========================================================================

    def test_manage_regions_superuser(self):
        """Superuser can manage regions"""
        self.assertTrue(can_manage_regions(self.superuser))

    def test_manage_regions_staff_without_perm(self):
        """Staff without permission cannot manage regions"""
        self.assertFalse(can_manage_regions(self.staff_user))


class PermissionDecoratorTests(TestCase):
    """Tests for permission decorators"""

    def setUp(self):
        self.factory = RequestFactory()
        self.regular_user = User.objects.create_user(
            email="regular@test.com",
            password="testpass123",
        )
        self.superuser = User.objects.create_superuser(
            email="super@test.com",
            password="testpass123",
        )

    def _get_request(self, user):
        """Create a request with the given user"""
        request = self.factory.get("/test/")
        request.user = user
        return request

    # =========================================================================
    # require_infrastructure_view tests
    # =========================================================================

    def test_require_infrastructure_view_allows_superuser(self):
        """Decorator allows superuser access"""

        @require_infrastructure_view
        def test_view(request):
            return "success"

        request = self._get_request(self.superuser)
        result = test_view(request)
        self.assertEqual(result, "success")

    def test_require_infrastructure_view_denies_regular_user(self):
        """Decorator denies regular user access"""

        @require_infrastructure_view
        def test_view(request):
            return "success"

        request = self._get_request(self.regular_user)
        with self.assertRaises(PermissionDenied):
            test_view(request)

    # =========================================================================
    # require_deploy_permission tests
    # =========================================================================

    def test_require_deploy_permission_allows_superuser(self):
        """Decorator allows superuser to deploy"""

        @require_deploy_permission
        def test_view(request):
            return "success"

        request = self._get_request(self.superuser)
        result = test_view(request)
        self.assertEqual(result, "success")

    def test_require_deploy_permission_denies_regular_user(self):
        """Decorator denies regular user deploy access"""

        @require_deploy_permission
        def test_view(request):
            return "success"

        request = self._get_request(self.regular_user)
        with self.assertRaises(PermissionDenied):
            test_view(request)

    # =========================================================================
    # require_destroy_permission tests
    # =========================================================================

    def test_require_destroy_permission_allows_superuser(self):
        """Decorator allows superuser to destroy"""

        @require_destroy_permission
        def test_view(request):
            return "success"

        request = self._get_request(self.superuser)
        result = test_view(request)
        self.assertEqual(result, "success")

    def test_require_destroy_permission_denies_regular_user(self):
        """Decorator denies regular user destroy access"""

        @require_destroy_permission
        def test_view(request):
            return "success"

        request = self._get_request(self.regular_user)
        with self.assertRaises(PermissionDenied):
            test_view(request)

    # =========================================================================
    # require_deployment_management tests
    # =========================================================================

    def test_require_deployment_management_allows_superuser(self):
        """Decorator allows superuser to manage deployments"""

        @require_deployment_management
        def test_view(request):
            return "success"

        request = self._get_request(self.superuser)
        result = test_view(request)
        self.assertEqual(result, "success")

    def test_require_deployment_management_denies_regular_user(self):
        """Decorator denies regular user management access"""

        @require_deployment_management
        def test_view(request):
            return "success"

        request = self._get_request(self.regular_user)
        with self.assertRaises(PermissionDenied):
            test_view(request)
