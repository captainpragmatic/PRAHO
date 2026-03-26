"""H15: Default object permission must deny, not allow."""

from unittest.mock import MagicMock

from django.http import HttpRequest
from django.test import SimpleTestCase

from apps.api.core.permissions import IsAuthenticatedAndAccessible


class DefaultObjectPermissionTests(SimpleTestCase):
    """H15: has_object_permission must return False by default."""

    def test_has_object_permission_denies_by_default(self) -> None:
        perm = IsAuthenticatedAndAccessible()
        request = HttpRequest()
        request.user = MagicMock(is_authenticated=True)
        view = MagicMock()
        obj = MagicMock()
        result = perm.has_object_permission(request, view, obj)
        self.assertFalse(result, "Default object permission must deny access")

    def test_has_permission_still_allows_authenticated(self) -> None:
        perm = IsAuthenticatedAndAccessible()
        request = HttpRequest()
        request.user = MagicMock(is_authenticated=True)
        view = MagicMock()
        result = perm.has_permission(request, view)
        self.assertTrue(result)
