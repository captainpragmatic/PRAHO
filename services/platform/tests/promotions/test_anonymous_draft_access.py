"""H12: Anonymous users must not access draft orders they don't own."""
from unittest.mock import MagicMock

from django.http import HttpRequest
from django.test import SimpleTestCase

from apps.promotions.views import _user_can_access_order


class AnonymousDraftOrderAccessTests(SimpleTestCase):
    """H12: _user_can_access_order must deny anonymous access to unowned drafts."""

    def _make_anonymous_request(self) -> HttpRequest:
        request = HttpRequest()
        request.user = MagicMock(is_authenticated=False)
        return request

    def test_anonymous_cannot_access_draft_order(self) -> None:
        """Anonymous user MUST NOT access any draft order without session binding."""
        order = MagicMock()
        order.status = "draft"
        request = self._make_anonymous_request()

        self.assertFalse(
            _user_can_access_order(request, order),
            "Anonymous users should not access draft orders without session binding",
        )

    def test_anonymous_cannot_access_non_draft_order(self) -> None:
        """Anonymous user MUST NOT access non-draft orders."""
        order = MagicMock()
        order.status = "awaiting_payment"
        request = self._make_anonymous_request()

        self.assertFalse(_user_can_access_order(request, order))
