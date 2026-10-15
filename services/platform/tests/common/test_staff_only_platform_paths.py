"""StaffOnlyPlatformMiddleware exempts only paths that are really mounted (#689).

`/admin/` was exempt for a Django admin that is not mounted, so the exemption only
waited for something to appear at that path to open it to customer accounts.
"""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

User = get_user_model()

_WITH_STAFF_ONLY = [
    *settings.MIDDLEWARE,
    "apps.common.middleware.StaffOnlyPlatformMiddleware",
]


@override_settings(MIDDLEWARE=_WITH_STAFF_ONLY)
class StaffOnlyPlatformPathsTests(TestCase):
    def test_a_customer_account_is_turned_away_from_admin_paths(self) -> None:
        customer = User.objects.create_user(email="customer@example.com", password="x-pass-123")
        self.client.force_login(customer)

        response = self.client.get("/admin/anything/")

        self.assertRedirects(response, "/auth/login/", fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_staff_still_reach_admin_paths_unchanged(self) -> None:
        staff = User.objects.create_user(
            email="staff@example.com", password="x-pass-123", is_staff=True, staff_role="support"
        )
        self.client.force_login(staff)

        # Nothing is mounted there: staff get the ordinary 404.
        self.assertEqual(self.client.get("/admin/anything/").status_code, 404)
