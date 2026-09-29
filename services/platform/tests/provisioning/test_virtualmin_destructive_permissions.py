"""Destroying customer hosting must require admin, not merely staff.

``virtualmin_account_delete`` permanently destroys a customer's hosting account, and
``virtualmin_account_toggle_protection`` disarms the flag that exists to prevent it.
Both were guarded by a local predicate that reduced to plain ``is_staff_user``, so the
``support`` role could reach them — a role that ``FINANCIAL_STAFF_ROLES`` in
``apps/users/models.py`` deliberately excludes from money operations. The analogous
``deployment_destroy`` in infrastructure is superuser-only.

403 versus 404 is the discriminator. The decorator runs before the view body, so a
blocked caller gets 403 while an allowed caller reaches ``get_object_or_404`` and gets
404 for an account id that does not exist. That distinguishes "refused" from "allowed
through", without building the whole account fixture.
"""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

User = get_user_model()

DESTRUCTIVE_VIEWS = (
    "provisioning:virtualmin_account_delete",
    "provisioning:virtualmin_account_toggle_protection",
)


class VirtualminDestructivePermissionTests(TestCase):
    def setUp(self) -> None:
        self.client = Client()
        self.account_id = uuid.uuid4()
        self.support = User.objects.create_user(
            email="support-agent@test.ro", password="testpass123", is_staff=True, staff_role="support"
        )
        self.billing = User.objects.create_user(
            email="billing-agent@test.ro", password="testpass123", is_staff=True, staff_role="billing"
        )
        self.admin = User.objects.create_user(
            email="admin-agent@test.ro", password="testpass123", is_staff=True, staff_role="admin"
        )

    def _post(self, view_name: str) -> int:
        return self.client.post(reverse(view_name, args=[self.account_id])).status_code

    def test_support_role_cannot_destroy_hosting(self) -> None:
        self.client.force_login(self.support)
        for view_name in DESTRUCTIVE_VIEWS:
            with self.subTest(view=view_name):
                self.assertEqual(
                    self._post(view_name),
                    403,
                    f"{view_name} let a support-role user through",
                )

    def test_billing_role_cannot_destroy_hosting(self) -> None:
        """Any staff role that is not admin must be refused, not just support."""
        self.client.force_login(self.billing)
        for view_name in DESTRUCTIVE_VIEWS:
            with self.subTest(view=view_name):
                self.assertEqual(self._post(view_name), 403)

    def test_admin_role_is_allowed_through_the_gate(self) -> None:
        """404, not 403: the decorator passed and the view looked for the account."""
        self.client.force_login(self.admin)
        for view_name in DESTRUCTIVE_VIEWS:
            with self.subTest(view=view_name):
                self.assertEqual(
                    self._post(view_name),
                    404,
                    f"{view_name} refused an admin; the gate is now too strict",
                )

    def test_the_protection_toggle_is_gated_as_tightly_as_the_delete(self) -> None:
        """The guard and its disarm must not sit at different tiers.

        Anyone who can clear deletion protection can then delete, so a weaker gate on
        the toggle would make the stronger gate on the delete decorative.
        """
        self.client.force_login(self.support)

        delete_status = self._post("provisioning:virtualmin_account_delete")
        toggle_status = self._post("provisioning:virtualmin_account_toggle_protection")

        self.assertEqual(delete_status, toggle_status)
        self.assertEqual(delete_status, 403)
