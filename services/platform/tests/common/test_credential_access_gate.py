"""#271: only superusers and admin-role staff may decrypt vault credentials.

Decrypting infrastructure secrets (Virtualmin/SSH/cloud keys) is an admin capability,
not a general-staff one — so support/billing/manager roles, and a bare `is_staff` flag
with no admin role, are denied. System/task access (user=None) stays allowed.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.common.credential_vault import CredentialVault

User = get_user_model()


class CredentialAccessGateTests(TestCase):
    def setUp(self) -> None:
        self.vault = CredentialVault()
        self.credential = MagicMock()  # the gate never consults the credential itself

    def _allowed(self, **user_fields: object) -> bool:
        # Unsaved User instances — the gate only reads attributes, no DB needed.
        return self.vault._check_credential_access_permission(self.credential, User(**user_fields))

    def test_superuser_allowed(self) -> None:
        self.assertTrue(self._allowed(is_superuser=True))

    def test_admin_role_allowed(self) -> None:
        self.assertTrue(self._allowed(staff_role="admin"))

    def test_support_role_denied(self) -> None:
        self.assertFalse(self._allowed(staff_role="support"))

    def test_billing_role_denied(self) -> None:
        self.assertFalse(self._allowed(staff_role="billing"))

    def test_bare_is_staff_flag_denied(self) -> None:
        # A plain is_staff=True user with no admin role no longer decrypts secrets (#271 tightening).
        self.assertFalse(self._allowed(is_staff=True))

    def test_plain_customer_denied(self) -> None:
        self.assertFalse(self._allowed())

    def test_system_access_allowed(self) -> None:
        self.assertTrue(self.vault._check_credential_access_permission(self.credential, None))
