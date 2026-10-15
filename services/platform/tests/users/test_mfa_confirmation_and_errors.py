"""Staff 2FA pages: the confirmation is enforced on the server, and each error is shown once (#689).

- Disabling 2FA and regenerating backup codes each ask the person to tick that they understand
  what happens. Only the browser enforced it: a request without the box went through.
- The disable, regenerate and sign-in-code pages showed every error twice: once as the toast
  every page shows, and again in a list of the same messages inside the form.
"""

from __future__ import annotations

import pyotp
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from apps.users.mfa import TOTPService
from apps.users.models import User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
INCORRECT = "The password or the code is incorrect."


class StaffMFAPagesTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        # A customer-role account: staff_role would make 2FA mandatory and refuse disabling.
        self.user = User.objects.create_user(email="pages@example.ro", password=PASSWORD, is_staff=True)
        self.secret = TOTPService.generate_secret()
        self.user.two_factor_secret = self.secret
        self.user.two_factor_enabled = True
        self.user.save()
        self.codes = self.user.generate_backup_codes()
        self.client.force_login(self.user)

    def test_disabling_without_the_confirmation_changes_nothing(self) -> None:
        response = self.client.post(reverse("users:mfa_disable"), {"password": PASSWORD, "token": self.codes[0]})
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertEqual(len(self.user.backup_tokens), 8)  # the code offered was not spent

    def test_disabling_with_the_confirmation_works(self) -> None:
        response = self.client.post(
            reverse("users:mfa_disable"), {"password": PASSWORD, "token": self.codes[0], "confirm_disable": "on"}
        )
        self.assertEqual(response.status_code, 302)
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)

    def test_regenerating_without_the_confirmation_changes_nothing(self) -> None:
        before = list(self.user.backup_tokens)
        response = self.client.post(
            reverse("users:mfa_regenerate_backup_codes"), {"password": PASSWORD, "token": self.codes[0]}
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.backup_tokens, before)

    def test_regenerating_with_the_confirmation_works(self) -> None:
        response = self.client.post(
            reverse("users:mfa_regenerate_backup_codes"),
            {"password": PASSWORD, "token": self.codes[0], "confirm_regenerate": "on"},
        )
        self.assertEqual(len(response.context["backup_codes"]), 8)

    def test_each_error_is_shown_once(self) -> None:
        wrong = {"password": "not-the-password", "token": pyotp.TOTP(self.secret).now()}
        for url, confirm in (
            (reverse("users:mfa_disable"), "confirm_disable"),
            (reverse("users:mfa_regenerate_backup_codes"), "confirm_regenerate"),
        ):
            with self.subTest(url=url):
                response = self.client.post(url, {**wrong, confirm: "on"})
                self.assertContains(response, INCORRECT, count=1)

    def test_the_sign_in_code_page_shows_its_error_once(self) -> None:
        self.client.logout()
        self.user.staff_role = "support"
        self.user.save(update_fields=["staff_role"])
        self.client.post(reverse("users:login"), {"email": self.user.email, "password": PASSWORD})
        response = self.client.post(reverse("users:mfa_verify"), {"token": "000000"}, follow=True)
        self.assertContains(response, "The 2FA code or backup code is invalid.", count=1)
