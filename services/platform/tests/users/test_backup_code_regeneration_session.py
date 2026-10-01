"""Regenerating 2FA backup codes rotates the acting session's key (#555).

Enabling and disabling 2FA cycle the session key; regeneration did not, so the key the
browser held before the change kept working after it. Regeneration is deliberately NOT a
credential change: codes are spent in ordinary use, they are not part of the session
auth hash, and the credential version stays put. So only the acting session rotates,
matching the portal's regeneration view. Signing out other sessions would need a
credential bump to be reliable, because index-based revocation alone misses sessions an
old worker left unindexed.
"""

from __future__ import annotations

from django.contrib.sessions.backends.base import SessionBase
from django.test import Client, TestCase
from django.urls import reverse

from apps.users.models import User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


class BackupCodeRegenerationSessionTests(TestCase):
    def setUp(self) -> None:
        self.user = User.objects.create_user(email="codes@example.ro", password=PASSWORD)
        self.user.two_factor_enabled = True
        self.user.save()
        self.acting = Client()
        self.acting.force_login(self.user)
        self.other = Client()
        self.other.force_login(self.user)

    def session_key(self, client: Client) -> str:
        session: SessionBase = client.session
        return str(session.session_key)

    def is_signed_in(self, client: Client) -> bool:
        return client.get(reverse("users:user_profile")).status_code == 200

    def test_post_cycles_the_acting_session_key(self) -> None:
        before = self.session_key(self.acting)

        response = self.acting.post(reverse("users:mfa_regenerate_backup_codes"))

        self.assertRedirects(response, reverse("users:mfa_backup_codes"), fetch_redirect_response=False)
        self.assertNotEqual(self.session_key(self.acting), before, "the acting session key was not cycled")
        self.assertTrue(self.is_signed_in(self.acting), "regeneration signed the acting user out")
        # The new codes are shown on the next page; cycling the key must carry them over.
        self.assertEqual(len(self.acting.session["new_backup_codes"]), 8)

    def test_other_sessions_are_left_alone(self) -> None:
        other_key = self.session_key(self.other)
        self.acting.post(reverse("users:mfa_regenerate_backup_codes"))
        self.assertEqual(self.session_key(self.other), other_key)
        self.assertTrue(self.is_signed_in(self.other))

    def test_get_does_not_rotate(self) -> None:
        before = self.session_key(self.acting)
        self.assertEqual(self.acting.get(reverse("users:mfa_regenerate_backup_codes")).status_code, 200)
        self.assertEqual(self.session_key(self.acting), before)
        self.assertTrue(self.is_signed_in(self.other))
