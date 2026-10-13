"""Staff 2FA keeps neither the setup secret nor recovery codes in the session (#689).

The session row lives in the database for as long as the session does. The setup secret now
waits in a pending enrolment of its own, and new recovery codes are shown once, in the
response to the request that made them, and stored nowhere.
"""

from __future__ import annotations

import pyotp
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from apps.users.models import User
from apps.users.pending_totp import PendingTOTPEnrolment

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
SETUP_URL = "/auth/mfa/setup/totp/"


def _sessions_hold(fragment: str) -> bool:
    return any(fragment in str(session.get_decoded()) for session in Session.objects.all())


class WebTOTPEnrolmentStorageTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="storage@example.ro", password=PASSWORD, staff_role="support")
        self.client.force_login(self.user)

    def _enrol(self) -> tuple[str, object]:
        secret = self.client.get(SETUP_URL).context["secret"]
        response = self.client.post(SETUP_URL, {"token": pyotp.TOTP(secret).now(), "password": PASSWORD})
        return secret, response

    def test_the_setup_secret_waits_in_a_pending_enrolment_not_the_session(self) -> None:
        secret = self.client.get(SETUP_URL).context["secret"]

        self.assertNotIn("2fa_secret", self.client.session)
        self.assertFalse(_sessions_hold(secret))
        self.assertEqual(PendingTOTPEnrolment.objects.get(user=self.user).secret(), secret)

    def test_recovery_codes_are_shown_in_the_response_and_stored_nowhere(self) -> None:
        _secret, response = self._enrol()

        self.assertEqual(response.status_code, 200)
        codes = response.context["backup_codes"]
        self.assertEqual(len(codes), 8)
        for code in codes:
            self.assertContains(response, code)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertNotIn("new_backup_codes", self.client.session)
        self.assertFalse(any(_sessions_hold(code) for code in codes))
        self.assertFalse(PendingTOTPEnrolment.objects.filter(user=self.user).exists())

    def test_regenerated_codes_are_shown_in_the_response_and_stored_nowhere(self) -> None:
        self._enrol()
        self.user.refresh_from_db()
        response = self.client.post(
            reverse("users:mfa_regenerate_backup_codes"),
            {"password": PASSWORD, "token": self.user.generate_backup_codes()[0], "confirm_regenerate": "on"},
        )

        self.assertEqual(response.status_code, 200)
        codes = response.context["backup_codes"]
        self.assertEqual(len(codes), 8)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertNotIn("new_backup_codes", self.client.session)
        self.assertFalse(any(_sessions_hold(code) for code in codes))

    def test_the_old_codes_page_no_longer_reads_anything(self) -> None:
        # Codes left in a session by the old flow are not shown by the old page.
        session = self.client.session
        session["new_backup_codes"] = ["LEFTOVER1", "LEFTOVER2"]
        session.save()
        response = self.client.get(reverse("users:mfa_backup_codes"), follow=True)
        self.assertRedirects(response, reverse("users:user_profile"))
        self.assertNotContains(response, "LEFTOVER1")
