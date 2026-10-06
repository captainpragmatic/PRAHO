"""The settings sweep's staff login, driven against a live server.

`scripts/qa_settings_sweep.py` logs in over HTTP and then trusts every result that follows. It used to
"prove" the login with `session.get("/settings/").status_code == 200`. `requests` follows redirects, and
an anonymous request for `/settings/` redirects to the login page, which answers 200. So a wrong password
passed. So did an account whose login stopped at the second factor, and every key then failed later with
an unrelated-looking JSON error. These tests drive the real login views over a real socket, because the
defect lived in what a redirect-following client sees, which a test client would not reproduce.
"""

from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pyotp
import requests
from django.core.cache import cache
from django.test import LiveServerTestCase

from apps.users.mfa import TOTPService
from apps.users.models import User

_SCRIPTS_DIR = str(Path(__file__).resolve().parents[4] / "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

import qa_sweep_auth  # noqa: E402
from qa_sweep_auth import LoginFailedError, login  # noqa: E402

# Generated per run: a password literal here would be flagged by the repository's secret scanner.
PASSWORD = secrets.token_urlsafe(16)


class SweepLoginTests(LiveServerTestCase):
    def setUp(self) -> None:
        cache.clear()  # login rate limits, the TOTP replay marker and the MFA attempt budget live here
        self.addCleanup(cache.clear)
        self.session = requests.Session()
        self.addCleanup(self.session.close)

    def make_staff(self, email: str, *, enrolled: bool) -> tuple[User, str]:
        user = User.objects.create_user(email=email, password=PASSWORD, is_staff=True, staff_role="admin")
        secret = TOTPService.generate_secret()
        if enrolled:
            user.two_factor_secret = secret
            user.two_factor_enabled = True
            user.save()
        return user, secret

    def assert_has_staff_session(self) -> None:
        response = self.session.get(f"{self.live_server_url}/settings/", allow_redirects=False)
        self.assertEqual(response.status_code, 200, msg=f"no staff session: {response.headers.get('Location')}")

    def test_a_correct_password_logs_in(self) -> None:
        self.make_staff("plain@example.ro", enrolled=False)
        login(self.session, self.live_server_url, "plain@example.ro", PASSWORD)
        self.assert_has_staff_session()

    def test_a_wrong_password_raises(self) -> None:
        self.make_staff("plain@example.ro", enrolled=False)
        with self.assertRaises(LoginFailedError):
            login(self.session, self.live_server_url, "plain@example.ro", "not-the-password")

    def test_an_enrolled_account_without_a_secret_raises_and_says_why(self) -> None:
        self.make_staff("totp@example.ro", enrolled=True)
        with self.assertRaisesRegex(LoginFailedError, "two-factor"):
            login(self.session, self.live_server_url, "totp@example.ro", PASSWORD)

    def test_an_enrolled_account_logs_in_with_its_totp_secret(self) -> None:
        _user, secret = self.make_staff("totp@example.ro", enrolled=True)
        login(self.session, self.live_server_url, "totp@example.ro", PASSWORD, totp_secret=secret)
        self.assert_has_staff_session()

    def test_a_wrong_code_raises(self) -> None:
        _user, secret = self.make_staff("totp@example.ro", enrolled=True)
        # A deterministic wrong code: one that is not valid for the enrolled secret in the current
        # window or either neighbour the verifier accepts. A random second secret would collide
        # with it about once in 330,000 runs.
        totp = pyotp.TOTP(secret)
        valid = {totp.at(time.time() + offset) for offset in (-totp.interval, 0, totp.interval)}
        wrong = next(code for code in ("000000", "111111", "222222", "333333") if code not in valid)
        # Only the sweep's own pyotp is replaced; the server still verifies with the real one.
        stub = SimpleNamespace(TOTP=lambda _secret: SimpleNamespace(interval=totp.interval, now=lambda: wrong))
        with patch.object(qa_sweep_auth, "pyotp", stub), self.assertRaises(LoginFailedError):
            login(self.session, self.live_server_url, "totp@example.ro", PASSWORD, totp_secret=secret)
