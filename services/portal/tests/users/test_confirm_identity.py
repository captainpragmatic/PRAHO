"""The confirm page asks for the password, and the code when 2FA is on, then goes back.

Every signed-in role reaches it, and whether it asks for a code is read from Platform each time,
never from what login saw. Only a wrong password or code spends the person's re-auth budget: an
outage, a throttle or a timeout never does. It goes back only to a page on this site.
"""

from __future__ import annotations

import re
from datetime import timedelta
from http.cookies import SimpleCookie
from typing import Any
from unittest.mock import patch

from django.contrib.sessions.backends.cache import SessionStore
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.api_client.services import PlatformAPIError

SESSION_ID = "6f1c2a0e-8a5b-4d0c-9a77-0d4b3c2e1f00"
SETTINGS = {
    "SESSION_ENGINE": "django.contrib.sessions.backends.cache",
    "CACHES": {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "confirm"}},
    "RATE_LIMITING_ENABLED": True,
}
PATH = "/confirm-identity/"
PLATFORM = "apps.users.views.api_client"


def _failed(code: str, status: int = 400) -> PlatformAPIError:
    return PlatformAPIError("refused", status_code=status, response_data={"success": False, "code": code})


@override_settings(**SETTINGS)
class ConfirmIdentityTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.sign_in(role="owner")

    def sign_in(self, *, role: str) -> None:
        now = timezone.now()
        session = self.client.session
        session.update(
            {
                "user_id": 42,
                "customer_id": 7,
                "active_customer_id": 7,
                "email": "user@example.com",
                "session_auth_hash": "stored",
                "portal_session_id": SESSION_ID,
                "authenticated_at": now.isoformat(),
                "session_created_at": now.isoformat(),
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
                "user_memberships": [{"customer_id": 7, "customer_name": "Acme", "role": role}],
                "user_memberships_fetched_at": now.timestamp(),
                "selected_customer_role": role,
            }
        )
        session.save()

    def get(self, *, two_factor: bool, **query: str) -> Any:
        with patch(PLATFORM) as platform:
            platform.get_mfa_status.return_value = {
                "success": True,
                "enabled": two_factor,
                "backup_codes_remaining": 2 if two_factor else 0,
            }
            return self.client.get(PATH, query)

    def post(self, fields: dict[str, str], *, answer: Any = None, next_url: str = "/billing/") -> Any:
        with patch(PLATFORM) as platform:
            platform.get_mfa_status.return_value = {"success": True, "enabled": "token" in fields}
            if isinstance(answer, Exception):
                platform.confirm_identity.side_effect = answer
            else:
                platform.confirm_identity.return_value = answer or {"success": True}
            response = self.client.post(f"{PATH}?next={next_url}", fields)
            self.calls = platform.confirm_identity.call_args_list
        return response

    def test_it_asks_for_the_code_only_when_two_factor_is_on(self) -> None:
        self.assertContains(self.get(two_factor=True), 'name="token"')
        self.assertNotContains(self.get(two_factor=False), 'name="token"')
        self.assertContains(self.get(two_factor=False), 'name="password"')

    def test_when_two_factor_is_unknown_the_code_is_optional(self) -> None:
        with patch(PLATFORM) as platform:
            platform.get_mfa_status.side_effect = PlatformAPIError("down", status_code=503, is_unavailable=True)
            page = self.client.get(PATH)
            self.assertContains(page, 'name="token"')
            platform.confirm_identity.return_value = {"success": True}
            response = self.client.post(f"{PATH}?next=/billing/", {"password": "secret-1"})
        self.assertRedirects(response, "/billing/", fetch_redirect_response=False)
        self.assertEqual(platform.confirm_identity.call_args.args, (42, "secret-1", ""))

    def test_a_copy_of_the_cookie_does_not_share_the_window_the_person_opened(self) -> None:
        # Someone holding a copy of this browser's cookie must not ride the check its owner passes.
        copy = self.client_class()
        copy.cookies = SimpleCookie({name: morsel.value for name, morsel in self.client.cookies.items()})
        before = self.client.session.session_key
        response = self.post({"password": "secret-1"})
        self.assertRedirects(response, "/billing/", fetch_redirect_response=False)
        self.assertNotEqual(self.client.session.session_key, before)  # the person's browser has a new key
        self.assertEqual(self.client.session["portal_session_id"], SESSION_ID)  # the same Platform session
        self.assertNotIn("user_id", copy.session)  # the copied key no longer signs anyone in

    def test_the_key_turns_before_platform_is_asked_and_the_new_window_lives_only_under_it(self) -> None:
        old_key = self.client.session.session_key
        seen: list[bool] = []

        def confirm(*args: object) -> dict[str, object]:
            # The old key is gone before Platform opens the window, so a second submit of it loses first.
            seen.append(SessionStore().exists(old_key))
            return {"success": True, "step_up_at": "2026-10-29T18:00:00.123456+00:00"}

        with patch(PLATFORM) as platform:
            platform.confirm_identity.side_effect = confirm
            response = self.client.post(f"{PATH}?next=/billing/", {"password": "secret-1"})
        self.assertRedirects(response, "/billing/", fetch_redirect_response=False)
        self.assertEqual(seen, [False])
        self.assertEqual(self.client.session["step_up_at"], "2026-10-29T18:00:00.123456+00:00")
        self.assertFalse(SessionStore().exists(old_key))

    def test_the_confirm_button_submits_once(self) -> None:
        page = self.get(two_factor=False).content.decode()
        self.assertIn("data-submit-once", page)

    def test_the_cursor_starts_in_the_password(self) -> None:
        page = self.get(two_factor=True).content.decode()
        password = re.search(r"<input[^>]*name=\"password\"[^>]*>", page).group(0)
        token = re.search(r"<input[^>]*name=\"token\"[^>]*>", page).group(0)
        self.assertIn("autofocus", password)
        self.assertNotIn("autofocus", token)

    def test_an_answer_costs_one_call_to_platform(self) -> None:
        with patch(PLATFORM) as platform:
            platform.confirm_identity.return_value = {"success": True}
            self.client.post(f"{PATH}?next=/billing/", {"password": "secret-1"})
        platform.get_mfa_status.assert_not_called()  # Platform decides what the answer needs
        platform.confirm_identity.assert_called_once()

    def test_it_warns_when_backup_codes_run_low(self) -> None:
        self.assertContains(self.get(two_factor=True), "You have 2 backup codes left.")

    def test_every_role_can_confirm(self) -> None:
        for role in ("owner", "billing", "tech", "viewer"):
            with self.subTest(role=role):
                self.sign_in(role=role)
                self.assertEqual(self.get(two_factor=False).status_code, 200)

    def test_a_right_answer_goes_back_to_the_page(self) -> None:
        response = self.post({"password": "secret-1"}, next_url="/billing/gift-cards/abc/")
        self.assertRedirects(response, "/billing/gift-cards/abc/", fetch_redirect_response=False)
        self.assertEqual(self.calls[0].args, (42, "secret-1", ""))

    def test_it_goes_back_only_to_a_page_on_this_site(self) -> None:
        for target in ("//evil.example/", "https://evil.example/", "javascript:alert(1)", ""):
            with self.subTest(next=target):
                response = self.post({"password": "secret-1"}, next_url=target)
                self.assertRedirects(response, "/dashboard/", fetch_redirect_response=False)

    def test_a_wrong_answer_is_said_once_and_spends_the_budget(self) -> None:
        response = self.post({"password": "wrong"}, answer=_failed("reauth_failed"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "password or code is not right")
        for _ in range(4):
            self.post({"password": "wrong"}, answer=_failed("reauth_failed"))
        throttled = self.post({"password": "right"}, next_url="/billing/")
        self.assertEqual(self.calls, [])  # never reached Platform
        self.assertRedirects(throttled, f"{PATH}?next=/billing/", fetch_redirect_response=False)

    def test_an_outage_throttle_or_timeout_spends_nothing(self) -> None:
        outages = [
            PlatformAPIError("down", status_code=503, is_unavailable=True),
            PlatformAPIError("slow", is_unavailable=True),
            PlatformAPIError("throttled", status_code=429, is_rate_limited=True),
            _failed("not_found", status=404),
        ]
        for _ in range(2):
            for answer in outages:
                self.assertEqual(self.post({"password": "right"}, answer=answer).status_code, 200)
        response = self.post({"password": "right"}, next_url="/billing/")
        self.assertRedirects(response, "/billing/", fetch_redirect_response=False)

    def test_a_locked_account_is_told_so(self) -> None:
        response = self.post({"password": "right"}, answer=_failed("account_locked"))
        self.assertContains(response, "Too many attempts. Please wait and try again.")
