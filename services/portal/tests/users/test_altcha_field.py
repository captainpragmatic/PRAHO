"""The public forms' proof-of-work accepts each solution once (apps.common.altcha).

A solution is refused when it was accepted before, in any encoding; when its challenge expired, is
not signed by this service or has no expiry; when it is far longer than a solution can be; and in
the widget's test mode. The challenge endpoint answers only while the feature is on, and limits each
client IP.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from pathlib import Path
from unittest.mock import patch

from altcha import Challenge, Payload, create_challenge, solve_challenge
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.common import altcha
from apps.users.forms import CustomerRegistrationForm, PasswordResetRequestForm

FAST = {"ALTCHA_ENABLED": True, "ALTCHA_COST": 1, "ALTCHA_EXPIRY_SECONDS": 600}
REPO_ROOT = Path(__file__).resolve().parents[4]
VENDOR = REPO_ROOT / "services/portal/static/js/vendor/altcha"


def solve(challenge: dict) -> Payload:
    parsed = Challenge.from_dict(challenge)
    solution = solve_challenge(parsed)
    assert solution is not None
    return Payload(parsed, solution)


def solved() -> str:
    return solve(altcha.new_challenge()).to_base64()


@override_settings(**FAST)
class AcceptSolutionTests(TestCase):
    def test_replayed_reencoded_concurrent_or_oversized_solution_is_rejected(self) -> None:
        payload = solve(altcha.new_challenge())
        first = payload.to_base64()
        # The same challenge and solution, serialised another way: other bytes, the same signature.
        reencoded = base64.b64encode(json.dumps(payload.to_dict(), indent=2, sort_keys=True).encode()).decode()
        self.assertNotEqual(first, reencoded)

        self.assertTrue(altcha.accept_solution(first))
        self.assertFalse(altcha.accept_solution(first), "a replayed solution is refused")
        self.assertFalse(altcha.accept_solution(reencoded), "a re-encoded copy is the same solution")

        with patch.object(altcha.Payload, "from_base64") as decode:
            self.assertFalse(altcha.accept_solution("A" * (altcha.MAX_PAYLOAD_LENGTH + 1)))
        decode.assert_not_called()

    def test_an_expired_challenge_is_refused(self) -> None:
        with override_settings(ALTCHA_EXPIRY_SECONDS=-1):
            payload = solved()
        self.assertFalse(altcha.accept_solution(payload))

    def test_a_challenge_without_expiry_is_refused_even_when_signed_here(self) -> None:
        challenge = create_challenge(altcha.ALGORITHM, 1, hmac_secret=altcha._signing_secret())
        self.assertFalse(altcha.accept_solution(solve(challenge.to_dict()).to_base64()))

    def test_a_challenge_signed_elsewhere_is_refused(self) -> None:
        challenge = create_challenge(altcha.ALGORITHM, 1, expires_at=int(time.time()) + 600, hmac_secret="another")
        self.assertFalse(altcha.accept_solution(solve(challenge.to_dict()).to_base64()))

    def test_the_widgets_test_mode_and_junk_are_refused(self) -> None:
        test_mode = base64.b64encode(json.dumps({"challenge": None, "solution": None, "test": True}).encode()).decode()
        for payload in (test_mode, "", "not base64 at all", base64.b64encode(b"[]").decode()):
            with self.subTest(payload=payload[:20]):
                self.assertFalse(altcha.accept_solution(payload))


class AltchaFormFieldTests(TestCase):
    def test_the_field_exists_only_while_the_feature_is_on(self) -> None:
        for form_class in (CustomerRegistrationForm, PasswordResetRequestForm):
            with self.subTest(form=form_class.__name__):
                with override_settings(ALTCHA_ENABLED=False):
                    self.assertNotIn("altcha", form_class().fields)
                with override_settings(ALTCHA_ENABLED=True):
                    self.assertIn("altcha", form_class().fields)

    @override_settings(**FAST)
    def test_a_missing_or_spent_solution_is_a_form_error(self) -> None:
        payload = solved()
        self.assertTrue(PasswordResetRequestForm(data={"email": "a@example.com", "altcha": payload}).is_valid())
        for data in ({"email": "a@example.com"}, {"email": "a@example.com", "altcha": payload}):
            with self.subTest(sent="altcha" in data):
                form = PasswordResetRequestForm(data=data)
                self.assertFalse(form.is_valid())
                self.assertEqual(form.errors["altcha"], [str(altcha.VERIFICATION_FAILED)])


class ChallengeEndpointTests(TestCase):
    url = "/altcha/challenge/"

    @override_settings(ALTCHA_ENABLED=False)
    def test_absent_while_the_feature_is_off(self) -> None:
        self.assertEqual(self.client.get(self.url).status_code, 404)

    @override_settings(**FAST)
    def test_an_anonymous_visitor_gets_a_signed_uncached_challenge(self) -> None:
        self.assertEqual(reverse("altcha_challenge"), self.url)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-cache", response["Cache-Control"])
        challenge = response.json()
        self.assertEqual(challenge["parameters"]["algorithm"], altcha.ALGORITHM)
        self.assertTrue(altcha.accept_solution(solve(challenge).to_base64()))

    @override_settings(**FAST, RATE_LIMITING_ENABLED=True)
    def test_each_client_ip_has_a_budget(self) -> None:
        from apps.common.views import ALTCHA_CHALLENGES_PER_MINUTE  # noqa: PLC0415

        for _ in range(ALTCHA_CHALLENGES_PER_MINUTE):
            self.assertEqual(self.client.get(self.url).status_code, 200)
        refused = self.client.get(self.url)
        self.assertEqual(refused.status_code, 429)
        self.assertEqual(refused["Retry-After"], "60")


class VendoredWidgetTests(TestCase):
    def test_the_vendored_files_are_the_upstream_bytes_notice_records(self) -> None:
        notice = (REPO_ROOT / "NOTICE.md").read_text()
        recorded = dict(re.findall(r"`([\w.]+)` \(dist/\w+\) — ([0-9a-f]{64})", notice))
        self.assertEqual(set(recorded), {"altcha.min.js", "altcha.css", "pbkdf2.js", "ro.js"})
        for name, digest in recorded.items():
            with self.subTest(file=name):
                self.assertEqual(hashlib.sha256((VENDOR / name).read_bytes()).hexdigest(), digest)
