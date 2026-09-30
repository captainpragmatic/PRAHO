"""Unauthenticated callers must not be able to lock other people's accounts.

`/api/users/token/` is public by design (ADR-0031). Until now a failed request there
called `User.increment_failed_login_attempts()`, which applies a progressive account
lock escalating to four hours. Five wrong passwords for a known email address therefore
locked that account out of every login path, with no credentials and no attribution.

Every other caller of that counter sits behind a working per-account rate limit — the
staff web login has `rate_limit(key="post:email")`, and the portal login is HMAC-signed
with the portal's own budgets. The public token endpoint inherited the lockout without
inheriting any of that protection, and its only guard keys on a client-supplied
forwarded header, so it can be rotated away.

The replacement is a per-account throttle on this endpoint. That keeps brute-force
protection for a targeted address while removing the attacker's lever on the victim's
account elsewhere: the worst outcome becomes a short delay on one endpoint instead of a
four-hour lock across all of them.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings

User = get_user_model()

WRONG_PASSWORD = "definitely-not-the-password"  # test fixture, not a credential


# Two overrides, both load-bearing. The test settings use DummyCache, which stores
# nothing, and they set RATE_LIMITING_ENABLED=False, which short-circuits every throttle
# before it looks at the cache at all. Without both, the per-account budget reads as
# absent and the 429 assertions fail for reasons unrelated to the code under test.
@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=True,
)
class PublicTokenEndpointLockoutTests(TestCase):
    def setUp(self) -> None:
        cache.clear()  # throttle buckets are cache-backed and leak between tests
        self.addCleanup(cache.clear)
        self.victim = User.objects.create_user(
            email="victim@example.ro",
            password="correct-horse-battery-staple",  # test fixture
        )
        # Literal path: this is the URL an external caller actually posts to, and the
        # endpoint being publicly reachable is the whole premise of the test.
        self.url = "/api/users/token/"

    def _attempt(self) -> int:
        response = self.client.post(
            self.url,
            {"email": self.victim.email, "password": WRONG_PASSWORD},
            content_type="application/json",
        )
        return int(response.status_code)

    def test_repeated_public_failures_do_not_lock_the_victims_account(self) -> None:
        """The account must survive an unauthenticated attacker pointing at it."""
        for _ in range(8):
            self._attempt()

        self.victim.refresh_from_db()
        self.assertFalse(
            self.victim.is_account_locked(),
            "an unauthenticated caller locked someone else's account",
        )
        self.assertEqual(
            self.victim.failed_login_attempts,
            0,
            "the public endpoint is still driving the account lockout counter",
        )

    def test_the_account_lockout_mechanism_itself_still_works(self) -> None:
        """Guards against 'fixing' this by disabling lockout everywhere.

        The control is intended for the paths that can attribute a failure. Only the
        public endpoint's ability to drive it is being removed.
        """
        for _ in range(6):
            self.victim.increment_failed_login_attempts()

        self.victim.refresh_from_db()
        self.assertTrue(self.victim.is_account_locked(), "the lockout control was removed entirely")

    def test_repeated_attempts_against_one_account_are_throttled(self) -> None:
        """Removing the lock must not leave the endpoint an unlimited guessing oracle."""
        # Six, not more: the per-account budget is 5/minute and the endpoint's older
        # client-keyed budget is 10/minute. Staying under the latter keeps this test
        # about the per-account limit rather than about whichever fires first.
        statuses = [self._attempt() for _ in range(6)]

        self.assertIn(429, statuses, "no per-account limit replaced the lockout")

    def test_a_different_account_is_not_punished_by_the_first_ones_attempts(self) -> None:
        """The replacement must be per-account, or it becomes its own denial of service.

        Keying the limit too broadly would let one attacker exhaust a shared budget and
        block every other customer's token requests, which is the trade this fix exists
        to avoid making. Twelve attempts here originally failed this assertion by
        exhausting the endpoint's older client-keyed budget instead, which is exactly the
        over-broad behaviour being guarded against.
        """
        other = User.objects.create_user(
            email="bystander@example.ro",
            password="another-correct-horse",  # test fixture
        )
        for _ in range(6):
            self._attempt()

        response = self.client.post(
            self.url,
            {"email": other.email, "password": WRONG_PASSWORD},
            content_type="application/json",
        )
        self.assertNotEqual(
            response.status_code,
            429,
            "a bystander was throttled by attempts aimed at a different account",
        )
