"""A lock is never extended by failures that were already in flight when it was set.

Concurrent failed logins each check "is the account locked?" before any of them takes the row
lock, so all of them can pass that check. The first to reach the row-locked increment sets the
lock; without a second look under the row lock, every request queued behind it would count again
and push the lock further out, turning one burst into a much longer lockout. Anyone who knows an
address could use that to keep the account locked.
"""

from __future__ import annotations

from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.users.models import User

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential


@override_settings(ACCOUNT_LOCKOUT_THRESHOLD=5, DISABLE_ACCOUNT_LOCKOUT=False)
class LockNotExtendedByStaleCallersTests(TestCase):
    def test_a_failure_that_saw_the_account_unlocked_does_not_extend_a_new_lock(self) -> None:
        user = User.objects.create_user(email="stale-caller@example.test", password=PASSWORD)
        stale = User.objects.get(pk=user.pk)  # loaded, and checked unlocked, before the lock was set
        locked_until = timezone.now() + timedelta(minutes=5)
        User.objects.filter(pk=user.pk).update(failed_login_attempts=5, account_locked_until=locked_until)

        stale.increment_failed_login_attempts()

        stored = User.objects.get(pk=user.pk)
        self.assertEqual(stored.failed_login_attempts, 5)
        self.assertEqual(stored.account_locked_until, locked_until)
        self.assertTrue(stale.is_account_locked())  # the caller sees the lock that is in force

    def test_an_unlocked_account_still_counts_and_locks_at_the_threshold(self) -> None:
        user = User.objects.create_user(email="still-counts@example.test", password=PASSWORD)
        for _ in range(5):
            User.objects.get(pk=user.pk).increment_failed_login_attempts()
        stored = User.objects.get(pk=user.pk)
        self.assertEqual(stored.failed_login_attempts, 5)
        self.assertTrue(stored.is_account_locked())
