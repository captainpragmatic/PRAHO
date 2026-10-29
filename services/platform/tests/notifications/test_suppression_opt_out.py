"""A marketing opt-out is kept apart from delivery blocks.

One suppression row held one reason, and each new reason replaced the old one. An unsubscribe
over a bounce let security notices reach a bounced address, and a temporary block over an
unsubscribe took the opt-out with it when it expired, so marketing resumed with no new consent.
The opt-out is now its own field: an unsubscribe never touches a block, a block never touches
the opt-out, and only a live block stops essential mail.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.db.models.query import QuerySet
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.notifications.models import EmailSuppression
from apps.notifications.services import EmailSuppressionService
from config.settings.test import LOCMEM_TEST_CACHE

ADDRESS = "opted-out@example.ro"
BLOCKS = ("hard_bounce", "complaint", "invalid", "manual", "soft_bounce_threshold")


def _suppressed(*, essential: bool) -> bool:
    return EmailSuppression.is_suppressed(ADDRESS, essential=essential)


def _later(days: int) -> object:
    return patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(days=days))


class OptOutAndBlockTests(TestCase):
    def test_an_unsubscribe_keeps_the_block_it_finds(self) -> None:
        for block in BLOCKS:
            with self.subTest(block=block):
                EmailSuppression.objects.all().delete()
                EmailSuppression.suppress(ADDRESS, block)
                EmailSuppression.suppress(ADDRESS, "unsubscribe")
                row = EmailSuppression.objects.get()
                self.assertEqual(row.reason, block)
                self.assertIsNotNone(row.marketing_opt_out_at)
                self.assertTrue(_suppressed(essential=True))
                self.assertTrue(_suppressed(essential=False))

    def test_a_block_keeps_the_opt_out_it_finds(self) -> None:
        for block in BLOCKS:
            with self.subTest(block=block):
                EmailSuppression.objects.all().delete()
                EmailSuppression.suppress(ADDRESS, "unsubscribe")
                EmailSuppression.suppress(ADDRESS, block, expires_days=30)
                row = EmailSuppression.objects.get()
                self.assertEqual(row.reason, block)
                self.assertIsNotNone(row.marketing_opt_out_at)
                self.assertTrue(_suppressed(essential=True))

    def test_an_opt_out_alone_stops_only_ordinary_mail(self) -> None:
        EmailSuppression.suppress(ADDRESS, "unsubscribe")
        self.assertEqual(EmailSuppression.objects.get().reason, "")
        self.assertTrue(_suppressed(essential=False))
        self.assertFalse(_suppressed(essential=True))

    def test_a_second_unsubscribe_keeps_the_first_time(self) -> None:
        first = EmailSuppression.suppress(ADDRESS, "unsubscribe").marketing_opt_out_at
        with _later(days=3):
            EmailSuppression.suppress(ADDRESS, "unsubscribe")
        self.assertEqual(EmailSuppression.objects.get().marketing_opt_out_at, first)


class ExpiryTests(TestCase):
    def test_an_expired_block_leaves_the_opt_out_in_either_order(self) -> None:
        orders = {
            "unsubscribe first": (("unsubscribe", None), ("manual", 1)),
            "block first": (("manual", 1), ("unsubscribe", None)),
        }
        for name, writes in orders.items():
            with self.subTest(order=name):
                EmailSuppression.objects.all().delete()
                for reason, days in writes:
                    EmailSuppression.suppress(ADDRESS, reason, expires_days=days)
                with _later(days=2):
                    self.assertTrue(_suppressed(essential=False))
                    self.assertFalse(_suppressed(essential=True))
                row = EmailSuppression.objects.get()
                self.assertEqual((row.reason, row.expires_at), ("", None))
                self.assertIsNotNone(row.marketing_opt_out_at)

    def test_an_expired_block_with_no_opt_out_is_removed(self) -> None:
        EmailSuppression.suppress(ADDRESS, "soft_bounce_threshold", expires_days=30)
        with _later(days=31):
            self.assertFalse(_suppressed(essential=False))
        self.assertFalse(EmailSuppression.objects.exists())

    def test_control_a_live_block_is_not_lifted(self) -> None:
        EmailSuppression.suppress(ADDRESS, "soft_bounce_threshold", expires_days=30)
        with _later(days=29):
            self.assertTrue(_suppressed(essential=True))
        self.assertEqual(EmailSuppression.objects.get().reason, "soft_bounce_threshold")


class LiftBlockTests(TestCase):
    def test_lifting_a_block_keeps_the_opt_out(self) -> None:
        EmailSuppressionService.suppress_email(ADDRESS, "unsubscribe")
        EmailSuppressionService.suppress_email(ADDRESS, "hard_bounce")
        self.assertTrue(EmailSuppressionService.unsuppress_email(ADDRESS))
        self.assertTrue(EmailSuppressionService.is_suppressed(ADDRESS))
        self.assertFalse(EmailSuppressionService.is_suppressed(ADDRESS, essential=True))

    def test_an_opt_out_alone_is_not_lifted(self) -> None:
        EmailSuppressionService.suppress_email(ADDRESS, "unsubscribe")
        self.assertFalse(EmailSuppressionService.unsuppress_email(ADDRESS))
        self.assertTrue(EmailSuppressionService.is_suppressed(ADDRESS))

    def test_control_lifting_a_block_with_no_opt_out_removes_the_row(self) -> None:
        EmailSuppressionService.suppress_email(ADDRESS, "hard_bounce")
        self.assertTrue(EmailSuppressionService.unsuppress_email(ADDRESS))
        self.assertFalse(EmailSuppression.objects.exists())


class ConcurrentFirstWriteTests(TestCase):
    def test_a_first_write_that_loses_the_insert_race_updates_the_winner(self) -> None:
        EmailSuppression.suppress(ADDRESS, "hard_bounce")
        # The lookup misses, as it does for a writer that read before the other writer's insert committed.
        with patch.object(QuerySet, "first", return_value=None):
            EmailSuppression.suppress(ADDRESS, "unsubscribe")
        row = EmailSuppression.objects.get()
        self.assertEqual(row.reason, "hard_bounce")
        self.assertIsNotNone(row.marketing_opt_out_at)


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class SuppressionCacheTests(TestCase):
    def setUp(self) -> None:
        cache.clear()

    def test_a_not_suppressed_answer_is_never_cached(self) -> None:
        self.assertFalse(EmailSuppressionService.is_suppressed(ADDRESS))
        # Written straight to the model, as a concurrent unsubscribe's row is before its cache write.
        EmailSuppression.suppress(ADDRESS, "unsubscribe")
        self.assertTrue(EmailSuppressionService.is_suppressed(ADDRESS))

    def test_control_a_suppressed_answer_is_cached(self) -> None:
        EmailSuppression.suppress(ADDRESS, "hard_bounce")
        self.assertTrue(EmailSuppressionService.is_suppressed(ADDRESS))
        EmailSuppression.objects.all().delete()
        self.assertTrue(EmailSuppressionService.is_suppressed(ADDRESS))
