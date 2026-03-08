"""
Tests for CustomerCreditService — locking, score calculation, clamping, and reversion.

Regression guard: these tests capture the chaos-monkey findings around:
- Score reads using stale (pre-lock) data instead of the locked row value
- Missing clamping at MIN_CREDIT_SCORE / MAX_CREDIT_SCORE boundaries
- Score calculation returning a non-integer
"""

from django.test import TestCase
from django.utils import timezone

from apps.customers.credit_service import (
    MAX_CREDIT_SCORE,
    MIN_CREDIT_SCORE,
    CustomerCreditService,
    get_credit_adjustments,
)
from tests.factories.core_factories import create_admin_user, create_full_customer


def _create_customer() -> object:
    """Create a minimal test customer via the core factory."""
    return create_full_customer()


def _create_user() -> object:
    """Create a minimal test staff user via the core factory."""
    return create_admin_user()


class TestCreditServiceConstants(TestCase):
    """Sanity-check that public constants are within expected bounds."""

    def test_min_credit_score_is_zero(self) -> None:
        self.assertEqual(MIN_CREDIT_SCORE, 0)

    def test_max_credit_score_is_one_thousand(self) -> None:
        self.assertEqual(MAX_CREDIT_SCORE, 1000)

    def test_min_less_than_max(self) -> None:
        self.assertLess(MIN_CREDIT_SCORE, MAX_CREDIT_SCORE)

    def test_get_credit_adjustments_returns_dict(self) -> None:
        adjustments = get_credit_adjustments()
        self.assertIsInstance(adjustments, dict)

    def test_credit_adjustments_has_positive_payment_key(self) -> None:
        adjustments = get_credit_adjustments()
        self.assertIn("positive_payment", adjustments)

    def test_credit_adjustments_has_failed_payment_key(self) -> None:
        adjustments = get_credit_adjustments()
        self.assertIn("failed_payment", adjustments)


class TestCreditServiceUpdateScore(TestCase):
    """CustomerCreditService.update_credit_score() — happy path and return shape."""

    def setUp(self) -> None:
        self.customer = _create_customer()

    def test_update_returns_success_true(self) -> None:
        result = CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )
        self.assertTrue(result["success"])

    def test_update_returns_score_before_key(self) -> None:
        result = CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )
        self.assertIn("score_before", result)

    def test_update_returns_score_after_key(self) -> None:
        result = CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )
        self.assertIn("score_after", result)

    def test_update_returns_customer_id(self) -> None:
        result = CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )
        self.assertEqual(result["customer_id"], str(self.customer.id))

    def test_update_returns_event_type(self) -> None:
        result = CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )
        self.assertEqual(result["event_type"], "positive_payment")

    def test_score_persisted_to_meta(self) -> None:
        """After update, the new score should be stored in customer.meta."""
        CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )
        self.customer.refresh_from_db()
        self.assertIsNotNone(self.customer.meta)
        self.assertIn("credit_score", self.customer.meta)


class TestCreditServiceScoreClamping(TestCase):
    """Score clamping — score must never exceed MAX or fall below MIN."""

    def setUp(self) -> None:
        self.customer = _create_customer()

    def test_score_never_exceeds_max(self) -> None:
        """Applying positive events when score is near MAX should not exceed MAX."""
        self.customer.meta = {"credit_score": MAX_CREDIT_SCORE - 2}
        self.customer.save(update_fields=["meta"])

        result = CustomerCreditService.update_credit_score(
            self.customer, "early_payment", timezone.now()
        )
        self.assertLessEqual(result["score_after"], MAX_CREDIT_SCORE)

    def test_score_never_exceeds_max_at_exact_max(self) -> None:
        """Applying positive events when score is exactly MAX must stay at MAX."""
        self.customer.meta = {"credit_score": MAX_CREDIT_SCORE}
        self.customer.save(update_fields=["meta"])

        result = CustomerCreditService.update_credit_score(
            self.customer, "early_payment", timezone.now()
        )
        self.assertEqual(result["score_after"], MAX_CREDIT_SCORE)

    def test_score_never_falls_below_min(self) -> None:
        """Applying negative events when score is near MIN should not go below MIN."""
        self.customer.meta = {"credit_score": MIN_CREDIT_SCORE + 10}
        self.customer.save(update_fields=["meta"])

        result = CustomerCreditService.update_credit_score(
            self.customer, "chargeback", timezone.now()
        )
        self.assertGreaterEqual(result["score_after"], MIN_CREDIT_SCORE)

    def test_score_never_falls_below_min_at_exact_min(self) -> None:
        """Applying negative events when score is exactly MIN must stay at MIN."""
        self.customer.meta = {"credit_score": MIN_CREDIT_SCORE}
        self.customer.save(update_fields=["meta"])

        result = CustomerCreditService.update_credit_score(
            self.customer, "chargeback", timezone.now()
        )
        self.assertEqual(result["score_after"], MIN_CREDIT_SCORE)

    def test_score_after_is_integer(self) -> None:
        """score_after must be an integer (not float)."""
        result = CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )
        self.assertIsInstance(result["score_after"], int)

    def test_score_before_is_integer(self) -> None:
        result = CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )
        self.assertIsInstance(result["score_before"], int)


class TestCreditServiceLockedRowRead(TestCase):
    """Regression: update_credit_score must read score from the locked row, not stale object."""

    def setUp(self) -> None:
        self.customer = _create_customer()

    def test_score_before_reflects_stored_meta_not_stale_object(self) -> None:
        """
        Set a specific credit_score in meta, then stale the in-memory customer
        object to a different value and call update_credit_score.  The reported
        score_before should come from the DB-locked row (500), not the stale
        in-memory value (999).
        """
        # Write the authoritative score to the DB
        self.customer.meta = {"credit_score": 500}
        self.customer.save(update_fields=["meta"])

        # Stale the in-memory object with a different value
        self.customer.meta = {"credit_score": 999}
        # Do NOT save — the DB still holds 500

        result = CustomerCreditService.update_credit_score(
            self.customer, "positive_payment", timezone.now()
        )

        # The service must read the locked row (500), not the stale in-memory 999
        self.assertEqual(result["score_before"], 500)

    def test_update_is_stored_persistently(self) -> None:
        """Score written inside the transaction must survive a fresh DB fetch."""
        CustomerCreditService.update_credit_score(
            self.customer, "failed_payment", timezone.now()
        )
        self.customer.refresh_from_db()
        stored_score = (self.customer.meta or {}).get("credit_score")
        self.assertIsNotNone(stored_score)
        self.assertGreaterEqual(stored_score, MIN_CREDIT_SCORE)
        self.assertLessEqual(stored_score, MAX_CREDIT_SCORE)


class TestCreditServiceReversion(TestCase):
    """CustomerCreditService.revert_credit_change() — reverses the original adjustment."""

    def setUp(self) -> None:
        self.customer = _create_customer()

    def test_revert_returns_success_true(self) -> None:
        CustomerCreditService.update_credit_score(
            self.customer, "failed_payment", timezone.now()
        )
        self.customer.refresh_from_db()

        result = CustomerCreditService.revert_credit_change(
            self.customer, "failed_payment", timezone.now()
        )
        self.assertTrue(result["success"])

    def test_revert_returns_customer_id(self) -> None:
        CustomerCreditService.update_credit_score(
            self.customer, "failed_payment", timezone.now()
        )
        self.customer.refresh_from_db()

        result = CustomerCreditService.revert_credit_change(
            self.customer, "failed_payment", timezone.now()
        )
        self.assertEqual(result["customer_id"], str(self.customer.id))

    def test_revert_score_after_clamped_to_valid_range(self) -> None:
        """Score after reversion must still be in [MIN, MAX]."""
        CustomerCreditService.update_credit_score(
            self.customer, "chargeback", timezone.now()
        )
        self.customer.refresh_from_db()

        result = CustomerCreditService.revert_credit_change(
            self.customer, "chargeback", timezone.now()
        )
        self.assertGreaterEqual(result["score_after"], MIN_CREDIT_SCORE)
        self.assertLessEqual(result["score_after"], MAX_CREDIT_SCORE)

    def test_revert_applies_opposite_adjustment(self) -> None:
        """Reversion adjustment must be the negative of the original."""
        adjustments = get_credit_adjustments()
        original_adj = adjustments.get("failed_payment", 0)

        CustomerCreditService.update_credit_score(
            self.customer, "failed_payment", timezone.now()
        )
        self.customer.refresh_from_db()

        result = CustomerCreditService.revert_credit_change(
            self.customer, "failed_payment", timezone.now()
        )
        self.assertEqual(result["adjustment"], -original_adj)


class TestCreditServiceCalculate(TestCase):
    """CustomerCreditService.calculate_credit_score() — returns int in valid range."""

    def setUp(self) -> None:
        self.customer = _create_customer()

    def test_calculate_returns_integer(self) -> None:
        score = CustomerCreditService.calculate_credit_score(self.customer)
        self.assertIsInstance(score, int)

    def test_calculate_within_valid_range(self) -> None:
        score = CustomerCreditService.calculate_credit_score(self.customer)
        self.assertGreaterEqual(score, MIN_CREDIT_SCORE)
        self.assertLessEqual(score, MAX_CREDIT_SCORE)

    def test_calculate_uses_cached_score_when_fresh(self) -> None:
        """When meta has a fresh credit_score, it should be returned directly."""
        target_score = 720
        now_iso = timezone.now().isoformat()
        self.customer.meta = {"credit_score": target_score, "credit_updated_at": now_iso}
        self.customer.save(update_fields=["meta"])

        score = CustomerCreditService.calculate_credit_score(self.customer)
        self.assertEqual(score, target_score)

    def test_get_credit_rating_excellent(self) -> None:
        self.assertEqual(CustomerCreditService.get_credit_rating(900), "Excellent")

    def test_get_credit_rating_good(self) -> None:
        self.assertEqual(CustomerCreditService.get_credit_rating(750), "Good")

    def test_get_credit_rating_fair(self) -> None:
        self.assertEqual(CustomerCreditService.get_credit_rating(650), "Fair")

    def test_get_credit_rating_poor(self) -> None:
        self.assertEqual(CustomerCreditService.get_credit_rating(500), "Poor")

    def test_get_credit_rating_very_poor(self) -> None:
        self.assertEqual(CustomerCreditService.get_credit_rating(100), "Very Poor")
