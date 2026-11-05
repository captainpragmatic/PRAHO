"""A broken opt-in/discovery hook must never report a green zero-test gate."""

import unittest
from collections.abc import Sequence
from typing import Any

from tests.runner import PostgreSQLSafeRunner


def _case_ids(suite: unittest.TestSuite) -> list[str]:
    result = []
    for case in suite:
        if isinstance(case, unittest.TestSuite):
            result.extend(_case_ids(case))
        elif case is not None:
            result.append(case.id())
    return result


class CheckoutBrowserRunner(PostgreSQLSafeRunner):
    def build_suite(self, test_labels: Sequence[str] | None = None, **kwargs: Any) -> unittest.TestSuite:
        suite = super().build_suite(test_labels, **kwargs)
        prefix = "tests.browser.test_plan_change_full_chain.FullPlanCheckoutBrowserTests."
        expected = {
            prefix + "test_real_paid_checkout_replays_one_intent_then_signed_webhook_settles",
            prefix + "test_real_zero_due_acceptance_has_no_payment_or_provider_call",
        }
        discovered = _case_ids(suite)
        if len(discovered) != len(expected) or set(discovered) != expected:
            raise RuntimeError(
                f"The required full checkout gate must discover exactly its two named journeys: {discovered}"
            )
        return suite
