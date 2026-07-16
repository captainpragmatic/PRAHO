"""
_classify_stripe_error maps real Stripe SDK exception classes to Retriability.

The classifier matches by class NAME (the stripe module is imported lazily),
which silently rots if a name doesn't exist in the installed SDK — so the
first test pins every configured name against the real module.
"""

import stripe
from django.test import SimpleTestCase

from apps.billing.stripe_metering import (
    _NOT_RETRIABLE_STRIPE_ERROR_NAMES,
    _RETRIABLE_STRIPE_ERROR_NAMES,
    _classify_stripe_error,
)
from apps.common.types import Retriability


def _real_stripe_error_names() -> set[str]:
    # Pin against the PUBLIC stripe.error module — stripe._error is private and can
    # rename/move across SDK versions.
    return {
        name
        for name in dir(stripe.error)
        if isinstance(getattr(stripe.error, name), type)
        and issubclass(getattr(stripe.error, name), BaseException)
    }


class StripeErrorClassificationTests(SimpleTestCase):
    def test_configured_names_reference_real_stripe_classes(self) -> None:
        """A name that no Stripe class carries is dead configuration."""
        real = _real_stripe_error_names()
        self.assertLessEqual(_RETRIABLE_STRIPE_ERROR_NAMES, real)
        self.assertLessEqual(_NOT_RETRIABLE_STRIPE_ERROR_NAMES, real)

    def test_only_rate_limit_is_retriable(self) -> None:
        """RateLimitError is the ONLY provably-unapplied case: Stripe rejects it before
        processing. Everything else may have committed server-side."""
        self.assertEqual(_classify_stripe_error(stripe.RateLimitError("rate limited")), Retriability.RETRIABLE)

    def test_permanent_errors_classify_not_retriable(self) -> None:
        for exc in (
            stripe.InvalidRequestError("bad param", param=None),
            stripe.AuthenticationError("bad key"),
        ):
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(_classify_stripe_error(exc), Retriability.NOT_RETRIABLE)

    def test_ambiguous_errors_fall_back_to_unknown(self) -> None:
        """A lost response also raises APIConnectionError, so retrying a keyless POST
        (Meter/Subscription/Item create) could double-create — UNKNOWN, not RETRIABLE.
        APIError (indeterminate 5xx) and CardError (per-decline advice) are likewise
        unsafe to classify blind."""
        for exc in (
            stripe.APIConnectionError("connection dropped"),
            stripe.APIError("server error"),
            stripe.CardError("declined", param=None, code="card_declined"),
            stripe.StripeError("mystery"),
        ):
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(_classify_stripe_error(exc), Retriability.UNKNOWN)
