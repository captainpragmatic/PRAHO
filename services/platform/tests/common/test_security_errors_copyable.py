"""Typed rate-limit refusals survive copying and pickling like the strings they stand in for.

Results travel through the database cache and Django-Q (both pickle) and through the parallel test
runner, so a string-compatible error that cannot be pickled would crash far from where it was made.
"""

import copy
import pickle

from django.test import SimpleTestCase

from apps.common.security_errors import RateLimitFailure, RateLimitValidationError
from apps.common.types import Err


def _round_trip(value: object) -> object:
    return pickle.loads(pickle.dumps(value))  # noqa: S301 -- unpickles only bytes this test just produced


class SecurityErrorCopyTests(SimpleTestCase):
    def test_failure_round_trips_with_its_metadata(self) -> None:
        failure = RateLimitFailure("Too many attempts", status_code=429, retry_after=3600)
        for clone in (copy.copy(failure), copy.deepcopy(failure), _round_trip(failure)):
            with self.subTest(clone=type(clone)):
                self.assertEqual(clone, "Too many attempts")
                self.assertIsInstance(clone, RateLimitFailure)
                self.assertEqual((clone.status_code, clone.retry_after), (429, 3600))

    def test_validation_error_and_err_round_trip(self) -> None:
        error = RateLimitValidationError(RateLimitFailure("Store down", status_code=503))
        clone = _round_trip(error)
        self.assertEqual((clone.failure, clone.failure.status_code), ("Store down", 503))
        self.assertEqual(copy.deepcopy(error).failure.status_code, 503)
        result = _round_trip(Err(error.failure))
        self.assertEqual(result.unwrap_err().status_code, 503)
