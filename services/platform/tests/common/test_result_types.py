"""
Tests for the Result pattern (Ok/Err) in apps.common.types.

Covers the retriable signal on Err (issue #121) and core Result behavior.
"""

from django.test import TestCase

from apps.common.types import Err, Ok


class OkTests(TestCase):
    """Tests for the Ok result type."""

    def test_ok_is_ok(self) -> None:
        self.assertTrue(Ok(42).is_ok())

    def test_ok_is_not_err(self) -> None:
        self.assertFalse(Ok(42).is_err())

    def test_ok_unwrap(self) -> None:
        self.assertEqual(Ok("hello").unwrap(), "hello")

    def test_ok_unwrap_or_returns_value(self) -> None:
        self.assertEqual(Ok(42).unwrap_or(0), 42)

    def test_ok_map_transforms_value(self) -> None:
        result = Ok(5).map(lambda x: x * 2)
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), 10)

    def test_ok_map_exception_returns_err(self) -> None:
        result = Ok(5).map(lambda x: 1 / 0)
        self.assertTrue(result.is_err())

    def test_ok_and_then_chains(self) -> None:
        result = Ok(5).and_then(lambda x: Ok(x + 1))
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), 6)

    def test_ok_and_then_to_err(self) -> None:
        result = Ok(5).and_then(lambda _x: Err("fail"))
        self.assertTrue(result.is_err())

    def test_ok_unwrap_err_raises(self) -> None:
        with self.assertRaises(ValueError):
            Ok(42).unwrap_err()


class ErrTests(TestCase):
    """Tests for the Err result type."""

    def test_err_is_err(self) -> None:
        self.assertTrue(Err("oops").is_err())

    def test_err_is_not_ok(self) -> None:
        self.assertFalse(Err("oops").is_ok())

    def test_err_unwrap_raises(self) -> None:
        with self.assertRaises(ValueError):
            Err("oops").unwrap()

    def test_err_unwrap_or_returns_default(self) -> None:
        self.assertEqual(Err("oops").unwrap_or(99), 99)

    def test_err_unwrap_err(self) -> None:
        self.assertEqual(Err("oops").unwrap_err(), "oops")

    def test_err_map_is_noop(self) -> None:
        err = Err("fail")
        result = err.map(lambda x: x * 2)
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err(), "fail")

    def test_err_and_then_is_noop(self) -> None:
        err = Err("fail")
        result = err.and_then(Ok)
        self.assertTrue(result.is_err())
        self.assertEqual(result.unwrap_err(), "fail")


class ErrRetriableTests(TestCase):
    """Tests for the retriable signal on Err (issue #121)."""

    def test_err_defaults_to_not_retriable(self) -> None:
        """Existing Err('msg') calls default to retriable=False."""
        err = Err("database timeout")
        self.assertFalse(err.retriable)

    def test_err_explicit_retriable_true(self) -> None:
        err = Err("lock contention", retriable=True)
        self.assertTrue(err.retriable)

    def test_err_explicit_retriable_false(self) -> None:
        err = Err("validation failed", retriable=False)
        self.assertFalse(err.retriable)

    def test_retriable_preserved_through_map(self) -> None:
        """Err.map() returns self, so retriable must survive."""
        err = Err("timeout", retriable=True)
        result = err.map(lambda x: x)
        self.assertTrue(result.is_err())
        self.assertTrue(result.retriable)

    def test_retriable_preserved_through_and_then(self) -> None:
        """Err.and_then() returns self, so retriable must survive."""
        err = Err("timeout", retriable=True)
        result = err.and_then(Ok)
        self.assertTrue(result.is_err())
        self.assertTrue(result.retriable)

    def test_non_retriable_preserved_through_map(self) -> None:
        err = Err("bad input", retriable=False)
        result = err.map(lambda x: x)
        self.assertFalse(result.retriable)

    def test_frozen_dataclass_prevents_mutation(self) -> None:
        """Err is frozen — retriable cannot be changed after creation."""
        err = Err("fail", retriable=True)
        with self.assertRaises(AttributeError):
            err.retriable = False  # type: ignore[misc]  # intentional: testing frozen dataclass rejects mutation

    def test_ok_map_exception_creates_non_retriable_err(self) -> None:
        """When Ok.map() catches an exception, the resulting Err should not be retriable."""
        result = Ok(1).map(lambda x: 1 / 0)
        self.assertTrue(result.is_err())
        self.assertFalse(result.retriable)
