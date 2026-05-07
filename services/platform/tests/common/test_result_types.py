"""
Tests for the Result pattern (Ok/Err) in apps.common.types.

Covers the retriable signal on Err (issue #121) and core Result behavior.
"""

from django.test import TestCase

from apps.common.types import Err, Ok, Retriability


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


class ErrRetriabilityTests(TestCase):
    """Tests for the retriability signal on Err (issue #121).

    The signal is tri-state (RETRIABLE / NOT_RETRIABLE / UNKNOWN) so that
    legacy ``Err(str(e))`` sites that cannot classify the underlying error
    do not silently assert permanence. ``is_retriable`` is the conservative
    "should I retry?" check used by non-idempotent consumers.
    """

    def test_err_defaults_to_unknown(self) -> None:
        """Legacy Err('msg') calls default to UNKNOWN, not NOT_RETRIABLE."""
        err = Err("database timeout")
        self.assertEqual(err.retriability, Retriability.UNKNOWN)
        self.assertFalse(err.is_retriable)

    def test_err_explicit_retriable(self) -> None:
        err = Err("lock contention", retriability=Retriability.RETRIABLE)
        self.assertEqual(err.retriability, Retriability.RETRIABLE)
        self.assertTrue(err.is_retriable)

    def test_err_explicit_not_retriable(self) -> None:
        err = Err("validation failed", retriability=Retriability.NOT_RETRIABLE)
        self.assertEqual(err.retriability, Retriability.NOT_RETRIABLE)
        self.assertFalse(err.is_retriable)

    def test_is_retriable_only_true_for_retriable_state(self) -> None:
        """is_retriable returns False for UNKNOWN — non-idempotent consumers fail closed."""
        self.assertFalse(Err("x", retriability=Retriability.UNKNOWN).is_retriable)
        self.assertFalse(Err("x", retriability=Retriability.NOT_RETRIABLE).is_retriable)
        self.assertTrue(Err("x", retriability=Retriability.RETRIABLE).is_retriable)

    def test_retriability_preserved_through_map(self) -> None:
        """Err.map() returns self, so retriability must survive."""
        err = Err("timeout", retriability=Retriability.RETRIABLE)
        result = err.map(lambda x: x)
        self.assertTrue(result.is_err())
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_retriability_preserved_through_and_then(self) -> None:
        err = Err("timeout", retriability=Retriability.RETRIABLE)
        result = err.and_then(Ok)
        self.assertTrue(result.is_err())
        self.assertEqual(result.retriability, Retriability.RETRIABLE)

    def test_frozen_dataclass_prevents_mutation(self) -> None:
        err = Err("fail", retriability=Retriability.RETRIABLE)
        with self.assertRaises(AttributeError):
            err.retriability = Retriability.NOT_RETRIABLE  # type: ignore[misc]  # intentional: testing frozen dataclass rejects mutation

    def test_ok_map_exception_creates_unknown_err(self) -> None:
        """When Ok.map() catches an exception, retriability is UNKNOWN — caller did not classify."""
        result = Ok(1).map(lambda x: 1 / 0)
        self.assertTrue(result.is_err())
        self.assertEqual(result.retriability, Retriability.UNKNOWN)


class ErrEqualityContractTests(TestCase):
    """Tests documenting the equality/hash contract change introduced by retriability.

    Two ``Err`` instances are equal iff both ``error`` AND ``retriability`` match.
    This is intentional: if a caller cares whether a failure is retriable, two
    errs with different retriability should compare unequal.
    """

    def test_err_equal_when_default_retriability_matches(self) -> None:
        self.assertEqual(Err("x"), Err("x"))
        self.assertEqual(Err("x"), Err("x", retriability=Retriability.UNKNOWN))

    def test_err_not_equal_when_retriability_differs(self) -> None:
        self.assertNotEqual(Err("x"), Err("x", retriability=Retriability.RETRIABLE))
        self.assertNotEqual(
            Err("x", retriability=Retriability.NOT_RETRIABLE),
            Err("x", retriability=Retriability.RETRIABLE),
        )

    def test_err_hash_matches_equality(self) -> None:
        self.assertEqual(hash(Err("x")), hash(Err("x", retriability=Retriability.UNKNOWN)))
        self.assertNotEqual(hash(Err("x")), hash(Err("x", retriability=Retriability.RETRIABLE)))


class ErrPatternMatchTests(TestCase):
    """``case Err(x)`` should still bind ``x`` to ``.error`` after the new field.

    Dataclass ``__match_args__`` is positional, so ``case Err(msg)`` continues
    to match the first field (``error``); ``retriability`` is reachable via
    ``case Err(msg, r)`` if needed.
    """

    def test_single_positional_match_binds_error(self) -> None:
        err: Err[str] = Err("boom", retriability=Retriability.RETRIABLE)
        match err:
            case Err(msg):
                self.assertEqual(msg, "boom")
            case _:  # pragma: no cover
                self.fail("Err did not match")

    def test_two_positional_match_binds_error_and_retriability(self) -> None:
        err: Err[str] = Err("boom", retriability=Retriability.RETRIABLE)
        match err:
            case Err(msg, r):
                self.assertEqual(msg, "boom")
                self.assertEqual(r, Retriability.RETRIABLE)
            case _:  # pragma: no cover
                self.fail("Err did not match")
