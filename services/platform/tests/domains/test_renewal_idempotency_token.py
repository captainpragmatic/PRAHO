"""#259: distinct renewal intents must not share an idempotency key.

The key was ``domain_renew:{gateway}:{domain}:{years}``, so a legitimate second
one-year renewal of the same domain inside the cache TTL replayed the first cached
result instead of contacting the registrar — the customer is billed for a renewal that
never happened, and the expiry never moves.

Note the CACHES override: the default test cache is DummyCache, which stores nothing, so
idempotency replay cannot happen at all under it — a replay test written against the
default backend would pass while proving nothing.

``idempotency_token`` names ONE intent. The order path passes the ``DomainOrderItem``
pk. Callers with no durable identifier keep the old key shape, deliberately: a fresh
random token per call would remove double-submit protection entirely, which is the worse
failure (a duplicate chargeable renewal at the registrar).
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import ANY, patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.common.types import Err, Ok, Retriability
from apps.domains.gateways.base import MAX_RETRIES, DomainRenewalResult
from apps.domains.gateways.errors import RegistrarAPIError, RegistrarConflictError
from apps.domains.gateways.gandi import GandiGateway
from apps.domains.models import Registrar
from config.settings.test import LOCMEM_TEST_CACHE


def _make_registrar(name: str = "gandi") -> Registrar:
    return Registrar.objects.create(
        name=name,
        display_name=name.title(),
        website_url="https://example.test",
        status="active",
    )


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True, CACHES=LOCMEM_TEST_CACHE)
class RenewalIdempotencyTokenTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.registrar = _make_registrar()
        self.gateway = GandiGateway(self.registrar)

    def _renewal(self) -> DomainRenewalResult:
        # A real dataclass, not a MagicMock: the idempotency cache PICKLES the result,
        # and a MagicMock raises PicklingError — so a mock would make every replay path
        # error instead of exercising the cache.
        return DomainRenewalResult(new_expires_at=datetime(2027, 1, 1, tzinfo=UTC))

    def test_idempotency_claim_outlives_queue_redelivery(self) -> None:
        """A Django-Q2 task that dies after the registrar call is redelivered after
        Q_CLUSTER['retry'] seconds. If the idempotency claim expires first, the
        redelivered task re-issues the same chargeable operation — the claim TTL
        must therefore exceed the redelivery window."""
        from django.conf import settings  # noqa: PLC0415

        from apps.domains.gateways.base import IDEMPOTENCY_TTL_SECONDS  # noqa: PLC0415

        self.assertGreater(IDEMPOTENCY_TTL_SECONDS, settings.Q_CLUSTER["retry"])

    def test_same_domain_and_years_without_a_token_still_collapses(self) -> None:
        """Documents the unchanged fallback — this is the behaviour #259 describes.

        Kept as an explicit assertion rather than left implicit, so the remaining
        exposure is visible instead of looking like it was fixed everywhere.
        """
        with patch.object(GandiGateway, "_do_renew", return_value=Ok(self._renewal())) as do_renew:
            self.gateway.renew_domain("g-1", "example.ro", 1)
            self.gateway.renew_domain("g-1", "example.ro", 1)

        self.assertEqual(do_renew.call_count, 1, "second call should replay the cached result")

    def test_distinct_tokens_reach_the_registrar_separately(self) -> None:
        """The fix: two genuine one-year renewals are two calls, not one plus a replay."""
        with patch.object(GandiGateway, "_do_renew", return_value=Ok(self._renewal())) as do_renew:
            self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:1")
            self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:2")

        self.assertEqual(do_renew.call_count, 2)

    def test_the_same_token_still_replays(self) -> None:
        """A retried batch must NOT re-charge — the token is what makes replay correct."""
        with patch.object(GandiGateway, "_do_renew", return_value=Ok(self._renewal())) as do_renew:
            first = self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:7")
            second = self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:7")

        self.assertEqual(do_renew.call_count, 1)
        self.assertTrue(first.is_ok())
        self.assertTrue(second.is_ok())

    def test_a_token_does_not_collide_with_the_tokenless_key(self) -> None:
        """Even a token equal to the year must occupy a separate namespace."""
        with patch.object(GandiGateway, "_do_renew", return_value=Ok(self._renewal())) as do_renew:
            self.gateway.renew_domain("g-1", "example.ro", 1)
            self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="1")

        self.assertEqual(do_renew.call_count, 2)

    def test_empty_token_does_not_silently_become_tokenless(self) -> None:
        """None means legacy behavior; an explicitly supplied string stays tokened."""
        with patch.object(GandiGateway, "_do_renew", return_value=Ok(self._renewal())) as do_renew:
            self.gateway.renew_domain("g-1", "example.ro", 1)
            self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="")

        self.assertEqual(do_renew.call_count, 2)

    def test_token_is_scoped_per_domain(self) -> None:
        """The same order-item token on a different domain is still a separate renewal."""
        with patch.object(GandiGateway, "_do_renew", return_value=Ok(self._renewal())) as do_renew:
            self.gateway.renew_domain("g-1", "one.ro", 1, idempotency_token="order_item:3")
            self.gateway.renew_domain("g-2", "two.ro", 1, idempotency_token="order_item:3")

        self.assertEqual(do_renew.call_count, 2)

    def test_unknown_outcome_blocks_same_token_retry(self) -> None:
        ambiguous = Err(RegistrarAPIError("registrar response lost"))

        with patch.object(GandiGateway, "_do_renew", return_value=ambiguous) as do_renew:
            first = self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:8")
            second = self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:8")

        self.assertTrue(first.is_err())
        self.assertTrue(second.is_err())
        self.assertIsInstance(second.unwrap_err(), RegistrarConflictError)
        self.assertEqual(do_renew.call_count, 1, "an ambiguous result must retain the idempotency claim")

    def test_not_retriable_outcome_releases_same_token_claim(self) -> None:
        rejected = Err(
            RegistrarAPIError("definite rejection"),
            retriability=Retriability.NOT_RETRIABLE,
        )

        with patch.object(GandiGateway, "_do_renew", return_value=rejected) as do_renew:
            first = self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:9")
            second = self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:9")

        self.assertTrue(first.is_err())
        self.assertTrue(second.is_err())
        self.assertNotIsInstance(second.unwrap_err(), RegistrarConflictError)
        self.assertEqual(do_renew.call_count, 2, "a definite rejection must release the claim")

    def test_retriable_outcome_releases_same_token_claim(self) -> None:
        safely_retriable = Err(
            RegistrarAPIError("request never reached registrar"),
            retriability=Retriability.RETRIABLE,
        )

        with (
            patch.object(GandiGateway, "_do_renew", return_value=safely_retriable) as do_renew,
            patch("apps.domains.gateways.base.time.sleep"),
        ):
            first = self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:10")
            second = self.gateway.renew_domain("g-1", "example.ro", 1, idempotency_token="order_item:10")

        self.assertTrue(first.is_err())
        self.assertTrue(second.is_err())
        self.assertNotIsInstance(second.unwrap_err(), RegistrarConflictError)
        self.assertEqual(
            do_renew.call_count,
            2 * MAX_RETRIES,
            "both outer calls must exhaust the registrar retry path",
        )

    def test_cache_write_failure_after_success_still_reports_success(self) -> None:
        renewal = self._renewal()

        with (
            patch.object(GandiGateway, "_do_renew", return_value=Ok(renewal)),
            patch("apps.domains.gateways.base.cache.set", side_effect=RuntimeError("cache unavailable")),
            patch.object(GandiGateway, "_audit_api_call") as mock_audit,
            self.assertLogs("apps.domains.gateways.gandi", level="ERROR") as logs,
        ):
            result = self.gateway.renew_domain(
                "g-1", "example.ro", 1, idempotency_token="order_item:11"
            )

        # The registrar call genuinely succeeded — a real, paid renewal happened. Losing
        # the cache write must not turn that into a reported failure.
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), renewal)
        self.assertTrue(any("idempotency" in message.lower() for message in logs.output))
        # Success bookkeeping (the audit trail for a chargeable operation) must still run —
        # this is what pins the fix to "wrap only cache.set", not "wrap the whole success
        # block", per ADR-0016. A too-broad try/except would silently drop this call.
        mock_audit.assert_called_once_with("domain_renewal", "example.ro", success=True, metadata=ANY)
