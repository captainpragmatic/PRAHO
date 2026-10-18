"""DNS-01 support in the Cloudflare gateway: several TXT values per name, per-order ownership, stale sweep (ADR-0061 P1.9).

Only the HTTP layer is faked, by the in-memory Cloudflare double shared with the gateway tests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.types import Retriability
from apps.infrastructure.dns_gateway import CloudflareDnsGateway, ReconcileOutcome
from tests.infrastructure.test_dns_gateway_cloudflare import (
    SAFE_REQUEST,
    SLEEP,
    ZONE,
    FakeCloudflare,
    failure,
)

CHALLENGE_NAME = "_acme-challenge.h7k3p2q8.accounts.example.net"
ORDER_A = "praho:acme:aaaaaaaaaaaaaaaa"
ORDER_B = "praho:acme:bbbbbbbbbbbbbbbb"


def txt(content: str, owner: str, *, record_id: str | None = None, age_seconds: float = 0.0) -> dict[str, Any]:
    created = datetime.now(UTC) - timedelta(seconds=age_seconds)
    record: dict[str, Any] = {
        "type": "TXT",
        "name": CHALLENGE_NAME,
        "content": content,
        "comment": owner,
        "created_on": created.isoformat(),
    }
    if record_id is not None:
        record["id"] = record_id
    return record


def publish(fake: FakeCloudflare, values: list[str], owner: str, *, name: str = CHALLENGE_NAME) -> ReconcileOutcome:
    with patch(SAFE_REQUEST, fake), patch(SLEEP):
        return CloudflareDnsGateway(token="tok").reconcile_txt_values(ZONE, name, values, owner)


def sweep(fake: FakeCloudflare, **kwargs: Any) -> Any:
    kwargs.setdefault("keep_owner_tags", frozenset())
    kwargs.setdefault("min_age_seconds", 600.0)
    with patch(SAFE_REQUEST, fake), patch(SLEEP):
        return CloudflareDnsGateway(token="tok").sweep_owned_records(ZONE, "praho:acme:", **kwargs)


def contents(fake: FakeCloudflare, owner: str) -> list[str]:
    return sorted(str(r["content"]) for r in fake.owned(owner))


class SeveralValuesPerNameTests(SimpleTestCase):
    def test_every_value_becomes_its_own_owned_record(self) -> None:
        fake = FakeCloudflare()

        outcome = publish(fake, ["token-one", "token-two"], ORDER_A)

        self.assertIsNone(outcome.error)
        self.assertEqual(contents(fake, ORDER_A), ["token-one", "token-two"])
        self.assertEqual(len(outcome.applied), 2)
        self.assertEqual({r.record_type for r in outcome.applied}, {"TXT"})

    def test_a_second_run_with_the_same_values_writes_nothing(self) -> None:
        fake = FakeCloudflare([txt("token-one", ORDER_A), txt("token-two", ORDER_A)])

        outcome = publish(fake, ["token-one", "token-two"], ORDER_A)

        self.assertIsNone(outcome.error)
        self.assertEqual([m for m, _ in fake.calls if m != "GET"], [])

    def test_a_value_that_is_no_longer_wanted_is_removed_and_a_new_one_added(self) -> None:
        fake = FakeCloudflare([txt("old", ORDER_A), txt("keep", ORDER_A)])

        outcome = publish(fake, ["keep", "new"], ORDER_A)

        self.assertIsNone(outcome.error)
        self.assertEqual(contents(fake, ORDER_A), ["keep", "new"])

    def test_a_replayed_duplicate_of_a_value_is_converged_to_one(self) -> None:
        fake = FakeCloudflare([txt("same", ORDER_A, record_id="d1"), txt("same", ORDER_A, record_id="d2")])

        outcome = publish(fake, ["same"], ORDER_A)

        self.assertIsNone(outcome.error)
        self.assertEqual(contents(fake, ORDER_A), ["same"])

    def test_a_value_stored_with_quotes_matches_the_bare_value(self) -> None:
        fake = FakeCloudflare([txt('"quoted-token"', ORDER_A)])

        outcome = publish(fake, ["quoted-token"], ORDER_A)

        self.assertIsNone(outcome.error)
        self.assertEqual([m for m, _ in fake.calls if m != "GET"], [])

    def test_a_listing_failure_is_a_typed_retriable_error(self) -> None:
        fake = FakeCloudflare()
        fake.fail("GET", failure(429, retry_after="120"))

        outcome = publish(fake, ["token"], ORDER_A)

        self.assertIsNotNone(outcome.error)
        self.assertIs(outcome.retriability, Retriability.RETRIABLE)
        self.assertEqual(outcome.retry_after_seconds, 120.0)
        self.assertEqual(fake.count("POST"), 0)


class OwnedByItsOrderTests(SimpleTestCase):
    def test_two_orders_share_a_challenge_name_without_touching_each_other(self) -> None:
        fake = FakeCloudflare()

        first = publish(fake, ["token-a"], ORDER_A)
        second = publish(fake, ["token-b"], ORDER_B)

        self.assertIsNone(first.error)
        self.assertIsNone(second.error)
        self.assertEqual(contents(fake, ORDER_A), ["token-a"])
        self.assertEqual(contents(fake, ORDER_B), ["token-b"])

    def test_converging_one_order_never_deletes_the_others_values(self) -> None:
        fake = FakeCloudflare([txt("token-b", ORDER_B)])

        publish(fake, ["token-a"], ORDER_A)
        publish(fake, ["token-a2"], ORDER_A)

        self.assertEqual(contents(fake, ORDER_B), ["token-b"])
        self.assertEqual(contents(fake, ORDER_A), ["token-a2"])

    def test_an_unowned_txt_record_on_the_name_is_left_alone(self) -> None:
        fake = FakeCloudflare([txt("someone-elses", "manual")])

        outcome = publish(fake, ["token-a"], ORDER_A)

        self.assertIsNone(outcome.error)
        self.assertEqual(contents(fake, "manual"), ["someone-elses"])
        self.assertEqual(contents(fake, ORDER_A), ["token-a"])

    def test_cleanup_of_one_order_removes_only_its_records(self) -> None:
        fake = FakeCloudflare([txt("token-a", ORDER_A), txt("token-b", ORDER_B)])

        with patch(SAFE_REQUEST, fake), patch(SLEEP):
            result = CloudflareDnsGateway(token="tok").delete_owned_records(ZONE, ORDER_A)

        self.assertTrue(result.is_ok())
        self.assertEqual(contents(fake, ORDER_A), [])
        self.assertEqual(contents(fake, ORDER_B), ["token-b"])


class StaleSweepTests(SimpleTestCase):
    def test_an_old_record_of_an_order_nobody_is_running_is_deleted(self) -> None:
        fake = FakeCloudflare([txt("stale", ORDER_A, age_seconds=3600)])

        result = sweep(fake)

        self.assertTrue(result.is_ok())
        self.assertEqual(len(result.unwrap()), 1)
        self.assertEqual(contents(fake, ORDER_A), [])

    def test_a_record_of_a_live_order_is_kept_however_old(self) -> None:
        fake = FakeCloudflare([txt("live", ORDER_A, age_seconds=7200), txt("stale", ORDER_B, age_seconds=7200)])

        sweep(fake, keep_owner_tags=frozenset({ORDER_A}))

        self.assertEqual(contents(fake, ORDER_A), ["live"])
        self.assertEqual(contents(fake, ORDER_B), [])

    def test_a_young_record_is_kept_because_its_order_may_not_be_saved_yet(self) -> None:
        fake = FakeCloudflare([txt("young", ORDER_A, age_seconds=30)])

        sweep(fake)

        self.assertEqual(contents(fake, ORDER_A), ["young"])

    def test_a_record_without_a_creation_time_is_kept(self) -> None:
        record = txt("odd", ORDER_A)
        del record["created_on"]
        fake = FakeCloudflare([record])

        sweep(fake)

        self.assertEqual(contents(fake, ORDER_A), ["odd"])

    def test_records_outside_the_prefix_and_other_types_are_never_touched(self) -> None:
        fake = FakeCloudflare(
            [
                txt("manual", "manual", age_seconds=9999),
                {"type": "A", "name": "x.accounts.example.net", "content": "203.0.113.1", "comment": ORDER_A},
            ]
        )

        sweep(fake)

        self.assertEqual(contents(fake, "manual"), ["manual"])
        self.assertEqual(len(fake.owned(ORDER_A)), 1)

    def test_a_prefix_that_is_not_ours_is_refused_before_any_request(self) -> None:
        fake = FakeCloudflare([txt("x", "manual", age_seconds=9999)])

        with patch(SAFE_REQUEST, fake), patch(SLEEP):
            result = CloudflareDnsGateway(token="tok").sweep_owned_records(
                ZONE, "", keep_owner_tags=frozenset(), min_age_seconds=0
            )

        self.assertTrue(result.is_err())
        self.assertEqual(fake.calls, [])
        self.assertEqual(contents(fake, "manual"), ["x"])
