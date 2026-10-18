"""Cloudflare DNS gateway: drift, paging, one-name reconcile and retriable errors (ADR-0061 P0.10).

Only the HTTP layer (``dns_gateway.safe_request``) is faked, by an in-memory Cloudflare v4
double that pages its listings and can script failures, so every assertion runs through the
real gateway logic. Complements ``apps/infrastructure/tests/test_dns_gateway.py``.
"""

from __future__ import annotations

import itertools
import json
from collections import deque
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import requests
from django.test import SimpleTestCase, TestCase

from apps.common.types import Ok, Retriability, retriability_of
from apps.infrastructure.dns_gateway import (
    CLOUDFLARE_API_BASE,
    CloudflareDnsGateway,
    DnsRecordSpec,
    DnsRecordType,
    ReconcileOutcome,
)
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service

ZONE = "zone123"
OWNER = "praho:account:abc"
OTHER_OWNER = "praho:account:other"
NAME = "h7k3p2q8.accounts.example.net"
RECORDS_PATH = f"/zones/{ZONE}/dns_records"
SLEEP = "apps.infrastructure.dns_gateway.time.sleep"
SAFE_REQUEST = "apps.infrastructure.dns_gateway.safe_request"


class FakeResponse:
    """The slice of ``requests.Response`` the gateway reads."""

    def __init__(self, status: int, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self.content = json.dumps(body).encode()
        self.headers = {"content-length": str(len(self.content)), **(headers or {})}
        self._body = body

    def json(self) -> dict[str, Any]:
        return self._body


def failure(status: int, *, retry_after: str | None = None) -> FakeResponse:
    headers = {"Retry-After": retry_after} if retry_after is not None else None
    return FakeResponse(status, {"success": False, "errors": [{"message": f"http {status}"}]}, headers)


class FakeCloudflare:
    """In-memory Cloudflare DNS API: paged listings, ttl/proxied, scripted failures."""

    def __init__(self, records: list[dict[str, Any]] | None = None, *, page_size: int = 100) -> None:
        self._ids = itertools.count(1)
        self.page_size = page_size
        self.store: dict[str, dict[str, Any]] = {}
        for record in records or []:
            self.add(**record)
        self.calls: list[tuple[str, str]] = []
        self.scripted: dict[str, deque[FakeResponse]] = {}

    def add(self, **fields: Any) -> str:
        record_id = str(fields.pop("id", f"seed{next(self._ids)}"))
        self.store[record_id] = {"ttl": 60, "proxied": False, **fields, "id": record_id}
        return record_id

    def fail(self, method: str, *responses: FakeResponse) -> None:
        """The next calls with this HTTP method answer with these responses, in order."""
        self.scripted.setdefault(method, deque()).extend(responses)

    def count(self, method: str) -> int:
        return sum(1 for m, _ in self.calls if m == method)

    def owned(self, owner: str = OWNER) -> list[dict[str, Any]]:
        return [r for r in self.store.values() if r.get("comment") == owner]

    def __call__(  # noqa: PLR0911  # a router: one return per endpoint
        self, method: str, url: str, *, policy: Any = None, headers: Any = None, **kwargs: Any
    ) -> Any:
        path = url.replace(CLOUDFLARE_API_BASE, "")
        self.calls.append((method, path))
        queue = self.scripted.get(method)
        if queue:
            return queue.popleft()
        params = kwargs.get("params") or {}
        body = kwargs.get("json") or {}
        if method == "GET" and path == f"/zones/{ZONE}":
            return FakeResponse(200, {"success": True, "result": {"id": ZONE, "name": "accounts.example.net"}})
        if method == "GET" and path == RECORDS_PATH:
            return self._list(params)
        if method == "POST" and path == RECORDS_PATH:
            record_id = self.add(created_on=datetime.now(UTC).isoformat(), **body)
            return FakeResponse(200, {"success": True, "result": self.store[record_id]})
        record_id = path.rsplit("/", 1)[-1]
        if method == "PUT" and path.startswith(f"{RECORDS_PATH}/"):
            self.store[record_id] = {**self.store[record_id], **body}
            return FakeResponse(200, {"success": True, "result": self.store[record_id]})
        if method == "DELETE" and path.startswith(f"{RECORDS_PATH}/"):
            if self.store.pop(record_id, None) is None:
                return failure(404)
            return FakeResponse(200, {"success": True, "result": {"id": record_id}})
        return failure(404)

    def _list(self, params: dict[str, Any]) -> FakeResponse:
        matched = [
            r
            for r in self.store.values()
            if ("name" not in params or r["name"] == params["name"])
            and ("type" not in params or r["type"] == params["type"])
            and ("comment.exact" not in params or r.get("comment") == params["comment.exact"])
            and ("comment.startswith" not in params or str(r.get("comment", "")).startswith(params["comment.startswith"]))
        ]
        page = int(params.get("page", 1))
        size = min(int(params.get("per_page", self.page_size)), self.page_size)
        total_pages = max(1, -(-len(matched) // size))
        window = matched[(page - 1) * size : page * size]
        info = {"page": page, "per_page": size, "count": len(window), "total_count": len(matched)}
        return FakeResponse(200, {"success": True, "result": window, "result_info": {**info, "total_pages": total_pages}})


def spec(
    rtype: DnsRecordType = "A",
    content: str = "203.0.113.10",
    *,
    name: str = NAME,
    ttl: int = 60,
    proxied: bool = False,
) -> DnsRecordSpec:
    return DnsRecordSpec(record_type=rtype, name=name, content=content, owner_tag=OWNER, ttl=ttl, proxied=proxied)


def reconcile(fake: FakeCloudflare, specs: list[DnsRecordSpec], **gateway_kwargs: Any) -> ReconcileOutcome:
    with patch(SAFE_REQUEST, fake), patch(SLEEP):
        return CloudflareDnsGateway(token="tok", **gateway_kwargs).reconcile_records(ZONE, specs, OWNER)


class DriftTests(SimpleTestCase):
    """An owned record that differs in anything but its content is drift too."""

    def test_a_ttl_only_change_is_written(self) -> None:
        fake = FakeCloudflare([{"id": "r1", "type": "A", "name": NAME, "content": "203.0.113.10", "comment": OWNER, "ttl": 300}])

        outcome = reconcile(fake, [spec(ttl=60)])

        self.assertIsNone(outcome.error)
        self.assertEqual(fake.store["r1"]["ttl"], 60)
        self.assertEqual(fake.count("PUT"), 1)
        self.assertEqual(fake.count("POST"), 0)

    def test_a_proxied_flag_change_is_written(self) -> None:
        fake = FakeCloudflare(
            [{"id": "r1", "type": "A", "name": NAME, "content": "203.0.113.10", "comment": OWNER, "proxied": True}]
        )

        outcome = reconcile(fake, [spec(proxied=False)])

        self.assertIsNone(outcome.error)
        self.assertIs(fake.store["r1"]["proxied"], False)
        self.assertEqual(fake.count("PUT"), 1)

    def test_a_record_that_already_matches_is_not_written(self) -> None:
        fake = FakeCloudflare([{"id": "r1", "type": "A", "name": NAME, "content": "203.0.113.10", "comment": OWNER}])

        outcome = reconcile(fake, [spec()])

        self.assertIsNone(outcome.error)
        self.assertEqual([m for m, _ in fake.calls if m != "GET"], [])
        self.assertEqual(len(outcome.applied), 1)

    def test_addresses_are_compared_as_addresses_not_as_text(self) -> None:
        fake = FakeCloudflare(
            [
                {
                    "id": "r6",
                    "type": "AAAA",
                    "name": NAME,
                    "content": "2001:0DB8:0000:0000:0000:0000:0000:0001",
                    "comment": OWNER,
                }
            ]
        )

        outcome = reconcile(fake, [spec("AAAA", "2001:db8::1")])

        self.assertIsNone(outcome.error)
        self.assertEqual(fake.count("PUT"), 0)

    def test_a_different_address_is_still_written(self) -> None:
        fake = FakeCloudflare([{"id": "r1", "type": "A", "name": NAME, "content": "203.0.113.99", "comment": OWNER}])

        reconcile(fake, [spec()])

        self.assertEqual(fake.store["r1"]["content"], "203.0.113.10")


class PagingTests(SimpleTestCase):
    """Listings follow every page; a record on page two is never invisible."""

    def test_teardown_deletes_owned_records_on_every_page(self) -> None:
        fake = FakeCloudflare(page_size=2)
        for index in range(5):
            fake.add(type="TXT", name=f"_t{index}.{NAME}", content=f"v{index}", comment=OWNER)
        fake.add(id="keep", type="A", name=NAME, content="198.51.100.9", comment=OTHER_OWNER)

        with patch(SAFE_REQUEST, fake), patch(SLEEP):
            result = CloudflareDnsGateway(token="tok").delete_owned_records(ZONE, OWNER)

        self.assertTrue(result.is_ok(), result)
        self.assertEqual(len(result.unwrap()), 5)
        self.assertEqual(fake.owned(), [])
        self.assertIn("keep", fake.store)

    def test_an_unowned_conflict_on_page_two_still_fails_closed(self) -> None:
        fake = FakeCloudflare(page_size=1)
        fake.add(id="mine", type="A", name=NAME, content="203.0.113.10", comment=OWNER)
        fake.add(id="theirs", type="A", name=NAME, content="198.51.100.9", comment="operator-manual")

        outcome = reconcile(fake, [spec()])

        self.assertIsNotNone(outcome.error)
        self.assertIn("unowned", outcome.error or "")
        self.assertEqual(fake.count("PUT") + fake.count("POST") + fake.count("DELETE"), 0)

    def test_owned_duplicates_split_across_pages_are_converged(self) -> None:
        fake = FakeCloudflare(page_size=1)
        for record_id in ("d1", "d2", "d3"):
            fake.add(id=record_id, type="A", name=NAME, content="203.0.113.10", comment=OWNER)

        outcome = reconcile(fake, [spec()])

        self.assertIsNone(outcome.error)
        self.assertEqual(len(fake.owned()), 1)

    def test_a_listing_that_never_ends_is_an_error_not_a_loop(self) -> None:
        endless = MagicMock(
            return_value=FakeResponse(
                200, {"success": True, "result": [], "result_info": {"page": 1, "total_pages": 10**6}}
            )
        )
        with patch(SAFE_REQUEST, endless), patch(SLEEP):
            result = CloudflareDnsGateway(token="tok").delete_owned_records(ZONE, OWNER)

        self.assertTrue(result.is_err())
        self.assertLess(endless.call_count, 1000)


class OneNameTests(SimpleTestCase):
    """A reconcile call converges one record name; a second name is refused before any request."""

    def test_specs_for_two_names_are_refused_without_a_request(self) -> None:
        fake = FakeCloudflare()

        outcome = reconcile(fake, [spec(name=NAME), spec("AAAA", "2001:db8::1", name=f"other.{NAME}")])

        self.assertIsNotNone(outcome.error)
        self.assertIn("one record name", outcome.error or "")
        self.assertEqual(fake.calls, [])
        self.assertEqual(outcome.applied, [])

    def test_names_differing_only_in_case_are_one_name(self) -> None:
        fake = FakeCloudflare()

        outcome = reconcile(fake, [spec(name=NAME), spec("AAAA", "2001:db8::1", name=NAME.upper())])

        self.assertIsNone(outcome.error)
        self.assertEqual(len(outcome.applied), 2)


class RetriableErrorTests(SimpleTestCase):
    """429 and 5xx answers are retried, honour Retry-After, and end as typed errors."""

    def test_a_429_is_retried_after_the_advertised_delay(self) -> None:
        fake = FakeCloudflare()
        fake.fail("GET", failure(429, retry_after="2"))

        with patch(SAFE_REQUEST, fake), patch(SLEEP) as sleep:
            outcome = CloudflareDnsGateway(token="tok").reconcile_records(ZONE, [spec()], OWNER)

        self.assertIsNone(outcome.error)
        self.assertEqual(len(outcome.applied), 1)
        sleep.assert_called_once_with(2.0)
        self.assertEqual(fake.count("GET"), 2)

    def test_a_429_on_a_write_is_replayed_because_it_was_not_applied(self) -> None:
        fake = FakeCloudflare()
        fake.fail("POST", failure(429, retry_after="1"))

        outcome = reconcile(fake, [spec()])

        self.assertIsNone(outcome.error)
        self.assertEqual(len(fake.owned()), 1)
        self.assertEqual(fake.count("POST"), 2)

    def test_a_5xx_on_a_read_is_retried(self) -> None:
        fake = FakeCloudflare()
        fake.fail("GET", failure(503), failure(502))

        outcome = reconcile(fake, [spec()])

        self.assertIsNone(outcome.error)
        self.assertEqual(fake.count("GET"), 3)

    def test_a_5xx_on_a_delete_is_retried(self) -> None:
        fake = FakeCloudflare([{"id": "r1", "type": "A", "name": NAME, "content": "203.0.113.10", "comment": OWNER}])
        fake.fail("DELETE", failure(500))

        with patch(SAFE_REQUEST, fake), patch(SLEEP):
            result = CloudflareDnsGateway(token="tok").delete_owned_records(ZONE, OWNER)

        self.assertEqual(result, Ok(["r1"]))
        self.assertEqual(fake.count("DELETE"), 2)

    def test_exhausted_retries_end_as_a_typed_retriable_error_with_the_delay(self) -> None:
        fake = FakeCloudflare()
        fake.fail("GET", *(failure(429, retry_after="3") for _ in range(10)))

        outcome = reconcile(fake, [spec()], max_retries=2)

        self.assertIsNotNone(outcome.error)
        self.assertEqual(outcome.retriability, Retriability.RETRIABLE)
        self.assertEqual(outcome.retry_after_seconds, 3.0)
        self.assertEqual(fake.count("GET"), 3)  # the first attempt and two retries
        self.assertEqual(fake.count("POST"), 0)

    def test_a_delay_longer_than_the_in_process_cap_is_handed_to_the_caller(self) -> None:
        fake = FakeCloudflare()
        fake.fail("GET", failure(429, retry_after="900"))

        with patch(SAFE_REQUEST, fake), patch(SLEEP) as sleep:
            outcome = CloudflareDnsGateway(token="tok").reconcile_records(ZONE, [spec()], OWNER)

        sleep.assert_not_called()
        self.assertEqual(fake.count("GET"), 1)
        self.assertEqual(outcome.retriability, Retriability.RETRIABLE)
        self.assertEqual(outcome.retry_after_seconds, 900.0)

    def test_a_5xx_on_a_create_is_not_replayed_and_is_not_claimed_safe(self) -> None:
        # A POST that died with a 5xx may have been applied: replaying it could duplicate a record.
        fake = FakeCloudflare()
        fake.fail("POST", failure(503))

        outcome = reconcile(fake, [spec()])

        self.assertIsNotNone(outcome.error)
        self.assertEqual(fake.count("POST"), 1)
        self.assertEqual(outcome.retriability, Retriability.UNKNOWN)

    def test_a_client_error_is_not_retried(self) -> None:
        fake = FakeCloudflare()
        fake.fail("GET", failure(403))

        with patch(SAFE_REQUEST, fake), patch(SLEEP) as sleep:
            outcome = CloudflareDnsGateway(token="tok").reconcile_records(ZONE, [spec()], OWNER)

        sleep.assert_not_called()
        self.assertEqual(fake.count("GET"), 1)
        self.assertEqual(outcome.retriability, Retriability.UNKNOWN)

    def test_a_zero_retry_gateway_makes_one_attempt(self) -> None:
        fake = FakeCloudflare()
        fake.fail("GET", failure(429, retry_after="1"))

        with patch(SAFE_REQUEST, fake), patch(SLEEP) as sleep:
            result = CloudflareDnsGateway(token="tok", max_retries=0).get_zone_name(ZONE)

        sleep.assert_not_called()
        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)
        self.assertEqual(fake.count("GET"), 1)

    def test_the_zone_lookup_retries_a_5xx_then_succeeds(self) -> None:
        fake = FakeCloudflare()
        fake.fail("GET", failure(503))

        with patch(SAFE_REQUEST, fake), patch(SLEEP):
            result = CloudflareDnsGateway(token="tok").get_zone_name(ZONE)

        self.assertEqual(result, Ok("accounts.example.net"))

    def test_a_transport_error_stays_a_plain_error(self) -> None:
        def boom(*_a: Any, **_k: Any) -> Any:
            raise requests.ConnectionError("down")

        with patch(SAFE_REQUEST, boom), patch(SLEEP):
            outcome = CloudflareDnsGateway(token="tok").reconcile_records(ZONE, [spec()], OWNER)

        self.assertIn("transport error", outcome.error or "")
        self.assertEqual(outcome.retriability, Retriability.UNKNOWN)


class NodeDeployKeepsHardFailureTests(TestCase):
    """The node deploy treats any DNS error as a failed stage; typing it retriable changes nothing."""

    def test_a_retriable_reconcile_error_still_fails_the_stage(self) -> None:
        deployment = _create_deployment("provisioning_node")
        deployment.ipv4_address = "1.2.3.4"
        deployment.save()
        gateway = MagicMock()
        gateway.get_zone_name.return_value = Ok("test.example.com")
        gateway.reconcile_records.return_value = ReconcileOutcome(
            applied=[], error="cloudflare HTTP 429", retriability=Retriability.RETRIABLE, retry_after_seconds=5.0
        )

        with patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=gateway):
            result = _make_service()._configure_dns(deployment, "tok", "z1", lambda level, message: None)

        self.assertTrue(result.is_err())
        self.assertIn("DNS configuration failed: cloudflare HTTP 429", result.unwrap_err())
        self.assertEqual(retriability_of(result), Retriability.UNKNOWN)
