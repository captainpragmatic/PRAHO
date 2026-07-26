"""Tests for the Cloudflare DNS gateway (#347 GAP 3).

These mock ONLY the network seam (``dns_gateway.safe_request``) so every
assertion flows through the real gateway logic: ownership scoping, idempotent
upsert, replay dedupe, fail-closed on unowned records, and partial-outcome
persistence. A faithful in-memory ``FakeCloudflare`` stands in for the API so
tests express desired end-state, not brittle call ordering.
"""

from __future__ import annotations

import itertools
import json as _json
from typing import Any
from unittest.mock import patch

import requests
from django.test import SimpleTestCase

from apps.common.outbound_http import OutboundSecurityError
from apps.infrastructure.dns_gateway import (
    CLOUDFLARE_API_BASE,
    CloudflareDnsGateway,
    DnsRecordSpec,
    DnsRecordType,
    get_dns_gateway,
)

_OWNER = "praho:node-deploy:abc-123"
_ZONE = "zone123"
_FQDN = "node1.hosting.example.com"


class _Resp:
    """Minimal requests.Response stand-in."""

    def __init__(self, status: int, body: Any, *, bad_json: bool = False) -> None:
        self.status_code = status
        self._body = body
        self._bad_json = bad_json
        raw = "" if bad_json else _json.dumps(body)
        self.content = raw.encode()
        self.headers: dict[str, str] = {"content-length": str(len(self.content))}

    def json(self) -> Any:
        if self._bad_json:
            raise ValueError("no json")
        return self._body


class FakeCloudflare:
    """In-memory Cloudflare v4 DNS double, callable as ``safe_request``."""

    def __init__(
        self,
        records: list[dict[str, Any]] | None = None,
        *,
        post_fail_types: set[str] | None = None,
        post_raise_types: set[str] | None = None,
        post_badjson_types: set[str] | None = None,
        zone_success: bool = True,
    ) -> None:
        self._ids = itertools.count(1)
        self.store: dict[str, dict[str, Any]] = {}
        for r in records or []:
            rid = r.get("id") or f"seed{next(self._ids)}"
            self.store[rid] = {**r, "id": rid}
        self.post_fail_types = post_fail_types or set()
        self.post_raise_types = post_raise_types or set()
        self.post_badjson_types = post_badjson_types or set()
        self.zone_success = zone_success
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method: str, url: str, *, policy: Any = None, headers: Any = None, **kwargs: Any) -> _Resp:
        path = url.replace(CLOUDFLARE_API_BASE, "")
        self.calls.append((method, path))
        params = kwargs.get("params") or {}
        body = kwargs.get("json") or {}
        records_path = f"/zones/{_ZONE}/dns_records"
        if method == "GET" and path == f"/zones/{_ZONE}":
            return self._get_zone()
        if method == "GET" and path == records_path:
            return self._list(params)
        if method == "POST" and path == records_path:
            return self._create(body)
        if method == "PUT" and path.startswith(f"{records_path}/"):
            return self._update(path.rsplit("/", 1)[-1], body)
        if method == "DELETE" and path.startswith(f"{records_path}/"):
            return self._delete(path.rsplit("/", 1)[-1])
        return _Resp(404, {"success": False, "errors": [{"message": f"unhandled {method} {path}"}]})

    def _get_zone(self) -> _Resp:
        if not self.zone_success:
            return _Resp(403, {"success": False, "errors": [{"message": "not authorized"}]})
        return _Resp(200, {"success": True, "result": {"id": _ZONE, "name": "hosting.example.com"}})

    def _list(self, params: dict[str, Any]) -> _Resp:
        matched = [
            r
            for r in self.store.values()
            if ("name" not in params or r["name"] == params["name"])
            and ("type" not in params or r["type"] == params["type"])
            and ("comment.exact" not in params or r.get("comment") == params["comment.exact"])
        ]
        return _Resp(200, {"success": True, "result": matched})

    def _create(self, body: dict[str, Any]) -> _Resp:
        rtype = body.get("type")
        if rtype in self.post_raise_types:
            raise requests.ConnectionError("boom")
        if rtype in self.post_badjson_types:
            return _Resp(200, {}, bad_json=True)
        if rtype in self.post_fail_types:
            return _Resp(400, {"success": False, "errors": [{"message": "bad"}]})
        rid = f"new{next(self._ids)}"
        rec = {
            "id": rid,
            "type": rtype,
            "name": body["name"],
            "content": body["content"],
            "comment": body.get("comment", ""),
        }
        self.store[rid] = rec
        return _Resp(200, {"success": True, "result": rec})

    def _update(self, rid: str, body: dict[str, Any]) -> _Resp:
        self.store[rid] = {**self.store[rid], "content": body["content"], "comment": body.get("comment", "")}
        return _Resp(200, {"success": True, "result": self.store[rid]})

    def _delete(self, rid: str) -> _Resp:
        if self.store.pop(rid, None) is None:
            return _Resp(404, {"success": False, "errors": [{"code": 81044}]})
        return _Resp(200, {"success": True, "result": {"id": rid}})

    # convenience
    def owned(self, owner: str = _OWNER) -> list[dict[str, Any]]:
        return [r for r in self.store.values() if r.get("comment") == owner]

    def n_posts(self) -> int:
        return sum(1 for m, _ in self.calls if m == "POST")


def _spec(rtype: DnsRecordType, content: str, owner: str = _OWNER) -> DnsRecordSpec:
    return DnsRecordSpec(record_type=rtype, name=_FQDN, content=content, owner_tag=owner)


class GetDnsGatewayFactoryTests(SimpleTestCase):
    def test_resolves_cloudflare(self) -> None:
        gw = get_dns_gateway("cloudflare", "tok")
        self.assertIsInstance(gw, CloudflareDnsGateway)

    def test_unknown_provider_raises(self) -> None:
        with self.assertRaises(ValueError):
            get_dns_gateway("route53", "tok")


class ReconcileRecordsTests(SimpleTestCase):
    def _gw(self) -> CloudflareDnsGateway:
        return CloudflareDnsGateway(token="tok")

    def test_create_when_no_owned_record_posts(self) -> None:
        fake = FakeCloudflare()
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNone(out.error)
        self.assertEqual(len(out.applied), 1)
        self.assertEqual(out.applied[0].content, "203.0.113.10")
        self.assertEqual(out.applied[0].owner_tag, _OWNER)
        self.assertEqual(len(fake.owned()), 1)

    def test_idempotent_update_uses_put_not_post(self) -> None:
        # An owned A already exists with a stale IP → reconcile must PUT, never POST.
        fake = FakeCloudflare(
            [{"type": "A", "name": _FQDN, "content": "203.0.113.1", "comment": _OWNER}]
        )
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNone(out.error)
        self.assertEqual(fake.n_posts(), 0)  # discriminator: no create
        self.assertEqual(len(fake.owned()), 1)
        self.assertEqual(fake.owned()[0]["content"], "203.0.113.10")

    def test_dedupe_owned_duplicates_from_replay(self) -> None:
        # Two owned A records (a prior POST replay) → converge to exactly one.
        fake = FakeCloudflare(
            [
                {"id": "dup1", "type": "A", "name": _FQDN, "content": "203.0.113.10", "comment": _OWNER},
                {"id": "dup2", "type": "A", "name": _FQDN, "content": "203.0.113.10", "comment": _OWNER},
            ]
        )
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNone(out.error)
        self.assertEqual(len(fake.owned()), 1)
        self.assertEqual(len(out.applied), 1)

    def test_owned_but_no_longer_desired_is_deleted(self) -> None:
        # Owned A + owned AAAA exist; retry desires only A → AAAA removed.
        fake = FakeCloudflare(
            [
                {"type": "A", "name": _FQDN, "content": "203.0.113.10", "comment": _OWNER},
                {"type": "AAAA", "name": _FQDN, "content": "2001:db8::1", "comment": _OWNER},
            ]
        )
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNone(out.error)
        types = sorted(r["type"] for r in fake.owned())
        self.assertEqual(types, ["A"])

    def test_unowned_record_fails_closed(self) -> None:
        # An operator's unowned A for the same fqdn must never be touched.
        fake = FakeCloudflare(
            [{"id": "op1", "type": "A", "name": _FQDN, "content": "198.51.100.9", "comment": "operator-manual"}]
        )
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNotNone(out.error)
        # The operator record is intact and untouched.
        self.assertIn("op1", fake.store)
        self.assertEqual(fake.store["op1"]["content"], "198.51.100.9")

    def test_partial_failure_returns_applied_a_before_failing_aaaa(self) -> None:
        # A succeeds, AAAA POST fails → applied carries A so it is not leaked.
        fake = FakeCloudflare(post_fail_types={"AAAA"})
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(
                _ZONE, [_spec("A", "203.0.113.10"), _spec("AAAA", "2001:db8::1")], _OWNER
            )
        self.assertIsNotNone(out.error)
        self.assertEqual([r.record_type for r in out.applied], ["A"])

    def test_success_false_envelope_is_error(self) -> None:
        fake = FakeCloudflare(post_fail_types={"A"})
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNotNone(out.error)
        self.assertEqual(out.applied, [])

    def test_malformed_json_is_error(self) -> None:
        fake = FakeCloudflare(post_badjson_types={"A"})
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNotNone(out.error)

    def test_transport_exception_is_error_not_raised(self) -> None:
        fake = FakeCloudflare(post_raise_types={"A"})
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNotNone(out.error)

    def test_security_error_is_caught(self) -> None:
        def boom(*_a: Any, **_k: Any) -> Any:
            raise OutboundSecurityError("blocked")

        with patch("apps.infrastructure.dns_gateway.safe_request", boom):
            out = self._gw().reconcile_records(_ZONE, [_spec("A", "203.0.113.10")], _OWNER)
        self.assertIsNotNone(out.error)


class DeleteOwnedRecordsTests(SimpleTestCase):
    def _gw(self) -> CloudflareDnsGateway:
        return CloudflareDnsGateway(token="tok")

    def test_deletes_only_owned_by_tag(self) -> None:
        fake = FakeCloudflare(
            [
                {"id": "a1", "type": "A", "name": _FQDN, "content": "203.0.113.10", "comment": _OWNER},
                {"id": "a2", "type": "AAAA", "name": _FQDN, "content": "2001:db8::1", "comment": _OWNER},
                {"id": "op1", "type": "A", "name": _FQDN, "content": "198.51.100.9", "comment": "operator-manual"},
            ]
        )
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            res = self._gw().delete_owned_records(_ZONE, _OWNER)
        self.assertTrue(res.is_ok())
        self.assertEqual(sorted(res.unwrap()), ["a1", "a2"])
        self.assertIn("op1", fake.store)  # operator record untouched

    def test_get_zone_name_ok(self) -> None:
        fake = FakeCloudflare()
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            res = self._gw().get_zone_name(_ZONE)
        self.assertTrue(res.is_ok())
        self.assertEqual(res.unwrap(), "hosting.example.com")

    def test_get_zone_name_unauthorized_is_err(self) -> None:
        fake = FakeCloudflare(zone_success=False)
        with patch("apps.infrastructure.dns_gateway.safe_request", fake):
            res = self._gw().get_zone_name(_ZONE)
        self.assertTrue(res.is_err())
