"""Cloudflare full-zone API with immutable bindings, complete inventories and exact record owners."""

from __future__ import annotations

import re
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import replace
from functools import wraps
from typing import Any, Protocol, cast

import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import requests
from dns.rdtypes.ANY.CAA import CAA
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.IN.SRV import SRV

from apps.common.outbound_http import OutboundSecurityError
from apps.common.types import Err, Ok, Result, Retriability
from apps.infrastructure import dns_gateway as dns_transport
from apps.infrastructure.dns_gateway import CloudflareDnsGateway

from .dns_zone_gateway import (
    ZONE_RECORD_TYPES,
    DnssecStatus,
    ProviderZoneRecord,
    ZoneBinding,
    ZoneGateway,
    ZoneIdentity,
    ZoneInventory,
    ZoneRecordSpec,
    ZoneRecordType,
    canonical_dns_name,
    canonical_rdata,
    owned_local_id,
    validate_record_spec,
)

PAGE_SIZE = 100
MAX_PAGES = 100
MAX_RECORDS = 10000
MAX_NAMESERVERS = 8
MIN_NAMESERVERS = 2
HTTP_OK = 200
HTTP_REDIRECT = 300
READ_METHODS = frozenset({"GET"})
HTTP_RATE_LIMIT = 429
HTTP_SERVER_ERROR = 500
HTTP_NOT_FOUND = 404
OPERATION_SECONDS = 90.0
MAX_RETRY_SLEEP = 30.0


class _HttpBoundary(Protocol):
    safe_request: Callable[..., requests.Response]


class ZoneProviderError(Exception):
    def __init__(
        self,
        message: str,
        retriability: Retriability = Retriability.NOT_RETRIABLE,
        *,
        http_status: int | None = None,
        path: str = "",
    ):
        super().__init__(message)
        self.retriability = retriability
        self.http_status = http_status
        self.path = path


def _result[**P, T](function: Callable[P, T]) -> Callable[P, Result[T, str]]:
    @wraps(function)
    def checked(*args: P.args, **kwargs: P.kwargs) -> Result[T, str]:
        gateway = cast("CloudflareZoneGateway", args[0])
        previous_deadline, previous_mutation = gateway._deadline, gateway._mutation_sent
        gateway._deadline = gateway._clock() + OPERATION_SECONDS
        gateway._mutation_sent = False
        try:
            value = function(*args, **kwargs)
            gateway._remaining()
            return Ok(value)
        except ZoneProviderError as error:
            return Err(str(error), retriability=error.retriability)
        except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, dns.exception.DNSException):
            # A malformed provider response may follow an applied mutation. Never replay it.
            return Err("Cloudflare customer-zone evidence is invalid or incomplete", retriability=Retriability.UNKNOWN)
        finally:
            gateway._deadline, gateway._mutation_sent = previous_deadline, previous_mutation

    return checked


def _identifier(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise ZoneProviderError("A canonical Cloudflare identifier is required")
    return value


class CloudflareZoneGateway(ZoneGateway):
    provider = "cloudflare"

    def __init__(
        self,
        token: str,
        account_id: str,
        *,
        max_retries: int = 2,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        try:
            self.account_id = _identifier(account_id)
        except ZoneProviderError as error:
            raise ValueError("The customer-zone Cloudflare account is not configured") from error
        if not isinstance(token, str) or not token.strip():
            raise ValueError("Customer-zone Cloudflare credentials are not configured")
        # Reuse only transport, TLS/host policy and explicit retry classification. The existing
        # node/name reconciler and its ownership/pagination behavior are not used for zones.
        self._transport = CloudflareDnsGateway(token=token, max_retries=max_retries)
        self._max_retries = min(2, max(0, max_retries))
        self._clock, self._sleep = clock, sleep
        self._deadline: float | None = None
        self._mutation_sent = False

    def _remaining(self) -> float:
        remaining = self._deadline - self._clock() if self._deadline is not None else 0.0
        if remaining <= 0:
            retry = Retriability.UNKNOWN if self._mutation_sent else Retriability.RETRIABLE
            raise ZoneProviderError("The complete Cloudflare operation exceeded its time budget", retry)
        return remaining

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        attempt = 0
        while True:
            remaining = self._remaining()
            policy = replace(
                self._transport._policy,
                timeout_seconds=min(self._transport._policy.timeout_seconds, remaining),
                connect_timeout_seconds=min(self._transport._policy.connect_timeout_seconds, remaining),
            )
            if method not in READ_METHODS:
                self._mutation_sent = True
            response = cast(_HttpBoundary, dns_transport).safe_request(
                method,
                f"{dns_transport.CLOUDFLARE_API_BASE}{path}",
                policy=policy,
                headers=self._transport._headers(),
                **kwargs,
            )
            remaining = self._remaining()
            retryable = response.status_code == HTTP_RATE_LIMIT or response.status_code >= HTTP_SERVER_ERROR
            if method not in READ_METHODS or not retryable or attempt >= self._max_retries:
                return response
            delay = self._transport._retry_after_seconds(response)
            delay = delay if delay is not None else float(2**attempt)
            if delay > MAX_RETRY_SLEEP or delay >= remaining:
                raise ZoneProviderError(
                    "Cloudflare retry must be deferred beyond this call budget", Retriability.RETRIABLE
                )
            self._sleep(delay)
            attempt += 1

    def _send(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self._request(method, path, **kwargs)
        except (requests.RequestException, OutboundSecurityError) as error:
            retry = Retriability.RETRIABLE if method in READ_METHODS else Retriability.UNKNOWN
            raise ZoneProviderError("Cloudflare customer-zone request could not be confirmed", retry) from error
        if response.status_code == HTTP_RATE_LIMIT:
            raise ZoneProviderError("Cloudflare customer-zone request was rate limited", Retriability.RETRIABLE)
        if response.status_code >= HTTP_SERVER_ERROR:
            retry = Retriability.RETRIABLE if method in READ_METHODS else Retriability.UNKNOWN
            raise ZoneProviderError("Cloudflare customer-zone mutation outcome is uncertain", retry)
        if not HTTP_OK <= response.status_code < HTTP_REDIRECT:
            raise ZoneProviderError(
                "Cloudflare customer-zone request was refused", http_status=response.status_code, path=path
            )
        try:
            body = self._transport._safe_json(response)
        except ValueError as error:
            retry = Retriability.RETRIABLE if method == "GET" else Retriability.UNKNOWN
            raise ZoneProviderError("Cloudflare customer-zone response could not be confirmed", retry) from error
        if not isinstance(body, dict) or body.get("success") is not True or "result" not in body:
            raise ZoneProviderError("Cloudflare customer-zone response did not confirm success", Retriability.UNKNOWN)
        return body

    def _check_account(self, account_id: str) -> None:
        if _identifier(account_id) != self.account_id:
            raise ZoneProviderError("The customer zone belongs to another configured Cloudflare account")

    def _check_binding(self, binding: ZoneBinding) -> None:
        self._check_account(binding.account_id)
        _identifier(binding.zone_id)
        if binding.provider != self.provider or canonical_dns_name(binding.name) != binding.name:
            raise ZoneProviderError("The persisted customer-zone provider binding is invalid")

    def _identity(self, data: dict[str, Any], *, expected_name: str | None = None) -> ZoneIdentity:
        zone_id = _identifier(data["id"])
        account_id = _identifier(data["account"]["id"])
        self._check_account(account_id)
        name = canonical_dns_name(data["name"])
        if (expected_name is not None and name != expected_name) or data.get("type") != "full":
            raise ZoneProviderError("The Cloudflare zone does not match the persisted full-zone identity")
        status = data["status"]
        servers = data["name_servers"]
        if (
            not isinstance(status, str)
            or not status
            or not isinstance(servers, list)
            or not servers
            or len(servers) > MAX_NAMESERVERS
        ):
            raise ValueError("Missing Cloudflare zone activation evidence")
        canonical_servers = tuple(canonical_dns_name(server) for server in servers)
        if len(canonical_servers) < MIN_NAMESERVERS or len(set(canonical_servers)) != len(canonical_servers):
            raise ValueError("Cloudflare full zones require distinct assigned nameservers")
        nameservers = tuple(sorted(canonical_servers))
        plan = data.get("plan", {})
        description = str(plan.get("legacy_id", plan.get("name", "free"))).lower() if isinstance(plan, dict) else "free"
        return ZoneIdentity(
            ZoneBinding(self.provider, account_id, zone_id, name),
            status,
            nameservers,
            "free" if "free" in description else "paid",
        )

    def _read_zone(self, binding: ZoneBinding) -> ZoneIdentity:
        self._check_binding(binding)
        identity = self._identity(self._send("GET", f"/zones/{binding.zone_id}")["result"], expected_name=binding.name)
        if identity.binding != binding:
            raise ZoneProviderError("Cloudflare returned a different provider, account or zone binding")
        return identity

    def _pages(self, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        ids: set[str] = set()
        expected: tuple[int, int, int] | None = None
        for page in range(1, MAX_PAGES + 1):
            body = self._send("GET", path, params={**params, "page": page, "per_page": PAGE_SIZE})
            batch, info = body["result"], body.get("result_info")
            if not isinstance(batch, list) or not isinstance(info, dict):
                raise ZoneProviderError("Cloudflare inventory completeness metadata is missing")
            fields = [info.get(key) for key in ("page", "per_page", "count", "total_count", "total_pages")]
            if any(type(value) is not int for value in fields):
                raise ZoneProviderError("Cloudflare inventory completeness metadata is invalid")
            number, size, count, total, pages = [cast(int, value) for value in fields]
            if (
                number != page
                or not 1 <= size <= PAGE_SIZE
                or count != len(batch)
                or not 0 <= total <= MAX_RECORDS
                or not 0 <= pages <= MAX_PAGES
                or (pages != max(1, (total + size - 1) // size) and not (total == 0 and pages == 0))
                or count != min(size, max(0, total - (page - 1) * size))
            ):
                raise ZoneProviderError("Cloudflare inventory pagination is inconsistent")
            metadata = (size, total, pages)
            if expected is not None and metadata != expected:
                raise ZoneProviderError("Cloudflare inventory changed during pagination")
            expected = metadata
            for row in batch:
                if not isinstance(row, dict):
                    raise ZoneProviderError("Cloudflare inventory contains an invalid entry")
                row_id = _identifier(row.get("id"))
                if row_id in ids:
                    raise ZoneProviderError("Cloudflare inventory repeated a record or page")
                ids.add(row_id)
                rows.append(row)
            if page >= pages:
                if len(rows) != total:
                    raise ZoneProviderError("Cloudflare inventory is truncated")
                return rows
        raise ZoneProviderError("Cloudflare inventory exceeds the complete-list limit")

    @_result
    def list_zones(self, account_id: str, name: str) -> tuple[ZoneIdentity, ...]:
        self._check_account(account_id)
        name = canonical_dns_name(name)
        rows = self._pages("/zones", {"account.id": account_id, "name": name, "match": "all"})
        return tuple(self._identity(row, expected_name=name) for row in rows)

    @_result
    def read_zone(self, binding: ZoneBinding) -> ZoneIdentity:
        return self._read_zone(binding)

    @_result
    def create_zone(self, account_id: str, name: str) -> ZoneIdentity:
        self._check_account(account_id)
        name = canonical_dns_name(name)
        if self._pages("/zones", {"account.id": account_id, "name": name, "match": "all"}):
            raise ZoneProviderError("A Cloudflare zone already exists; it cannot be adopted by this import")
        result = self._send("POST", "/zones", json={"account": {"id": account_id}, "name": name, "type": "full"})
        return self._identity(result["result"], expected_name=name)

    def _confirmed_id(self, body: dict[str, Any], expected: str) -> None:
        if not isinstance(body["result"], dict) or body["result"].get("id") != expected:
            raise ZoneProviderError("Cloudflare did not confirm the requested mutation", Retriability.UNKNOWN)

    @_result
    def delete_zone(self, binding: ZoneBinding, *, expected_records: tuple[ZoneRecordSpec, ...] | None = None) -> None:
        path = f"/zones/{binding.zone_id}"
        try:
            self._read_zone(binding)
            if expected_records is not None:
                expected = tuple(self._validated(binding, record) for record in expected_records)
                if len({record.local_id for record in expected}) != len(expected):
                    raise ZoneProviderError("The expected customer-zone inventory has duplicate owners")
                # The earlier move-away proof may precede a long TTL wait. Repeat the complete
                # inventory immediately before deletion, under this operation's same 90s deadline.
                current = tuple(self._record(binding, row).spec for row in self._pages(path + "/dns_records", {}))
                if Counter(current) != Counter(expected):
                    raise ZoneProviderError(
                        "The customer-zone inventory changed before deletion", Retriability.NOT_RETRIABLE
                    )
            self._confirmed_id(self._send("DELETE", path), binding.zone_id)
        except ZoneProviderError as error:
            if error.http_status != HTTP_NOT_FOUND or error.path != path:
                raise

    @_result
    def trigger_activation(self, binding: ZoneBinding) -> None:
        self._read_zone(binding)
        self._confirmed_id(self._send("PUT", f"/zones/{binding.zone_id}/activation_check"), binding.zone_id)

    @staticmethod
    def _record_text(data: dict[str, Any], kind: str) -> str:
        if kind == "MX":
            return f"{data['priority']} {str(data['content']).rstrip('.')}."
        if kind == "SRV":
            srv = data["data"]
            return f"{srv['priority']} {srv['weight']} {srv['port']} {str(srv['target']).rstrip('.')}."
        if kind == "CAA":
            caa = data["data"]
            if type(caa["flags"]) is not int or not isinstance(caa["tag"], str) or not isinstance(caa["value"], str):
                raise ValueError("Invalid Cloudflare CAA fields")
            tag = caa["tag"].encode("ascii")
            wire = bytes([caa["flags"], len(tag)]) + tag + caa["value"].encode("utf-8")
            record = dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.CAA, wire, 0, len(wire))
            return record.to_text()
        content = data["content"]
        if not isinstance(content, str):
            raise ValueError("Cloudflare record content is invalid")
        return content.rstrip(".") + "." if kind == "CNAME" else content

    def _record(self, binding: ZoneBinding, data: dict[str, Any]) -> ProviderZoneRecord:
        record_id = _identifier(data["id"])
        kind = data["type"]
        if not isinstance(kind, str) or kind not in ZONE_RECORD_TYPES:
            raise ZoneProviderError("The complete zone contains a record type this adapter cannot preserve")
        name = canonical_dns_name(data["name"])
        if not dns.name.from_text(name).is_subdomain(dns.name.from_text(binding.name)):
            raise ZoneProviderError("Cloudflare returned a record outside the persisted zone")
        if (
            data.get("zone_id", binding.zone_id) != binding.zone_id
            or data.get("zone_name", binding.name) != binding.name
        ):
            raise ZoneProviderError("Cloudflare returned a record from another zone")
        ttl, proxied = data["ttl"], data.get("proxied", False)
        if type(ttl) is not int or ttl < 1 or type(proxied) is not bool:
            raise ValueError("Cloudflare record TTL or proxy state is invalid")
        owner = data.get("comment") or ""
        if not isinstance(owner, str):
            raise ValueError("Cloudflare record owner is invalid")
        try:
            local_id = owned_local_id(owner)
        except ValueError:
            local_id = ""
        record = ZoneRecordSpec(
            local_id,
            name,
            cast(ZoneRecordType, kind),
            ttl,
            canonical_rdata(kind, self._record_text(data, kind), origin=binding.name),
            owner,
            proxied,
        )
        return ProviderZoneRecord(record_id, record)

    @_result
    def list_records(self, binding: ZoneBinding) -> ZoneInventory:
        identity = self._read_zone(binding)
        return ZoneInventory(
            identity,
            tuple(self._record(binding, row) for row in self._pages(f"/zones/{binding.zone_id}/dns_records", {})),
        )

    def _get_record(self, binding: ZoneBinding, record_id: str, owner: str | None) -> ProviderZoneRecord:
        self._read_zone(binding)
        _identifier(record_id)
        record = self._record(binding, self._send("GET", f"/zones/{binding.zone_id}/dns_records/{record_id}")["result"])
        if record.id != record_id or (owner is not None and record.spec.owner_tag != owner):
            raise ZoneProviderError("The Cloudflare record is not owned by this local customer-zone record")
        return record

    @_result
    def get_record(
        self, binding: ZoneBinding, record_id: str, *, expected_owner_tag: str | None = None
    ) -> ProviderZoneRecord:
        return self._get_record(binding, record_id, expected_owner_tag)

    @staticmethod
    def _payload(spec: ZoneRecordSpec) -> dict[str, Any]:
        record = dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.from_text(spec.record_type), spec.rdata, relativize=False
        )
        payload: dict[str, Any] = {
            "name": spec.name,
            "type": spec.record_type,
            "ttl": spec.ttl,
            "comment": spec.owner_tag,
        }
        if spec.record_type in {"A", "AAAA", "CNAME"}:
            payload.update(content=record.to_text().rstrip("."), proxied=False)
        elif spec.record_type == "MX":
            mx = cast(MX, record)
            payload.update(content=mx.exchange.to_text(omit_final_dot=True) or ".", priority=mx.preference)
        elif spec.record_type == "TXT":
            payload["content"] = record.to_text()
        elif spec.record_type == "SRV":
            srv = cast(SRV, record)
            payload["data"] = {
                "priority": srv.priority,
                "weight": srv.weight,
                "port": srv.port,
                "target": srv.target.to_text(omit_final_dot=True),
            }
        else:
            caa = cast(CAA, record)
            payload["data"] = {"flags": caa.flags, "tag": caa.tag.decode("ascii"), "value": caa.value.decode("utf-8")}
        return payload

    @staticmethod
    def _validated(binding: ZoneBinding, spec: ZoneRecordSpec) -> ZoneRecordSpec:
        checked = validate_record_spec(spec, zone_name=binding.name)
        if checked.is_err():
            raise ZoneProviderError(checked.unwrap_err())
        return checked.unwrap()

    def _confirmed_record(
        self, binding: ZoneBinding, body: dict[str, Any], expected: ZoneRecordSpec
    ) -> ProviderZoneRecord:
        record = self._record(binding, body["result"])
        if replace(record.spec, ttl=expected.ttl) != expected:
            raise ZoneProviderError("Cloudflare did not confirm the complete desired record", Retriability.UNKNOWN)
        return record

    def _owned_readback(self, binding: ZoneBinding, record_id: str, expected: ZoneRecordSpec) -> ProviderZoneRecord:
        record = self._get_record(binding, record_id, expected.owner_tag)
        if replace(record.spec, ttl=expected.ttl) != expected:
            raise ZoneProviderError("Cloudflare routing or owner differs from the desired record", Retriability.UNKNOWN)
        return record

    @_result
    def create_record(self, binding: ZoneBinding, spec: ZoneRecordSpec) -> ProviderZoneRecord:
        spec = self._validated(binding, spec)
        self._read_zone(binding)
        body = self._send("POST", f"/zones/{binding.zone_id}/dns_records", json=self._payload(spec))
        acknowledged = self._confirmed_record(binding, body, spec)
        return self._owned_readback(binding, acknowledged.id, spec)

    @_result
    def update_record(self, binding: ZoneBinding, record_id: str, spec: ZoneRecordSpec) -> ProviderZoneRecord:
        spec = self._validated(binding, spec)
        self._get_record(binding, record_id, spec.owner_tag)
        try:
            body = self._send("PUT", f"/zones/{binding.zone_id}/dns_records/{record_id}", json=self._payload(spec))
            record = self._confirmed_record(binding, body, spec)
            if record.id != record_id:
                raise ZoneProviderError("Cloudflare returned another record after the update", Retriability.UNKNOWN)
            record = self._owned_readback(binding, record_id, spec)
        except (ZoneProviderError, ValueError, TypeError, KeyError, UnicodeError, dns.exception.DNSException) as error:
            if isinstance(error, ZoneProviderError) and error.retriability is not Retriability.UNKNOWN:
                raise
            try:
                record = self._owned_readback(binding, record_id, spec)
            except (ZoneProviderError, ValueError, TypeError, KeyError, dns.exception.DNSException) as observed:
                raise ZoneProviderError(
                    "Cloudflare update ownership or outcome is uncertain", Retriability.UNKNOWN
                ) from observed
        return record

    @_result
    def delete_record(self, binding: ZoneBinding, record_id: str, *, expected_owner_tag: str) -> None:
        owned_local_id(expected_owner_tag)
        path = f"/zones/{binding.zone_id}/dns_records/{record_id}"
        try:
            self._get_record(binding, record_id, expected_owner_tag)
            self._confirmed_id(self._send("DELETE", path), record_id)
        except ZoneProviderError as error:
            # _get_record proves the zone binding first. Its record-level 404 is absence;
            # a forbidden/unreadable/missing zone never becomes record-deletion evidence.
            if error.http_status != HTTP_NOT_FOUND or error.path != path:
                raise

    @_result
    def get_dnssec(self, binding: ZoneBinding) -> DnssecStatus:
        self._read_zone(binding)
        data = self._send("GET", f"/zones/{binding.zone_id}/dnssec")["result"]
        if data.get("status") not in {"active", "pending", "disabled", "pending-disabled", "error"}:
            raise ValueError("Unknown Cloudflare DNSSEC state")
        ds = data.get("ds") or ""
        if not isinstance(ds, str):
            raise ValueError("Invalid Cloudflare DS value")
        details = {
            key: data[key] for key in ("key_tag", "algorithm", "digest", "digest_type", "public_key") if key in data
        }
        return DnssecStatus(data["status"], ds, details)
