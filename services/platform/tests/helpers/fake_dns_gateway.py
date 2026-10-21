"""An in-memory DNS provider for tests, registered under its own provider name.

It keeps the contract the Cloudflare gateway keeps: records are owned by a tag, an owned set is
converged to exactly the desired specs, and an unowned record on the same name is never touched
(the reconcile fails closed). Zones and failures are set per test through class attributes.
"""

from __future__ import annotations

import itertools
from typing import Any, ClassVar

from apps.common.types import Err, Ok, Result
from apps.infrastructure.dns_gateway import (
    DNS_RECORD_TTL_SECONDS,
    DnsProviderGateway,
    DnsRecordResult,
    DnsRecordSpec,
    DnsRecordType,
    ReconcileOutcome,
)

FAKE_PROVIDER = "fake"


class FakeDnsGateway(DnsProviderGateway):
    provider = FAKE_PROVIDER
    zones: ClassVar[dict[str, str]] = {}  # zone id -> zone name the token can read
    records: ClassVar[dict[str, dict[str, Any]]] = {}  # record id -> {zone_id, type, name, content, ttl, owner}
    calls: ClassVar[list[str]] = []
    fail_reconcile: ClassVar[str | None] = None
    _ids = itertools.count(1)

    def __init__(self, token: str, **kwargs: Any) -> None:
        self.token = token

    @classmethod
    def reset(cls, zones: dict[str, str] | None = None) -> None:
        cls.zones = dict(zones or {})
        cls.records = {}
        cls.calls = []
        cls.fail_reconcile = None

    def get_zone_name(self, zone_id: str) -> Result[str, str]:
        self.calls.append(f"zone {zone_id}")
        if zone_id not in self.zones:
            return Err("zone not readable with this token")
        return Ok(self.zones[zone_id])

    def reconcile_records(self, zone_id: str, specs: list[DnsRecordSpec], owner_tag: str) -> ReconcileOutcome:
        self.calls.append(f"reconcile {zone_id} {owner_tag} {[(s.record_type, s.content) for s in specs]}")
        outcome = ReconcileOutcome()
        if self.fail_reconcile:
            outcome.error = self.fail_reconcile
            return outcome
        names = {spec.name for spec in specs}
        for record in self.records.values():
            if record["zone_id"] == zone_id and record["name"] in names and record["owner"] != owner_tag:
                outcome.error = f"unowned record on {record['name']}"
                return outcome
        desired = {(spec.record_type, spec.name): spec for spec in specs}
        for record_id, record in list(self.records.items()):
            owned = record["zone_id"] == zone_id and record["owner"] == owner_tag
            if owned and (record["type"], record["name"]) not in desired:
                del self.records[record_id]
        for (record_type, name), spec in desired.items():
            existing = next(
                (
                    (rid, r)
                    for rid, r in self.records.items()
                    if r["zone_id"] == zone_id
                    and r["owner"] == owner_tag
                    and (r["type"], r["name"]) == (record_type, name)
                ),
                None,
            )
            record_id = existing[0] if existing else str(next(self._ids))
            self.records[record_id] = {
                "zone_id": zone_id,
                "type": record_type,
                "name": name,
                "content": spec.content,
                "ttl": spec.ttl,
                "owner": owner_tag,
            }
            outcome.applied.append(
                DnsRecordResult(
                    provider=self.provider,
                    zone_id=zone_id,
                    record_id=record_id,
                    record_type=record_type,
                    name=name,
                    content=spec.content,
                    owner_tag=owner_tag,
                    ttl=spec.ttl,
                )
            )
        return outcome

    def delete_owned_records(self, zone_id: str, owner_tag: str) -> Result[list[str], str]:
        self.calls.append(f"delete {zone_id} {owner_tag}")
        deleted = [rid for rid, r in self.records.items() if r["zone_id"] == zone_id and r["owner"] == owner_tag]
        for record_id in deleted:
            del self.records[record_id]
        return Ok(deleted)

    def reconcile_txt_values(
        self, zone_id: str, name: str, values: list[str], owner_tag: str, *, ttl: int = DNS_RECORD_TTL_SECONDS
    ) -> ReconcileOutcome:
        self.calls.append(f"txt {zone_id} {name} {owner_tag} {sorted(values)}")
        for record_id, record in list(self.records.items()):
            if (record["zone_id"], record["type"], record["name"], record["owner"]) == (
                zone_id,
                "TXT",
                name,
                owner_tag,
            ):
                del self.records[record_id]
        outcome = ReconcileOutcome()
        for value in values:
            record_id = str(next(self._ids))
            self.records[record_id] = {
                "zone_id": zone_id,
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": ttl,
                "owner": owner_tag,
            }
            outcome.applied.append(
                DnsRecordResult(
                    provider=self.provider,
                    zone_id=zone_id,
                    record_id=record_id,
                    record_type="TXT",
                    name=name,
                    content=value,
                    owner_tag=owner_tag,
                    ttl=ttl,
                )
            )
        return outcome

    def sweep_owned_records(
        self,
        zone_id: str,
        owner_prefix: str,
        *,
        keep_owner_tags: frozenset[str],
        min_age_seconds: float,
        record_type: DnsRecordType = "TXT",
    ) -> Result[list[str], str]:
        # Records here have no age: every unkept one counts as old enough.
        self.calls.append(f"sweep {zone_id} {owner_prefix}")
        stale = [
            rid
            for rid, r in self.records.items()
            if r["zone_id"] == zone_id
            and r["type"] == record_type
            and r["owner"].startswith(owner_prefix)
            and r["owner"] not in keep_owner_tags
        ]
        for record_id in stale:
            del self.records[record_id]
        return Ok(stale)

    @classmethod
    def published(cls, name: str) -> dict[str, str]:
        return {r["type"]: r["content"] for r in cls.records.values() if r["name"] == name}
