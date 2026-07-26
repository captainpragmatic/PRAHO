"""
DNS Provider Gateway — Abstract Base Class + Factory

Unified interface for creating/reconciling the DNS records a freshly deployed
node needs (its own A / AAAA record), plus owner-scoped teardown. Mirrors the
``cloud_gateway`` ABC/registry/factory idiom and the ``domains.gateways`` HTTP
pattern (``safe_request`` + ``OutboundPolicy`` + size-guarded JSON).

Ownership model (why every record carries an owner tag):
    Cloudflare allows multiple A/AAAA records for one hostname, and
    ``safe_request`` can replay a POST after a DNS-fallback on ConnectionError
    (outbound_http.py send()), so a create can silently produce a duplicate.
    Every record this gateway writes carries ``comment = <owner_tag>``. The
    gateway only ever mutates/deletes records bearing the caller's owner tag;
    an *unowned* record on the same name is never touched (fail closed), and
    duplicate *owned* records are converged to one. Teardown is owner-tag
    authoritative: it deletes every record in the stored zone bearing the tag,
    which also reclaims replay orphans.

See #347 GAP 3. Let's Encrypt / cert issuance is out of scope here (#436).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

import requests

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, safe_request
from apps.common.types import Err, Ok, Result

logger = logging.getLogger(__name__)

DnsRecordType = Literal["A", "AAAA"]

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"

# Non-retrying policy: safe_request's DNS-fallback would otherwise replay a POST
# (outbound_http send()), so we keep mutations single-shot and reconcile by
# owner tag afterwards rather than trusting a single response.
CLOUDFLARE_POLICY = OutboundPolicy(
    name="cloudflare_dns",
    require_https=True,
    allowed_domains=frozenset({"api.cloudflare.com"}),
    timeout_seconds=30.0,
    connect_timeout_seconds=10.0,
    verify_tls=True,
    max_retries=0,
)

_DEFAULT_TTL = 60
_MAX_RESPONSE_SIZE_BYTES = 256 * 1024
_HTTP_NOT_FOUND = 404


# =============================================================================
# Provider-agnostic dataclasses
# =============================================================================


@dataclass(frozen=True)
class DnsRecordSpec:
    """A desired DNS record for a node's fqdn."""

    record_type: DnsRecordType
    name: str
    content: str
    owner_tag: str
    ttl: int = _DEFAULT_TTL
    proxied: bool = False


@dataclass(frozen=True)
class DnsRecordResult:
    """A record that actually exists in the provider after reconciliation."""

    provider: str
    zone_id: str
    record_id: str
    record_type: DnsRecordType
    name: str
    content: str
    owner_tag: str

    def as_provenance(self) -> dict[str, str]:
        """Structured entry persisted to ``NodeDeployment.dns_record_ids``.

        Stores the zone_id per record so teardown deletes in the record's own
        zone, never the (possibly changed) current setting.
        """
        return {
            "provider": self.provider,
            "zone_id": self.zone_id,
            "record_id": self.record_id,
            "type": self.record_type,
            "name": self.name,
            "owner_tag": self.owner_tag,
        }


@dataclass
class ReconcileOutcome:
    """Result of reconciling a desired record set.

    ``applied`` carries every record confirmed to exist even when ``error`` is
    set — so a caller can persist the A record it did create before failing the
    deploy because AAAA failed (avoids leaking the A record).
    """

    applied: list[DnsRecordResult] = field(default_factory=list)
    error: str | None = None


# =============================================================================
# Abstract Base Class
# =============================================================================


class DnsProviderGateway(ABC):
    """Abstract gateway for node DNS record management."""

    provider: str

    @abstractmethod
    def __init__(self, token: str, **kwargs: Any) -> None: ...

    @abstractmethod
    def get_zone_name(self, zone_id: str) -> Result[str, str]:
        """Read-only zone lookup (preflight): confirm token access + return the zone name."""

    @abstractmethod
    def reconcile_records(self, zone_id: str, specs: list[DnsRecordSpec], owner_tag: str) -> ReconcileOutcome:
        """Converge the owned record set for ``owner_tag`` to exactly ``specs``.

        Create missing, update drifted, delete owned-but-no-longer-desired, and
        dedupe owned duplicates. Never touches an unowned record on the same
        name (fail closed). Returns applied records + optional error.
        """

    @abstractmethod
    def delete_owned_records(self, zone_id: str, owner_tag: str) -> Result[list[str], str]:
        """Delete every record in ``zone_id`` bearing ``owner_tag``; return deleted ids."""


# =============================================================================
# Cloudflare implementation
# =============================================================================


class CloudflareDnsGateway(DnsProviderGateway):
    """Cloudflare DNS gateway over the v4 REST API (Bearer token)."""

    provider = "cloudflare"

    def __init__(self, token: str, **kwargs: Any) -> None:
        self._token = token

    # -- HTTP helpers --------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Single-shot request via safe_request with the Cloudflare policy."""
        return safe_request(
            method,
            f"{CLOUDFLARE_API_BASE}{path}",
            policy=CLOUDFLARE_POLICY,
            headers=self._headers(),
            **kwargs,
        )

    def _safe_json(self, response: requests.Response) -> Any:
        """Parse JSON, rejecting oversized bodies before deserializing."""
        content_length = response.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > _MAX_RESPONSE_SIZE_BYTES:
            raise ValueError(f"cloudflare response too large: {content_length} bytes")
        if len(response.content) > _MAX_RESPONSE_SIZE_BYTES:
            raise ValueError(f"cloudflare response exceeds size limit ({_MAX_RESPONSE_SIZE_BYTES} bytes)")
        return response.json()

    def _envelope(self, response: requests.Response) -> Result[Any, str]:
        """Parse the Cloudflare v4 envelope; require ``success is True``."""
        try:
            data = self._safe_json(response)
        except ValueError as exc:
            return Err(f"cloudflare: invalid response body: {exc}")
        if not isinstance(data, dict) or data.get("success") is not True:
            errors = data.get("errors") if isinstance(data, dict) else None
            return Err(f"cloudflare API error (HTTP {response.status_code}): {errors}")
        return Ok(data.get("result"))

    def _body(self, spec: DnsRecordSpec) -> dict[str, Any]:
        return {
            "type": spec.record_type,
            "name": spec.name,
            "content": spec.content,
            "ttl": spec.ttl,
            "proxied": spec.proxied,
            "comment": spec.owner_tag,
        }

    def _to_result(self, zone_id: str, rec: dict[str, Any], spec: DnsRecordSpec) -> DnsRecordResult:
        return DnsRecordResult(
            provider=self.provider,
            zone_id=zone_id,
            record_id=str(rec.get("id", "")),
            record_type=spec.record_type,
            name=spec.name,
            content=str(rec.get("content", spec.content)),
            owner_tag=spec.owner_tag,
        )

    def _create(self, zone_id: str, spec: DnsRecordSpec) -> Result[DnsRecordResult, str]:
        resp = self._request("POST", f"/zones/{zone_id}/dns_records", json=self._body(spec))
        env = self._envelope(resp)
        if env.is_err():
            return Err(env.unwrap_err())
        return Ok(self._to_result(zone_id, env.unwrap() or {}, spec))

    def _update(self, zone_id: str, record_id: str, spec: DnsRecordSpec) -> Result[DnsRecordResult, str]:
        resp = self._request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", json=self._body(spec))
        env = self._envelope(resp)
        if env.is_err():
            return Err(env.unwrap_err())
        return Ok(self._to_result(zone_id, env.unwrap() or {}, spec))

    def _delete_ids(self, zone_id: str, ids: list[str]) -> None:
        """Best-effort delete (dedupe / stale cleanup); envelope errors ignored."""
        for rid in ids:
            self._request("DELETE", f"/zones/{zone_id}/dns_records/{rid}")

    # -- Operations ----------------------------------------------------------

    def get_zone_name(self, zone_id: str) -> Result[str, str]:
        try:
            resp = self._request("GET", f"/zones/{zone_id}")
        except (requests.RequestException, OutboundSecurityError) as exc:
            return Err(f"cloudflare transport error: {exc}")
        env = self._envelope(resp)
        if env.is_err():
            return Err(env.unwrap_err())
        result = env.unwrap()
        name = result.get("name") if isinstance(result, dict) else None
        if not name:
            return Err("cloudflare zone response missing name")
        return Ok(str(name))

    def reconcile_records(self, zone_id: str, specs: list[DnsRecordSpec], owner_tag: str) -> ReconcileOutcome:
        outcome = ReconcileOutcome()
        if not specs:
            return outcome
        name = specs[0].name
        desired_types = {s.record_type for s in specs}

        try:
            listed = self._request("GET", f"/zones/{zone_id}/dns_records", params={"name": name})
        except (requests.RequestException, OutboundSecurityError) as exc:
            outcome.error = f"cloudflare transport error: {exc}"
            return outcome
        env = self._envelope(listed)
        if env.is_err():
            outcome.error = env.unwrap_err()
            return outcome
        existing: list[dict[str, Any]] = env.unwrap() or []

        try:
            for spec in specs:
                same = [r for r in existing if r.get("type") == spec.record_type]
                unowned = [r for r in same if r.get("comment") != owner_tag]
                owned = [r for r in same if r.get("comment") == owner_tag]
                if unowned:
                    # Never touch a record we do not own (operator-managed) — fail closed.
                    outcome.error = f"unowned {spec.record_type} record exists for {name}; refusing to manage"
                    continue
                if not owned:
                    res = self._create(zone_id, spec)
                else:
                    keep = owned[0]
                    res = (
                        self._update(zone_id, str(keep["id"]), spec)
                        if keep.get("content") != spec.content
                        else Ok(self._to_result(zone_id, keep, spec))
                    )
                    # Converge replay duplicates down to the single kept record.
                    self._delete_ids(zone_id, [str(r["id"]) for r in owned[1:]])
                if res.is_err():
                    outcome.error = res.unwrap_err()
                    continue
                outcome.applied.append(res.unwrap())

            # Delete owned records whose type is no longer desired (e.g. a dropped AAAA on retry).
            stale = [
                str(r["id"]) for r in existing if r.get("comment") == owner_tag and r.get("type") not in desired_types
            ]
            self._delete_ids(zone_id, stale)
        except (requests.RequestException, OutboundSecurityError) as exc:
            outcome.error = f"cloudflare transport error: {exc}"
        return outcome

    def delete_owned_records(self, zone_id: str, owner_tag: str) -> Result[list[str], str]:
        try:
            listed = self._request("GET", f"/zones/{zone_id}/dns_records", params={"comment.exact": owner_tag})
        except (requests.RequestException, OutboundSecurityError) as exc:
            return Err(f"cloudflare transport error: {exc}")
        env = self._envelope(listed)
        if env.is_err():
            return Err(env.unwrap_err())
        records: list[dict[str, Any]] = env.unwrap() or []

        deleted: list[str] = []
        errors: list[str] = []
        for rec in records:
            rid = str(rec.get("id", ""))
            if not rid:
                continue
            try:
                resp = self._request("DELETE", f"/zones/{zone_id}/dns_records/{rid}")
            except (requests.RequestException, OutboundSecurityError) as exc:
                errors.append(f"{rid}: {exc}")
                continue
            if resp.status_code == _HTTP_NOT_FOUND:  # already gone — idempotent
                deleted.append(rid)
                continue
            del_env = self._envelope(resp)
            if del_env.is_err():
                errors.append(f"{rid}: {del_env.unwrap_err()}")
            else:
                deleted.append(rid)
        if errors:
            return Err(f"failed to delete {len(errors)} record(s): {'; '.join(errors)}")
        return Ok(deleted)


# =============================================================================
# Provider Registry + Factory (mirrors cloud_gateway)
# =============================================================================

_DNS_PROVIDER_REGISTRY: dict[str, type[DnsProviderGateway]] = {}
"""Populated once at startup by each provider module's ``register_dns_gateway`` call."""


def register_dns_gateway(provider_type: str, gateway_cls: type[DnsProviderGateway]) -> None:
    """Register a DNS gateway implementation for a provider type."""
    _DNS_PROVIDER_REGISTRY[provider_type] = gateway_cls
    logger.info(f"✅ [DnsGateway] Registered provider: {provider_type}")


def get_dns_gateway(provider_type: str, token: str, **kwargs: Any) -> DnsProviderGateway:
    """Factory: build a DNS gateway for ``provider_type``.

    Raises ValueError if the provider is not registered.
    """
    gateway_cls = _DNS_PROVIDER_REGISTRY.get(provider_type)
    if not gateway_cls:
        available = ", ".join(sorted(_DNS_PROVIDER_REGISTRY.keys())) or "(none)"
        raise ValueError(f"Unknown DNS provider: '{provider_type}'. Available: {available}")
    return gateway_cls(token=token, **kwargs)


def get_registered_dns_providers() -> list[str]:
    """Get list of registered DNS provider types."""
    return sorted(_DNS_PROVIDER_REGISTRY.keys())


register_dns_gateway("cloudflare", CloudflareDnsGateway)
