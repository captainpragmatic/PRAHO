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

DNS-01 challenges (ADR-0061 P1.9) use the same ownership idea one level down: a challenge name holds
several TXT values at once, one set per ACME order, each tagged ``praho:acme:<order>``. TXT records
therefore never conflict with another owner's TXT records; ``reconcile_txt_values`` converges only the
caller's own values, and ``sweep_owned_records`` reclaims the ones a crashed order left behind.

See #347 GAP 3. Certificate issuance itself lives in ``apps.provisioning.account_name_certificates``.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Literal

import requests

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, safe_request
from apps.common.types import Err, Ok, Result, Retriability

logger = logging.getLogger(__name__)

DnsRecordType = Literal["A", "AAAA", "TXT"]

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
    retry_connection_errors=False,
)

DNS_RECORD_TTL_SECONDS = 60
_MAX_RESPONSE_SIZE_BYTES = 256 * 1024
_HTTP_NOT_FOUND = 404
_HTTP_TOO_MANY_REQUESTS = 429
_HTTP_SERVER_ERROR = 500

# Rate limits (429) and server errors (5xx) are retried in-process a bounded number of times.
# A Retry-After longer than the cap is not slept through inside a worker: it is handed to the
# caller on the typed error so a task can reschedule itself.
DEFAULT_MAX_RETRIES = 2
_RETRY_BACKOFF_SECONDS = 1.0
_MAX_IN_PROCESS_RETRY_SECONDS = 30.0
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "PUT", "DELETE"})

# Only owner tags under this namespace may be swept: an empty or foreign prefix would match records
# PRAHO does not own.
OWNER_TAG_NAMESPACE = "praho:"

# Record listings follow every page (Cloudflare defaults to 100 per page).
_LIST_PAGE_SIZE = 100
_MAX_LIST_PAGES = 100


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
    ttl: int = DNS_RECORD_TTL_SECONDS
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
    # The TTL the provider reports for the record, so a lowered TTL is confirmed rather than assumed.
    ttl: int | None = None

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
    # RETRIABLE: the failing request was a rate limit, or a server error on an idempotent call,
    # so running the whole reconcile again is safe. ``retry_after_seconds`` is the delay the
    # provider asked for. A caller that cannot wait (the node deploy) may ignore both and treat
    # ``error`` as a hard failure, exactly as before.
    retriability: Retriability = Retriability.UNKNOWN
    retry_after_seconds: float | None = None


class DnsTransientError(Exception):
    """A rate-limit or server-error answer that survived the in-process retries.

    ``retriability`` follows ``Retriability``: RETRIABLE for a 429 (rejected before it was
    processed) and for a 5xx on an idempotent call; UNKNOWN for a 5xx on a create, which may
    already have been applied and must not be blindly replayed.
    """

    def __init__(self, message: str, *, retriability: Retriability, retry_after_seconds: float | None = None) -> None:
        super().__init__(message)
        self.retriability = retriability
        self.retry_after_seconds = retry_after_seconds


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

    @abstractmethod
    def reconcile_txt_values(
        self, zone_id: str, name: str, values: list[str], owner_tag: str, *, ttl: int = DNS_RECORD_TTL_SECONDS
    ) -> ReconcileOutcome:
        """Converge the TXT values ``owner_tag`` holds at ``name`` to exactly ``values``.

        Several values per name are normal (a DNS-01 challenge). Only records bearing ``owner_tag`` are
        created, changed or deleted; another owner's TXT records on the same name are never touched
        and never block, because a TXT set is multi-valued by nature.
        """

    @abstractmethod
    def sweep_owned_records(
        self,
        zone_id: str,
        owner_prefix: str,
        *,
        keep_owner_tags: frozenset[str],
        min_age_seconds: float,
        record_type: DnsRecordType = "TXT",
    ) -> Result[list[str], str]:
        """Delete stale ``record_type`` records whose owner tag starts with ``owner_prefix``.

        A record is stale when its tag is not in ``keep_owner_tags`` and it is older than
        ``min_age_seconds`` (a younger record may belong to an order that has not been saved yet).
        """


# =============================================================================
# Cloudflare implementation
# =============================================================================


class CloudflareDnsGateway(DnsProviderGateway):
    """Cloudflare DNS gateway over the v4 REST API (Bearer token)."""

    provider = "cloudflare"

    def __init__(
        self, token: str, *, timeout: float | None = None, max_retries: int = DEFAULT_MAX_RETRIES, **kwargs: Any
    ) -> None:
        self._token = token
        self._max_retries = max(0, max_retries)
        self._policy = (
            replace(
                CLOUDFLARE_POLICY,
                timeout_seconds=timeout,
                connect_timeout_seconds=timeout,
                retry_connection_errors=False,
            )
            if timeout is not None
            else CLOUDFLARE_POLICY
        )

    # -- HTTP helpers --------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """One logical request via safe_request with the Cloudflare policy.

        Each HTTP attempt is single-shot (the policy never replays a POST on its own). A 429, or
        a 5xx on an idempotent method, is retried here up to ``max_retries`` times after the
        provider's Retry-After (or a short backoff). A 5xx on a POST is never replayed: it may
        have been applied. What survives the retries is raised as ``DnsTransientError``.
        """
        attempt = 0
        while True:
            response = safe_request(
                method,
                f"{CLOUDFLARE_API_BASE}{path}",
                policy=self._policy,
                headers=self._headers(),
                **kwargs,
            )
            retriability = self._transient_retriability(method, response.status_code)
            if retriability is None:
                return response
            retry_after = self._retry_after_seconds(response)
            if retriability is Retriability.RETRIABLE and attempt < self._max_retries:
                delay = retry_after if retry_after is not None else _RETRY_BACKOFF_SECONDS * 2**attempt
                if delay <= _MAX_IN_PROCESS_RETRY_SECONDS:
                    logger.warning(
                        "⚠️ [DnsGateway] HTTP %s on %s %s; retrying in %.1fs", response.status_code, method, path, delay
                    )
                    time.sleep(delay)
                    attempt += 1
                    continue
            raise DnsTransientError(
                f"cloudflare HTTP {response.status_code} on {method} {path}",
                retriability=retriability,
                retry_after_seconds=retry_after,
            )

    @staticmethod
    def _transient_retriability(method: str, status: int) -> Retriability | None:
        """RETRIABLE/UNKNOWN for a rate-limit or server-error status, None for any other answer."""
        if status == _HTTP_TOO_MANY_REQUESTS:
            return Retriability.RETRIABLE  # rejected before processing: provably not applied
        if status >= _HTTP_SERVER_ERROR:
            return Retriability.RETRIABLE if method in _IDEMPOTENT_METHODS else Retriability.UNKNOWN
        return None

    @staticmethod
    def _retry_after_seconds(response: requests.Response) -> float | None:
        """The Retry-After header as seconds (delta-seconds or HTTP-date), or None when absent or invalid."""
        raw = response.headers.get("Retry-After")
        if not raw:
            return None
        raw = raw.strip()
        if raw.isdigit():
            return float(raw)
        try:
            when = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        return max(0.0, (when - datetime.now(UTC)).total_seconds())

    @staticmethod
    def _failure(outcome: ReconcileOutcome, exc: Exception) -> None:
        """Record a request failure on ``outcome``, keeping the retriable typing when there is one."""
        if isinstance(exc, DnsTransientError):
            outcome.error = f"cloudflare transient error: {exc}"
            outcome.retriability = exc.retriability
            outcome.retry_after_seconds = exc.retry_after_seconds
        else:
            outcome.error = f"cloudflare transport error: {exc}"

    def _safe_json(self, response: requests.Response) -> Any:
        """Parse JSON, rejecting oversized bodies before deserializing."""
        content_length = response.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > _MAX_RESPONSE_SIZE_BYTES:
            raise ValueError(f"cloudflare response too large: {content_length} bytes")
        if len(response.content) > _MAX_RESPONSE_SIZE_BYTES:
            raise ValueError(f"cloudflare response exceeds size limit ({_MAX_RESPONSE_SIZE_BYTES} bytes)")
        return response.json()

    def _parse(self, response: requests.Response) -> Result[dict[str, Any], str]:
        """Parse the Cloudflare v4 envelope; require ``success is True``. Returns the whole envelope."""
        try:
            data = self._safe_json(response)
        except ValueError as exc:
            return Err(f"cloudflare: invalid response body: {exc}")
        if not isinstance(data, dict) or data.get("success") is not True:
            errors = data.get("errors") if isinstance(data, dict) else None
            return Err(f"cloudflare API error (HTTP {response.status_code}): {errors}")
        return Ok(data)

    def _envelope(self, response: requests.Response) -> Result[Any, str]:
        """Parse the Cloudflare v4 envelope and return its ``result``."""
        parsed = self._parse(response)
        if parsed.is_err():
            return Err(parsed.unwrap_err())
        return Ok(parsed.unwrap().get("result"))

    def _list_records(self, zone_id: str, params: dict[str, Any]) -> Result[list[dict[str, Any]], str]:
        """List the DNS records matching ``params``, following every page.

        A listing that claims more than ``_MAX_LIST_PAGES`` pages is an error, never a partial
        answer: acting on half a listing could miss an unowned conflict or leave owned records behind.
        """
        records: list[dict[str, Any]] = []
        for page in range(1, _MAX_LIST_PAGES + 1):
            response = self._request(
                "GET", f"/zones/{zone_id}/dns_records", params={**params, "page": page, "per_page": _LIST_PAGE_SIZE}
            )
            parsed = self._parse(response)
            if parsed.is_err():
                return Err(parsed.unwrap_err())
            body = parsed.unwrap()
            batch = body.get("result") or []
            if not isinstance(batch, list):
                return Err("cloudflare: unexpected record listing")
            records.extend(batch)
            info = body.get("result_info")
            total_pages = info.get("total_pages") if isinstance(info, dict) else None
            if not isinstance(total_pages, int) or page >= total_pages:
                return Ok(records)
        return Err(f"cloudflare: record listing exceeds {_MAX_LIST_PAGES} pages")

    @staticmethod
    def _same_content(current: object, desired: str) -> bool:
        """Compare record contents as addresses when they are addresses ("2001:DB8:0::1" is "2001:db8::1")."""
        try:
            return ipaddress.ip_address(str(current)) == ipaddress.ip_address(desired)
        except ValueError:
            return str(current) == desired

    @classmethod
    def _in_sync(cls, record: dict[str, Any], spec: DnsRecordSpec) -> bool:
        """Whether an existing record already says what ``spec`` says: content, TTL and proxied flag."""
        return (
            cls._same_content(record.get("content"), spec.content)
            and record.get("ttl") == spec.ttl
            and bool(record.get("proxied", False)) == spec.proxied
        )

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
            ttl=ttl if isinstance(ttl := rec.get("ttl"), int) and not isinstance(ttl, bool) else None,
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

    def _delete_ids(self, zone_id: str, ids: list[str]) -> list[str]:
        """Delete records; return ids whose deletion was NOT confirmed (envelope error).

        A 404 counts as deleted (already gone). Callers surface any returned ids so a failed
        stale/duplicate cleanup is never reported as a successful reconciliation (P1).
        """
        failed: list[str] = []
        for rid in ids:
            resp = self._request("DELETE", f"/zones/{zone_id}/dns_records/{rid}")
            if resp.status_code == _HTTP_NOT_FOUND:
                continue
            if self._envelope(resp).is_err():
                failed.append(rid)
        return failed

    # -- Operations ----------------------------------------------------------

    def get_zone_name(self, zone_id: str) -> Result[str, str]:
        try:
            resp = self._request("GET", f"/zones/{zone_id}")
        except DnsTransientError as exc:
            return Err(f"cloudflare transient error: {exc}", retriability=exc.retriability)
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
        # One call converges one record name: the listing below, the conflict check and the
        # stale-record sweep are all scoped to it, so a spec for another name would be written blind.
        names = {s.name.lower().rstrip(".") for s in specs}
        if len(names) > 1:
            outcome.error = f"reconcile takes one record name per call; got {len(names)}: {sorted(names)}"
            return outcome
        desired_types = {s.record_type for s in specs}

        try:
            listed = self._list_records(zone_id, {"name": name})
        except (requests.RequestException, OutboundSecurityError, DnsTransientError) as exc:
            self._failure(outcome, exc)
            return outcome
        if listed.is_err():
            outcome.error = listed.unwrap_err()
            return outcome
        existing = listed.unwrap()

        # Fail closed atomically: if ANY desired record type collides with an unowned record,
        # refuse to mutate anything — never leave a half-configured record set (Copilot).
        for spec in specs:
            if any(r.get("type") == spec.record_type and r.get("comment") != owner_tag for r in existing):
                outcome.error = f"unowned {spec.record_type} record exists for {name}; refusing to manage"
                return outcome

        delete_failures: list[str] = []
        try:
            for spec in specs:
                owned = [r for r in existing if r.get("type") == spec.record_type and r.get("comment") == owner_tag]
                if not owned:
                    res = self._create(zone_id, spec)
                else:
                    keep = owned[0]
                    res = (
                        self._update(zone_id, str(keep["id"]), spec)
                        if not self._in_sync(keep, spec)
                        else Ok(self._to_result(zone_id, keep, spec))
                    )
                    # Converge replay duplicates down to the single kept record.
                    delete_failures += self._delete_ids(zone_id, [str(r["id"]) for r in owned[1:]])
                if res.is_err():
                    outcome.error = res.unwrap_err()
                    continue
                outcome.applied.append(res.unwrap())

            # Delete owned records whose type is no longer desired (e.g. a dropped AAAA on retry).
            stale = [
                str(r["id"]) for r in existing if r.get("comment") == owner_tag and r.get("type") not in desired_types
            ]
            delete_failures += self._delete_ids(zone_id, stale)
        except (requests.RequestException, OutboundSecurityError, DnsTransientError) as exc:
            self._failure(outcome, exc)

        # A failed stale/duplicate deletion must not read as success — a lingering wrong
        # record (e.g. a stale AAAA) would keep sending clients to a reassigned address (P1).
        if delete_failures and not outcome.error:
            outcome.error = f"failed to delete {len(delete_failures)} stale/duplicate record(s): {delete_failures}"
        return outcome

    def delete_owned_records(self, zone_id: str, owner_tag: str) -> Result[list[str], str]:
        try:
            listed = self._list_records(zone_id, {"comment.exact": owner_tag})
        except DnsTransientError as exc:
            return Err(f"cloudflare transient error: {exc}", retriability=exc.retriability)
        except (requests.RequestException, OutboundSecurityError) as exc:
            return Err(f"cloudflare transport error: {exc}")
        if listed.is_err():
            return Err(listed.unwrap_err())
        return self._delete_records(zone_id, listed.unwrap())

    def _delete_records(self, zone_id: str, records: list[dict[str, Any]]) -> Result[list[str], str]:
        deleted: list[str] = []
        errors: list[str] = []
        # Deleting is idempotent, so a teardown whose only failures were transient can simply be run again.
        only_transient = True
        for rec in records:
            rid = str(rec.get("id", ""))
            if not rid:
                continue
            try:
                resp = self._request("DELETE", f"/zones/{zone_id}/dns_records/{rid}")
            except (requests.RequestException, OutboundSecurityError, DnsTransientError) as exc:
                errors.append(f"{rid}: {exc}")
                only_transient &= isinstance(exc, DnsTransientError) and exc.retriability is Retriability.RETRIABLE
                continue
            if resp.status_code == _HTTP_NOT_FOUND:  # already gone — idempotent
                deleted.append(rid)
                continue
            del_env = self._envelope(resp)
            if del_env.is_err():
                errors.append(f"{rid}: {del_env.unwrap_err()}")
                only_transient = False
            else:
                deleted.append(rid)
        if errors:
            return Err(
                f"failed to delete {len(errors)} record(s): {'; '.join(errors)}",
                retriability=Retriability.RETRIABLE if only_transient else Retriability.UNKNOWN,
            )
        return Ok(deleted)

    @staticmethod
    def _txt_value(content: object) -> str:
        """A TXT value without the quotes Cloudflare may store or return around it."""
        text = str(content).strip()
        if len(text) >= 2 and text.startswith('"') and text.endswith('"'):  # noqa: PLR2004  # an opening and a closing quote
            text = text[1:-1]
        return text

    def reconcile_txt_values(
        self, zone_id: str, name: str, values: list[str], owner_tag: str, *, ttl: int = DNS_RECORD_TTL_SECONDS
    ) -> ReconcileOutcome:
        outcome = ReconcileOutcome()
        wanted = list(dict.fromkeys(self._txt_value(v) for v in values))
        try:
            listed = self._list_records(zone_id, {"name": name, "type": "TXT"})
        except (requests.RequestException, OutboundSecurityError, DnsTransientError) as exc:
            self._failure(outcome, exc)
            return outcome
        if listed.is_err():
            outcome.error = listed.unwrap_err()
            return outcome

        owned: dict[str, list[dict[str, Any]]] = {}
        for rec in listed.unwrap():
            if rec.get("type") == "TXT" and rec.get("comment") == owner_tag:
                owned.setdefault(self._txt_value(rec.get("content")), []).append(rec)

        delete_ids: list[str] = []
        try:
            for value in wanted:
                spec = DnsRecordSpec(record_type="TXT", name=name, content=value, owner_tag=owner_tag, ttl=ttl)
                existing = owned.pop(value, [])
                if not existing:
                    res = self._create(zone_id, spec)
                else:
                    keep = existing[0]
                    res = (
                        Ok(self._to_result(zone_id, keep, spec))
                        if keep.get("ttl") == ttl
                        else self._update(zone_id, str(keep["id"]), spec)
                    )
                    delete_ids += [str(r["id"]) for r in existing[1:]]  # replayed duplicates
                if res.is_err():
                    outcome.error = res.unwrap_err()
                    continue
                outcome.applied.append(res.unwrap())
            # Whatever is left in ``owned`` is a value this order no longer wants.
            delete_ids += [str(r["id"]) for recs in owned.values() for r in recs]
            failed = self._delete_ids(zone_id, delete_ids)
        except (requests.RequestException, OutboundSecurityError, DnsTransientError) as exc:
            self._failure(outcome, exc)
            return outcome
        if failed and not outcome.error:
            outcome.error = f"failed to delete {len(failed)} stale/duplicate record(s): {failed}"
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
        if not owner_prefix.startswith(OWNER_TAG_NAMESPACE) or owner_prefix == OWNER_TAG_NAMESPACE:
            return Err(f"refusing to sweep records under owner prefix {owner_prefix!r}")
        try:
            listed = self._list_records(zone_id, {"type": record_type, "comment.startswith": owner_prefix})
        except DnsTransientError as exc:
            return Err(f"cloudflare transient error: {exc}", retriability=exc.retriability)
        except (requests.RequestException, OutboundSecurityError) as exc:
            return Err(f"cloudflare transport error: {exc}")
        if listed.is_err():
            return Err(listed.unwrap_err())

        cutoff = datetime.now(UTC).timestamp() - min_age_seconds
        stale = [
            rec
            for rec in listed.unwrap()
            if rec.get("type") == record_type
            and str(rec.get("comment", "")).startswith(owner_prefix)  # the provider filter is not trusted alone
            and rec.get("comment") not in keep_owner_tags
            and self._created_before(rec, cutoff)
        ]
        return self._delete_records(zone_id, stale)

    @staticmethod
    def _created_before(record: dict[str, Any], cutoff: float) -> bool:
        """Whether the record was created before ``cutoff`` (a timestamp); a record with no valid creation time is not."""
        raw = record.get("created_on")
        if not isinstance(raw, str):
            return False
        try:
            created = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return False
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        return created.timestamp() < cutoff


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
