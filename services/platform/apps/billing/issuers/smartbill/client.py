"""HTTP transport for SmartBill Cloud.

Every outbound call goes through `apps.common.outbound_http.safe_request` with a
domain-pinned policy, and every call reserves a slot from `SmartBillRateGate`
first. Both are mandatory, for different reasons: the first is the platform's
SSRF policy, the second is because exceeding SmartBill's limit blocks the token
for ten minutes, which during a billing run is an outage rather than a slowdown.

Document issuance lives in V1. V3 is used only to read VAT rates, because it is
the sole place SmartBill exposes `isReverseCharge` — the one machine-readable
signal of a rate's fiscal meaning. V3 cannot issue anything.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from apps.billing.issuers.models import SmartBillRateGate
from apps.common.outbound_http import OutboundPolicy, safe_request

from .responses import RawReply, SmartBillResponse, Verdict, classify

logger = logging.getLogger(__name__)

V1_BASE = "https://ws.smartbill.ro/SBORO/api"
V3_BASE = "https://ws.smartbill.ro/SBORO/api/v3"

SMARTBILL_POLICY = OutboundPolicy(
    name="smartbill",
    allowed_domains=frozenset({"smartbill.ro"}),
    timeout_seconds=30.0,
    # Zero transport retries on purpose. `requests`-level retries would replay a
    # POST whose response was merely lost, which is exactly how a second legally
    # numbered invoice gets created. Retry decisions belong to the caller, which
    # can tell REJECTED from AMBIGUOUS.
    max_retries=0,
)


class RateGateWait(Exception):  # noqa: N818  # Not an error: a scheduling instruction
    """Raised when the reserved slot is in the future.

    The caller should reschedule the task for `available_at` rather than sleep, so
    a worker is not held idle waiting on a shared schedule.
    """

    def __init__(self, available_at: Any) -> None:
        super().__init__(f"SmartBill slot reserved for {available_at}")
        self.available_at = available_at


@dataclass(frozen=True)
class _RequestSpec:
    """Per-call transport options, grouped so `_request` keeps a small signature."""

    base: str = V1_BASE
    query: dict[str, str] | None = None
    body: dict[str, Any] | None = None
    bearer: bool = False


@dataclass(frozen=True)
class SmartBillCredentials:
    """V1 issues documents; the V3 token is optional and read-only."""

    email: str
    token: str
    cif: str
    v3_token: str = ""

    def basic_auth_header(self) -> str:
        raw = f"{self.email}:{self.token}".encode()
        return "Basic " + base64.b64encode(raw).decode()


class SmartBillClient:
    """Thin transport. It classifies replies; it does not interpret documents."""

    def __init__(self, credentials: SmartBillCredentials) -> None:
        self._credentials = credentials

    def _gate_token(self, *, bearer: bool) -> str:
        """Pace against the credential actually being spent.

        V1 and V3 authenticate with different tokens. Keying every call to the V1
        token would let V3 traffic consume a budget it does not belong to, and
        would leave a shared V3 token unpaced across clients.
        """
        return self._credentials.v3_token if bearer else self._credentials.token

    # -- transport -------------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        spec: _RequestSpec | None = None,
    ) -> SmartBillResponse:
        options = spec or _RequestSpec()
        base, query, body, bearer = options.base, options.query, options.body, options.bearer
        # Grant or defer. Any answer other than "go now" must prevent the call:
        # an earlier design handed out future slots and trusted callers to wait,
        # which let thirteen requests fire at once while the schedule looked right.
        retry_at = SmartBillRateGate.acquire(self._gate_token(bearer=bearer))
        if retry_at is not None:
            raise RateGateWait(retry_at)

        url = f"{base}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"

        headers = {"Accept": "application/json"}
        if bearer:
            headers["Authorization"] = f"Bearer {self._credentials.v3_token}"
        else:
            headers["Authorization"] = self._credentials.basic_auth_header()
        if body is not None:
            headers["Content-Type"] = "application/json"

        try:
            response = safe_request(
                method,
                url,
                policy=SMARTBILL_POLICY,
                headers=headers,
                data=json.dumps(body) if body is not None else None,
            )
        except Exception as exc:  # Any transport failure is ambiguous by definition
            logger.warning(f"⚠️ [SmartBill] {method} {path} produced no usable reply: {exc}")
            return classify(RawReply(status=None, transport_failed=True, is_write=method.upper() != "GET"))

        raw = response.text or ""
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = None
        if not isinstance(parsed, dict):
            parsed = None

        retry_after_raw = response.headers.get("Retry-After") or ""
        retry_after = int(retry_after_raw) if retry_after_raw.isdigit() else None

        result = classify(
            RawReply(
                status=response.status_code,
                body=raw,
                parsed=parsed,
                retry_after=retry_after,
                is_write=method.upper() != "GET",
            )
        )
        if result.error_codes and "rate_limit_exceeded" in result.error_codes:
            # Handing Retry-After to only the caller that saw the 429 leaves every
            # other worker free to keep spending the same token, which is how a
            # short throttle becomes the documented ten-minute block.
            blocked_until = SmartBillRateGate.record_throttled(
                self._gate_token(bearer=bearer), result.retry_after_seconds
            )
            logger.error(f"🔥 [SmartBill] Throttled; suppressing all calls until {blocked_until}")

        if result.verdict is not Verdict.SUCCESS:
            logger.warning(f"⚠️ [SmartBill] {method} {path} -> {result.verdict.value}: {result.error_text}")
        return result

    # -- reads -----------------------------------------------------------------

    def get_series(self, series_type: str = "f") -> SmartBillResponse:
        """List document series. Each carries `nextNumber`."""
        spec = _RequestSpec(query={"cif": self._credentials.cif, "type": series_type})
        return self._request("GET", "/series", spec=spec)

    def get_tax_rates(self) -> SmartBillResponse:
        """V1 VAT rates: name and percentage only, no fiscal semantics."""
        return self._request("GET", "/tax", spec=_RequestSpec(query={"cif": self._credentials.cif}))

    def get_vat_rates_v3(self) -> SmartBillResponse:
        """V3 VAT rates, the only surface exposing `isReverseCharge`."""
        spec = _RequestSpec(base=V3_BASE, query={"limit": "100"}, bearer=True)
        return self._request("GET", f"/companies/{self._credentials.cif}/vat-rates", spec=spec)

    def get_invoice_pdf_url(self, series: str, number: str) -> str:
        """The PDF endpoint, built here so the path is defined in one place."""
        query = urlencode({"cif": self._credentials.cif, "seriesname": series, "number": number})
        return f"{V1_BASE}/invoice/pdf?{query}"

    # -- writes ----------------------------------------------------------------

    def create_invoice(self, payload: dict[str, Any]) -> SmartBillResponse:
        """Issue an invoice. NOT idempotent: SmartBill offers no idempotency key.

        An AMBIGUOUS verdict from here must never be retried automatically.
        """
        return self._request("POST", "/invoice/v2", spec=_RequestSpec(body=payload))

    def reverse_invoice(self, payload: dict[str, Any]) -> SmartBillResponse:
        """Issue a storno. Carries the same non-idempotency hazard as issuance."""
        return self._request("POST", "/invoice/reverse", spec=_RequestSpec(body=payload))
