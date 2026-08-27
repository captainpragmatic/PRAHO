"""
Gandi REST API gateway for international domain registration.

API docs: https://api.gandi.net/docs/domains/
Auth: Personal Access Token via Authorization header.
Rate limit: 30 requests / 2 seconds (negotiable for resellers).

PROVISIONAL — NOT SANDBOX-VERIFIED. Documented 202 acceptance responses are
represented as accepted-but-unconfirmed results carrying the Location operation
handle; inline completed-resource responses remain supported for compatibility.
Live sandbox validation is still outstanding. Chargeable register/renew calls are
gated behind settings.REGISTRAR_ADAPTERS_VERIFIED (default off) until an operator
validates the adapter against real credentials.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import requests

from apps.common.outbound_http import OutboundPolicy
from apps.common.types import Err, Ok, Result, Retriability

from .base import (
    HTTP_ACCEPTED,
    HTTP_OK,
    BaseRegistrarGateway,
    DomainAvailabilityResult,
    DomainInfoResult,
    DomainLockResult,
    DomainRegistrationResult,
    DomainRenewalResult,
    DomainTransferResult,
    NameserverUpdateResult,
    RegistrarGatewayFactory,
)
from .errors import RegistrarAPIError, RegistrarErrorCode, RegistrarTransientError

logger = logging.getLogger(__name__)

GANDI_API_BASE = "https://api.gandi.net/v5"

GANDI_POLICY = OutboundPolicy(
    name="gandi_registrar",
    allowed_domains=frozenset({"api.gandi.net"}),
    timeout_seconds=30.0,
    connect_timeout_seconds=10.0,
    verify_tls=True,
    max_retries=0,  # we handle retries in base class
)


class GandiGateway(BaseRegistrarGateway):
    """Gandi REST API gateway for international domains (.com, .net, .org, .eu, etc.)."""

    @property
    def gateway_name(self) -> str:
        return "gandi"

    def _get_outbound_policy(self) -> OutboundPolicy:
        return GANDI_POLICY

    def _auth_headers(self) -> dict[str, str]:
        _, api_key = self.registrar.get_api_credentials()
        return {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def _get_sharing_id(self) -> str | None:
        """Reseller sharing_id for per-customer billing (stored in api_username)."""
        username = self.registrar.api_username
        return username if username else None

    # -- Core operations -----------------------------------------------------

    def _do_register(
        self,
        domain_name: str,
        years: int,
        registrant_data: dict[str, Any],
        nameservers: list[str] | None,
    ) -> Result[DomainRegistrationResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/domains"

        body: dict[str, Any] = {
            "fqdn": domain_name,
            "duration": years,
            "owner": self._map_registrant_to_gandi(registrant_data),
        }

        if nameservers:
            body["nameservers"] = nameservers

        # Gandi documents sharing_id as a query parameter, not a body field.
        params = {}
        sharing_id = self._get_sharing_id()
        if sharing_id:
            params["sharing_id"] = sharing_id

        try:
            response = self._api_request("POST", url, json=body, params=params, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                # A registration POST may have reached the registrar before the network
                # error — not provably safe to replay, so leave UNKNOWN (the default).
                RegistrarTransientError(self.registrar.name, f"Network error during registration: {exc}"),
            )

        if response.status_code == HTTP_ACCEPTED:
            data = self._safe_json(response)
            expires_at = _parse_gandi_date(data.get("expires_at", ""))
            if expires_at is not None:
                return Ok(
                    DomainRegistrationResult(
                        registrar_domain_id=data.get("id", domain_name),
                        expires_at=expires_at,
                        nameservers=nameservers or self.registrar.default_nameservers or [],
                        # authinfo, not auth_info — the identical misspelling this change
                        # fixed on the write side. Gandi's domain-details response documents a
                        # top-level `authinfo`, so the EPP credential read back was always "".
                        epp_code=data.get("authinfo", ""),
                    )
                )
            # The DOCUMENTED 202: body is {"message": ...} only, the operation handle is
            # in Location. This is acceptance, not completion (#257) — returning it as a
            # pending result replaces the old INVALID_RESPONSE error that would have
            # failed every real registration.
            return Ok(
                DomainRegistrationResult(
                    registrar_domain_id=data.get("id", ""),
                    expires_at=None,
                    nameservers=nameservers or self.registrar.default_nameservers or [],
                    epp_code=data.get("authinfo", ""),
                    pending=True,
                    operation_handle=response.headers.get("Location", ""),
                )
            )

        return self._handle_error_response(response, f"register {domain_name}", domain_name=domain_name)

    def _do_renew(
        self,
        registrar_domain_id: str,
        domain_name: str,
        years: int,
    ) -> Result[DomainRenewalResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/domains/{domain_name}/renew"

        body = {"duration": years}

        # Reseller billing attribution, same rule as _do_register: sharing_id is a query
        # param; without it the chargeable renewal bills the PAT's default organization.
        params = {}
        sharing_id = self._get_sharing_id()
        if sharing_id:
            params["sharing_id"] = sharing_id

        try:
            response = self._api_request(
                "POST",
                url,
                json=body,
                params=params,
                headers=self._auth_headers(),
            )
        except requests.RequestException as exc:
            return Err(
                # Renewal is not idempotent (a second renewal double-charges/double-extends)
                # and the POST may have landed — leave UNKNOWN (the default).
                RegistrarTransientError(self.registrar.name, f"Network error during renewal: {exc}"),
            )

        if response.status_code in (HTTP_OK, HTTP_ACCEPTED):
            data = self._safe_json(response)
            new_expires_at = _parse_gandi_date(data.get("expires_at", ""))
            if new_expires_at is not None:
                return Ok(DomainRenewalResult(new_expires_at=new_expires_at))
            if response.status_code == HTTP_ACCEPTED:
                # Documented acceptance: {"message": ...} + Location. Pending, not failed.
                return Ok(
                    DomainRenewalResult(
                        new_expires_at=None,
                        pending=True,
                        operation_handle=response.headers.get("Location", ""),
                    )
                )
            # A 200 is a completed-resource contract; without an expiry it is malformed.
            return Err(
                RegistrarAPIError(
                    f"Gandi renewal response missing/invalid expires_at for {domain_name}",
                    code=RegistrarErrorCode.INVALID_RESPONSE,
                    registrar_name=self.registrar.name,
                )
            )

        return self._handle_error_response(response, f"renew {domain_name}", domain_name=domain_name)

    def _do_check_availability(
        self,
        domain_name: str,
    ) -> Result[DomainAvailabilityResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/check"
        params = {"name": domain_name}
        # Reseller pricing: without sharing_id the check quotes the PAT's default
        # organization's prices, not the reseller's.
        sharing_id = self._get_sharing_id()
        if sharing_id:
            params["sharing_id"] = sharing_id

        try:
            response = self._api_request("GET", url, params=params, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                # Availability is a read-only GET — safe to replay after a network error.
                RegistrarTransientError(self.registrar.name, f"Network error during availability check: {exc}"),
                retriability=Retriability.RETRIABLE,
            )

        if response.status_code == HTTP_OK:
            data = self._safe_json(response)
            products = data.get("products", [])
            if products:
                product = products[0]
                status = product.get("status", "unavailable")
                price_data = product.get("prices", [{}])
                price_cents = None
                if price_data:
                    price_raw = price_data[0].get("price_after_taxes")
                    if price_raw is not None:
                        # A malformed price must not raise out of the Result contract;
                        # availability is the primary signal, so just omit the price.
                        try:
                            price_cents = int(float(price_raw) * 100)
                        except (TypeError, ValueError):
                            logger.warning("Gandi returned unparseable price %r for %s", price_raw, domain_name)
                            price_cents = None

                return Ok(
                    DomainAvailabilityResult(
                        domain_name=domain_name,
                        available=status == "available",
                        premium=product.get("premium", False),
                        price_cents=price_cents,
                    )
                )

            return Ok(
                DomainAvailabilityResult(
                    domain_name=domain_name,
                    available=False,
                )
            )

        return self._handle_error_response(response, f"check availability for {domain_name}", domain_name=domain_name)

    def _do_verify_webhook(self, payload: str, signature: str, secret: str) -> bool:
        return self._verify_hmac_sha256(payload, signature, secret)

    # -- Phase 2 operations --------------------------------------------------

    def _do_initiate_transfer(
        self,
        domain_name: str,
        epp_code: str,
        registrant_data: dict[str, Any] | None = None,
    ) -> Result[DomainTransferResult, RegistrarAPIError]:
        # #265: Gandi requires `authinfo` and an owner contact on transfer-in. The
        # service supplies validated registrant data; direct callers that omit it keep
        # today's registrar-side missing-contact rejection rather than fabricating one.
        url = f"{GANDI_API_BASE}/domain/transferin"
        body: dict[str, Any] = {"fqdn": domain_name, "authinfo": epp_code}
        if registrant_data is not None:
            body["owner"] = self._map_registrant_to_gandi(registrant_data)

        # Query string, not body — the same rule _do_register already follows above. Gandi
        # documents sharing_id as a query param AND as the reseller billing identifier, so
        # in the body it is at best ignored: the chargeable transfer then bills the PAT's
        # default organization instead of the customer's sharing org.
        params = {}
        sharing_id = self._get_sharing_id()
        if sharing_id:
            params["sharing_id"] = sharing_id

        try:
            response = self._api_request("POST", url, json=body, params=params, headers=self._auth_headers())
        except requests.RequestException as exc:
            # Transfer POST may have reached the registrar — not provably unapplied (UNKNOWN default).
            return Err(RegistrarTransientError(self.registrar.name, f"Network error during transfer: {exc}"))

        # 202 ONLY: a 200 here is the documented Dry-Run *validation* response, whose body
        # can be {"status": "error", "errors": [...]} — accepting it would report a failed
        # validation as a started transfer.
        if response.status_code == HTTP_ACCEPTED:
            data = self._safe_json(response)  # size-capped, like every sibling parse
            # The 202 body is documented as {"message": ...} only; the Location header is
            # the sole operation handle. Reading id/status/expected_completion from it
            # yields ""/"pending"/None on every real response, and services.py stores that
            # empty string as the registrar operation id.
            transfer_id = data.get("id") or response.headers.get("Location", "")
            return Ok(
                DomainTransferResult(
                    transfer_id=transfer_id,
                    status=data.get("status", "pending"),
                    expected_completion=_parse_gandi_date(data.get("expected_completion", "")),
                )
            )
        return self._handle_error_response(response, f"transfer {domain_name}", domain_name=domain_name)

    def _do_get_domain_info(self, domain_name: str) -> Result[DomainInfoResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/domains/{domain_name}"

        try:
            response = self._api_request("GET", url, headers=self._auth_headers())
        except requests.RequestException as exc:
            # get_domain_info is a read — safe to replay.
            return Err(
                RegistrarTransientError(self.registrar.name, f"Network error: {exc}"),
                retriability=Retriability.RETRIABLE,
            )

        if response.status_code == HTTP_OK:
            data = response.json()
            return Ok(
                DomainInfoResult(
                    registrar_domain_id=data.get("id", domain_name),
                    domain_name=data.get("fqdn", domain_name),
                    status=data.get("status", "unknown"),
                    expires_at=_parse_gandi_date(data.get("dates", {}).get("registry_ends_at", "")),
                    nameservers=data.get("nameservers", []),
                    locked="clientTransferProhibited" in data.get("status", [])
                    if isinstance(data.get("status"), list)
                    else False,
                    whois_privacy=data.get("whois_privacy", False),
                    # authinfo, not auth_info — the identical misspelling this change
                    # fixed on the write side. Gandi's domain-details response documents a
                    # top-level `authinfo`, so the EPP credential read back was always "".
                    epp_code=data.get("authinfo", ""),
                )
            )
        return self._handle_error_response(response, f"info {domain_name}", domain_name=domain_name)

    def _do_update_nameservers(
        self, domain_name: str, nameservers: list[str]
    ) -> Result[NameserverUpdateResult, RegistrarAPIError]:
        # #265: the endpoint expects the documented object wrapper {"nameservers": [...]},
        # not a bare array. A bare array is a client error, so the update could never
        # succeed — the service correctly reported failure, but for the wrong reason.
        url = f"{GANDI_API_BASE}/domain/domains/{domain_name}/nameservers"

        try:
            response = self._api_request("PUT", url, json={"nameservers": nameservers}, headers=self._auth_headers())
        except requests.RequestException as exc:
            # Nameserver update is a mutation — may have applied; UNKNOWN default.
            return Err(RegistrarTransientError(self.registrar.name, f"Network error: {exc}"))

        if response.status_code == HTTP_OK:
            return Ok(NameserverUpdateResult(nameservers=nameservers))
        if response.status_code == HTTP_ACCEPTED:
            # Acceptance, not completion — the caller must not record the new
            # nameservers locally until the registrar confirms (#257).
            return Ok(
                NameserverUpdateResult(
                    nameservers=nameservers,
                    pending=True,
                    operation_handle=response.headers.get("Location", ""),
                )
            )
        return self._handle_error_response(response, f"update nameservers for {domain_name}", domain_name=domain_name)

    def _do_set_lock(self, domain_name: str, locked: bool) -> Result[DomainLockResult, RegistrarAPIError]:
        # #265: transfer lock lives on the /status sub-resource, not the domain resource.
        # The previous body patched the DOMAIN with tags/autorenew, so lock/unlock never
        # touched the transfer-lock state at all — and unlock sent {"autorenew": None},
        # which risked clearing autorenew instead. See https://api.gandi.net/docs/domains/
        # (PATCH /v5/domain/domains/{domain}/status).
        url = f"{GANDI_API_BASE}/domain/domains/{domain_name}/status"
        body: dict[str, Any] = {"clientTransferProhibited": locked}

        try:
            response = self._api_request("PATCH", url, json=body, headers=self._auth_headers())
        except requests.RequestException as exc:
            # Lock toggle is a mutation — may have applied; UNKNOWN default.
            return Err(RegistrarTransientError(self.registrar.name, f"Network error: {exc}"))

        if response.status_code == HTTP_OK:
            return Ok(DomainLockResult(locked=locked))
        if response.status_code == HTTP_ACCEPTED:
            # Acceptance, not completion — local lock state must wait for confirmation (#257).
            return Ok(
                DomainLockResult(
                    locked=locked,
                    pending=True,
                    operation_handle=response.headers.get("Location", ""),
                )
            )
        return self._handle_error_response(response, f"{'lock' if locked else 'unlock'} {domain_name}")

    # -- Helpers -------------------------------------------------------------

    def _map_registrant_to_gandi(self, registrant_data: dict[str, Any]) -> dict[str, Any]:
        """Map PRAHO registrant data to Gandi's owner contact format."""
        return {
            "given": registrant_data.get("first_name", ""),
            "family": registrant_data.get("last_name", ""),
            "email": registrant_data.get("email", ""),
            "phone": registrant_data.get("phone", ""),
            "streetaddr": registrant_data.get("address", ""),
            "city": registrant_data.get("city", ""),
            "zip": registrant_data.get("postal_code", ""),
            "country": registrant_data.get("country_code", "RO"),
            "type": registrant_data.get("entity_type", "individual"),
            "orgname": registrant_data.get("company_name", ""),
        }


def _parse_gandi_date(date_str: str) -> datetime | None:
    """Parse ISO 8601 date from Gandi API response.

    Returns None on missing/unparseable input. Callers distinguish a malformed
    completed-resource response from a documented 202 acceptance that is still
    awaiting registrar confirmation — neither may fabricate a date.
    """
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None


# Register with factory
RegistrarGatewayFactory.register_gateway("gandi", GandiGateway)
