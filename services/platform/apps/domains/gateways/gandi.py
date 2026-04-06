"""
Gandi REST API gateway for international domain registration.

API docs: https://api.gandi.net/docs/domains/
Auth: Personal Access Token via Authorization header.
Rate limit: 30 requests / 2 seconds (negotiable for resellers).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import requests

from apps.common.outbound_http import OutboundPolicy
from apps.common.types import Err, Ok, Result

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
from .errors import RegistrarAPIError, RegistrarTransientError

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

        sharing_id = self._get_sharing_id()
        if sharing_id:
            body["sharing_id"] = sharing_id

        try:
            response = self._api_request("POST", url, json=body, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                RegistrarTransientError(self.registrar.name, f"Network error during registration: {exc}"),
                retriable=True,
            )

        if response.status_code == HTTP_ACCEPTED:
            data = response.json()
            return Ok(
                DomainRegistrationResult(
                    registrar_domain_id=data.get("id", domain_name),
                    expires_at=_parse_gandi_date(data.get("expires_at", "")),
                    nameservers=nameservers or self.registrar.default_nameservers or [],
                    epp_code=data.get("auth_info", ""),
                )
            )

        return self._handle_error_response(response, f"register {domain_name}")

    def _do_renew(
        self,
        registrar_domain_id: str,
        domain_name: str,
        years: int,
    ) -> Result[DomainRenewalResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/domains/{domain_name}/renew"

        body = {"duration": years}

        try:
            response = self._api_request("POST", url, json=body, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                RegistrarTransientError(self.registrar.name, f"Network error during renewal: {exc}"),
                retriable=True,
            )

        if response.status_code in (HTTP_OK, HTTP_ACCEPTED):
            data = response.json()
            return Ok(
                DomainRenewalResult(
                    new_expires_at=_parse_gandi_date(data.get("expires_at", "")),
                )
            )

        return self._handle_error_response(response, f"renew {domain_name}")

    def _do_check_availability(
        self,
        domain_name: str,
    ) -> Result[DomainAvailabilityResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/check"
        params = {"name": domain_name}

        try:
            response = self._api_request("GET", url, params=params, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                RegistrarTransientError(self.registrar.name, f"Network error during availability check: {exc}"),
                retriable=True,
            )

        if response.status_code == HTTP_OK:
            data = response.json()
            products = data.get("products", [])
            if products:
                product = products[0]
                status = product.get("status", "unavailable")
                price_data = product.get("prices", [{}])
                price_cents = None
                if price_data:
                    price_raw = price_data[0].get("price_after_taxes")
                    if price_raw is not None:
                        price_cents = int(float(price_raw) * 100)

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

        return self._handle_error_response(response, f"check availability for {domain_name}")

    def _do_verify_webhook(self, payload: str, signature: str, secret: str) -> bool:
        return self._verify_hmac_sha256(payload, signature, secret)

    # -- Phase 2 operations --------------------------------------------------

    def _do_initiate_transfer(self, domain_name: str, epp_code: str) -> Result[DomainTransferResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/transferin"
        body: dict[str, Any] = {"fqdn": domain_name, "auth_info": epp_code}

        sharing_id = self._get_sharing_id()
        if sharing_id:
            body["sharing_id"] = sharing_id

        try:
            response = self._api_request("POST", url, json=body, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                RegistrarTransientError(self.registrar.name, f"Network error during transfer: {exc}"), retriable=True
            )

        if response.status_code in (HTTP_OK, HTTP_ACCEPTED):
            data = response.json()
            return Ok(
                DomainTransferResult(
                    transfer_id=data.get("id", ""),
                    status=data.get("status", "pending"),
                    expected_completion=_parse_gandi_date(data.get("expected_completion", "")),
                )
            )
        return self._handle_error_response(response, f"transfer {domain_name}")

    def _do_get_domain_info(self, domain_name: str) -> Result[DomainInfoResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/domains/{domain_name}"

        try:
            response = self._api_request("GET", url, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(RegistrarTransientError(self.registrar.name, f"Network error: {exc}"), retriable=True)

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
                    epp_code=data.get("auth_info", ""),
                )
            )
        return self._handle_error_response(response, f"info {domain_name}")

    def _do_update_nameservers(
        self, domain_name: str, nameservers: list[str]
    ) -> Result[NameserverUpdateResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/domains/{domain_name}/nameservers"

        try:
            response = self._api_request("PUT", url, json=nameservers, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(RegistrarTransientError(self.registrar.name, f"Network error: {exc}"), retriable=True)

        if response.status_code in (HTTP_OK, HTTP_ACCEPTED):
            return Ok(NameserverUpdateResult(nameservers=nameservers))
        return self._handle_error_response(response, f"update nameservers for {domain_name}")

    def _do_set_lock(self, domain_name: str, locked: bool) -> Result[DomainLockResult, RegistrarAPIError]:
        url = f"{GANDI_API_BASE}/domain/domains/{domain_name}"
        # Gandi uses PATCH on domain to toggle transfer lock
        body = {"autorenew": None}  # Gandi lock is via domain status update
        if locked:
            body = {"tags": ["locked"]}

        try:
            response = self._api_request("PATCH", url, json=body, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(RegistrarTransientError(self.registrar.name, f"Network error: {exc}"), retriable=True)

        if response.status_code in (HTTP_OK, HTTP_ACCEPTED):
            return Ok(DomainLockResult(locked=locked))
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


def _parse_gandi_date(date_str: str) -> datetime:
    """Parse ISO 8601 date from Gandi API response."""
    from django.utils import timezone  # noqa: PLC0415

    if not date_str:
        return timezone.now()
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return timezone.now()


# Register with factory
RegistrarGatewayFactory.register_gateway("gandi", GandiGateway)
