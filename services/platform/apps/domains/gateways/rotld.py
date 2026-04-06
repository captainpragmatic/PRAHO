"""
ROTLD REST API v2.0 gateway for .ro domain registration.

ROTLD is the sole authority for Romanian domains (.ro, .com.ro, etc.).
Test environment: registrar2-test.rotld.ro
Production: rest2.rotld.ro

Romanian-specific requirements:
- CUI (Company Unique Identifier) for businesses
- CNP (Personal Numeric Code) for individuals
- Registrar accreditation from ICI-Bucharest required
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
    HTTP_CREATED,
    HTTP_OK,
    BaseRegistrarGateway,
    DomainAvailabilityResult,
    DomainRegistrationResult,
    DomainRenewalResult,
    RegistrarGatewayFactory,
)
from .errors import RegistrarAPIError, RegistrarTransientError

logger = logging.getLogger(__name__)

ROTLD_POLICY = OutboundPolicy(
    name="rotld_registrar",
    allowed_domains=frozenset({"rest2.rotld.ro", "registrar2-test.rotld.ro"}),
    timeout_seconds=30.0,
    connect_timeout_seconds=10.0,
    verify_tls=True,
    max_retries=0,
)


class ROTLDGateway(BaseRegistrarGateway):
    """ROTLD REST API gateway for .ro domains."""

    @property
    def gateway_name(self) -> str:
        return "rotld"

    def _get_outbound_policy(self) -> OutboundPolicy:
        return ROTLD_POLICY

    def _auth_headers(self) -> dict[str, str]:
        _username, api_key = self.registrar.get_api_credentials()
        return {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @property
    def _api_base(self) -> str:
        """Use the registrar's configured API endpoint."""
        return self.registrar.api_endpoint.rstrip("/")

    # -- Core operations -----------------------------------------------------

    def _do_register(
        self,
        domain_name: str,
        years: int,
        registrant_data: dict[str, Any],
        nameservers: list[str] | None,
    ) -> Result[DomainRegistrationResult, RegistrarAPIError]:
        url = f"{self._api_base}/domain/register"

        body: dict[str, Any] = {
            "domain": domain_name,
            "period": years,
            "registrant": self._map_registrant_to_rotld(registrant_data),
        }

        if nameservers:
            body["nameservers"] = [{"hostname": ns} for ns in nameservers]

        try:
            response = self._api_request("POST", url, json=body, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                RegistrarTransientError(self.registrar.name, f"Network error during registration: {exc}"),
                retriable=True,
            )

        if response.status_code in (HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED):
            data = response.json()
            domain_data = data.get("domain", data)
            return Ok(
                DomainRegistrationResult(
                    registrar_domain_id=str(domain_data.get("id", domain_name)),
                    expires_at=_parse_rotld_date(domain_data.get("expire_at", "")),
                    nameservers=nameservers or self.registrar.default_nameservers or [],
                    epp_code=domain_data.get("authcode", ""),
                )
            )

        return self._handle_error_response(response, f"register {domain_name}")

    def _do_renew(
        self,
        registrar_domain_id: str,
        domain_name: str,
        years: int,
    ) -> Result[DomainRenewalResult, RegistrarAPIError]:
        url = f"{self._api_base}/domain/renew"

        body = {
            "domain": domain_name,
            "period": years,
        }

        try:
            response = self._api_request("POST", url, json=body, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                RegistrarTransientError(self.registrar.name, f"Network error during renewal: {exc}"),
                retriable=True,
            )

        if response.status_code in (HTTP_OK, HTTP_ACCEPTED):
            data = response.json()
            domain_data = data.get("domain", data)
            return Ok(
                DomainRenewalResult(
                    new_expires_at=_parse_rotld_date(domain_data.get("expire_at", "")),
                )
            )

        return self._handle_error_response(response, f"renew {domain_name}")

    def _do_check_availability(
        self,
        domain_name: str,
    ) -> Result[DomainAvailabilityResult, RegistrarAPIError]:
        url = f"{self._api_base}/domain/check"
        params = {"domain": domain_name}

        try:
            response = self._api_request("GET", url, params=params, headers=self._auth_headers())
        except requests.RequestException as exc:
            return Err(
                RegistrarTransientError(self.registrar.name, f"Network error during availability check: {exc}"),
                retriable=True,
            )

        if response.status_code == HTTP_OK:
            data = response.json()
            return Ok(
                DomainAvailabilityResult(
                    domain_name=domain_name,
                    available=data.get("available", False),
                    premium=False,
                    price_cents=None,
                )
            )

        return self._handle_error_response(response, f"check availability for {domain_name}")

    def _do_verify_webhook(self, payload: str, signature: str, secret: str) -> bool:
        return self._verify_hmac_sha256(payload, signature, secret)

    # -- Helpers -------------------------------------------------------------

    def _map_registrant_to_rotld(self, registrant_data: dict[str, Any]) -> dict[str, Any]:
        """Map PRAHO registrant data to ROTLD's registrant format.

        Romanian domains require CUI for businesses or CNP for individuals.
        """
        entity_type = registrant_data.get("entity_type", "individual")
        result: dict[str, Any] = {
            "name": f"{registrant_data.get('first_name', '')} {registrant_data.get('last_name', '')}".strip(),
            "email": registrant_data.get("email", ""),
            "phone": registrant_data.get("phone", ""),
            "address": registrant_data.get("address", ""),
            "city": registrant_data.get("city", ""),
            "postal_code": registrant_data.get("postal_code", ""),
            "country": registrant_data.get("country_code", "RO"),
        }

        if entity_type == "company":
            result["org"] = registrant_data.get("company_name", "")
            result["fiscal_code"] = registrant_data.get("cui", "")
        else:
            result["cnp"] = registrant_data.get("cnp", "")

        return result


def _parse_rotld_date(date_str: str) -> datetime:
    """Parse date from ROTLD API response."""
    from django.utils import timezone  # noqa: PLC0415

    if not date_str:
        return timezone.now()
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return timezone.now()


# Register with factory
RegistrarGatewayFactory.register_gateway("rotld", ROTLDGateway)
