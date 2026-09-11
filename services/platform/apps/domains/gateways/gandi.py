"""Gandi REST v5 contract (https://api.gandi.net/docs/domains/).

Documentation-aligned, NOT live-validated. Mutations acknowledge acceptance with
202; only domain-details reads confirm state. The verification gate stays off.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from apps.common.outbound_http import OutboundPolicy
from apps.common.types import Err, Ok, Result, Retriability, retriability_of

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
from .contracts import api_endpoint, domain_identity, invalid_response, parse_date, required_contact, string_list
from .errors import RegistrarAPIError, RegistrarTransientError

MAX_OPERATION_REFERENCE_LENGTH = 2048
MIN_PRINTABLE_CHARACTER = 32

GANDI_API_BASE = "https://api.gandi.net/v5"
GANDI_HOSTS = frozenset({"api.gandi.net", "api.sandbox.gandi.net"})
GANDI_POLICY = OutboundPolicy(
    name="gandi_registrar",
    allowed_domains=GANDI_HOSTS,
    allowed_ports=frozenset({443}),
    timeout_seconds=30.0,
    connect_timeout_seconds=10.0,
    verify_tls=True,
    max_retries=0,
    retry_connection_errors=False,
)


class GandiGateway(BaseRegistrarGateway):
    @property
    def gateway_name(self) -> str:
        return "gandi"

    @property
    def _api_base(self) -> str:
        return api_endpoint(self.registrar.api_endpoint, GANDI_HOSTS, "/v5", frozenset({443}))

    def _get_outbound_policy(self) -> OutboundPolicy:
        return replace(GANDI_POLICY, allowed_domains=frozenset({str(urlsplit(self._api_base).hostname)}))

    def _auth_headers(self) -> dict[str, str]:
        _, api_key = self.registrar.get_api_credentials()
        return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def _get_sharing_id(self) -> str | None:
        return self.registrar.api_username or None

    def _send(self, method: str, path: str, **kwargs: Any) -> Result[requests.Response, RegistrarAPIError]:
        url = f"{self._api_base}{path}"
        try:
            return Ok(self._api_request(method, url, headers=self._auth_headers(), **kwargs))
        except requests.RequestException:
            return Err(
                RegistrarTransientError(self.registrar.name, "Registrar connection failed"),
                retriability=Retriability.RETRIABLE if method == "GET" else Retriability.UNKNOWN,
            )

    def _sharing_params(self) -> dict[str, str]:
        sharing_id = self._get_sharing_id()
        return {"sharing_id": sharing_id} if sharing_id else {}

    def _operation_handle(self, response: requests.Response) -> str:
        """Retain a bounded same-origin reference, never a URL to blindly follow."""
        value = response.headers.get("Location", "")
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_OPERATION_REFERENCE_LENGTH
            or any(ord(c) < MIN_PRINTABLE_CHARACTER for c in value)
        ):
            return ""
        try:
            url = urljoin(f"{self._api_base}/", value)
            parsed, base = urlsplit(url), urlsplit(self._api_base)
            if (
                parsed.scheme != base.scheme
                or parsed.hostname != base.hostname
                or (parsed.port or 443) != (base.port or 443)
                or parsed.username
                or parsed.password
                or parsed.fragment
                or parsed.query
                or not parsed.path.startswith("/v5/")
                or len(url) > MAX_OPERATION_REFERENCE_LENGTH
            ):
                return ""
        except ValueError:
            return ""
        return url

    def _mutation_error(self, response: requests.Response, domain_name: str) -> Err[RegistrarAPIError]:
        # A 200 is documented as dry-run validation, never mutation completion.
        if response.status_code == HTTP_OK:
            return Err(invalid_response("Gandi returned validation instead of mutation acceptance"))
        return self._handle_error_response(response, "mutation", domain_name=domain_name)

    def validate_registration_data(self, registrant_data: dict[str, Any]) -> None:
        _ = self._api_base  # validate configuration before creating contacts or sending credentials
        required_contact(registrant_data, ("first_name", "last_name", "email", "address", "country_code"))
        if registrant_data.get("entity_type") == "company":
            required_contact(registrant_data, ("company_name",))

    def _do_register(
        self,
        domain_name: str,
        years: int,
        registrant_data: dict[str, Any],
        nameservers: list[str] | None,
    ) -> Result[DomainRegistrationResult, RegistrarAPIError]:
        body: dict[str, Any] = {
            "fqdn": domain_name,
            "duration": years,
            "owner": self._map_registrant_to_gandi(registrant_data),
        }
        if nameservers:
            body["nameservers"] = nameservers
        result = self._send("POST", "/domain/domains", json=body, params=self._sharing_params())
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        response = result.unwrap()
        if response.status_code == HTTP_ACCEPTED:
            # No response-body fields are proof of completion, even if an upstream
            # happens to include id/expiry. Acceptance survives an empty/broken body.
            return Ok(
                DomainRegistrationResult(
                    registrar_domain_id="",
                    expires_at=None,
                    nameservers=[],
                    pending=True,
                    operation_handle=self._operation_handle(response),
                )
            )
        return self._mutation_error(response, domain_name)

    def _do_renew(
        self,
        registrar_domain_id: str,
        domain_name: str,
        years: int,
    ) -> Result[DomainRenewalResult, RegistrarAPIError]:
        result = self._send(
            "POST",
            f"/domain/domains/{domain_name}/renew",
            json={"duration": years},
            params=self._sharing_params(),
        )
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        response = result.unwrap()
        if response.status_code == HTTP_ACCEPTED:
            return Ok(
                DomainRenewalResult(
                    new_expires_at=None,
                    pending=True,
                    operation_handle=self._operation_handle(response),
                )
            )
        return self._mutation_error(response, domain_name)

    def _do_check_availability(self, domain_name: str) -> Result[DomainAvailabilityResult, RegistrarAPIError]:
        result = self._send("GET", "/domain/check", params={"name": domain_name, **self._sharing_params()})
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        response = result.unwrap()
        if response.status_code != HTTP_OK:
            return self._handle_error_response(response, "availability", domain_name=domain_name)
        data = self._safe_object(response)
        products = data.get("products")
        if not isinstance(products, list) or not products:
            raise invalid_response("Gandi availability response has no products")
        product = products[0]
        if not isinstance(product, dict) or product.get("status") not in ("available", "unavailable"):
            raise invalid_response("Invalid Gandi availability status")
        price_cents = None
        prices = product.get("prices", [])
        if isinstance(prices, list) and prices and isinstance(prices[0], dict):
            try:
                price = Decimal(str(prices[0].get("price_after_taxes")))
                if price.is_finite() and price >= 0:
                    price_cents = int(price * 100)
            except (InvalidOperation, ValueError, OverflowError):
                pass  # pricing is optional; never fabricate it from malformed data
        return Ok(
            DomainAvailabilityResult(
                domain_name=domain_name,
                available=product["status"] == "available",
                premium=product.get("premium") is True,
                price_cents=price_cents,
            )
        )

    def _do_verify_webhook(self, payload: str, signature: str, secret: str) -> bool:
        return self._verify_hmac_sha256(payload, signature, secret)

    def _do_initiate_transfer(
        self,
        domain_name: str,
        epp_code: str,
        registrant_data: dict[str, Any] | None = None,
    ) -> Result[DomainTransferResult, RegistrarAPIError]:
        body: dict[str, Any] = {"fqdn": domain_name, "authinfo": epp_code}
        if registrant_data is not None:
            body["owner"] = self._map_registrant_to_gandi(registrant_data)
        result = self._send("POST", "/domain/transferin", json=body, params=self._sharing_params())
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        response = result.unwrap()
        if response.status_code == HTTP_ACCEPTED:
            return Ok(DomainTransferResult(transfer_id=self._operation_handle(response), status="pending"))
        return self._mutation_error(response, domain_name)

    def _do_get_domain_info(self, domain_name: str) -> Result[DomainInfoResult, RegistrarAPIError]:
        result = self._send("GET", f"/domain/domains/{domain_name}")
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        response = result.unwrap()
        if response.status_code != HTTP_OK:
            return self._handle_error_response(response, "info", domain_name=domain_name)
        data = self._safe_object(response)
        name = domain_identity(data.get("fqdn"), domain_name)
        statuses = string_list(data.get("status"))
        nameservers = string_list(data.get("nameservers"))
        dates = data.get("dates")
        if not isinstance(dates, dict):
            raise invalid_response("Gandi domain details are missing dates")
        expiry = parse_date(dates.get("registry_ends_at"))
        if dates.get("registry_ends_at") and expiry is None:
            raise invalid_response("Invalid Gandi registry expiry")
        blocked = {"clientHold", "serverHold", "pendingTransfer"}
        known = blocked | {
            "clientUpdateProhibited",
            "clientTransferProhibited",
            "clientDeleteProhibited",
            "clientRenewProhibited",
            "serverTransferProhibited",
        }
        status = "unknown" if set(statuses) - known else "pending" if blocked.intersection(statuses) else "active"
        owner = data.get("contacts", {}).get("owner", {}) if isinstance(data.get("contacts", {}), dict) else {}
        return Ok(
            DomainInfoResult(
                registrar_domain_id=str(data.get("id") or name),
                domain_name=name,
                status=status,
                expires_at=expiry,
                nameservers=nameservers,
                registry_statuses=tuple(statuses),
                locked="clientTransferProhibited" in statuses or "serverTransferProhibited" in statuses,
                whois_privacy=isinstance(owner, dict) and owner.get("data_obfuscated") is True,
                epp_code=data.get("authinfo", "") if isinstance(data.get("authinfo", ""), str) else "",
            )
        )

    def _do_update_nameservers(
        self,
        domain_name: str,
        nameservers: list[str],
    ) -> Result[NameserverUpdateResult, RegistrarAPIError]:
        result = self._send("PUT", f"/domain/domains/{domain_name}/nameservers", json={"nameservers": nameservers})
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        response = result.unwrap()
        if response.status_code == HTTP_ACCEPTED:
            return Ok(
                NameserverUpdateResult(
                    nameservers=nameservers,
                    pending=True,
                    operation_handle=self._operation_handle(response),
                )
            )
        return self._mutation_error(response, domain_name)

    def _do_set_lock(self, domain_name: str, locked: bool) -> Result[DomainLockResult, RegistrarAPIError]:
        result = self._send("PATCH", f"/domain/domains/{domain_name}/status", json={"clientTransferProhibited": locked})
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        response = result.unwrap()
        if response.status_code == HTTP_ACCEPTED:
            return Ok(DomainLockResult(locked=locked, pending=True, operation_handle=self._operation_handle(response)))
        return self._mutation_error(response, domain_name)

    def _map_registrant_to_gandi(self, registrant_data: dict[str, Any]) -> dict[str, Any]:
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
    return parse_date(date_str)


RegistrarGatewayFactory.register_gateway("gandi", GandiGateway)
