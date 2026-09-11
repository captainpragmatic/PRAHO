"""ROTLD REST v2, revision 1.0.2 (2013-01-09), NOT live-validated.

The selected historical specification uses Digest-authenticated form POSTs, not
JSON REST resources. See docs/development/REGISTRAR_VALIDATION.md for provenance
and the outstanding checks required before enabling this adapter.
"""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime
from typing import Any, ClassVar
from urllib.parse import urlsplit

import requests
from requests.auth import HTTPDigestAuth

from apps.common.outbound_http import OutboundPolicy
from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from .base import (
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
from .errors import (
    RegistrarAPIError,
    RegistrarAuthError,
    RegistrarConflictError,
    RegistrarErrorCode,
    RegistrarNotFoundError,
    RegistrarTransientError,
)

MAX_PHONE_LENGTH = 20
MAX_NAMESERVERS = 6

ROTLD_HOSTS = frozenset({"rest2.rotld.ro", "rest2-test.rotld.ro"})
ROTLD_POLICY = OutboundPolicy(
    name="rotld_registrar",
    allowed_domains=ROTLD_HOSTS,
    allowed_ports=frozenset({443, 6080}),
    timeout_seconds=30.0,
    connect_timeout_seconds=10.0,
    verify_tls=True,
    max_retries=0,
    retry_connection_errors=False,
)


class ROTLDGateway(BaseRegistrarGateway):
    registration_sets_nameservers: ClassVar[bool] = False
    registration_requires_contact: ClassVar[bool] = True

    @property
    def gateway_name(self) -> str:
        return "rotld"

    @property
    def _api_base(self) -> str:
        return api_endpoint(self.registrar.api_endpoint, ROTLD_HOSTS, "", frozenset({443, 6080}))

    def _get_outbound_policy(self) -> OutboundPolicy:
        return replace(ROTLD_POLICY, allowed_domains=frozenset({str(urlsplit(self._api_base).hostname)}))

    def _command(
        self,
        command: str,
        parameters: dict[str, Any],
        *,
        read_only: bool = False,
    ) -> Result[dict[str, Any], RegistrarAPIError]:
        url = self._api_base  # validate before accessing credentials
        username, password = self.registrar.get_api_credentials()
        try:
            response = self._api_request(
                "POST",
                url,
                data={"command": command, "format": "json", "lang": "en", **parameters},
                auth=HTTPDigestAuth(username, password),
                headers={"Accept": "application/json"},
            )
        except requests.RequestException:
            return Err(
                RegistrarTransientError(self.registrar.name, "Registrar connection failed"),
                retriability=Retriability.RETRIABLE if read_only else Retriability.UNKNOWN,
            )
        if response.status_code != HTTP_OK:
            return self._handle_error_response(response, command, domain_name=parameters.get("domain", ""))
        envelope = self._safe_object(response)
        code, error, data = envelope.get("result_code"), envelope.get("error"), envelope.get("data")
        if (
            not isinstance(code, str)
            or re.fullmatch(r"[0-9]{5}", code) is None
            or type(error) is not int
            or error not in (0, 1)
            or not isinstance(data, dict)
        ):
            raise invalid_response("Malformed ROTLD response envelope")
        if code == "00200" and error == 0:
            return Ok(data)
        if code == "00200" or error == 0:
            raise invalid_response("Inconsistent ROTLD result code and error flag")
        return self._business_error(code, str(parameters.get("domain", "")), read_only=read_only)

    def _business_error(self, code: str, domain_name: str, *, read_only: bool) -> Err[RegistrarAPIError]:
        error: RegistrarAPIError
        if code in {"10001", "10014"}:
            error = RegistrarNotFoundError(domain_name, self.registrar.name)
        elif code == "10009":
            error = RegistrarConflictError(domain_name, self.registrar.name)
        elif code in {"10002", "10004", "10008", "10011", "40001", "40003", "40004", "40404"}:
            # Ownership/access denial is never proof that a domain does not exist.
            error = RegistrarAuthError(self.registrar.name)
        elif code in {"10506", "10508", "10512", "40002"}:
            error = RegistrarAPIError("ROTLD operation not eligible", code=RegistrarErrorCode.DOMAIN_NOT_ELIGIBLE)
        elif code in {"10501", "10502", "50017", "50018"}:
            error = RegistrarAPIError("ROTLD nameserver update rejected", code=RegistrarErrorCode.INVALID_NAMESERVERS)
        elif code.startswith("50"):
            error = RegistrarAPIError("ROTLD parameters rejected", code=RegistrarErrorCode.INVALID_REGISTRANT_DATA)
        elif code in {"20001", "20002"}:
            error = RegistrarAPIError("ROTLD account has insufficient funds", code=RegistrarErrorCode.NOT_CONFIGURED)
        else:
            # Unclassified/internal errors cannot prove a write was not applied.
            return Err(
                RegistrarTransientError(self.registrar.name, f"Unconfirmed ROTLD outcome ({code[:5]})"),
                retriability=Retriability.RETRIABLE if read_only else Retriability.UNKNOWN,
            )
        return Err(error, retriability=Retriability.NOT_RETRIABLE)

    def validate_registration_data(self, registrant_data: dict[str, Any]) -> None:
        _ = self._api_base
        required_contact(registrant_data, ("email", "phone", "address", "city", "country_code"))
        company = registrant_data.get("entity_type") == "company"
        required_contact(registrant_data, ("company_name",) if company else ("first_name", "last_name"))
        if registrant_data.get("country_code") == "RO":
            required_contact(registrant_data, ("cui", "registration_number") if company else ("cnp",))
        self._contact_phone(str(registrant_data["phone"]))

    @staticmethod
    def _contact_phone(phone: str) -> str:
        # Existing Romanian E.164 customer numbers have an unambiguous +40 code.
        if re.fullmatch(r"\+40\d{9}", phone):
            phone = f"+40.{phone[3:]}"
        if not re.fullmatch(r"\+\d{1,3}\.\d{4,14}", phone) or len(phone) > MAX_PHONE_LENGTH:
            raise RegistrarAPIError(
                "ROTLD requires an international phone number in +country.number format",
                code=RegistrarErrorCode.INVALID_REGISTRANT_DATA,
            )
        return phone

    def _map_registrant_to_rotld(self, data: dict[str, Any]) -> dict[str, Any]:
        company = data.get("entity_type") == "company"
        return {
            "name": data.get("company_name", "")
            if company
            else f"{data.get('first_name', '')} {data.get('last_name', '')}".strip(),
            "address1": data.get("address", ""),
            "city": data.get("city", ""),
            "postal_code": data.get("postal_code", ""),
            "country_code": data.get("country_code", ""),
            "phone": self._contact_phone(str(data.get("phone", ""))),
            "email": data.get("email", ""),
            "person_type": "c" if company else "p",
            "cnp_fiscal_code": data.get("cui" if company else "cnp", ""),
            "registration_number": data.get("registration_number", ""),
        }

    def prepare_registration_contact(self, registrant_data: dict[str, Any]) -> Result[str | None, RegistrarAPIError]:
        if guard := self._verified_adapter_guard():
            return guard
        try:
            self.validate_registration_data(registrant_data)
        except RegistrarAPIError as exc:
            return Err(exc, retriability=Retriability.NOT_RETRIABLE)
        return self._run_phase2_op(
            lambda: self._create_contact(registrant_data),
            "contact-create",
            "Contact creation unsupported",
        )

    def _create_contact(self, data: dict[str, Any]) -> Result[str, RegistrarAPIError]:
        result = self._command("contact-create", self._map_registrant_to_rotld(data))
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        cid = result.unwrap().get("cid")
        if not isinstance(cid, str) or not cid:
            raise invalid_response("ROTLD contact response is missing cid")
        return Ok(cid)

    def _do_register(
        self,
        domain_name: str,
        years: int,
        registrant_data: dict[str, Any],
        nameservers: list[str] | None,
    ) -> Result[DomainRegistrationResult, RegistrarAPIError]:
        cid = registrant_data.get("registrar_contact_id")
        if not isinstance(cid, str) or not cid:
            return Err(
                RegistrarAPIError(
                    "ROTLD registration requires a persisted contact ID",
                    code=RegistrarErrorCode.NOT_CONFIGURED,
                ),
                retriability=Retriability.NOT_RETRIABLE,
            )
        result = self._command(
            "domain-register",
            {
                "domain": domain_name,
                "domain_period": years,
                "c_registrant": cid,
                "reservation": 0,
            },
        )
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        data = result.unwrap()
        name = domain_identity(data.get("domain"), domain_name)
        expiry = _parse_rotld_date(data.get("expiration_date", ""))
        # Nameserver assignment is a separate command and a separate operation.
        # A missing expiry leaves a confirmed write pending local verification.
        return Ok(DomainRegistrationResult(name, expiry, [], pending=expiry is None))

    def _do_renew(
        self,
        registrar_domain_id: str,
        domain_name: str,
        years: int,
    ) -> Result[DomainRenewalResult, RegistrarAPIError]:
        result = self._command("domain-renew", {"domain": domain_name, "domain_period": years})
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        data = result.unwrap()
        domain_identity(data.get("domain"), domain_name)
        expiry = _parse_rotld_date(data.get("expiration_date", ""))
        return Ok(DomainRenewalResult(expiry, pending=expiry is None))

    def _do_check_availability(self, domain_name: str) -> Result[DomainAvailabilityResult, RegistrarAPIError]:
        result = self._command("check-availability", {"domain": domain_name}, read_only=True)
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        status = result.unwrap().get("status")
        if status not in ("Available", "Not Available", "Not Allowed"):
            raise invalid_response("Unknown ROTLD availability status")
        return Ok(DomainAvailabilityResult(domain_name=domain_name, available=status == "Available"))

    def _do_get_domain_info(self, domain_name: str) -> Result[DomainInfoResult, RegistrarAPIError]:
        result = self._command("domain-info", {"domain": domain_name}, read_only=True)
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        data = result.unwrap()
        name = domain_identity(data.get("domain"), domain_name)
        statuses = string_list(data.get("statuses"))
        nameservers = string_list(data.get("nameservers"))
        expiry = _parse_rotld_date(data.get("expiration_date", ""))
        if data.get("expiration_date") and expiry is None:
            raise invalid_response("Invalid or ambiguous ROTLD expiration date")
        pending = {"Hold", "Reserved", "PendingDelete", "RegistrantPendingTransfer"}
        known = pending | {
            "OK",
            "Locked",
            "DeleteProhibited",
            "RenewProhibited",
            "TransferProhibited",
            "UpdateProhibited",
            "RegistrantTransferProhibited",
        }
        status = (
            "unknown"
            if not statuses or set(statuses) - known
            else "pending"
            if pending.intersection(statuses)
            else "active"
        )
        return Ok(
            DomainInfoResult(
                registrar_domain_id=name,
                domain_name=name,
                status=status,
                expires_at=expiry,
                nameservers=nameservers,
                registry_statuses=tuple(statuses),
                locked="TransferProhibited" in statuses,
            )
        )

    def _do_update_nameservers(
        self,
        domain_name: str,
        nameservers: list[str],
    ) -> Result[NameserverUpdateResult, RegistrarAPIError]:
        if len(nameservers) > MAX_NAMESERVERS or any("," in ns for ns in nameservers):
            return Err(
                RegistrarAPIError(
                    "Invalid ROTLD nameserver list",
                    code=RegistrarErrorCode.INVALID_NAMESERVERS,
                ),
                retriability=Retriability.NOT_RETRIABLE,
            )
        result = self._command("domain-reset-ns", {"domain": domain_name, "nameservers": ",".join(nameservers)})
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        return Ok(NameserverUpdateResult(nameservers=nameservers))

    def _do_initiate_transfer(
        self,
        domain_name: str,
        epp_code: str,
        registrant_data: dict[str, Any] | None = None,
    ) -> Result[DomainTransferResult, RegistrarAPIError]:
        result = self._command("domain-transfer", {"domain": domain_name, "authorization_key": epp_code})
        if result.is_err():
            return Err(result.unwrap_err(), retriability=retriability_of(result))
        # The command returns an empty data object, not a transfer ID/auth code.
        return Ok(DomainTransferResult(transfer_id="", status="pending"))

    def _do_set_lock(self, domain_name: str, locked: bool) -> Result[DomainLockResult, RegistrarAPIError]:
        return Err(
            RegistrarAPIError(
                "ROTLD REST v2 does not document a lock mutation",
                code=RegistrarErrorCode.UNSUPPORTED_OPERATION,
            ),
            retriability=Retriability.NOT_RETRIABLE,
        )

    def _do_verify_webhook(self, payload: str, signature: str, secret: str) -> bool:
        # Compatibility seam only: neither the selected specification nor offline
        # fixtures establish that ROTLD sends these application-level webhooks.
        return self._verify_hmac_sha256(payload, signature, secret)


def _parse_rotld_date(date_str: object) -> datetime | None:
    return parse_date(date_str, local_timezone="Europe/Bucharest")


RegistrarGatewayFactory.register_gateway("rotld", ROTLDGateway)
