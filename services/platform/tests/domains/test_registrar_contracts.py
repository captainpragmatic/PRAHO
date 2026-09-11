"""Offline wire contracts. Fixtures are synthetic, never evidence of live validation."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from requests.auth import HTTPDigestAuth

from apps.common.outbound_http import PinnedIPAdapter
from apps.common.types import Retriability, retriability_of
from apps.domains.gateways import RegistrarErrorCode
from apps.domains.gateways.contracts import parse_date
from apps.domains.gateways.gandi import GandiGateway
from apps.domains.gateways.rotld import ROTLDGateway
from apps.domains.models import Registrar
from config.settings.test import LOCMEM_TEST_CACHE

FIXTURES = json.loads((Path(__file__).parent / "fixtures/registrar_contracts.json").read_text())
CONTACT = {
    "first_name": "Test",
    "last_name": "Registrant",
    "email": "test@example.net",
    "phone": "+40721000000",
    "address": "Example Street 1",
    "city": "Bucharest",
    "postal_code": "010101",
    "country_code": "RO",
    "entity_type": "company",
    "company_name": "Example SRL",
    "cui": "RO12345678",
    "registration_number": "J40/100/2000",
}


def response(data: object, status: int = 200, headers: dict[str, str] | None = None) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    result.headers.update(headers or {})
    return result


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True, CACHES=LOCMEM_TEST_CACHE)
class RegistrarContractTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.gandi = GandiGateway(
            Registrar(pk=1, name="gandi", api_endpoint="https://api.sandbox.gandi.net/v5", api_username="org")
        )
        self.rotld = ROTLDGateway(Registrar(name="rotld", api_endpoint="https://rest2-test.rotld.ro:6080"))
        self.credentials = patch.object(Registrar, "get_api_credentials", return_value=("account", "test-secret"))
        self.credentials.start()
        self.addCleanup(self.credentials.stop)
        self.audit = patch("apps.domains.gateways.base.BaseRegistrarGateway._audit_api_call")
        self.audit.start()
        self.addCleanup(self.audit.stop)

    def test_gandi_acceptance_ignores_inline_fields_and_malformed_body(self) -> None:
        for body in ({"id": "123", "dates": {"registry_ends_at": "2028-01-01T00:00:00Z"}}, None, []):
            with (
                self.subTest(body=body),
                patch.object(self.gandi, "_api_request", return_value=response(body, 202)) as send,
            ):
                cache.clear()
                result = self.gandi.register_domain("example.com", 2, CONTACT, ["ns1.example.net"])
                self.assertTrue(result.is_ok(), result)
                self.assertTrue(result.unwrap().pending)
                self.assertIsNone(result.unwrap().expires_at)
                self.assertEqual(result.unwrap().registrar_domain_id, "")
                self.assertEqual(send.call_count, 1)
                args, kwargs = send.call_args
                self.assertEqual(args, ("POST", "https://api.sandbox.gandi.net/v5/domain/domains"))
                self.assertEqual(kwargs["headers"]["Authorization"], "Bearer test-secret")
                self.assertEqual(kwargs["params"], {"sharing_id": "org"})
                self.assertEqual(kwargs["json"]["duration"], 2)
                self.assertEqual(kwargs["json"]["nameservers"], ["ns1.example.net"])
                self.assertNotIn("cnp", kwargs["json"]["owner"])

    def test_gandi_all_writes_treat_200_as_unconfirmed_not_completed(self) -> None:
        calls = [
            lambda: self.gandi.register_domain("example.com", 1, CONTACT),
            lambda: self.gandi.renew_domain("example.com", "example.com", 1),
            lambda: self.gandi.update_nameservers("example.com", ["ns1.example.net"]),
            lambda: self.gandi.set_lock("example.com", False),
            lambda: self.gandi.initiate_transfer("example.com", "test-auth", CONTACT),
        ]
        for call in calls:
            with (
                self.subTest(call=call),
                patch.object(self.gandi, "_api_request", return_value=response({"status": "success"})) as send,
            ):
                result = call()
                self.assertTrue(result.is_err())
                self.assertEqual(retriability_of(result), Retriability.UNKNOWN)
                self.assertEqual(send.call_count, 1)

    def test_gandi_operation_reference_is_bounded_and_same_origin(self) -> None:
        examples = {
            "/v5/domain/domains/example.com": "https://api.sandbox.gandi.net/v5/domain/domains/example.com",
            "https://api.gandi.net/v5/domain/domains/example.com": "",
            "https://evil.example/v5/request": "",
            "http://api.sandbox.gandi.net/v5/request": "",
            "https://user:secret@api.sandbox.gandi.net/v5/request": "",
            "/v5/request\nheader": "",
            "x" * 2049: "",
        }
        for reference, expected in examples.items():
            with self.subTest(reference=reference):
                self.assertEqual(self.gandi._operation_handle(response({}, 202, {"Location": reference})), expected)

    def test_gandi_info_uses_registry_fields_and_retains_statuses(self) -> None:
        with patch.object(self.gandi, "_api_request", return_value=response(FIXTURES["gandi_info"])):
            result = self.gandi.get_domain_info("example.com").unwrap()
        self.assertEqual(result.registrar_domain_id, "example.com")
        self.assertEqual(result.expires_at, datetime(2028, 1, 1, tzinfo=UTC))
        self.assertEqual(result.registry_statuses, ("clientTransferProhibited",))
        self.assertTrue(result.locked)
        self.assertTrue(result.whois_privacy)

    def test_gandi_documented_empty_restriction_list_is_valid(self) -> None:
        # The official domain-list example includes an unlocked domain with
        # status: []; these are restriction flags, not a mandatory "active" enum.
        body = {**FIXTURES["gandi_info"], "status": []}
        with patch.object(self.gandi, "_api_request", return_value=response(body)):
            result = self.gandi.get_domain_info("example.com").unwrap()
        self.assertEqual(result.status, "active")
        self.assertFalse(result.locked)
        self.assertEqual(result.registry_statuses, ())

    def test_gandi_pending_and_unknown_statuses_do_not_confirm_active(self) -> None:
        for statuses in (["pendingTransfer"], ["clientHold"], ["futureStatus"]):
            body = {**FIXTURES["gandi_info"], "status": statuses}
            with self.subTest(statuses=statuses), patch.object(self.gandi, "_api_request", return_value=response(body)):
                self.assertNotEqual(self.gandi.get_domain_info("example.com").unwrap().status, "active")

    def test_info_rejects_mismatched_identity_and_wrong_collection_types(self) -> None:
        for change in ({"fqdn": "different.com"}, {"status": "active"}, {"nameservers": {}}):
            with (
                self.subTest(change=change),
                patch.object(self.gandi, "_api_request", return_value=response({**FIXTURES["gandi_info"], **change})),
            ):
                self.assertTrue(self.gandi.get_domain_info("example.com").is_err())

    def test_rotld_contact_and_registration_use_digest_form_commands(self) -> None:
        with patch.object(
            self.rotld,
            "_api_request",
            side_effect=[response(FIXTURES["rotld_contact"]), response(FIXTURES["rotld_register"])],
        ) as send:
            cid = self.rotld.prepare_registration_contact(CONTACT).unwrap()
            registration = self.rotld.register_domain(
                "example.ro", 2, {**CONTACT, "registrar_contact_id": cid}
            ).unwrap()
        contact_call, register_call = send.call_args_list
        self.assertEqual(contact_call.args, ("POST", "https://rest2-test.rotld.ro:6080"))
        self.assertIsInstance(contact_call.kwargs["auth"], HTTPDigestAuth)
        self.assertNotIn("json", contact_call.kwargs)
        data = contact_call.kwargs["data"]
        self.assertEqual(data["command"], "contact-create")
        self.assertEqual(data["person_type"], "c")
        self.assertEqual(data["cnp_fiscal_code"], "RO12345678")
        self.assertEqual(data["registration_number"], CONTACT["registration_number"])
        self.assertEqual(data["phone"], "+40.721000000")
        self.assertEqual(
            register_call.kwargs["data"],
            {
                "command": "domain-register",
                "format": "json",
                "lang": "en",
                "domain": "example.ro",
                "domain_period": 2,
                "c_registrant": cid,
                "reservation": 0,
            },
        )
        self.assertEqual(registration.registrar_domain_id, "example.ro")
        self.assertEqual(registration.epp_code, "")
        self.assertEqual(registration.nameservers, [])
        self.assertEqual(registration.expires_at, datetime(2027, 12, 31, 22, tzinfo=UTC))

    def test_rotld_renew_nameservers_transfer_and_unsupported_lock(self) -> None:
        with patch.object(
            self.rotld,
            "_api_request",
            side_effect=[
                response(FIXTURES["rotld_register"]),
                response(FIXTURES["rotld_empty"]),
                response(FIXTURES["rotld_empty"]),
            ],
        ) as send:
            self.assertTrue(self.rotld.renew_domain("example.ro", "example.ro", 1).is_ok())
            self.assertTrue(self.rotld.update_nameservers("example.ro", ["ns1.example.net", "ns2.example.net"]).is_ok())
            self.assertTrue(self.rotld.initiate_transfer("example.ro", "test-auth").is_ok())
            self.assertEqual(
                self.rotld.set_lock("example.ro", True).unwrap_err().code, RegistrarErrorCode.UNSUPPORTED_OPERATION
            )
        self.assertEqual(send.call_count, 3)
        self.assertEqual(send.call_args_list[0].kwargs["data"]["command"], "domain-renew")
        self.assertEqual(send.call_args_list[1].kwargs["data"]["nameservers"], "ns1.example.net,ns2.example.net")
        self.assertEqual(send.call_args_list[2].kwargs["data"]["authorization_key"], "test-auth")

    def test_rotld_http_200_business_errors_preserve_ownership_and_uncertainty(self) -> None:
        for code, expected in {
            "10001": RegistrarErrorCode.DOMAIN_NOT_FOUND,
            "10002": RegistrarErrorCode.AUTH_FAILED,
            "50001": RegistrarErrorCode.INVALID_REGISTRANT_DATA,
            "60001": RegistrarErrorCode.NETWORK_ERROR,
        }.items():
            with (
                self.subTest(code=code),
                patch.object(
                    self.rotld, "_api_request", return_value=response({"error": 1, "result_code": code, "data": {}})
                ) as send,
            ):
                cache.clear()
                result = self.rotld.renew_domain("example.ro", "example.ro", 1)
                self.assertEqual(result.unwrap_err().code, expected)
                self.assertEqual(send.call_count, 1)
                if code == "60001":
                    self.assertEqual(retriability_of(result), Retriability.UNKNOWN)

    def test_rotld_missing_expiry_never_fabricates_one(self) -> None:
        data = copy.deepcopy(FIXTURES["rotld_register"])
        data["data"]["expiration_date"] = ""
        with patch.object(self.rotld, "_api_request", return_value=response(data)):
            result = self.rotld.renew_domain("example.ro", "example.ro", 1).unwrap()
        self.assertTrue(result.pending)
        self.assertIsNone(result.new_expires_at)

    def test_rotld_local_dates_reject_dst_ambiguity(self) -> None:
        self.assertIsNone(parse_date("2026-10-25 03:30:00", local_timezone="Europe/Bucharest"))
        self.assertIsNone(parse_date("2026-03-29 03:30:00", local_timezone="Europe/Bucharest"))
        self.assertIsNone(parse_date("2026-01-01 00:00:00"))
        self.assertEqual(
            parse_date("2026-01-01 00:00:00", local_timezone="Europe/Bucharest"), datetime(2025, 12, 31, 22, tzinfo=UTC)
        )

    def test_invalid_endpoints_refuse_before_accessing_credentials(self) -> None:
        for endpoint in (
            "http://api.gandi.net/v5",
            "https://api.gandi.net.evil.test/v5",
            "https://api.gandi.net/v5?key=x",
            "https://user:password@api.gandi.net/v5",
            "https://api.gandi.net:6080/v5",
        ):
            self.gandi.registrar.api_endpoint = endpoint
            with (
                self.subTest(endpoint=endpoint),
                patch.object(Registrar, "get_api_credentials") as credentials,
                patch.object(self.gandi, "_api_request") as send,
            ):
                self.assertTrue(self.gandi.get_domain_info("example.com").is_err())
                credentials.assert_not_called()
                send.assert_not_called()

    def test_registrar_and_environment_isolate_cache_and_policy(self) -> None:
        other = GandiGateway(Registrar(pk=2, name="gandi", api_endpoint=self.gandi.registrar.api_endpoint))
        self.assertNotEqual(other.cache_namespace, self.gandi.cache_namespace)
        sandbox = self.gandi.cache_namespace
        self.gandi.registrar.api_endpoint = "https://api.gandi.net/v5"
        self.assertNotEqual(sandbox, self.gandi.cache_namespace)
        self.assertEqual(self.gandi._get_outbound_policy().allowed_domains, frozenset({"api.gandi.net"}))

    def test_rotld_digest_challenge_keeps_pinned_transport_host_and_tls(self) -> None:
        calls = []

        def transport(adapter, request, **kwargs):
            calls.append((request.copy(), kwargs, adapter))
            result = response(FIXTURES["rotld_available"], 200 if len(calls) == 2 else 401)
            result.request = request
            result.url = request.url
            result.connection = adapter
            result.raw = BytesIO(result.content)
            if len(calls) == 1:
                result.headers["WWW-Authenticate"] = 'Digest realm="rotld", nonce="test-nonce", qop="auth"'
            return result

        with (
            patch("apps.common.outbound_http._resolve_dns", return_value=["8.8.8.8"]),
            patch("requests.adapters.HTTPAdapter.send", autospec=True, side_effect=transport),
        ):
            result = self.rotld.check_availability("example.ro")
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(len(calls), 2)
        for request, options, adapter in calls:
            self.assertIsInstance(adapter, PinnedIPAdapter)
            self.assertEqual(request.url, "https://8.8.8.8:6080/")
            self.assertEqual(request.headers["Host"], "rest2-test.rotld.ro:6080")
            self.assertTrue(options["verify"])
            self.assertEqual(options["timeout"], (10.0, 30.0))
        self.assertNotIn("Authorization", calls[0][0].headers)
        self.assertTrue(calls[1][0].headers["Authorization"].startswith("Digest "))
        self.assertEqual(calls[0][0].body, calls[1][0].body)

    def test_http_error_body_never_leaks_registrant_data(self) -> None:
        for status in (400, 401, 403, 422, 500, 599):
            with (
                self.subTest(status=status),
                patch.object(
                    self.gandi,
                    "_api_request",
                    return_value=response({"message": "CNP=TEST-PRIVATE-VALUE authinfo=TEST-SECRET"}, status),
                ),
            ):
                cache.clear()
                result = self.gandi.register_domain("example.com", 1, CONTACT)
                self.assertTrue(result.is_err())
                self.assertNotIn("TEST-PRIVATE", str(result.unwrap_err()))
                self.assertNotIn("TEST-SECRET", result.unwrap_err().detail)

    def test_transport_does_not_retry_a_mutation_after_connection_error(self) -> None:
        with (
            patch("apps.common.outbound_http._resolve_dns", side_effect=[["8.8.8.8"], ["8.8.4.4"]]) as dns,
            patch("requests.adapters.HTTPAdapter.send", side_effect=requests.ConnectionError("response lost")) as send,
        ):
            result = self.gandi.renew_domain("example.com", "example.com", 1)
        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.UNKNOWN)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(dns.call_count, 1)
