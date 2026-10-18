"""The ACME library adapter: Retry-After surfaces, errors are sorted into the three the issuer decides on, and
requests go through `safe_request` (ADR-0061 P1.10). No ACME server is contacted.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Any
from unittest.mock import MagicMock, patch

import josepy as jose
import requests
from acme import challenges, messages
from acme import errors as acme_errors
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.test import SimpleTestCase

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError
from apps.provisioning import acme_client
from apps.provisioning.acme_client import (
    AcmeOrder,
    AcmeOrderFailed,
    AcmeRateLimited,
    AcmeTransientError,
    Dns01Challenge,
    LibraryAcmeClient,
    SafeAcmeNetwork,
    retry_after_seconds,
)

POLICY = OutboundPolicy(name="acme-test", allowed_domains=frozenset({"acme.test"}))


def response(status: int = 200, headers: dict[str, str] | None = None, body: bytes = b"{}") -> requests.Response:
    fake = requests.Response()
    fake.status_code = status
    fake._content = body
    fake.headers.update(headers or {})
    return fake


def network() -> SafeAcmeNetwork:
    key = jose.JWKEC(key=ec.generate_private_key(ec.SECP256R1()))
    return SafeAcmeNetwork(key, POLICY)


class RetryAfterTests(SimpleTestCase):
    def test_delta_seconds_and_http_dates_are_read(self) -> None:
        self.assertEqual(retry_after_seconds(response(headers={"Retry-After": "120"})), 120.0)
        later = format_datetime(datetime.now(UTC) + timedelta(seconds=300), usegmt=True)
        parsed = retry_after_seconds(response(headers={"Retry-After": later}))
        self.assertIsNotNone(parsed)
        self.assertTrue(250 < parsed < 301)

    def test_absent_or_invalid_is_none(self) -> None:
        self.assertIsNone(retry_after_seconds(response()))
        self.assertIsNone(retry_after_seconds(response(headers={"Retry-After": "soon"})))


class NetworkTests(SimpleTestCase):
    def test_requests_go_through_safe_request_with_the_acme_policy(self) -> None:
        with patch.object(acme_client, "safe_request", return_value=response(200)) as sent:
            network()._send_request("GET", "https://acme.test/directory")

        self.assertIs(sent.call_args.kwargs["policy"], POLICY)
        self.assertEqual(sent.call_args.args[:2], ("GET", "https://acme.test/directory"))

    def test_a_429_carries_the_servers_retry_after(self) -> None:
        with (
            patch.object(acme_client, "safe_request", return_value=response(429, {"Retry-After": "900"})),
            self.assertRaises(AcmeRateLimited) as caught,
        ):
            network()._send_request("POST", "https://acme.test/new-order", data=b"{}")

        self.assertEqual(caught.exception.retry_after_seconds, 900.0)

    def test_a_429_without_retry_after_waits_the_default(self) -> None:
        with (
            patch.object(acme_client, "safe_request", return_value=response(429)),
            self.assertRaises(AcmeRateLimited) as caught,
        ):
            network()._send_request("POST", "https://acme.test/new-order", data=b"{}")

        self.assertEqual(caught.exception.retry_after_seconds, acme_client.DEFAULT_RATE_LIMIT_SECONDS)

    def test_a_503_is_transient_and_keeps_its_retry_after(self) -> None:
        with (
            patch.object(acme_client, "safe_request", return_value=response(503, {"Retry-After": "30"})),
            self.assertRaises(AcmeTransientError) as caught,
        ):
            network()._send_request("GET", "https://acme.test/directory")

        self.assertEqual(caught.exception.retry_after_seconds, 30.0)


class TranslationTests(SimpleTestCase):
    def raised(self, exc: BaseException) -> Any:
        with self.assertRaises(acme_client.AcmeError) as caught, acme_client._translating():
            raise exc
        return caught.exception

    def test_a_rate_limit_problem_is_a_rate_limit(self) -> None:
        problem = messages.Error(typ="urn:ietf:params:acme:error:rateLimited", detail="slow down")

        self.assertIsInstance(self.raised(problem), AcmeRateLimited)

    def test_other_problems_and_failed_validation_end_the_order(self) -> None:
        for exc in (
            messages.Error(typ="urn:ietf:params:acme:error:rejectedIdentifier", detail="no"),
            acme_errors.ValidationError([]),
            acme_errors.IssuanceError(messages.Error(typ="urn:ietf:params:acme:error:serverInternal", detail="x")),
        ):
            with self.subTest(exc=type(exc).__name__):
                self.assertIsInstance(self.raised(exc), AcmeOrderFailed)

    def test_an_invalid_order_without_a_reason_ends_the_order(self) -> None:
        # What the library raises when the server marks the order invalid and gives no error object.
        exc = acme_errors.Error("The certificate order failed. No further information was provided by the server.")

        self.assertIsInstance(self.raised(exc), AcmeOrderFailed)

    def test_network_trouble_and_timeouts_keep_the_order(self) -> None:
        for exc in (
            requests.ConnectionError("down"),
            OutboundSecurityError("blocked"),
            acme_errors.TimeoutError(),
            acme_errors.ClientError("odd"),
            messages.Error(typ="urn:ietf:params:acme:error:serverInternal", detail="x"),
        ):
            with self.subTest(exc=type(exc).__name__):
                self.assertIsInstance(self.raised(exc), AcmeTransientError)


class ClientFlowTests(SimpleTestCase):
    """The adapter drives the library's client in the order the protocol needs, answering only dns-01."""

    def build(self) -> tuple[LibraryAcmeClient, MagicMock]:
        key_pem = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            .decode()
        )
        client = MagicMock()
        with patch.object(acme_client, "ClientV2", return_value=client):
            adapter = LibraryAcmeClient("https://acme.test/directory", key_pem)
        return adapter, client

    def test_an_existing_account_for_the_key_is_adopted(self) -> None:
        key_pem = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            .decode()
        )
        client = MagicMock()
        client.new_account.side_effect = acme_errors.ConflictError("https://acme.test/acct/1")
        with patch.object(acme_client, "ClientV2") as factory:
            factory.return_value = client
            adapter = LibraryAcmeClient("https://acme.test/directory", key_pem)

        self.assertEqual(adapter._net.account.uri, "https://acme.test/acct/1")

    def test_complete_answers_each_challenge_then_polls_and_finalises(self) -> None:
        adapter, client = self.build()
        challb = MagicMock()
        order = AcmeOrder(
            url="https://acme.test/order/1",
            challenges=(Dns01Challenge(name="_acme-challenge.x", value="v", handle=challb),),
            handle="orderr",
        )
        client.poll_authorizations.return_value = "polled"
        client.finalize_order.return_value = MagicMock(fullchain_pem="CHAIN")

        chain = adapter.complete(order)

        client.answer_challenge.assert_called_once()
        self.assertIs(client.answer_challenge.call_args.args[0], challb)
        self.assertEqual(client.poll_authorizations.call_args.args[0], "orderr")
        self.assertEqual(client.finalize_order.call_args.args[0], "polled")
        self.assertEqual(chain, b"CHAIN")

    def test_a_library_failure_while_completing_is_translated(self) -> None:
        adapter, client = self.build()
        client.poll_authorizations.side_effect = acme_errors.ValidationError([])
        order = AcmeOrder(url="u", challenges=(), handle="orderr")

        with self.assertRaises(AcmeOrderFailed):
            adapter.complete(order)

    @staticmethod
    def authz(status: Any, *chall: Any) -> Any:
        bodies = [
            messages.ChallengeBody(chall=c, uri=f"https://acme.test/chall/{i}", status=messages.STATUS_PENDING)
            for i, c in enumerate(chall)
        ]
        return messages.AuthorizationResource(
            body=messages.Authorization(
                identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="h7k3p2q8.praho-sites.net"),
                status=status,
                challenges=tuple(bodies),
            ),
            uri="https://acme.test/authz/1",
        )

    def test_an_order_offers_the_dns01_challenge_of_each_pending_authorization_only(self) -> None:
        adapter, client = self.build()
        token = b"a" * 32
        pending = self.authz(messages.STATUS_PENDING, challenges.HTTP01(token=token), challenges.DNS01(token=token))
        done = self.authz(messages.STATUS_VALID, challenges.DNS01(token=token))
        client.new_order.return_value = MagicMock(uri="https://acme.test/order/1", authorizations=[pending, done])

        order = adapter.place_order(b"csr")

        self.assertEqual(order.url, "https://acme.test/order/1")
        self.assertEqual([c.name for c in order.challenges], ["_acme-challenge.h7k3p2q8.praho-sites.net"])
        self.assertTrue(order.challenges[0].value)
        self.assertNotIn("=", order.challenges[0].value, "a DNS-01 value is unpadded base64url")

    def test_a_stored_order_the_server_now_calls_invalid_is_not_resumed(self) -> None:
        adapter, client = self.build()
        body = messages.Order(
            identifiers=(messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="h7k3p2q8.praho-sites.net"),),
            status=messages.STATUS_INVALID,
            authorizations=(),
        )
        client._post_as_get.return_value.json.return_value = body.to_json()

        with self.assertRaises(AcmeOrderFailed):
            adapter.load_order("https://acme.test/order/7", b"the-csr")

    def test_a_stored_order_is_read_back_by_its_url_and_keeps_its_csr(self) -> None:
        adapter, client = self.build()
        url = "https://acme.test/order/7"
        body = messages.Order(
            identifiers=(messages.Identifier(typ=messages.IDENTIFIER_FQDN, value="h7k3p2q8.praho-sites.net"),),
            status=messages.STATUS_PENDING,
            authorizations=("https://acme.test/authz/1",),
        )
        client._post_as_get.return_value.json.return_value = body.to_json()
        client._authzr_from_response.return_value = self.authz(
            messages.STATUS_PENDING, challenges.DNS01(token=b"a" * 32)
        )

        order = adapter.load_order(url, b"the-csr")

        self.assertEqual(
            [call.args[0] for call in client._post_as_get.call_args_list], [url, "https://acme.test/authz/1"]
        )
        self.assertEqual(order.url, url)
        self.assertEqual((order.handle.uri, order.handle.csr_pem), (url, b"the-csr"))
        self.assertEqual([c.name for c in order.challenges], ["_acme-challenge.h7k3p2q8.praho-sites.net"])
        client.new_order.assert_not_called()
