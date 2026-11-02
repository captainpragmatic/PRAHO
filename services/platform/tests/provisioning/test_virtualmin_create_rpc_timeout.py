"""Public provisioning waits for its own RPC budget without replaying uncertain creates.

Only DNS resolution points at the owned HTTPS fixture. The real gateway, pinned
TLS transport, parser, provisioning preflight and durable state writers run.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import ssl
import threading
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.cache import cache
from django.db import connection
from django.test import TransactionTestCase, override_settings

from apps.billing.models import Currency
from apps.common.outbound_http import OutboundPolicy, ResolvedTarget
from apps.common.types import Result, Retriability, retriability_of
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import process_failed_virtualmin_jobs
from apps.settings.services import SettingsService

HOST = "rpc-budget.example.test"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


class _DelayedVirtualmin(ThreadingHTTPServer):
    """Accept create once, retaining that outcome even if its HTTP response is lost."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.programs: list[str] = []
        self.accepted: list[tuple[str, str]] = []
        self.release = threading.Event()
        self.create_replied = threading.Event()
        self.info_replied = threading.Event()
        self.info_delay = 0.0


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        endpoint = cast("_DelayedVirtualmin", self.server)
        params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        program = params["program"][0]
        endpoint.programs.append(program)
        if program == "create-domain":
            endpoint.accepted.append((params["domain"][0], params["user"][0]))
            endpoint.release.wait(2)
            payload: dict[str, object] = {"output": "Domain created\n"}
        elif program == "info":
            endpoint.release.wait(endpoint.info_delay)
            payload = {"output": "disk_free: 104857600000\ndisk_total: 209715200000\n"}
        elif program == "list-domains":
            payload = {"data": []}
        elif program == "list-templates":
            payload = {"data": ["Default Settings"]}
        else:
            raise AssertionError(f"Unexpected external command: {program}")
        body = json.dumps({"command": program, "status": "success", **payload}).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            # The fixture retains acceptance when the client timed out first.
            pass
        finally:
            if program == "create-domain":
                endpoint.create_replied.set()
            elif program == "info":
                endpoint.info_replied.set()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 -- standard HTTP handler signature
        pass  # Requests carry credentials; the fixture must not log URLs or headers.


def _certificate(directory: Path) -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    key_path.chmod(0o600)
    return cert_path, key_path, hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


@override_settings(CACHES=LOCMEM, VIRTUALMIN_TIMEOUTS={"API_REQUEST_TIMEOUT": 1, "PROVISIONING_TIMEOUT": 4})
class CreateRpcTimeoutTests(TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.enterContext(
            patch.dict(os.environ, {"VIRTUALMIN_API_REQUEST_TIMEOUT": "1", "VIRTUALMIN_PROVISIONING_TIMEOUT": "4"})
        )
        private = self.enterContext(TemporaryDirectory(prefix="praho-rpc-timeout-"))
        certificate, key, fingerprint = _certificate(Path(private))
        self.endpoint = _DelayedVirtualmin()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.endpoint.socket = context.wrap_socket(self.endpoint.socket, server_side=True)
        self.thread = threading.Thread(target=self.endpoint.serve_forever, name="owned-rpc-timeout")
        self.thread.start()
        self.addCleanup(self._stop_endpoint)
        customer = Customer.objects.create(
            name="RPC budget customer", customer_type="individual", primary_email="rpc@example.test"
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(
            name="RPC budget plan", plan_type="shared_hosting", price_monthly=Decimal("10")
        )
        self.service = Service.objects.create(
            customer=customer,
            currency=currency,
            service_plan=plan,
            service_name="rpc.example.com",
            domain="rpc.example.com",
            billing_cycle="monthly",
            price=Decimal("10"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="RPC budget node",
            hostname=HOST,
            api_username="fixture-api",
            api_port=self.endpoint.server_port,
            status="active",
            ssl_verify=False,
            ssl_cert_fingerprint=fingerprint,
            legacy_security_admission=True,
        )
        self.server.set_api_password(secrets.token_urlsafe(24))
        self.server.save(update_fields=["encrypted_api_password"])
        self.assertIsNone(destination_refusal(self.server), "The intended legacy fixture must be truly admitted")
        self.io_atomic: list[bool] = []
        self.timeouts: list[float] = []
        self.enterContext(patch("apps.common.outbound_http.validate_and_resolve", side_effect=self._owned_target))

    def _stop_endpoint(self) -> None:
        self.endpoint.release.set()
        self.endpoint.shutdown()
        self.endpoint.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive(), "The owned HTTPS server must finish")

    def _owned_target(self, url: str, policy: OutboundPolicy) -> ResolvedTarget:
        self.assertEqual(url, self.server.api_url)
        self.assertEqual(policy.tls_cert_fingerprint, self.server.ssl_cert_fingerprint)
        self.io_atomic.append(connection.in_atomic_block)
        self.timeouts.append(policy.timeout_seconds)
        return ResolvedTarget(
            url, "https", HOST, self.endpoint.server_port, ["127.0.0.1"], "/virtual-server/remote.cgi"
        )

    def _create(self) -> Result[VirtualminAccount, str]:
        return VirtualminProvisioningService(self.server).create_virtualmin_account(
            VirtualminAccountCreationData(service=self.service, domain=self.service.domain, server=self.server)
        )

    def test_public_create_waits_for_provisioning_budget_and_commits_once(self) -> None:
        result = self._create()
        account = VirtualminAccount.objects.get(service=self.service)
        self.assertEqual(self.endpoint.accepted, [(self.service.domain, account.virtualmin_username)])
        self.assertTrue(result.is_ok(), result)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        self.server.refresh_from_db()
        self.assertEqual((account.status, job.status, self.server.current_domains), ("active", "completed", 1))
        self.assertTrue(self.endpoint.create_replied.is_set())
        self.assertEqual(self.endpoint.programs.count("create-domain"), 1)
        self.assertNotIn("delete-domain", self.endpoint.programs)
        self.assertEqual(self.timeouts[-1], 4)
        self.assertEqual(set(self.timeouts[:-1]), {1})
        self.assertEqual(set(self.io_atomic), {False})

    def test_explicit_short_provisioning_timeout_is_unknown_and_never_replayed(self) -> None:
        with patch.dict(os.environ, {"VIRTUALMIN_PROVISIONING_TIMEOUT": "1"}):
            result = self._create()
        self.assertTrue(result.is_err(), result)
        self.assertIs(retriability_of(result), Retriability.UNKNOWN)
        self.assertTrue(self.endpoint.create_replied.wait(3), "The accepted remote fixture finishes after timeout")
        account = VirtualminAccount.objects.get(service=self.service)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        self.assertEqual((account.status, job.status), ("error", "failed"))
        self.assertEqual(job.result["retriability"], Retriability.UNKNOWN.value)
        self.assertIsNone(job.next_retry_at)
        swept = process_failed_virtualmin_jobs()
        self.assertTrue(swept["success"], swept)
        self.assertEqual(swept["results"]["retried_jobs"], 0)
        self.assertEqual(self.endpoint.accepted, [(self.service.domain, account.virtualmin_username)])
        self.assertEqual(self.endpoint.programs.count("create-domain"), 1)
        self.assertNotIn("delete-domain", self.endpoint.programs)
        self.assertEqual(set(self.io_atomic), {False})

    def test_small_read_keeps_standard_timeout(self) -> None:
        changed = SettingsService.update_setting("virtualmin.max_retries", 1)
        self.assertTrue(changed.is_ok(), changed)
        self.endpoint.info_delay = 2
        result = VirtualminGateway(VirtualminConfig(server=self.server)).call("info")
        self.assertTrue(result.is_err(), result)
        self.assertIs(retriability_of(result), Retriability.UNKNOWN)
        self.assertIn("Read timeout", str(result.unwrap_err()))
        self.assertTrue(self.endpoint.info_replied.wait(3), "The external read fixture finishes after timeout")
        self.assertEqual(self.endpoint.programs, ["info"])
        self.assertEqual(self.timeouts, [1])
