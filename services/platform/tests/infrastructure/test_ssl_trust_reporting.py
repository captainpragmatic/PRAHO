"""#436 item 3: the SSL check must report whether the panel certificate is CA-trusted.

``_check_ssl`` used ``verify_mode=CERT_NONE`` + ``check_hostname=False`` and then passed
on ``ssock.version()`` alone, so **any** TLS listener passed — self-signed, wrong-SAN,
expired, all reported as "SSL/TLS enabled". A node could reach ``active`` while serving a
self-signed panel certificate and nothing said so.

These tests stand up a **real TLS server with real certificates** and drive the real
handshake. #436 says explicitly that "a mocked probe does not prove trust-chain
behavior" — so the certificates, the sockets and the verification are all real. Two
things are patched, neither of them the behaviour under test: the port constant, and a
thin wrapper around ssl.create_default_context that loads the generated test CA into the
verified context (otherwise no locally-issued certificate could ever be trusted).
"""

from __future__ import annotations

import datetime
import socket
import ssl
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.test import SimpleTestCase

from apps.infrastructure.validation_service import NodeValidationService

_HOST = "127.0.0.1"


def _make_cert(
    common_name: str,
    *,
    issuer_key: Any = None,
    issuer_name: x509.Name | None = None,
    not_after_days: int = 365,
    san: str | None = None,
) -> tuple[bytes, bytes, x509.Certificate, Any]:
    """Return (cert_pem, key_pem, cert, key). Self-signed unless an issuer is supplied."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    signer_key = issuer_key or key
    issuer = issuer_name or subject

    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=not_after_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san or common_name)]),
            critical=False,
        )
    )
    # Modern OpenSSL rejects a chain whose leaf carries no Authority Key Identifier
    # ("Missing Authority Key Identifier"), so both SKI and AKI are required for the
    # trusted case to verify at all.
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    if issuer_key is None:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        # OpenSSL also demands keyCertSign on the CA ("CA cert does not include key
        # usage extension") before it will build a chain through it.
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )

    cert = builder.sign(signer_key, hashes.SHA256())
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        cert,
        key,
    )


@contextmanager
def _tls_server(cert_pem: bytes, key_pem: bytes):
    """Serve TLS on an ephemeral port with the supplied certificate."""
    with tempfile.TemporaryDirectory() as tmp:
        cert_path = Path(tmp) / "cert.pem"
        key_path = Path(tmp) / "key.pem"
        cert_path.write_bytes(cert_pem)
        key_path.write_bytes(key_pem)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((_HOST, 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def serve() -> None:
            listener.settimeout(0.2)
            while not stop.is_set():
                try:
                    raw, _ = listener.accept()
                except (TimeoutError, OSError):
                    continue
                try:
                    with context.wrap_socket(raw, server_side=True):
                        pass
                except OSError:
                    pass
                finally:
                    raw.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield port
        finally:
            stop.set()
            thread.join(timeout=3)
            listener.close()


class SSLTrustReportingTests(SimpleTestCase):
    """Real handshakes against real certificates — no mocked probe."""

    def _deployment(self, fqdn: str = "node.example.test") -> MagicMock:
        deployment = MagicMock()
        deployment.ipv4_address = _HOST
        deployment.fqdn = fqdn
        deployment.hostname = "node"
        return deployment

    def _check(self, port: int, deployment: MagicMock, ca_pem: bytes | None = None):
        """Run _check_ssl against our ephemeral port, optionally trusting a test CA."""
        service = NodeValidationService(timeout=5)
        real_default_context = ssl.create_default_context

        def default_context(*args: Any, **kwargs: Any) -> ssl.SSLContext:
            ctx = real_default_context(*args, **kwargs)
            if ca_pem is not None:
                ctx.load_verify_locations(cadata=ca_pem.decode())
            return ctx

        with (
            patch("apps.infrastructure.validation_service.WEBMIN_PORT", port),
            patch("apps.infrastructure.validation_service.ssl.create_default_context", side_effect=default_context),
        ):
            return service._check_ssl(deployment)

    def test_self_signed_certificate_is_reported_untrusted(self) -> None:
        """The regression: this previously reported a bare 'SSL/TLS enabled' success."""
        cert_pem, key_pem, _, _ = _make_cert("node.example.test")

        with _tls_server(cert_pem, key_pem) as port:
            result = self._check(port, self._deployment())

        self.assertTrue(result.passed)  # #436: reporting only, still not gating
        self.assertFalse(result.details["trusted"])
        self.assertIn("NOT CA-trusted", result.message)
        self.assertTrue(result.details["trust_evaluated"], "a self-signed chain IS a verdict")
        self.assertIn("self-signed", result.details["trust_error"])

    def test_trusted_certificate_with_matching_name_is_reported_trusted(self) -> None:
        ca_pem, _, ca_cert, ca_key = _make_cert("Test CA")
        leaf_pem, leaf_key_pem, _, _ = _make_cert("node.example.test", issuer_key=ca_key, issuer_name=ca_cert.subject)

        with _tls_server(leaf_pem, leaf_key_pem) as port:
            result = self._check(port, self._deployment("node.example.test"), ca_pem=ca_pem)

        self.assertTrue(result.passed)
        self.assertTrue(result.details["trusted"])
        # assertIn("CA-trusted") would also pass on "NOT CA-trusted" — assert the absence
        # of the negation, which is the thing that actually distinguishes the two messages.
        self.assertNotIn("NOT CA-trusted", result.message)
        self.assertIn("CA-trusted", result.message)
        self.assertIsNone(result.details["trust_error"])
        self.assertTrue(result.details["trust_evaluated"])
        self.assertIsNotNone(result.details["not_after"])
        self.assertRegex(result.details["cert_sha256"], r"^[0-9a-f]{64}$")

    def test_trusted_ca_but_wrong_hostname_is_reported_untrusted(self) -> None:
        """A CA-signed cert for the WRONG host must not count as trusted."""
        ca_pem, _, ca_cert, ca_key = _make_cert("Test CA")
        leaf_pem, leaf_key_pem, _, _ = _make_cert("other.example.test", issuer_key=ca_key, issuer_name=ca_cert.subject)

        with _tls_server(leaf_pem, leaf_key_pem) as port:
            result = self._check(port, self._deployment("node.example.test"), ca_pem=ca_pem)

        self.assertFalse(result.details["trusted"])
        self.assertIn("NOT CA-trusted", result.message)
        self.assertTrue(result.details["trust_evaluated"], "a name mismatch IS a verdict")
        # The check's stated value is that an operator can tell the failure modes apart
        # WITHOUT re-probing. Asserting only trusted=False leaves that claim unprotected:
        # every reason could collapse to one generic string and the suite would stay green.
        self.assertIn("Hostname mismatch", result.details["trust_error"])

    def test_expired_certificate_is_reported_untrusted(self) -> None:
        ca_pem, _, ca_cert, ca_key = _make_cert("Test CA")
        leaf_pem, leaf_key_pem, _, _ = _make_cert(
            "node.example.test", issuer_key=ca_key, issuer_name=ca_cert.subject, not_after_days=-1
        )

        with _tls_server(leaf_pem, leaf_key_pem) as port:
            result = self._check(port, self._deployment("node.example.test"), ca_pem=ca_pem)

        self.assertFalse(result.details["trusted"])
        self.assertTrue(result.details["trust_evaluated"])
        self.assertIn("expired", result.details["trust_error"])

    def test_untrusted_certificate_does_not_fail_the_check(self) -> None:
        """#436 explicitly defers gating to a staging drill — nothing may flip red yet."""
        cert_pem, key_pem, _, _ = _make_cert("node.example.test")

        with _tls_server(cert_pem, key_pem) as port:
            result = self._check(port, self._deployment())

        self.assertTrue(result.passed, "gating on trust is a rollout decision, not this change")

    def test_protocol_and_cipher_are_still_reported(self) -> None:
        """The liveness pass must keep the diagnostics the old check provided."""
        cert_pem, key_pem, _, _ = _make_cert("node.example.test")

        with _tls_server(cert_pem, key_pem) as port:
            result = self._check(port, self._deployment())

        self.assertIsNotNone(result.details["protocol"])
        self.assertIsNotNone(result.details["cipher"])

    def test_no_tls_listener_fails_the_check(self) -> None:
        """A dead port is still a genuine failure — trust reporting must not mask it."""
        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.bind((_HOST, 0))
        port = closed.getsockname()[1]
        closed.close()

        result = self._check(port, self._deployment())

        self.assertFalse(result.passed)


class SSLTrustIndeterminateTests(SSLTrustReportingTests):
    """A failed PROBE must not be reported as a failed CERTIFICATE.

    The two passes are separate TCP connections. A Webmin restart, a reset, a rate limit
    or a timeout between them used to land in the same bucket as a real verification
    failure and render as "the certificate is NOT CA-trusted: [Errno 32] Broken pipe".
    That is a false accusation against a certificate nobody actually examined — and for a
    check whose entire purpose is to be read, crying wolf is the way it stops being read.
    """

    def test_transport_failure_on_the_verified_pass_is_not_a_certificate_verdict(self) -> None:
        cert_pem, key_pem, _, _ = _make_cert("node.example.test")

        with _tls_server(cert_pem, key_pem) as port:
            deployment = self._deployment()
            real_create_connection = socket.create_connection
            calls = {"n": 0}

            def flaky_connect(*args: Any, **kwargs: Any) -> socket.socket:
                # Pass 1 (liveness) succeeds; pass 2 (the verdict) never connects.
                calls["n"] += 1
                if calls["n"] >= 2:
                    raise ConnectionResetError(104, "Connection reset by peer")
                return real_create_connection(*args, **kwargs)

            with patch.object(socket, "create_connection", side_effect=flaky_connect):
                result = self._check(port, deployment)

        self.assertTrue(result.passed)
        self.assertFalse(result.details["trusted"])
        # The load-bearing assertion: we did not reach a verdict, and must not imply one.
        self.assertFalse(result.details["trust_evaluated"])
        self.assertIn("could NOT be evaluated", result.message)
        self.assertNotIn("NOT CA-trusted", result.message)

    def test_timeout_on_the_verified_pass_is_also_indeterminate(self) -> None:
        """TimeoutError subclasses OSError, so it never reached the caller's own handler."""
        cert_pem, key_pem, _, _ = _make_cert("node.example.test")

        with _tls_server(cert_pem, key_pem) as port:
            real_create_connection = socket.create_connection
            calls = {"n": 0}

            def slow_second(*args: Any, **kwargs: Any) -> socket.socket:
                calls["n"] += 1
                if calls["n"] >= 2:
                    raise TimeoutError("timed out")
                return real_create_connection(*args, **kwargs)

            with patch.object(socket, "create_connection", side_effect=slow_second):
                result = self._check(port, self._deployment())

        self.assertFalse(result.details["trust_evaluated"])
        self.assertIn("could NOT be evaluated", result.message)
