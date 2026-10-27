"""Real TLS peers: default roots, native explicit anchors, name/pin and resource cleanup."""

from __future__ import annotations

import importlib.util
import os
import socket
import ssl
import tempfile
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.test import SimpleTestCase

HELPER = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-account-name-neutral.py"
NAME = "a1234567.accounts.example.net"


def issue_certificate(name, key, parent=None, parent_key=None, *, ca=False):
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent.subject if parent else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((parent_key or key).public_key()), False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
    )
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
    return builder.sign(parent_key or key, hashes.SHA256())


class NeutralTransportTests(SimpleTestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        spec = importlib.util.spec_from_file_location("neutral_transport", HELPER)
        assert spec and spec.loader
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        root_key, issuer_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
        root = issue_certificate("Default trusted root", root_key, ca=True)
        self.issuer = issue_certificate("Served intermediate", issuer_key, root, root_key, ca=True)
        self.issuer_key = issuer_key
        self.trust = self.root / "root.pem"
        self.trust.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        self.empty_store = self.root / "empty-ca-directory"
        self.empty_store.mkdir()
        self.expected, self.expected_key = self.leaf(NAME, "expected")

    def leaf(self, name, label):
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = issue_certificate(name, key, self.issuer, self.issuer_key)
        certificate, private = self.root / (label + ".pem"), self.root / (label + ".key")
        # The root is deliberately absent, as allowed for normal served chains.
        certificate.write_bytes(
            leaf.public_bytes(serialization.Encoding.PEM) + self.issuer.public_bytes(serialization.Encoding.PEM)
        )
        private.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        private.chmod(0o600)
        return certificate, private

    @contextmanager
    def peer(self, certificate, key):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(8)
        port = listener.getsockname()[1]
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(certificate, key)

        def serve():
            try:
                raw, _address = listener.accept()
                with raw, server.wrap_socket(raw, server_side=True) as connection:
                    if connection.recv(8192):
                        connection.sendall(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found"
                        )
            except (ssl.SSLError, ConnectionResetError):
                pass  # Negative controls deliberately abort the handshake/request.
            finally:
                listener.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        actual_connect, actual_context = socket.create_connection, ssl.create_default_context

        def native_context(*args, **kwargs):
            context = actual_context(*args, **kwargs)
            # Match the pinned node's Python3.11 defaults on Python3.13 hosts,
            # whose newer PARTIAL_CHAIN default would mask a missing root.
            context.verify_flags = ssl.VERIFY_X509_TRUSTED_FIRST
            return context

        try:
            with (
                patch.dict(os.environ, {"SSL_CERT_FILE": str(self.trust), "SSL_CERT_DIR": str(self.empty_store)}),
                patch.object(self.module.ssl, "create_default_context", native_context),
                patch.object(
                    self.module.socket,
                    "create_connection",
                    lambda address, **kwargs: actual_connect(("127.0.0.1", port), **kwargs),
                ),
            ):
                yield
        finally:
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive(), "The owned local TLS peer did not stop")

    def probe(self, fingerprint=None):
        self.module.probe_response(
            name=NAME,
            host=NAME,
            certificate=self.expected,
            certificate_sha256=fingerprint or self.module.leaf_fingerprint(self.expected.read_bytes()),
            named=True,
            addresses={"443": ["127.0.0.1"]},
        )

    def test_served_chain_without_root_uses_default_trust_and_exact_named_leaf(self):
        with self.peer(self.expected, self.expected_key):
            self.probe()

    def test_default_roots_never_disable_peer_name_or_exact_leaf_checks(self):
        wrong_name, key = self.leaf("foreign.example.net", "foreign")
        with self.peer(wrong_name, key), self.assertRaises(ssl.SSLCertVerificationError):
            self.probe()
        with self.peer(self.expected, self.expected_key), self.assertRaisesRegex(ValueError, "leaf pin"):
            self.probe("0" * 64)

    def test_failed_tls_wrap_closes_raw_socket_and_propagates_control_errors(self):
        for error in (ssl.SSLError("Invalid TLS peer"), KeyboardInterrupt("Cancelled TLS probe")):
            with self.subTest(error=type(error).__name__):
                raw = MagicMock()
                raw.__enter__.return_value = raw
                raw.close.return_value = None
                raw.__exit__.side_effect = lambda *args, raw=raw: raw.close() or False
                context, connection = Mock(), Mock()
                context.wrap_socket.side_effect = error
                response = connection.getresponse.return_value
                response.status = 404
                response.read.return_value = b"Not Found"
                response.getheader.return_value = None
                with (
                    patch.object(self.module.ssl, "create_default_context", return_value=context),
                    patch.object(self.module.socket, "create_connection", return_value=raw),
                    patch.object(self.module.http.client, "HTTPConnection", return_value=connection),
                    self.assertRaises(type(error)),
                ):
                    self.probe()
                raw.close.assert_called_once()
                connection.close.assert_called_once()
