"""Cross-node SSL restoration never writes an archived certificate path."""

import importlib.util
import io
import subprocess
import tarfile
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

SCRIPT = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-recovery-ssl.py"


class RecoverySslPathTests(SimpleTestCase):
    def load(self):
        self.assertTrue(SCRIPT.exists(), "Recovery needs bounded SSL-path relocation before native restore")
        spec = importlib.util.spec_from_file_location("recovery_ssl", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_every_certificate_directive_uses_the_verified_target_namespace(self):
        node = self.load()
        original = (
            b'<VirtualHost 10.0.0.1:443>\nServerName customer.example\n'
            b'SSLCertificateFile /etc/ssl/virtualmin/111/ssl.combined\n'
            b'SSLCertificateKeyFile "/another-customer/secret.key"\n'
            b'SSLCACertificateFile /etc/ssl/virtualmin/111/ssl.ca\n'
            b'SSLCertificateChainFile /old/chain.pem\nDocumentRoot /home/customer/public_html\n</VirtualHost>\n'
        )
        relocated = node.relocate_ssl_config(original, "222")
        self.assertNotIn(b"/etc/ssl/virtualmin/111/", relocated)
        self.assertNotIn(b"/another-customer/", relocated)
        self.assertNotIn(b"/old/", relocated)
        self.assertIn(b'/etc/ssl/virtualmin/222/ssl.combined', relocated)
        self.assertIn(b'/etc/ssl/virtualmin/222/ssl.key', relocated)
        self.assertNotIn(b'File "', relocated, "the native SSL getter does not unquote directive values")
        self.assertEqual(relocated.count(b'/etc/ssl/virtualmin/222/ssl.ca'), 2)
        self.assertIn(b"DocumentRoot /home/customer/public_html", relocated)

    def test_missing_certificate_or_key_directive_is_refused(self):
        node = self.load()
        for content in (b"<VirtualHost *:443>\n</VirtualHost>\n", b"SSLCertificateFile /foreign/cert\n"):
            with self.subTest(content=content), self.assertRaises(ValueError):
                node.relocate_ssl_config(content, "222")

    def test_native_combined_certificate_and_key_backup_is_normalized_to_separate_target_paths(self):
        node = self.load()
        combined = b"certificate and private key PEM bundle"
        with tempfile.TemporaryDirectory() as scratch:
            archive = Path(scratch) / "backup.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                for feature, content in {"virtualmin": b"dom=customer.example\n", "ssl": b"vhost", "ssl_cert": combined}.items():
                    member = tarfile.TarInfo(f"./customer.example_{feature}")
                    member.size = len(content)
                    bundle.addfile(member, io.BytesIO(content))
            features = node.read_features(archive, "customer.example")
        self.assertEqual(features["ssl_key"], combined)
        self.assertEqual(features["ssl_cert"], combined)

    def test_combined_pem_really_contains_a_matching_private_key_before_native_restore(self):
        node = self.load()
        with tempfile.TemporaryDirectory() as scratch:
            directory = Path(scratch)
            cert, key = directory / "source.cert", directory / "source.key"
            subprocess.run(  # noqa: S603  # Fixed OpenSSL invocation creates disposable test material
                ["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=customer.example", "-keyout", str(key), "-out", str(cert)],
                capture_output=True, check=True, timeout=30,
            )
            bundle = cert.read_bytes() + key.read_bytes()
            node.verify_pair({"ssl_cert": bundle, "ssl_key": bundle}, directory)
            with self.assertRaises(subprocess.CalledProcessError):
                node.verify_pair({"ssl_cert": cert.read_bytes(), "ssl_key": cert.read_bytes()}, directory)
