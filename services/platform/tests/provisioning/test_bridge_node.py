"""The bridge's node operations against real files and certificates, with Apache stubbed."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.test import SimpleTestCase

HELPER = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-bridge.py"
BRIDGE_ID = "11111111-2222-4333-8444-555555555555"
SECOND_ID = "99999999-2222-4333-8444-555555555555"
DOMAIN = "shop.example.com"
ACCOUNT_NAME = "h7k3p2q8.accounts.example.net"
ORIGIN = "bridge-" + BRIDGE_ID.replace("-", "") + ".invalid"


class BridgeNodeTests(SimpleTestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        spec = importlib.util.spec_from_file_location("bridge_node", HELPER)
        assert spec and spec.loader
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.commands: list[list[str]] = []

        def command(argv: list[str]) -> str:
            self.commands.append(argv)
            if argv[0] == "openssl":
                return subprocess.run(argv, text=True, capture_output=True, check=True).stdout  # noqa: S603
            if argv[0] == "curl" and "--write-out" in argv:
                return "404"
            if argv[:2] == ["ip", "-j"]:
                return json.dumps(
                    [
                        {
                            "addr_info": [
                                {"local": "127.0.0.1"},
                                {"local": "192.0.2.20"},
                                {"local": "192.0.2.10"},
                                {"local": "2001:db8::20"},
                            ]
                        }
                    ]
                )
            if argv[:3] == ["ss", "-H", "-lnt"]:
                return "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 511 [::]:80 [::]:*\nLISTEN 0 511 [::]:443 [::]:*\n"
            return ""

        self.node = self.module.NodeBridge(self.root, execute=command)
        self.node.owner_uid = os.geteuid()
        self.node.sites.mkdir(parents=True)
        self.node.conf.mkdir(parents=True)
        default = HELPER.parent / "praho-default-site.conf"
        (self.node.conf / "praho-default-site.conf").write_text(default.read_text())
        self.certificate = self.root / "virtualmin/42/ssl.combined"
        self.certificate.parent.mkdir(parents=True)
        self.key = self.certificate.with_name("ssl.key")
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN), x509.DNSName(f"www.{DOMAIN}")]), False)
            .sign(key, hashes.SHA256())
        )
        self.certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        self.site = self.node.sites / f"{DOMAIN}.conf"
        self.site.write_text(
            f"<VirtualHost *:80>\nServerName {DOMAIN}\nServerAlias www.{DOMAIN}\n</VirtualHost>\n"
            f"<VirtualHost *:443>\nServerName {DOMAIN}\nServerAlias www.{DOMAIN}\nSSLEngine on\n"
            f"SSLCertificateFile {self.certificate}\nSSLCertificateKeyFile {self.key}\n</VirtualHost>\n"
        )

    def add_account_name_site(self) -> None:
        key = serialization.load_pem_private_key(self.key.read_bytes(), password=None)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ACCOUNT_NAME)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(ACCOUNT_NAME), x509.DNSName(f"www.{ACCOUNT_NAME}")]),
                False,
            )
            .sign(key, hashes.SHA256())
        )
        self.account_certificate = self.certificate.with_name("account-chain.pem")
        self.account_certificate.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        self.account_site = self.node.sites / f"{ACCOUNT_NAME}.conf"
        self.account_site.write_text(
            f"<VirtualHost *:80>\nServerName {ACCOUNT_NAME}\nServerAlias www.{ACCOUNT_NAME}\n</VirtualHost>\n"
            f"<VirtualHost *:443>\nServerName {ACCOUNT_NAME}\nServerAlias www.{ACCOUNT_NAME}\nSSLEngine on\n"
            f"SSLCertificateFile {self.account_certificate}\nSSLCertificateKeyFile {self.key}\n</VirtualHost>\n"
        )

    def test_source_and_target_use_their_own_native_address_groups_and_real_http_backend(self) -> None:
        self.site.write_text(self.site.read_text().replace("*:80", "192.0.2.10:80").replace("*:443", "192.0.2.10:443"))
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.assertEqual([item["bindings"] for item in manifest["vhosts"]], [["192.0.2.10"], ["192.0.2.10"]])
        self.site.write_text(self.site.read_text().replace("192.0.2.10", "192.0.2.20"))
        certificate = self.node.install_origin(BRIDGE_ID, manifest)
        origin = (self.node.conf / f"praho-origin-{BRIDGE_ID}.conf").read_text()
        self.assertIn("192.0.2.20:443", origin)
        self.assertIn("http://192.0.2.20:80/", origin)
        self.assertNotIn("192.0.2.10:443", origin)
        self.node.install_source(BRIDGE_ID, certificate)
        source = (self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").read_text()
        self.assertIn("<VirtualHost 192.0.2.10:80>", source)
        self.assertIn("<VirtualHost 192.0.2.10:443>", source)
        self.site.unlink()
        self.node.install_source(BRIDGE_ID, certificate)
        self.assertEqual(source, (self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").read_text())
        self.node.execute = Mock(side_effect=self.neutral_response)
        self.node.verify(BRIDGE_ID)
        probes = [call.args[0] for call in self.node.execute.call_args_list if "--dump-header" in call.args[0]]
        self.assertTrue(probes)
        self.assertTrue(
            all(any(f":{port}:192.0.2.10" in value for value in argv for port in (80, 443)) for argv in probes)
        )

    def test_ipv6_target_http_backend_is_bracketed_and_changed_target_binding_is_refused(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.site.write_text(
            self.site.read_text().replace("*:80", "[2001:db8::20]:80").replace("*:443", "[2001:db8::20]:443")
        )
        self.node.install_origin(BRIDGE_ID, manifest)
        origin = (self.node.conf / f"praho-origin-{BRIDGE_ID}.conf").read_text()
        self.assertIn("http://[2001:db8::20]:80/", origin)
        self.site.write_text(self.site.read_text().replace("[2001:db8::20]", "192.0.2.20"))
        with self.assertRaisesRegex(ValueError, "binding"):
            self.node.install_origin(BRIDGE_ID, manifest)

    def test_failed_config_transaction_keeps_every_private_pem_referenced_by_the_restored_bridge(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_source(BRIDGE_ID, self.node.install_origin(BRIDGE_ID, manifest))
        directory = self.node.directory(BRIDGE_ID)
        before = {path: path.read_bytes() for path in directory.glob("*.pem")}
        original = self.node.bindings().transaction

        @contextmanager
        def fail_after_operation(*args, **kwargs):
            with original(*args, **kwargs):
                yield
                raise ValueError("Observed dispatcher failure before transaction commit")

        with (
            patch.object(self.node.bindings(), "transaction", fail_after_operation),
            self.assertRaisesRegex(ValueError, "dispatcher"),
        ):
            self.node.remove_source(BRIDGE_ID)
        self.assertTrue((self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").exists())
        self.assertEqual(set(directory.glob("*.pem")), set(before))
        for path, content in before.items():
            self.assertTrue(path.read_bytes() == content, "A UUID-owned PEM changed during refused teardown")

    def test_source_teardown_reclaims_private_pems_after_commit_and_manifest_loss(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_source(BRIDGE_ID, self.node.install_origin(BRIDGE_ID, manifest))
        self.node.prepare(SECOND_ID, DOMAIN, "", "192.0.2.30", "192.0.2.10")
        adjacent = self.node.directory(SECOND_ID)
        kept = {path.name for path in adjacent.glob("*.pem")}
        directory = self.node.directory(BRIDGE_ID)
        note = directory / "operator-note.txt"
        note.write_text("Keep unrelated state")
        with (
            patch.object(self.node, "pin_origin", side_effect=OSError("Observed interruption after config commit")),
            self.assertRaisesRegex(OSError, "interruption"),
        ):
            self.node.remove_source(BRIDGE_ID)
        self.assertFalse((self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").exists())
        self.assertTrue((directory / "source-removed").exists())
        self.assertTrue(list(directory.glob("source-*-key.pem")))
        (directory / "source.json").unlink()  # A resumed terminal cleanup must not depend on the manifest.
        self.node.remove_source(BRIDGE_ID)
        self.assertFalse(list(directory.glob("source-*-*.pem")))
        self.assertFalse((directory / "upstream-ca.pem").exists())
        self.assertNotIn(self.node.origin_hostname(BRIDGE_ID), self.node.hosts.read_text())
        self.assertEqual({path.name for path in adjacent.glob("*.pem")}, kept)
        self.assertEqual(note.read_text(), "Keep unrelated state")

    def test_retirement_marker_and_directory_are_fsynced_before_any_owned_pem_is_pruned(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_source(BRIDGE_ID, self.node.install_origin(BRIDGE_ID, manifest))
        directory = self.node.directory(BRIDGE_ID)
        real_sync, real_unlink = os.fsync, Path.unlink
        for role, retire in (("source", self.node.remove_source), ("origin", self.node.remove_origin)):
            with self.subTest(role=role):
                marker = directory / f"{role}-removed"
                events = []
                flushed_files = set()

                def observe_sync(descriptor, marker=marker, events=events, flushed_files=flushed_files):
                    info = os.fstat(descriptor)
                    if stat.S_ISREG(info.st_mode):
                        flushed_files.add((info.st_dev, info.st_ino))
                    if marker.exists() and stat.S_ISDIR(info.st_mode) and info.st_ino == directory.stat().st_ino:
                        # Atomic writes fsync their temporary inode before rename.
                        # Bind that inode to the final marker at the directory flush.
                        actual = marker.stat()
                        self.assertIn((actual.st_dev, actual.st_ino), flushed_files)
                        events.append("marker_directory")
                    return real_sync(descriptor)

                def observe_unlink(path, *args, events=events, **kwargs):
                    if path.parent == directory and path.suffix == ".pem":
                        self.assertIn("marker_directory", events, "Retirement was not durable before PEM pruning")
                        events.append("pem_pruned")
                    return real_unlink(path, *args, **kwargs)

                with patch.object(os, "fsync", observe_sync), patch.object(Path, "unlink", observe_unlink):
                    retire(BRIDGE_ID)
                self.assertIn("pem_pruned", events)

    def test_origin_teardown_reclaims_keys_after_config_commit_and_manifest_loss(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_origin(BRIDGE_ID, manifest)
        directory = self.node.directory(BRIDGE_ID)
        original = Path.unlink

        def interrupted(path, *args, **kwargs):
            if path == directory / "origin.json":
                raise OSError("Observed origin cleanup interruption")
            return original(path, *args, **kwargs)

        with patch.object(Path, "unlink", interrupted), self.assertRaisesRegex(OSError, "interruption"):
            self.node.remove_origin(BRIDGE_ID)
        self.assertFalse((self.node.conf / f"praho-origin-{BRIDGE_ID}.conf").exists())
        self.assertTrue((directory / "origin-removed").exists())
        self.assertTrue((directory / "origin-key.pem").exists())
        (directory / "origin.json").unlink()
        self.node.remove_origin(BRIDGE_ID)
        self.assertFalse((directory / "origin-key.pem").exists())
        self.assertFalse((directory / "origin.pem").exists())

    def neutral_response(self, argv: list[str]) -> str:
        if ACCOUNT_NAME in argv[-1]:
            return "Not Found\n404"
        if "--dump-header" in argv:
            return f"HTTP/1.1 200 OK\nX-Praho-Bridge: {BRIDGE_ID}\n"
        return "403" if "--write-out" in argv else BRIDGE_ID

    def test_preparation_keeps_account_name_dns_and_certificate_but_marks_its_aliases_neutral(self) -> None:
        self.add_account_name_site()
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")
        self.assertEqual(manifest.get("account_name"), ACCOUNT_NAME)
        self.assertEqual(len(manifest["vhosts"]), 4)
        for item in manifest["vhosts"]:
            self.assertIs(item["neutral"], item["name"] == ACCOUNT_NAME)
            if item["name"] == ACCOUNT_NAME:
                self.assertEqual(item["names"], [ACCOUNT_NAME, f"www.{ACCOUNT_NAME}"])
                if item["port"] == 443:
                    self.assertEqual(Path(item["certificate"]).read_bytes(), self.account_certificate.read_bytes())
                    self.assertEqual(Path(item["key"]).read_bytes(), self.key.read_bytes())
        self.node.minimum_certificate_lifetime = 31 * 24 * 3600
        with self.assertRaisesRegex(ValueError, "expires"):
            self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")

    def test_source_account_name_vhosts_remain_fixed_neutral_after_native_child_and_guard_are_gone(self) -> None:
        self.add_account_name_site()
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")
        self.node.install_source(BRIDGE_ID, self.node.install_origin(BRIDGE_ID, manifest))
        self.account_site.unlink()
        self.account_certificate.unlink()
        self.key.unlink()
        conf = (self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").read_text()
        blocks = re.findall(r"<VirtualHost[^>]+>(.*?)</VirtualHost>", conf, re.S)
        self.assertEqual(len(blocks), 4)
        for item, block in zip(manifest["vhosts"], blocks, strict=True):
            if item["name"] == ACCOUNT_NAME:
                self.assertIn("Redirect 404 /", block)
                self.assertIn('ErrorDocument 404 "Not Found"', block)
                self.assertNotIn("Proxy", block)
                self.assertNotIn("RequestHeader", block)
                if item["port"] == 443:
                    self.assertIn(f"SSLCertificateFile {item['certificate']}", block)
                    self.assertTrue(Path(item["certificate"]).is_file())
            else:
                self.assertIn("ProxyPass / https://", block)

    def test_neutral_account_names_are_excluded_from_synthetic_origin_allowlist_and_checks(self) -> None:
        self.add_account_name_site()
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")
        certificate = self.node.install_origin(BRIDGE_ID, manifest)
        conf = (self.node.conf / f"praho-origin-{BRIDGE_ID}.conf").read_text()
        self.assertNotIn(re.escape(ACCOUNT_NAME), conf)
        self.assertIn(re.escape(DOMAIN), conf)
        self.node.execute = Mock(side_effect=self.neutral_response)
        self.node.verify_origin(BRIDGE_ID, certificate)
        synthetic = [call.args[0] for call in self.node.execute.call_args_list if ORIGIN in call.args[0][-1]]
        self.assertEqual(len(synthetic), 2)
        self.assertEqual(
            {argv[argv.index("--header") + 1] for argv in synthetic},
            {f"X-Praho-Original-Host: {DOMAIN}", f"X-Praho-Original-Host: www.{DOMAIN}"},
        )

    def test_target_and_source_neutral_checks_require_exact_404_body_and_verified_tls(self) -> None:
        self.add_account_name_site()
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")
        certificate = self.node.install_origin(BRIDGE_ID, manifest)
        self.node.install_source(BRIDGE_ID, certificate)
        for source, verifier in (
            (False, lambda: self.node.verify_origin(BRIDGE_ID, certificate)),
            (True, lambda: self.node.verify(BRIDGE_ID)),
        ):
            with self.subTest(verifier=verifier):
                self.node.execute = Mock(side_effect=self.neutral_response)
                verifier()
                neutral = [
                    call.args[0] for call in self.node.execute.call_args_list if ACCOUNT_NAME in call.args[0][-1]
                ]
                self.assertEqual(len(neutral), 16 if source else 4)
                self.assertEqual({argv[-1].split(":", 1)[0] for argv in neutral}, {"http", "https"})
                for argv in neutral:
                    self.assertNotIn("--fail", argv)
                    self.assertNotIn("--insecure", argv)
                    self.assertIn("--max-time", argv)
                    if argv[-1].startswith("https:"):
                        self.assertIn("--cacert", argv)
                for scheme in ("http:", "https:"):
                    for bad in ("customer content\n404", "Not Found\n200", "Not Found\n000", " Not Found\n404"):
                        with self.subTest(scheme=scheme, response=bad):
                            self.node.execute = Mock(
                                side_effect=lambda argv, bad=bad, scheme=scheme: (
                                    bad
                                    if ACCOUNT_NAME in argv[-1] and argv[-1].startswith(scheme)
                                    else self.neutral_response(argv)
                                )
                            )
                            with self.assertRaisesRegex(ValueError, "neutral"):
                                verifier()

                    def connection_failure(argv: list[str], scheme: str = scheme) -> str:
                        if ACCOUNT_NAME in argv[-1] and argv[-1].startswith(scheme):
                            raise subprocess.CalledProcessError(60, ["curl"])
                        return self.neutral_response(argv)

                    self.node.execute = Mock(side_effect=connection_failure)
                    with self.assertRaises(subprocess.CalledProcessError):
                        verifier()

    def test_preparation_upgrades_only_a_legacy_manifest_with_the_exact_captured_account_name(self) -> None:
        self.add_account_name_site()
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")
        manifest.pop("account_name", None)
        for item in manifest["vhosts"]:
            item.pop("neutral", None)
        kept = self.node.directory(BRIDGE_ID) / "source.json"
        kept.write_text(json.dumps(manifest))
        upgraded = self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")
        self.assertEqual(upgraded.get("account_name"), ACCOUNT_NAME)
        self.assertTrue(all(item.get("neutral") for item in upgraded["vhosts"] if item["name"] == ACCOUNT_NAME))
        self.assertEqual(json.loads(kept.read_text()), upgraded)
        with self.assertRaisesRegex(ValueError, "account|identity"):
            self.node.prepare(BRIDGE_ID, DOMAIN, "different.accounts.example.net", "192.0.2.20", "192.0.2.10")

    def test_unbound_legacy_manifest_is_refused_before_any_source_proxy_or_target_origin_reinstall(self) -> None:
        self.add_account_name_site()
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")
        certificate = self.node.install_origin(BRIDGE_ID, manifest)
        manifest.pop("account_name", None)
        for item in manifest["vhosts"]:
            item.pop("neutral", None)
        (self.node.directory(BRIDGE_ID) / "source.json").write_text(json.dumps(manifest))
        self.commands.clear()
        for action in (
            lambda: self.node.install_source(BRIDGE_ID, certificate),
            lambda: self.node.install_origin(BRIDGE_ID, manifest),
            lambda: self.node.verify_origin(BRIDGE_ID, certificate),
            lambda: self.node.verify(BRIDGE_ID),
        ):
            with self.subTest(action=action), self.assertRaisesRegex(ValueError, "manifest"):
                action()
        self.assertEqual(self.commands, [])

    def test_an_already_installed_legacy_source_proxy_is_not_reused_as_a_neutral_bridge(self) -> None:
        self.add_account_name_site()
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")
        self.node.install_source(BRIDGE_ID, self.node.install_origin(BRIDGE_ID, manifest))
        manifest.pop("account_name", None)
        for item in manifest["vhosts"]:
            item.pop("neutral", None)
        (self.node.directory(BRIDGE_ID) / "source.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "legacy|Legacy"):
            self.node.prepare(BRIDGE_ID, DOMAIN, ACCOUNT_NAME, "192.0.2.20", "192.0.2.10")

    def test_source_keeps_full_chain_keys_and_aliases_after_virtualmin_domain_is_deleted(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        origin = self.node.install_origin(BRIDGE_ID, manifest)
        self.node.install_source(BRIDGE_ID, origin)
        self.certificate.unlink()
        self.key.unlink()
        self.site.unlink()

        replay = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.assertEqual(replay, manifest)
        conf = (self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").read_text()
        self.assertIn(f"Define PRAHO_BRIDGE_{BRIDGE_ID.replace('-', '')}_0_1 www.{DOMAIN}", conf)
        self.assertIn(f"https://{ORIGIN}:443/", conf)
        self.assertIn("https://192.0.2.20:443/", conf)
        self.assertNotIn("http://192.0.2.20", conf)
        self.assertNotIn(str(self.certificate), conf)
        self.assertTrue((self.node.state / BRIDGE_ID / "source-1-chain.pem").exists())
        self.assertGreater(f"praho-migration-{BRIDGE_ID}.conf", "praho-default-site.conf")

    def test_node_entrypoint_passes_current_policy_without_rewriting_original_record(self) -> None:
        original = {"enabled": [{"name": DOMAIN, "enabled": True}]}
        environment = {
            "PRAHO_BRIDGE_ID": BRIDGE_ID,
            "PRAHO_BRIDGE_DOMAIN": DOMAIN,
            "PRAHO_BRIDGE_OWNER": "shop",
            "PRAHO_BRIDGE_DOMAIN_ID": "42",
            "PRAHO_BRIDGE_ENABLED": "0",
            "PRAHO_BARRIER_RECORD": json.dumps(original),
        }
        with (
            patch.dict(os.environ, {**environment, "PRAHO_BRIDGE_ACTION": "activate"}),
            patch.object(self.module, "NodeBridge", return_value=Mock()) as factory,
            patch("builtins.print"),
        ):
            self.module.main()
            factory.return_value.activate_target.assert_called_once_with(
                BRIDGE_ID,
                DOMAIN,
                "shop",
                original,
                enabled=False,
            )
        node = Mock()
        node.reconcile_policy.return_value = {"domain_id": "42", "owner": "shop", "enabled": False}
        with (
            patch.dict(os.environ, {**environment, "PRAHO_BRIDGE_ACTION": "reconcile_policy"}),
            patch.object(self.module, "NodeBridge", return_value=node),
            patch("builtins.print"),
        ):
            self.module.main()
        node.reconcile_policy.assert_called_once_with(BRIDGE_ID, DOMAIN, "shop", "42", False)

    def test_target_origin_preserves_http_and_carries_an_identity_outside_customer_content(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_origin(BRIDGE_ID, manifest)

        conf = (self.node.conf / f"praho-origin-{BRIDGE_ID}.conf").read_text()
        self.assertIn("<VirtualHost *:443>", conf)
        self.assertIn(f"ServerName {ORIGIN}", conf)
        self.assertIn("X-Praho-Original-Host", conf)
        self.assertIn("http://127.0.0.1:80/", conf)
        self.assertIn("Require ip 192.0.2.10", conf)
        self.assertEqual((self.node.probes / BRIDGE_ID).read_text(), BRIDGE_ID)
        self.assertIn(f"/.__praho_bridge_{BRIDGE_ID}", conf)

    def test_virtualmin_domain_lookup_cannot_select_the_bridge_for_customer_deletion(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_source(BRIDGE_ID, self.node.install_origin(BRIDGE_ID, manifest))
        conf = (self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").read_text()
        # Installed Virtualmin get_apache_virtual compares literal ServerName/ServerAlias words.
        # Apache expands Define variables; the Webmin parser intentionally leaves them literal.
        selected = [
            words[1:]
            for line in conf.splitlines()
            if (words := shlex.split(line)) and words[0].lower() in {"servername", "serveralias"}
        ]
        self.assertTrue(selected)
        self.assertFalse(any(DOMAIN in names or f"www.{DOMAIN}" in names for names in selected))

    def test_removing_one_origin_keeps_another_origin_and_never_changes_firewalls(self) -> None:
        first = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        second = self.node.prepare(SECOND_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_origin(BRIDGE_ID, first)
        self.node.install_origin(SECOND_ID, second)
        self.commands.clear()
        self.node.remove_origin(BRIDGE_ID)

        self.assertTrue((self.node.conf / f"praho-origin-{SECOND_ID}.conf").exists())
        self.assertFalse([argv for argv in self.commands if argv[0] == "ufw"])
        self.node.remove_origin(SECOND_ID)
        self.assertFalse((self.node.conf / "praho-origin-listen.conf").exists())
        self.assertFalse([argv for argv in self.commands if argv[0] == "ufw"])

    def test_verify_rejects_wrong_target_marker_and_runs_bounded_verified_curl_for_both_names(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        origin = self.node.install_origin(BRIDGE_ID, manifest)
        self.node.install_source(BRIDGE_ID, origin)
        self.node.execute = Mock(return_value="another target")
        with self.assertRaisesRegex(ValueError, "identity"):
            self.node.verify(BRIDGE_ID)
        self.node.execute = Mock(
            side_effect=lambda argv: (
                f"HTTP/1.1 200 OK\nX-Praho-Bridge: {BRIDGE_ID}\n" if "--dump-header" in argv else BRIDGE_ID
            )
        )
        self.node.verify(BRIDGE_ID)
        calls = self.node.execute.call_args_list
        self.assertEqual(len(calls), 18)  # Two origin names plus four source names at four real local addresses.
        for call in calls:
            argv = call.args[0]
            self.assertIn("--max-time", argv)
            self.assertIn("--connect-timeout", argv)
            self.assertNotIn("-k", argv)
            self.assertIn(f"/.__praho_bridge_{BRIDGE_ID}", argv[-1])

    def test_http_zero_and_connection_failures_never_confirm_the_bridge(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_source(BRIDGE_ID, self.node.install_origin(BRIDGE_ID, manifest))
        self.node.execute = Mock(return_value="000")
        with self.assertRaisesRegex(ValueError, "identity"):
            self.node.verify(BRIDGE_ID)
        self.node.execute = Mock(side_effect=subprocess.CalledProcessError(7, ["curl"]))
        with self.assertRaises(subprocess.CalledProcessError):
            self.node.verify(BRIDGE_ID)

    def test_precommit_origin_verification_also_proves_native_target_https_and_rejects_http_zero(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        certificate = self.node.install_origin(BRIDGE_ID, manifest)
        self.node.execute = Mock(side_effect=lambda argv: "000" if "--write-out" in argv else BRIDGE_ID)
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            self.node.verify_origin(BRIDGE_ID, certificate)
        self.node.execute = Mock(side_effect=lambda argv: "403" if "--write-out" in argv else BRIDGE_ID)
        self.node.verify_origin(BRIDGE_ID, certificate)
        native = [call.args[0] for call in self.node.execute.call_args_list if "--write-out" in call.args[0]]
        self.assertEqual(len(native), 2)
        for argv in native:
            self.assertIn("--cacert", argv)
            self.assertIn("--resolve", argv)
            self.assertNotIn("--insecure", argv)
            self.assertIn("192.0.2.20", argv[argv.index("--resolve") + 1])
        self.assertFalse((self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").exists())

    def test_replay_cannot_reuse_a_migration_directory_for_another_target(self) -> None:
        self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        with self.assertRaisesRegex(ValueError, "different"):
            self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.30", "192.0.2.10")

    def test_resumed_preparation_rechecks_the_saved_frontend_certificate_against_the_new_window(self) -> None:
        self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.certificate.unlink()
        self.node.minimum_certificate_lifetime = 31 * 24 * 3600
        with self.assertRaisesRegex(ValueError, "expires"):
            self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")

    def test_target_activation_restores_original_cron_and_keeps_a_previously_disabled_child(self) -> None:
        child = "h7k3p2q8.praho.test"
        disabled = {DOMAIN, child}
        cron = "*/5 * * * * /home/shop/report\n"
        target_cron = "# disabled\n"
        self.node.state.mkdir(parents=True, exist_ok=True)
        kept = self.node.directory(BRIDGE_ID) / "activation.crontab"
        kept.write_text(cron)
        kept.chmod(0o600)
        record = {
            "enabled": [{"name": DOMAIN, "enabled": True}, {"name": child, "enabled": False}],
            "accounts": [],
            "databases": [],
            "has_crontab": True,
            "active_sha": hashlib.sha256(cron.encode()).hexdigest(),
            "crontab_sha": hashlib.sha256(cron.encode().rstrip(b"\n")).hexdigest(),
        }

        def target(argv):
            nonlocal target_cron
            self.commands.append(argv)
            if argv[:2] == ["virtualmin", "list-domains"]:
                if "--disabled" in argv:
                    return "\n".join(sorted(disabled))
                return "1001" if "--id-only" in argv else "shop"
            if argv[:2] == ["virtualmin", "enable-domain"]:
                name = argv[argv.index("--domain") + 1]
                disabled.discard(name)
                if name == DOMAIN and "--subservers" in argv:
                    disabled.discard(child)
                if name == DOMAIN:
                    self.assertIn(
                        child, disabled, "An originally disabled name became enabled before activation finished"
                    )
            if argv[:2] == ["virtualmin", "disable-domain"]:
                disabled.add(argv[argv.index("--domain") + 1])
            if argv[:3] == ["crontab", "-u", "shop"]:
                if argv[-1] == "-l":
                    return target_cron
                target_cron = Path(argv[-1]).read_text()
            return ""

        self.node.execute = target
        kept.rename(kept.with_name("activation.incoming"))
        self.node.stage_activation(BRIDGE_ID, DOMAIN, "shop", record)
        self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)

        self.assertEqual(disabled, {child})
        self.assertEqual(target_cron, cron)
        self.assertFalse(kept.exists(), "the private transported cron is removed after verification")
        target_cron = "*/2 * * * * /home/shop/new-customer-job\n"
        # The old controller activation replay recopied the source cron before every invocation.
        kept.write_text(cron)
        self.commands.clear()
        self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        self.assertEqual(target_cron, "*/2 * * * * /home/shop/new-customer-job\n")
        self.assertFalse(any(argv[0] in {"mysql", "crontab"} for argv in self.commands))
        self.node.remove_origin(BRIDGE_ID)
        marker = self.node.directory(BRIDGE_ID) / "activation.json"
        self.assertEqual(json.loads(marker.read_text())["phase"], "completed")
        self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        self.assertEqual(target_cron, "*/2 * * * * /home/shop/new-customer-job\n")

    def test_a_target_owner_mismatch_stops_before_any_enable_or_cron_install(self) -> None:
        self.node.execute = Mock(return_value="another-customer")
        record = {
            "enabled": [{"name": DOMAIN, "enabled": True}],
            "accounts": [],
            "databases": [],
            "has_crontab": False,
            "active_sha": hashlib.sha256(b"").hexdigest(),
        }
        with self.assertRaisesRegex(ValueError, "owner"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        self.assertEqual(self.node.execute.call_count, 1)

    def stage_original_cron(self, cron: str = "*/5 * * * * /bin/true\n") -> dict:
        self.node.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        incoming = self.node.directory(BRIDGE_ID) / "activation.incoming"
        incoming.write_text(cron)
        incoming.chmod(0o600)
        record = {
            "enabled": [{"name": DOMAIN, "enabled": True}],
            "accounts": [],
            "databases": [],
            "has_crontab": True,
            "crontab_sha": hashlib.sha256(cron.encode().rstrip(b"\n")).hexdigest(),
            "active_sha": hashlib.sha256(cron.encode()).hexdigest(),
        }
        self.node.stage_activation(BRIDGE_ID, DOMAIN, "shop", record)
        return record

    def test_policy_on_unactivated_or_replaced_target_never_calls_native_mutation(self):
        self.node.execute = Mock(side_effect=lambda argv: "1001" if "--id-only" in argv else "shop")
        record = self.stage_original_cron()
        with (
            patch.object(self.node, "policy_native", create=True) as native,
            self.assertRaisesRegex(ValueError, "completed"),
        ):
            self.node.reconcile_policy(BRIDGE_ID, DOMAIN, "shop", "1001", False)
        native.assert_not_called()
        self.assertEqual(record["enabled"], [{"name": DOMAIN, "enabled": True}])

    def test_completed_policy_active_replay_preserves_customer_cron_and_original_record(self):
        disabled = set()

        def target(argv):
            self.commands.append(argv)
            if argv[:2] == ["virtualmin", "list-domains"]:
                if "--disabled" in argv:
                    return "\n".join(disabled)
                return "1001" if "--id-only" in argv else "shop"
            return ""

        self.node.execute = target
        record = self.stage_original_cron()
        saved = json.dumps(record, sort_keys=True)
        with patch.object(self.node, "restore_target_runtime"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        self.commands.clear()
        with patch.object(self.node, "policy_native", create=True) as native:
            proof = self.node.reconcile_policy(BRIDGE_ID, DOMAIN, "shop", "1001", True)
        self.assertEqual(proof, {"domain_id": "1001", "owner": "shop", "enabled": True})
        native.assert_not_called()
        self.assertFalse(any(argv[0] in {"mysql", "crontab"} for argv in self.commands))
        self.assertEqual(json.dumps(record, sort_keys=True), saved)
        # Enabled-only variation of a completed initial RPC also never replays cron/grants.
        with patch.object(self.node, "restore_target_runtime") as runtime:
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record, enabled=False)
        runtime.assert_not_called()

    def test_policy_release_preserves_original_and_customer_disabled_children(self):
        child = "preview.example.com"
        disabled = {child}

        def target(argv):
            self.commands.append(argv)
            if argv[:2] == ["virtualmin", "list-domains"]:
                if "--disabled" in argv:
                    return "\n".join(disabled)
                if "--id-only" in argv:
                    return "1002" if child in argv else "1001"
                return "shop"
            raise AssertionError("A retained disabled child needs no native enable or credential/cron mutation")

        def native(identity, domain, owner, domain_id, enabled):
            if enabled:
                disabled.discard(domain)
            else:
                disabled.add(domain)
            return {"domain_id": domain_id, "owner": owner, "enabled": enabled}

        self.node.execute = target
        record = self.stage_original_cron()
        with patch.object(self.node, "restore_target_runtime"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        directory = self.node.directory(BRIDGE_ID)
        marker = directory / "activation.json"
        completed = json.loads(marker.read_text())
        for originally_enabled in (False, True):
            with self.subTest(originally_enabled=originally_enabled):
                completed["policy_record"]["enabled"] = [
                    {"name": DOMAIN, "enabled": True},
                    {"name": child, "enabled": originally_enabled},
                ]
                completed["policy_record"]["ids"][child] = "1002"
                marker.write_text(json.dumps(completed))
                (directory / "policy.json").unlink(missing_ok=True)
                with patch.object(self.node, "policy_native", side_effect=native):
                    self.node.reconcile_policy(BRIDGE_ID, DOMAIN, "shop", "1001", False)
                    self.node.reconcile_policy(BRIDGE_ID, DOMAIN, "shop", "1001", True)
                self.assertEqual(disabled, {child})

    def test_interrupted_activation_keeps_applying_evidence_and_replay_never_reapplies_original_state(self) -> None:
        mutations = []

        def target(argv):
            if argv[:2] == ["virtualmin", "list-domains"]:
                if "--disabled" in argv:
                    return ""
                return "1001" if "--id-only" in argv else "shop"
            if argv[0] == "crontab":
                mutations.append(argv)
                raise RuntimeError("worker interrupted after target admitted writes")
            return ""

        self.node.execute = target
        record = self.stage_original_cron()
        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        marker = self.node.directory(BRIDGE_ID) / "activation.json"
        self.assertEqual(json.loads(marker.read_text())["phase"], "applying")
        with self.assertRaisesRegex(ValueError, "review"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        self.assertEqual(len(mutations), 1)

    def test_staged_activation_is_bound_to_actual_target_domain_id(self) -> None:
        self.node.execute = Mock(side_effect=lambda argv: "1001" if "--id-only" in argv else "shop")
        record = self.stage_original_cron()
        self.node.execute = Mock(side_effect=lambda argv: "2002" if "--id-only" in argv else "shop")
        with self.assertRaisesRegex(ValueError, "different target"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        self.assertFalse(any(call.args[0][0] in {"mysql", "crontab"} for call in self.node.execute.call_args_list))

    def test_compensated_activation_keeps_a_tombstone_that_refuses_late_rpc(self) -> None:
        self.node.execute = Mock(side_effect=lambda argv: "1001" if "--id-only" in argv else "shop")
        record = self.stage_original_cron()
        self.node.remove_origin(BRIDGE_ID)
        marker = self.node.directory(BRIDGE_ID) / "activation.json"
        self.assertEqual(json.loads(marker.read_text())["phase"], "removed")
        with self.assertRaisesRegex(ValueError, "review"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        self.assertFalse((self.node.directory(BRIDGE_ID) / "activation.crontab").exists())

    def test_terminal_retirement_removes_private_cron_but_keeps_completed_marker_and_active_origin(self) -> None:
        self.node.execute = Mock(side_effect=lambda argv: "1001" if "--id-only" in argv else "shop")
        self.stage_original_cron()
        directory = self.node.directory(BRIDGE_ID)
        marker = directory / "activation.json"
        completed = {**json.loads(marker.read_text()), "phase": "completed"}
        marker.write_text(json.dumps(completed))
        incoming = directory / "activation.incoming"
        incoming.write_text("private source cron from a late request")
        origin = self.node.conf / f"praho-origin-{BRIDGE_ID}.conf"
        origin.write_text("retained origin")
        self.node.execute.reset_mock()
        self.node.retire_activation_data(BRIDGE_ID)
        self.node.retire_activation_data(BRIDGE_ID)
        self.assertEqual(json.loads(marker.read_text()), completed)
        self.assertFalse((directory / "activation.crontab").exists())
        self.assertFalse(incoming.exists())
        self.assertEqual(origin.read_text(), "retained origin")
        self.node.execute.assert_not_called()

    def test_terminal_retirement_of_staged_activation_refuses_a_late_reactivation(self) -> None:
        self.node.execute = Mock(side_effect=lambda argv: "1001" if "--id-only" in argv else "shop")
        record = self.stage_original_cron()
        self.node.retire_activation_data(BRIDGE_ID)
        with self.assertRaisesRegex(ValueError, "review"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)

    def test_teardown_blocks_a_late_workers_source_or_origin_reinstall(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        certificate = self.node.install_origin(BRIDGE_ID, manifest)
        self.node.install_source(BRIDGE_ID, certificate)
        self.node.remove_source(BRIDGE_ID)
        self.node.remove_origin(BRIDGE_ID)

        with self.assertRaisesRegex(ValueError, "removed"):
            self.node.install_source(BRIDGE_ID, certificate)
        with self.assertRaisesRegex(ValueError, "removed"):
            self.node.install_origin(BRIDGE_ID, manifest)

    def test_a_disabled_target_can_be_proven_without_a_marker_in_its_disabled_page(self) -> None:
        manifest = self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.install_source(BRIDGE_ID, self.node.install_origin(BRIDGE_ID, manifest))

        self.assertIn("<VirtualHost", (self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").read_text())
        self.node.execute = Mock(
            side_effect=lambda argv: (
                f"HTTP/1.1 200 OK\nX-Praho-Bridge: {BRIDGE_ID}\n" if "--dump-header" in argv else BRIDGE_ID
            )
        )
        self.node.verify(BRIDGE_ID)
        self.assertTrue(any(ORIGIN in call.args[0][-1] for call in self.node.execute.call_args_list))

    def test_a_frontend_certificate_that_expires_during_the_bridge_window_is_refused(self) -> None:
        decoded = self.module.ssl._ssl._test_decode_cert(str(self.certificate))
        decoded["notAfter"] = (datetime.now(UTC) + timedelta(hours=1)).strftime("%b %d %H:%M:%S %Y GMT")
        with (
            patch.object(self.module.ssl._ssl, "_test_decode_cert", return_value=decoded),
            self.assertRaisesRegex(ValueError, "expires"),
        ):
            self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")

    def test_a_conflicting_operator_hosts_entry_is_never_overwritten_or_removed(self) -> None:
        hosts = self.root / "etc/hosts"
        original = f"127.0.0.1 localhost\n192.0.2.99 {ORIGIN}\n"
        hosts.write_text(original)
        with self.assertRaisesRegex(ValueError, "unowned"):
            self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.remove_source(BRIDGE_ID)
        self.assertEqual(hosts.read_text(), original)

    def test_removing_source_hosts_entry_preserves_other_migrations_and_operator_entries(self) -> None:
        hosts = self.root / "etc/hosts"
        hosts.write_text("127.0.0.1 localhost\n192.0.2.99 operator.example.com\n")
        self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.node.prepare(SECOND_ID, DOMAIN, "", "192.0.2.30", "192.0.2.10")
        self.node.remove_source(BRIDGE_ID)
        result = hosts.read_text()
        self.assertNotIn(ORIGIN, result)
        self.assertIn(SECOND_ID, result)
        self.assertIn("192.0.2.99 operator.example.com", result)

    def test_bind_mounted_hosts_fallback_preserves_existing_content_and_permissions(self) -> None:
        hosts = self.root / "etc/hosts"
        hosts.write_text("127.0.0.1 localhost\n")
        hosts.chmod(0o640)
        write = self.node.write

        def mounted(path, *args, **kwargs):
            if path == hosts:
                raise OSError(errno.EBUSY, "bind-mounted hosts file")
            return write(path, *args, **kwargs)

        with patch.object(self.node, "write", side_effect=mounted):
            self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
            self.assertIn(ORIGIN, hosts.read_text())
            self.node.remove_source(BRIDGE_ID)
        self.assertEqual(hosts.read_text(), "127.0.0.1 localhost\n")
        self.assertEqual(hosts.stat().st_mode & 0o777, 0o640)

    def test_final_cleanup_removes_only_original_cron_after_independently_proving_source_absence(self) -> None:
        record = self.root / f"var/lib/praho/migration/migration-42.{BRIDGE_ID}.crontab"
        record.parent.mkdir(parents=True)
        record.write_text("original secret cron")
        record.chmod(0o600)
        self.node.owner_uid = os.geteuid()
        self.node.execute = Mock(return_value="another.example.com\n")

        self.node.remove_source(BRIDGE_ID, domain=DOMAIN, cleanup_source_record=str(record))
        self.assertFalse(record.exists())
        marker = record.parent / f"migration-42.cancelled.{BRIDGE_ID}"
        self.assertTrue(marker.exists(), "retiring the original record must permanently fence its late apply RPC")
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertIn(
            ["virtualmin", "list-domains", "--name-only"], [call.args[0] for call in self.node.execute.call_args_list]
        )

    def test_final_source_cleanup_keeps_the_original_cron_when_durable_cancellation_cannot_be_written(self) -> None:
        record = self.node.barrier_state / f"migration-42.{BRIDGE_ID}.crontab"
        record.parent.mkdir(parents=True, mode=0o700)
        record.write_text("original secret cron")
        record.chmod(0o600)
        self.node.execute = Mock(return_value="")
        write = self.node.write

        def refuse_marker(path, *args, **kwargs):
            if path == record.parent / f"migration-42.cancelled.{BRIDGE_ID}":
                self.assertTrue(kwargs.get("durable"))
                raise OSError("cannot flush retirement marker")
            return write(path, *args, **kwargs)

        with patch.object(self.node, "write", side_effect=refuse_marker), self.assertRaisesRegex(OSError, "flush"):
            self.node.remove_source(BRIDGE_ID, domain=DOMAIN, cleanup_source_record=str(record))
        self.assertTrue(record.exists(), "failed durable retirement must never delete the only original record")

    def test_final_cleanup_refuses_a_live_source_and_never_follows_a_saved_cron_symlink(self) -> None:
        record = self.root / f"var/lib/praho/migration/migration-42.{BRIDGE_ID}.crontab"
        record.parent.mkdir(parents=True)
        original = record.parent / "other-customer.crontab"
        original.write_text("do not remove")
        record.symlink_to(original)
        self.node.execute = Mock(return_value=DOMAIN + "\n")
        with self.assertRaisesRegex(ValueError, "still exists"):
            self.node.remove_source(BRIDGE_ID, domain=DOMAIN, cleanup_source_record=str(record))
        self.node.execute = Mock(return_value="")
        with self.assertRaisesRegex(ValueError, "regular|owned"):
            self.node.remove_source(BRIDGE_ID, domain=DOMAIN, cleanup_source_record=str(record))
        self.assertTrue(original.exists())

    def test_missing_neutral_default_refuses_before_publishing_a_bridge(self) -> None:
        (self.node.conf / "praho-default-site.conf").unlink()
        with self.assertRaisesRegex(ValueError, "neutral default"):
            self.node.prepare(BRIDGE_ID, DOMAIN, "", "192.0.2.20", "192.0.2.10")
        self.assertFalse((self.node.conf / f"praho-migration-{BRIDGE_ID}.conf").exists())
