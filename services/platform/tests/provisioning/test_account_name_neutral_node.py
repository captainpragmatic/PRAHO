"""Account-name web policy is root-controlled and independent of native suspension/content."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.test import SimpleTestCase

HELPER = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-account-name-neutral.py"
ZONE = "accounts.example.net"
NAME = "a1234567." + ZONE
OWNER = "shop"
PARENT = "shop.example.org"
PARENT_ID = "1000"
CHILD_ID = "1001"


class AccountNameNeutralNodeTests(SimpleTestCase):
    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        spec = importlib.util.spec_from_file_location("account_neutral_node", HELPER)
        assert spec and spec.loader
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.commands: list[list[str]] = []
        self.child_present = True
        self.native_owner = OWNER
        self.disabled = {NAME}
        self.probe = Mock()

        def execute(argv: list[str]) -> str:  # noqa: PLR0911  # Fixed native command fixture, no dispatcher fallthrough.
            self.commands.append(argv)
            if argv[:2] == ["virtualmin", "list-domains"]:
                if "--disabled" in argv:
                    return "\n".join(sorted(self.disabled))
                if "--domain" not in argv:
                    return "\n".join([PARENT, *([NAME] if self.child_present else [])])
                name = argv[argv.index("--domain") + 1]
                if "--user-only" in argv:
                    return self.native_owner if name == NAME else OWNER
                return CHILD_ID if name == NAME else PARENT_ID
            if argv[0] == "openssl":
                return subprocess.run(argv, check=True, capture_output=True, text=True).stdout  # noqa: S603
            if argv[:2] == ["ip", "-j"]:
                return json.dumps([{"addr_info": [{"local": "127.0.0.1"}, {"local": "192.0.2.20"}, {"local": "::1"}]}])
            if argv[:3] == ["ss", "-H", "-lnt"]:
                return "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:443 0.0.0.0:*\nLISTEN 0 511 [::]:80 [::]:*\nLISTEN 0 511 [::]:443 [::]:*\n"
            return ""

        self.guard = self.module.NeutralGuard(self.root, execute=execute, probe=self.probe)
        self.guard.owner_uid = os.geteuid()
        self.guard.conf.mkdir(parents=True)
        self.guard.sites.mkdir(parents=True)
        (self.guard.conf / "praho-default-site.conf").write_text("ServerName praho-default.invalid\n")
        self.cert = self.root / "etc/ssl/virtualmin/1001/ssl.cert"
        self.key = self.cert.with_name("ssl.key")
        self.chain = self.cert.with_name("ssl.chain")
        self.cert.parent.mkdir(parents=True)
        self.make_certificate(self.cert, self.key, NAME)
        self.chain.write_text("")
        self.chain.chmod(0o600)
        self.guard.snakeoil_certificate.parent.mkdir(parents=True, exist_ok=True)
        self.guard.snakeoil_key.parent.mkdir(parents=True, exist_ok=True)
        self.make_certificate(self.guard.snakeoil_certificate, self.guard.snakeoil_key, "localhost", lifetime_days=3650)
        self.native_file = self.guard.sites / f"{NAME}.conf"
        self.native_file.write_text(
            f"<VirtualHost *:80>\nServerName {NAME}\nServerAlias www.{NAME} webmail.{NAME} admin.{NAME}\n"
            f"DocumentRoot /home/{OWNER}/domains/{NAME}/public_html\n</VirtualHost>\n"
            f"<VirtualHost *:443>\nServerName {NAME}\nSSLEngine on\nSSLCertificateFile {self.cert}\n"
            f"SSLCertificateKeyFile {self.key}\nSSLCertificateChainFile {self.chain}\n</VirtualHost>\n"
        )
        self.guard.native_domains.mkdir(parents=True)
        (self.guard.native_domains / CHILD_ID).write_text(f"dom={NAME}\nuser={OWNER}\nparent={PARENT_ID}\n")
        (self.guard.native_domains / PARENT_ID).write_text(f"dom={PARENT}\nuser={OWNER}\n")
        self.identity = str(uuid4())

    @staticmethod
    def make_certificate(
        certificate: Path, key_path: Path, name: str, *, now: datetime | None = None, lifetime_days: int = 30
    ) -> None:
        now = now or datetime.now(UTC)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=lifetime_days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            .sign(key, hashes.SHA256())
        )
        certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        certificate.chmod(0o600)
        key_path.chmod(0o600)

    def ensure(self) -> dict[str, object]:
        return self.guard.ensure(self.identity, ZONE, NAME, OWNER)

    def test_explicit_bindings_are_probed_and_stable_definitions_preserve_other_name_evidence(self) -> None:
        self.native_file.write_text(
            self.native_file.read_text().replace("*:80", "192.0.2.20:80").replace("*:443", "[::1]:443")
        )
        self.ensure()
        _, original = self.manifest()
        self.assertEqual(original["native_bindings"], {"80": ["192.0.2.20"], "443": ["::1"]})
        named = Path(original["named_config_path"])
        self.assertIn("${PRAHO_NEUTRAL_HTTP_BINDINGS}", named.read_text())
        self.assertTrue(any("192.0.2.20" in call.kwargs["addresses"]["80"] for call in self.probe.call_args_list))
        # A second native child changes the node's groups. Shared Defines change;
        # the first name's separately recorded config bytes remain exact.
        second = self.guard.sites / "other.conf"
        second.write_text("<VirtualHost 192.0.2.21:80>\nServerName other.example.net\n</VirtualHost>\n")
        self.ensure()
        self.assertEqual(self.manifest()[1]["named_config_sha256"], original["named_config_sha256"])
        self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)
        second.unlink()
        self.ensure()
        self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)
        self.child_present = False
        self.native_file.unlink()
        self.guard.retire(self.identity, ZONE, NAME, OWNER)
        self.assertTrue(any("192.0.2.20" in call.kwargs["addresses"]["80"] for call in self.probe.call_args_list))

    def manifest(self) -> tuple[Path, dict[str, object]]:
        path = self.guard.state / "names" / NAME / "state.json"
        return path, json.loads(path.read_text())

    def test_precreation_zone_guard_closes_the_window_without_claiming_a_named_certificate(self) -> None:
        self.child_present = False
        receipt = self.ensure()
        self.assertEqual(receipt["action"], "ensure")
        self.assertTrue(receipt["neutral"])
        self.assertNotIn("certificate_sha256", receipt)
        configs = sorted(self.guard.conf.glob("*.conf"))
        self.assertEqual(configs[0].name, "praho-00-neutral-bindings.conf")
        self.assertEqual(len(configs), 3)
        zone_text = configs[2].read_text()
        self.assertIn(f"*.{ZONE}", zone_text)
        self.assertIn('ErrorDocument 404 "Not Found"', zone_text)
        self.assertIn("RewriteEngine Off", zone_text)
        self.assertIn("RewriteOptions IgnoreInherit", zone_text)
        self.assertTrue(self.probe.called)
        self.assertFalse(any(call.kwargs["named"] for call in self.probe.call_args_list))

    def test_named_guard_keeps_local_full_chain_and_key_and_never_uses_tenant_content(self) -> None:
        receipt = self.ensure()
        manifest_path, manifest = self.manifest()
        configs = sorted(self.guard.conf.glob("*.conf"))
        self.assertEqual([item.name.split("-")[2] for item in configs[2:]], ["10", "20"])
        named = Path(manifest["named_config_path"])
        text = named.read_text()
        self.assertIn("ServerName ${PRAHO_NEUTRAL_NAME_", text)
        self.assertIn(f"*.{NAME}", text)
        self.assertNotIn("/home/", text)
        self.assertNotIn("Proxy", text)
        self.assertNotIn(".htaccess", text)
        self.assertIn('ErrorDocument 503 "Not Found"', text)
        self.assertEqual(manifest["phase"], "ready")
        self.assertEqual(manifest["native_domain_id"], CHILD_ID)
        self.assertEqual(manifest["native_parent_id"], PARENT_ID)
        self.assertEqual(manifest["native_parent_domain"], PARENT)
        self.assertEqual(manifest["owner"], OWNER)
        self.assertEqual(manifest_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(manifest["named_config_sha256"], hashlib.sha256(named.read_bytes()).hexdigest())
        self.assertEqual(receipt["certificate_sha256"], manifest["certificate_sha256"])
        private_files = list((self.guard.state / "names" / NAME / "versions").rglob("*.pem"))
        self.assertEqual(len(private_files), 2)
        self.assertTrue(all(item.stat().st_mode & 0o777 == 0o600 for item in private_files))

    def test_receipt_binds_nonce_action_zone_name_and_exact_config_bytes(self) -> None:
        receipt = self.ensure()
        _, manifest = self.manifest()
        expected = hashlib.sha256(
            Path(manifest["zone_config_path"]).read_bytes() + b"\0" + Path(manifest["named_config_path"]).read_bytes()
        ).hexdigest()
        self.assertEqual(
            receipt,
            {
                "version": 1,
                "identity": self.identity,
                "action": "ensure",
                "zone": ZONE,
                "name": NAME,
                "neutral": True,
                "config_sha256": expected,
                "certificate_sha256": manifest["certificate_sha256"],
            },
        )

    def test_certificate_rotation_changes_the_leaf_and_prunes_previous_private_keys(self) -> None:
        before = self.ensure()
        _, old_manifest = self.manifest()
        old_config = Path(old_manifest["named_config_path"]).read_text()
        self.make_certificate(self.cert, self.key, NAME)
        after = self.ensure()
        self.assertNotEqual(before["certificate_sha256"], after["certificate_sha256"])
        _, manifest = self.manifest()
        self.assertNotEqual(old_config, Path(manifest["named_config_path"]).read_text())
        versions = list((self.guard.state / "names" / NAME / "versions").iterdir())
        self.assertEqual(len(versions), 1)

    def test_idempotent_ensure_reproves_without_reloading_unchanged_configuration(self) -> None:
        first = self.ensure()
        self.commands.clear()
        self.probe.reset_mock()
        self.identity = str(uuid4())
        second = self.ensure()
        self.assertNotEqual(first["identity"], second["identity"])
        self.assertEqual(first["config_sha256"], second["config_sha256"])
        self.assertTrue(self.probe.called)
        self.assertNotIn(["apache2ctl", "graceful"], self.commands)

    def test_foreign_native_owner_is_refused_before_installing_a_named_guard(self) -> None:
        self.native_owner = "another"
        with self.assertRaisesRegex(ValueError, "owner"):
            self.ensure()
        self.assertFalse(list(self.guard.conf.glob("praho-neutral-10-*")))

    def test_native_child_cannot_be_replaced_by_a_same_owner_top_level_domain(self) -> None:
        (self.guard.native_domains / CHILD_ID).write_text(f"dom={NAME}\nuser={OWNER}\n")
        with self.assertRaisesRegex(ValueError, "child|parent"):
            self.ensure()

    def test_wrong_certificate_or_mismatched_key_never_becomes_ready(self) -> None:
        self.make_certificate(self.cert, self.key, "wrong.example.net")
        with self.assertRaisesRegex(ValueError, "certificate"):
            self.ensure()
        self.make_certificate(self.cert, self.key, NAME)
        foreign = self.key.with_name("foreign.key")
        self.make_certificate(self.cert.with_name("foreign.cert"), foreign, NAME)
        self.key.write_bytes(foreign.read_bytes())
        with self.assertRaisesRegex(ValueError, "key"):
            self.ensure()
        self.assertFalse((self.guard.state / "names" / NAME / "state.json").exists())

    def test_failed_exact_response_or_tls_pin_does_not_publish_a_ready_manifest(self) -> None:
        self.probe.side_effect = ValueError("The neutral response is not exact")
        with self.assertRaisesRegex(ValueError, "response"):
            self.ensure()
        self.assertFalse((self.guard.state / "names" / NAME / "state.json").exists())

    def test_unowned_config_and_symlinked_private_state_are_not_overwritten(self) -> None:
        zone_path = self.guard.conf / f"praho-neutral-20-zone-{hashlib.sha256(ZONE.encode()).hexdigest()}.conf"
        zone_path.write_text("# Another operator's config\n")
        with self.assertRaisesRegex(ValueError, "owned|managed"):
            self.ensure()
        self.assertEqual(zone_path.read_text(), "# Another operator's config\n")
        zone_path.unlink()
        outside = self.root / "outside"
        outside.mkdir()
        self.guard.state.parent.mkdir(parents=True, exist_ok=True)
        self.guard.state.rename(self.guard.state.with_name("previous-owned-state"))
        self.guard.state.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory|symlink"):
            self.ensure()
        self.assertEqual(list(outside.iterdir()), [])

    def test_retire_requires_native_absence_and_keeps_the_zone_fallback(self) -> None:
        self.ensure()
        _, manifest = self.manifest()
        with self.assertRaisesRegex(ValueError, "exists|present"):
            self.guard.retire(self.identity, ZONE, NAME, OWNER)
        self.assertTrue(Path(manifest["named_config_path"]).exists())
        self.child_present = False
        receipt = self.guard.retire(self.identity, ZONE, NAME, OWNER)
        self.assertEqual(receipt["action"], "retire")
        self.assertNotIn("certificate_sha256", receipt)
        self.assertFalse(Path(manifest["named_config_path"]).exists())
        self.assertTrue(Path(manifest["zone_config_path"]).exists())
        self.assertFalse(list((self.guard.state / "names" / NAME).rglob("*.pem")))
        self.assertEqual(self.manifest()[1]["phase"], "retired")

    def test_verify_is_read_only_and_requires_current_disabled_owned_child_and_parent(self) -> None:
        self.ensure()
        before = {path: path.read_bytes() for path in self.guard.state.rglob("*") if path.is_file()}
        self.commands.clear()
        self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, "WEBMAIL." + NAME.upper() + ".:443")
        after = {path: path.read_bytes() for path in self.guard.state.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertNotIn(["apache2ctl", "graceful"], self.commands)
        self.disabled.clear()
        with self.assertRaisesRegex(ValueError, "disabled"):
            self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)

    def test_verify_rejects_tampering_parent_change_sibling_host_and_zone_fallback_only(self) -> None:
        self.ensure()
        path, manifest = self.manifest()
        for host in (PARENT, "b1234567." + ZONE, "prefix" + NAME):
            with self.subTest(host=host), self.assertRaisesRegex(ValueError, "scope|host"):
                self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, host)
        with self.assertRaisesRegex(ValueError, "parent"):
            self.guard.verify(NAME, OWNER, PARENT, "2000", NAME)
        Path(manifest["named_config_path"]).write_text("# changed\n")
        with self.assertRaisesRegex(ValueError, "digest|config"):
            self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)
        path.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)

    def test_invalid_inputs_do_not_create_private_state(self) -> None:
        for identity, zone, name, owner in (
            ("not-a-uuid", ZONE, NAME, OWNER),
            (self.identity, ZONE + "\nInclude other", NAME, OWNER),
            (self.identity, ZONE, "other.example.net", OWNER),
            (self.identity, ZONE, "too-long-name." + ZONE, OWNER),
            (self.identity, ZONE, NAME, "root;bad"),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.guard.ensure(identity, zone, name, owner)
        self.assertFalse(self.guard.state.exists())

    def test_verify_refuses_symlinked_version_directories_and_public_state(self) -> None:
        self.ensure()
        manifest_path, _ = self.manifest()
        manifest_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)
        manifest_path.chmod(0o600)
        version = next((self.guard.state / "names" / NAME / "versions").iterdir())
        outside = self.root / "outside-tls"
        version.rename(outside)
        version.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory|symlink"):
            self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)

    def test_native_deletion_cannot_remove_the_private_frontend_certificate(self) -> None:
        receipt = self.ensure()
        _, manifest = self.manifest()
        self.child_present = False
        self.native_file.unlink()
        for path in (self.cert, self.key, self.chain):
            path.unlink()
        private_files = list((self.guard.state / "names" / NAME / "versions").rglob("*.pem"))
        self.assertEqual(len(private_files), 2)
        self.assertIn(
            receipt["certificate_sha256"],
            [self.module.leaf_fingerprint(path.read_bytes()) for path in private_files if path.name == "chain.pem"],
        )
        self.assertTrue(Path(manifest["named_config_path"]).exists())
        self.guard.retire(self.identity, ZONE, NAME, OWNER)
        self.assertFalse(any(path.exists() for path in private_files))

    def test_writable_state_ancestor_is_refused_before_private_tls_is_copied(self) -> None:
        self.guard.state.parent.mkdir(parents=True)
        self.guard.state.parent.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "ancestor|directory"):
            self.ensure()
        self.assertFalse(self.guard.state.exists())

    def test_existing_native_unix_owner_spelling_is_accepted(self) -> None:
        for owner in ("_legacy", "LegacyUser"):
            with self.subTest(owner=owner):
                self.module.validate(ZONE, NAME, owner, self.identity)

    def test_verify_refuses_a_private_key_with_unsafe_permissions(self) -> None:
        self.ensure()
        key = next((self.guard.state / "names" / NAME / "versions").glob("*/key.pem"))
        key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)

    def test_orphan_retirement_uses_owned_metadata_only_after_native_absence(self) -> None:
        self.ensure()
        _, manifest = self.manifest()
        self.child_present = False
        result = self.guard.retire(self.identity, ZONE, NAME, "")
        self.assertEqual(result["action"], "retire")
        self.assertFalse(Path(manifest["named_config_path"]).exists())
        self.assertEqual(self.manifest()[1]["owner"], OWNER)
        self.assertFalse(list((self.guard.state / "names" / NAME).rglob("*.pem")))

    def test_orphan_retirement_never_changes_a_present_native_child(self) -> None:
        self.ensure()
        _, manifest = self.manifest()
        with self.assertRaisesRegex(ValueError, "exists|present"):
            self.guard.retire(self.identity, ZONE, NAME, "")
        self.assertTrue(Path(manifest["named_config_path"]).exists())
        self.assertEqual(self.manifest()[1]["phase"], "ready")

    def test_orphan_retirement_refuses_tampered_binding_and_malformed_nonempty_owner(self) -> None:
        self.ensure()
        _, manifest = self.manifest()
        self.child_present = False
        for owner in ("bad;owner", "has space"):
            with self.subTest(owner=owner), self.assertRaisesRegex(ValueError, "owner"):
                self.guard.retire(self.identity, ZONE, NAME, owner)
        path = Path(manifest["named_config_path"])
        path.write_text(path.read_text() + "# modified after readiness\n")
        with self.assertRaisesRegex(ValueError, "digest|config"):
            self.guard.retire(self.identity, ZONE, NAME, "")
        self.assertTrue(path.exists())

    def test_prepare_uses_valid_native_tls_but_never_claims_certificate_readiness(self) -> None:
        result = self.guard.prepare(self.identity, ZONE, NAME, OWNER)
        self.assertEqual(result["action"], "prepare")
        self.assertNotIn("certificate_sha256", result)
        self.assertEqual(self.manifest()[1]["phase"], "ready")
        self.assertTrue(all(call.kwargs["named"] for call in self.probe.call_args_list))

    def test_prepare_keeps_valid_owned_tls_when_only_the_native_leaf_is_expired(self) -> None:
        self.ensure()
        _, original = self.manifest()
        self.make_certificate(self.cert, self.key, NAME, now=datetime.now(UTC) - timedelta(days=60))
        self.commands.clear()
        self.probe.reset_mock()
        result = self.guard.prepare(self.identity, ZONE, NAME, OWNER)
        self.assertNotIn("certificate_sha256", result)
        self.assertEqual(self.manifest()[1], original)
        self.assertNotIn(["apache2ctl", "graceful"], self.commands)
        self.assertTrue(all(call.kwargs["named"] for call in self.probe.call_args_list))

    def test_prepare_bootstraps_known_expired_copies_then_strict_ensure_installs_fresh_tls(self) -> None:
        self.ensure()
        future = datetime.now(UTC) + timedelta(days=31)
        with patch.object(self.module.time, "time", return_value=future.timestamp()):
            self.probe.reset_mock()
            result = self.guard.prepare(self.identity, ZONE, NAME, OWNER)
            self.assertNotIn("certificate_sha256", result)
            self.assertEqual(self.manifest()[1]["phase"], "bootstrap")
            self.assertTrue(all(not call.kwargs["named"] for call in self.probe.call_args_list))
            with self.assertRaisesRegex(ValueError, "expired|valid"):
                self.ensure()
            with self.assertRaisesRegex(ValueError, "ready|bootstrap"):
                self.guard.verify(NAME, OWNER, PARENT, PARENT_ID, NAME)
            self.make_certificate(self.cert, self.key, NAME, now=future)
            fresh = self.ensure()
            self.assertIn("certificate_sha256", fresh)
            self.assertEqual(self.manifest()[1]["phase"], "ready")
            self.assertEqual(len(list((self.guard.state / "names" / NAME / "versions").iterdir())), 1)

    def test_prepare_does_not_bootstrap_expired_native_tls_with_wrong_name_or_key(self) -> None:
        self.make_certificate(self.cert, self.key, "wrong.example.net", now=datetime.now(UTC) - timedelta(days=60))
        with self.assertRaisesRegex(ValueError, "certificate"):
            self.guard.prepare(self.identity, ZONE, NAME, OWNER)
        self.make_certificate(self.cert, self.key, NAME, now=datetime.now(UTC) - timedelta(days=60))
        foreign = self.key.with_name("foreign.key")
        self.make_certificate(self.cert.with_name("foreign.cert"), foreign, NAME)
        self.key.write_bytes(foreign.read_bytes())
        with self.assertRaisesRegex(ValueError, "key"):
            self.guard.prepare(self.identity, ZONE, NAME, OWNER)
        self.assertFalse((self.guard.state / "names" / NAME / "state.json").exists())

    def test_owned_bootstrap_can_be_retired_only_after_native_absence(self) -> None:
        self.ensure()
        with patch.object(self.module.time, "time", return_value=(datetime.now(UTC) + timedelta(days=31)).timestamp()):
            self.guard.prepare(self.identity, ZONE, NAME, OWNER)
        with self.assertRaisesRegex(ValueError, "exists|present"):
            self.guard.retire(self.identity, ZONE, NAME, "")
        self.child_present = False
        result = self.guard.retire(self.identity, ZONE, NAME, "")
        self.assertEqual(result["action"], "retire")
        self.assertFalse(list((self.guard.state / "names" / NAME).rglob("*.pem")))
