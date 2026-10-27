"""The bridge's node operations against real files and certificates, with Apache stubbed."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import tempfile
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
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN), x509.DNSName(f"www.{DOMAIN}")]), False)
            .sign(key, hashes.SHA256())
        )
        self.certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        self.site = self.node.sites / f"{DOMAIN}.conf"
        self.site.write_text(
            f"<VirtualHost *:80>\nServerName {DOMAIN}\nServerAlias www.{DOMAIN}\n</VirtualHost>\n"
            f"<VirtualHost *:443>\nServerName {DOMAIN}\nServerAlias www.{DOMAIN}\nSSLEngine on\n"
            f"SSLCertificateFile {self.certificate}\nSSLCertificateKeyFile {self.key}\n</VirtualHost>\n"
        )

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
        selected = [words[1:] for line in conf.splitlines() if (words := shlex.split(line))
                    and words[0].lower() in {"servername", "serveralias"}]
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
        self.node.execute = Mock(side_effect=lambda argv: f"HTTP/1.1 200 OK\nX-Praho-Bridge: {BRIDGE_ID}\n"
                                 if "--dump-header" in argv else BRIDGE_ID)
        self.node.verify(BRIDGE_ID)
        calls = self.node.execute.call_args_list
        self.assertEqual(len(calls), 6)
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
        record = {"enabled": [{"name": DOMAIN, "enabled": True}, {"name": child, "enabled": False}],
                  "accounts": [], "databases": [], "has_crontab": True,
                  "active_sha": hashlib.sha256(cron.encode()).hexdigest(),
                  "crontab_sha": hashlib.sha256(cron.encode().rstrip(b"\n")).hexdigest()}

        def target(argv):
            nonlocal target_cron
            self.commands.append(argv)
            if argv[:2] == ["virtualmin", "list-domains"]:
                if "--disabled" in argv:
                    return "\n".join(sorted(disabled))
                return "1001" if "--id-only" in argv else "shop"
            if argv[:2] == ["virtualmin", "enable-domain"]:
                disabled.clear()
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
        record = {"enabled": [{"name": DOMAIN, "enabled": True}], "accounts": [], "databases": [],
                  "has_crontab": False, "active_sha": hashlib.sha256(b"").hexdigest()}
        with self.assertRaisesRegex(ValueError, "owner"):
            self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", record)
        self.assertEqual(self.node.execute.call_count, 1)

    def stage_original_cron(self, cron: str = "*/5 * * * * /bin/true\n") -> dict:
        self.node.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        incoming = self.node.directory(BRIDGE_ID) / "activation.incoming"
        incoming.write_text(cron)
        incoming.chmod(0o600)
        record = {"enabled": [{"name": DOMAIN, "enabled": True}], "accounts": [], "databases": [],
                  "has_crontab": True, "crontab_sha": hashlib.sha256(cron.encode().rstrip(b"\n")).hexdigest(),
                  "active_sha": hashlib.sha256(cron.encode()).hexdigest()}
        self.node.stage_activation(BRIDGE_ID, DOMAIN, "shop", record)
        return record

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
        self.node.execute = Mock(side_effect=lambda argv: f"HTTP/1.1 200 OK\nX-Praho-Bridge: {BRIDGE_ID}\n"
                                 if "--dump-header" in argv else BRIDGE_ID)
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
        self.assertIn(["virtualmin", "list-domains", "--name-only"], [call.args[0] for call in self.node.execute.call_args_list])

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
