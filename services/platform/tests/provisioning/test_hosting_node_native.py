"""Preparation never converts occupied or already configured filesystems."""

import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

from tests.provisioning.test_hosting_node_policy import quota_evidence


class HostingNodeNativeTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho_hosting_node.py"
        spec = importlib.util.spec_from_file_location("hosting_node_native", path)
        cls.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.native)

    def inventory(self, **updates):
        return {
            "owned_new_deployment": True,
            "deployment": "f3dc92d5-0ac1-4de0-b663-f7daab29960a",
            "domains": 0,
            "tenant_homes": 0,
            "tenant_databases": 0,
            "quota_format": "none",
            "filesystem": "ext4",
            "root_filesystem": True,
            **updates,
        }

    def test_bootstrap_requires_owned_empty_brand_new_install(self):
        self.assertTrue(self.native.classic_bootstrap_allowed(self.inventory()))
        for field, value in (
            ("owned_new_deployment", False),
            ("domains", 1),
            ("tenant_homes", 1),
            ("tenant_databases", 1),
            ("quota_format", "native"),
            ("quota_format", "classic"),
            ("filesystem", "xfs"),
            ("root_filesystem", False),
            ("domains", False),
            ("deployment", "unknown"),
        ):
            with self.subTest(field=field, value=value):
                self.assertFalse(self.native.classic_bootstrap_allowed(self.inventory(**{field: value})))

    def test_first_install_guard_precedes_database_or_filesystem_mutation(self):
        playbook = (Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/virtualmin.yml").read_text()
        self.assertLess(
            playbook.index("Refuse occupied or ambiguous first-install nodes"), playbook.index("Download Virtualmin")
        )
        self.assertLess(
            playbook.index("Refuse occupied or ambiguous first-install nodes"),
            playbook.index("Exclude the database writer quota bypass capability"),
        )

    def test_source_only_mail_inventory_survives_an_unavailable_quota_runtime(self):
        notifications = {
            "evidence": {
                "emitters": {"domain_signup": False},
                "operator_alerts_preserved": True,
                "tenant_mail_preserved": True,
            },
            "inventory_digest": "a" * 64,
        }
        with (
            TemporaryDirectory() as directory,
            patch.object(self.native, "INSTALLATION", Path(directory) / "not-installed"),
            patch.object(self.native, "_read", return_value="f3dc92d50ac14de0b663f7daab29960a"),
            patch.object(self.native, "_run", return_value=json.dumps(notifications)) as transport,
            patch.dict("sys.modules", {"praho_quota_native": None}),
        ):
            result = self.native.inspect("a" * 64)
        self.assertEqual(result["quota"], {})
        self.assertEqual(result["notifications"]["emitters"], {"domain_signup": False})
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(transport.call_args.args[0][-1], "inspect")

    def test_fstab_changes_only_exact_root_entry_and_preserves_other_mounts(self):
        original = "# root\nUUID=one / ext4 defaults,errors=remount-ro 0 1\nUUID=two /data ext4 defaults 0 2\n"
        result = self.native.classic_fstab(original)
        self.assertIn("defaults,errors=remount-ro,usrquota,grpquota", result)
        self.assertIn("UUID=two /data ext4 defaults 0 2", result)
        self.assertEqual(self.native.classic_fstab(result), result)
        for original in (
            "UUID=one / xfs defaults 0 1\n",
            "UUID=one / ext4 defaults 0 1\nUUID=two / ext4 defaults 0 1\n",
            "UUID=one / ext4 usrjquota=aquota.user,jqfmt=vfsv0 0 1\n",
        ):
            with self.subTest(original=original), self.assertRaises(ValueError):
                self.native.classic_fstab(original)

    def test_existing_monitor_bypasses_and_master_alert_branch_are_corrected(self):
        fixtures = Path(settings.BASE_DIR) / "tests/fixtures"
        status = (fixtures / "virtualmin_existing_monitor_8_3.pl").read_text()
        ssl = (fixtures / "virtualmin_acme_notification_8_3.pl").read_text()
        patched_status, patched_ssl = self.native.notification_source_patches(status, ssl)
        self.assertEqual(patched_status.count("&monitor_email($d)"), 3)
        self.assertEqual(patched_status.count("# PRAHO customer-mail ownership"), 2)
        self.assertNotIn("= $d->{'emailto'}", patched_status)
        self.assertIn("elsif ($d->{'letsencrypt_email_master'})", patched_ssl)
        self.assertIn("$gconfig{'webmin_email_to'}", patched_ssl)
        self.assertEqual(
            self.native.notification_source_patches(patched_status, patched_ssl), (patched_status, patched_ssl)
        )
        for broken_status, broken_ssl in (
            (status + status, ssl),
            ("new upstream monitor", ssl),
            (status, "new upstream ACME"),
        ):
            with self.subTest(status=broken_status), self.assertRaises(ValueError):
                self.native.notification_source_patches(broken_status, broken_ssl)

    def test_native_emitter_drain_excludes_read_only_lookup_daemon(self):
        self.assertFalse(
            self.native.native_emitter_command(
                b"/usr/bin/perl\0/usr/share/webmin/virtual-server/lookup-domain-daemon.pl\0"
            )
        )
        self.assertFalse(
            self.native.native_emitter_command(b"/usr/bin/python3\0/root/praho-native-mail/mail_acceptance.py\0")
        )
        for command in (
            b"/usr/share/webmin/virtual-server/backup.pl\0--id\0123\0",
            b"/usr/bin/perl\0/usr/share/webmin/virtual-server/future-native-emitter.pl\0",
            b"/usr/bin/perl\0/usr/share/webmin/status/monitor.pl\0--force\0",
            b"/usr/sbin/virtualmin\0modify-domain\0--domain\0fixture.test\0",
        ):
            with self.subTest(command=command):
                self.assertTrue(self.native.native_emitter_command(command))

    def test_requalification_never_turns_historical_boot_into_current_enforcement(self):
        original = quota_evidence()
        original.pop("identity")
        for key in ("bw_auto_disable", "bw_auto_enable", "requalification_required", "qualification_id"):
            original.pop(key)
        current_boot = str(uuid4())
        historical = deepcopy(original)
        inventory = self.native.qualification_inventory(
            original,
            installation=original["installation"],
            filesystem_uuid=original["filesystem_uuid"],
            boot=current_boot,
        )
        self.assertTrue(inventory["requalification_required"])
        self.assertEqual(inventory["boot_id"], current_boot)
        self.assertEqual(inventory["acceptance_id"], original["acceptance_id"])
        self.assertEqual(original, historical)
        for changed in (
            {**original, "installation": str(uuid4())},
            {**original, "filesystem_uuid": str(uuid4())},
            {**original, "acceptance": {}},
            {**original, "acceptance_id": "unknown"},
            {**original, "physical_tables_verified": False},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.native.qualification_inventory(
                    changed,
                    installation=original["installation"],
                    filesystem_uuid=original["filesystem_uuid"],
                    boot=current_boot,
                )

    def test_failed_or_changed_requalification_keeps_original_acceptance(self):
        # Native I/O/kernel boundary doubles exercise publication ordering only;
        # actual UID/GID/PHP denial and cleanup remain mandatory VM gates.
        original = quota_evidence()
        original.pop("identity")
        for key in ("bw_auto_disable", "bw_auto_enable", "requalification_required", "qualification_id"):
            original.pop(key)
        inventory = {**original, "boot_id": str(uuid4()), "requalification_required": True}
        for failure in (OSError("probe failed"), None):
            with self.subTest(failure=failure), TemporaryDirectory() as directory:
                state = Path(directory)
                accepted = state / "native-acceptance.json"
                accepted.write_text(json.dumps(original))
                fs = {"source": "/dev/fixed", "uuid": original["filesystem_uuid"]}
                changed = {**inventory, "boot_id": str(uuid4())}
                with (
                    patch.object(self.native, "STATE", state),
                    patch.object(self.native, "filesystem", return_value=fs),
                    patch.object(self.native, "_read", side_effect=lambda path: path.read_text()),
                    patch.object(self.native, "_write", side_effect=lambda path, value: path.write_text(value)),
                    patch.object(self.native, "inspect", side_effect=[{"quota": inventory}, {"quota": changed}]),
                    patch.object(self.native, "_isolated_requalification_probe", side_effect=failure),
                    self.assertRaises((OSError, ValueError)),
                ):
                    self.native._requalify_quota("a" * 64, 17)
                self.assertEqual(json.loads(accepted.read_text()), original)
                self.assertEqual(json.loads((state / "native-acceptance.initial.json").read_text()), original)

    def test_successful_probe_boundary_publishes_fresh_boot_with_original_provenance(self):
        original = quota_evidence()
        original.pop("identity")
        for key in ("bw_auto_disable", "bw_auto_enable", "requalification_required", "qualification_id"):
            original.pop(key)
        inventory = {**original, "boot_id": str(uuid4()), "requalification_required": True}
        with TemporaryDirectory() as directory:
            state = Path(directory)
            accepted = state / "native-acceptance.json"
            accepted.write_text(json.dumps(original))

            def probe(_fs, descriptor):
                self.assertEqual(descriptor, 17)
                self.assertEqual(json.loads(accepted.read_text()), original)

            with (
                patch.object(self.native, "STATE", state),
                patch.object(
                    self.native,
                    "filesystem",
                    return_value={"source": "/dev/fixed", "uuid": original["filesystem_uuid"]},
                ),
                patch.object(self.native, "_read", side_effect=lambda path: path.read_text()),
                patch.object(self.native, "_write", side_effect=lambda path, value: path.write_text(value)),
                patch.object(self.native, "inspect", return_value={"quota": inventory}),
                patch.object(self.native, "_isolated_requalification_probe", side_effect=probe) as kernel,
            ):
                self.native._requalify_quota("a" * 64, 17)
            fresh = json.loads(accepted.read_text())
            self.assertEqual(fresh["boot_id"], inventory["boot_id"])
            self.assertEqual(fresh["acceptance_id"], original["acceptance_id"])
            self.assertNotEqual(fresh["qualification_id"], original["acceptance_id"])
            self.assertEqual(len(fresh["original_digest"]), 64)
            self.assertEqual(json.loads((state / "native-acceptance.initial.json").read_text()), original)
            kernel.assert_called_once()

    def test_isolated_action_never_calls_domain_policy_or_service_restart_and_fences_duplicates(self):
        token = str(uuid4())
        with TemporaryDirectory() as directory:
            state = Path(directory)
            with (
                patch.object(self.native, "STATE", state),
                patch.object(self.native, "_write", side_effect=lambda path, value: path.write_text(value)),
                patch.object(self.native, "_requalify_quota") as kernel,
                patch.object(self.native, "_run") as command,
                patch.object(self.native, "_notification_apply") as notification,
                patch.object(self.native, "inspect", return_value={"identity": "a" * 64}),
            ):
                result = self.native.perform("requalify", {"identity": "a" * 64, "token": token})
                self.assertEqual(result["fenced_token"], token)
                kernel.assert_called_once()
                command.assert_not_called()
                notification.assert_not_called()
                self.assertFalse((state / "resource-policy").exists())
                self.assertFalse((state / "notification-owner").exists())
                with self.assertRaises(ValueError):
                    self.native.perform("requalify", {"identity": "a" * 64, "token": token})
