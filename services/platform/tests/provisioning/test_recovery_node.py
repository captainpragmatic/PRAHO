"""Held-target archives preserve native credentials and cannot escape bounded feature readers."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.conf import settings
from django.test import SimpleTestCase

from apps.provisioning.virtualmin_backup_service import VirtualminBackupService

SCRIPT = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-recovery.py"
spec = importlib.util.spec_from_file_location("recovery_node", SCRIPT)
assert spec is not None and spec.loader is not None
node = importlib.util.module_from_spec(spec)
spec.loader.exec_module(node)


class RecoveryArchiveTests(SimpleTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.archive = Path(directory.name) / "backup.tar.gz"

    def bundle(self, members):
        with tarfile.open(self.archive, "w:gz") as output:
            for name, content, kind in members:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(content)
                output.addfile(info, io.BytesIO(content))

    def test_reads_only_the_exact_domain_feature_without_extracting_home_files(self):
        cron = b"* * * * * echo customer-cron\n"
        self.bundle(
            [("other.example_unix", b"wrong", tarfile.REGTYPE), ("customer.example_unix", cron, tarfile.REGTYPE)]
        )
        self.assertEqual(node.archive_cron(self.archive, "customer.example"), cron)
        self.assertEqual(list(self.archive.parent.iterdir()), [self.archive])

    def owner_metadata(self, *, archive="backup.tar.gz", bind=True, **changes):
        profile = {
            "version": 1,
            "domain": "customer.example",
            "owner": "customer",
            "source_domain_id": "123",
            "archive": archive,
            "credential_sha256": hashlib.sha256(b"$6$old$archive-hash").hexdigest(),
            "aging": {
                "change": "20500",
                "min": "2",
                "max": "80",
                "warn": "8",
                "inactive": "40",
                "expire": "20900",
                "flag": "",
            },
        }
        profile.update(changes)
        if not bind:
            profile.pop("credential_sha256")
        encoded = base64.b64encode(json.dumps(profile).encode()).decode()
        return (
            "id=123\ndom=customer.example\nuser=customer\nenc_pass=$6$old$archive-hash\n"
            "praho_backup_owner_shadow_v1=" + encoded + "\n"
        ).encode()

    def test_owner_shadow_aging_is_staged_from_the_exact_archive(self):
        self.bundle(
            [
                ("customer.example_unix", b"# original cron\n", tarfile.REGTYPE),
                ("customer.example_virtualmin", self.owner_metadata(), tarfile.REGTYPE),
            ]
        )
        cron, staged = self.archive.parent / "cron", self.archive.parent / "staged.json"
        node.stage_cron(
            self.archive,
            hashlib.sha256(self.archive.read_bytes()).hexdigest(),
            cron,
            staged,
            {"domain": "customer.example", "owner": "customer", "domain_id": "456"},
        )
        self.assertEqual(
            json.loads(staged.read_text())["owner_shadow"],
            {
                "change": "20500",
                "min": "2",
                "max": "80",
                "warn": "8",
                "inactive": "40",
                "expire": "20900",
                "flag": "",
            },
        )

    def test_held_stage_refuses_aging_from_before_a_native_password_change(self):
        mixed = self.owner_metadata() + b"backup_encpass=$6$new$new-password-hash\n"
        self.bundle(
            [
                ("customer.example_unix", b"# original cron\n", tarfile.REGTYPE),
                ("customer.example_virtualmin", mixed, tarfile.REGTYPE),
            ]
        )
        cron, staged = self.archive.parent / "cron", self.archive.parent / "staged.json"
        with self.assertRaisesRegex(ValueError, "credential"):
            node.stage_cron(
                self.archive,
                hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                cron,
                staged,
                {"domain": "customer.example", "owner": "customer", "domain_id": "456"},
            )
        self.assertFalse(cron.exists())
        self.assertFalse(staged.exists())

    def test_numeric_aging_without_credential_binding_remains_unknown(self):
        with self.assertRaisesRegex(ValueError, "aging.*unknown"):
            node.owner_shadow_fields(
                self.owner_metadata(bind=False),
                domain="customer.example",
                owner="customer",
                archive_name=self.archive.name,
            )

    def test_owner_binding_uses_exact_restore_precedence_and_preserves_lock_prefixes(self):
        for extra, selected in (
            (b"backup_encpass=!$6$old$archive-hash\n", "!$6$old$archive-hash"),
            (b"disabled=unix\ndisabled_oldpass=$y$old$original-hash\n", "$y$old$original-hash"),
            (b"backup_encpass=!\ndisabled=unix\ndisabled_oldpass=$y$old$original-hash\n", "!"),
        ):
            with self.subTest(selected_credential=selected[:2]):
                metadata = self.owner_metadata(credential_sha256=hashlib.sha256(selected.encode()).hexdigest()) + extra
                self.assertEqual(node.credential_hash(metadata), selected)
                aging = node.owner_shadow_fields(
                    metadata, domain="customer.example", owner="customer", archive_name=self.archive.name
                )
                self.assertNotIn("credential_sha256", aging)
        with self.assertRaisesRegex(ValueError, "credential"):
            node.owner_shadow_fields(
                self.owner_metadata() + b"backup_encpass=!$6$old$archive-hash\n",
                domain="customer.example",
                owner="customer",
                archive_name=self.archive.name,
            )

    def test_public_backup_verification_never_publishes_mixed_password_and_aging_evidence(self):
        mixed = self.owner_metadata() + b"backup_encpass=$6$new$new-password-hash\n"
        self.bundle([("customer.example_virtualmin", mixed, tarfile.REGTYPE)])
        service = object.__new__(VirtualminBackupService)
        service._update_backup_progress = Mock()
        service._expected_feature_members = Mock(return_value=["virtualmin"])
        metadata = {
            "domain": "customer.example",
            "backup_location": "spool",
            "backup_path": str(self.archive),
            "archive_name": self.archive.name,
            "owner_shadow_owner": "customer",
            "owner_shadow_version": 1,
            "checksum_sha256_remote": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
        }
        with patch("apps.provisioning.virtualmin_backup_service.SettingsService.get_integer_setting", return_value=4):
            result = service._verify_backup_integrity("mixed-backup", metadata)
        self.assertTrue(result.is_err())
        self.assertIn("credential", result.unwrap_err())
        self.assertNotEqual(metadata.get("verification_status"), "passed")

    def test_legacy_unknown_owner_aging_is_held_with_actionable_reason(self):
        self.bundle(
            [
                ("customer.example_unix", b"", tarfile.REGTYPE),
                (
                    "customer.example_virtualmin",
                    b"dom=customer.example\nuser=customer\nenc_pass=$6$old$archive-hash\n",
                    tarfile.REGTYPE,
                ),
            ]
        )
        with self.assertRaisesRegex(ValueError, "owner.*aging.*new backup|owner.*aging.*review"):
            node.stage_cron(
                self.archive,
                hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                self.archive.parent / "cron",
                self.archive.parent / "metadata",
                {"domain": "customer.example", "owner": "customer", "domain_id": "456"},
            )

    def test_owner_aging_wrong_archive_source_owner_or_reserved_flag_is_refused(self):
        invalid = [
            self.owner_metadata(archive="foreign.tar.gz"),
            self.owner_metadata(source_domain_id="999"),
            self.owner_metadata(owner="foreign"),
            self.owner_metadata(aging={"flag": "7"}),
        ]
        for index, metadata in enumerate(invalid):
            with self.subTest(metadata=metadata):
                self.bundle(
                    [
                        ("customer.example_unix", b"", tarfile.REGTYPE),
                        ("customer.example_virtualmin", metadata, tarfile.REGTYPE),
                    ]
                )
                with self.assertRaisesRegex(ValueError, "owner.*aging|owner.*shadow"):
                    node.stage_cron(
                        self.archive,
                        hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                        self.archive.parent / f"cron{index}",
                        self.archive.parent / f"metadata{index}",
                        {"domain": "customer.example", "owner": "customer", "domain_id": "456"},
                    )

    def test_duplicate_traversal_and_link_members_are_refused(self):
        cases = [
            [("customer.example_unix", b"", tarfile.REGTYPE)] * 2,
            [("../../customer.example_unix", b"", tarfile.REGTYPE)],
            [("customer.example_unix", b"", tarfile.SYMTYPE)],
            [("customer.example_unix", b"", tarfile.LNKTYPE)],
            [("customer.example_unix", b"\0malformed", tarfile.REGTYPE)],
            [("customer.example_unix", b"a" * (node.CRON_LIMIT + 1), tarfile.REGTYPE)],
        ]
        for members in cases:
            with self.subTest(members=[item[0] for item in members]):
                self.bundle(members)
                with self.assertRaises(ValueError):
                    node.archive_cron(self.archive, "customer.example")

    def test_suspension_uses_the_native_reversible_marker_and_preserves_environment(self):
        original = b"MAILTO=owner@example.com\n@reboot /home/customer/start\n* * * * * touch /tmp/cron-marker\n"
        disabled = node.suspended_cron(original)
        self.assertTrue(disabled.startswith(b"MAILTO=owner@example.com\n"))
        self.assertIn(b"# @reboot /home/customer/start # VIRTUALMIN DISABLE\n", disabled)
        self.assertIn(b"# * * * * * touch /tmp/cron-marker # VIRTUALMIN DISABLE\n", disabled)
        self.assertEqual(node.suspended_cron(b""), b"")

    def test_credential_selection_uses_the_backups_hash_including_a_disabled_users_original_hash(self):
        for metadata, expected in (
            (b"backup_encpass=$6$old$archive-hash\nenc_pass=$6$new$other\n", "$6$old$archive-hash"),
            (b"disabled=1\ndisabled_oldpass=$y$old$archive-hash\nenc_pass=!\n", "$y$old$archive-hash"),
            (b"backup_encpass=!\nenc_pass=$6$old$archive-hash\n", "!"),
        ):
            with self.subTest(expected=expected):
                self.bundle([("customer.example_virtualmin", metadata, tarfile.REGTYPE)])
                self.assertEqual(node.archive_credentials(self.archive, "customer.example"), expected)

    def test_activation_replay_does_not_overwrite_cron_after_it_becomes_accessible(self):
        marker = self.archive.parent / "activation"
        with patch.object(node, "checked"), patch.object(node, "apply_activation") as apply:
            node.activate_once(marker, {}, self.archive)
            node.activate_once(marker, {}, self.archive)
        self.assertEqual(apply.call_count, 1)

    def test_completed_replay_changes_only_enabled_policy_without_replaying_original_aging(self):
        marker = self.archive.parent / "activation"
        original = {"enabled": True, "owner_shadow": {"expire": "20900"}, "domain_id": "123"}
        with patch.object(node, "checked"), patch.object(node, "apply_activation") as apply:
            node.activate_once(marker, original, self.archive)
            node.activate_once(marker, {**original, "enabled": False}, self.archive)
            with self.assertRaisesRegex(ValueError, "identity"):
                node.activate_once(marker, {**original, "owner_shadow": {"expire": "21000"}}, self.archive)
        self.assertEqual(apply.call_count, 1)

    def test_policy_requires_completed_activation_and_uses_retained_identity_after_secret_cleanup(self):
        identity = "11111111-1111-4111-8111-111111111111"
        surface = {"domain": "customer.example", "owner": "customer", "domain_id": "123"}
        directory = self.archive.parent
        with (
            patch.object(node, "checked"),
            patch.object(node, "run") as run,
            self.assertRaisesRegex(ValueError, "completed"),
        ):
            node.reconcile_policy(directory, identity, surface, False)
        run.assert_not_called()
        (directory / f"{identity}.activation").write_text('{"state":"completed","payload_sha256":"verified"}')
        (directory / f"{identity}.cleaned").write_text(json.dumps(surface))
        proof = {"domain_id": "123", "owner": "customer", "enabled": False}
        response = b"PRAHO_POLICY_RESULT=" + base64.b64encode(json.dumps(proof).encode()) + b"\n"
        with patch.object(node, "checked"), patch.object(node, "run", return_value=response) as run:
            self.assertEqual(node.reconcile_policy(directory, identity, surface, False), proof)
        request = json.loads(run.call_args.kwargs["content"])
        self.assertEqual(
            request,
            {
                **surface,
                "action": "reconcile-policy",
                "enabled": False,
                "operation_id": identity,
                "activation_scope": "recovery",
            },
        )
        self.assertNotIn("owner_shadow", request)
        with (
            patch.object(node, "checked"),
            patch.object(node, "run") as run,
            self.assertRaisesRegex(ValueError, "identity"),
        ):
            node.reconcile_policy(directory, identity, {**surface, "domain_id": "456"}, True)
        run.assert_not_called()

    def test_interrupted_activation_is_not_reapplied(self):
        marker = self.archive.parent / "activation"
        with (
            patch.object(node, "checked"),
            patch.object(node, "apply_activation", side_effect=RuntimeError("crash")),
            self.assertRaises(RuntimeError),
        ):
            node.activate_once(marker, {}, self.archive)
        self.assertEqual(json.loads(marker.read_text())["state"], "applying")
        with (
            patch.object(node, "checked"),
            patch.object(node, "apply_activation") as apply,
            self.assertRaisesRegex(ValueError, "interrupted"),
        ):
            node.activate_once(marker, {}, self.archive)
        apply.assert_not_called()

    def test_suspended_cron_does_not_reactivate_originally_commented_jobs(self):
        original = b"# customer note\n# * * * * * keep-disabled\n# @reboot old # VIRTUALMIN DISABLE\nPATH=/usr/bin\n"
        self.assertEqual(node.suspended_cron(original), original)

    def test_credential_metadata_without_a_hash_is_refused(self):
        for metadata in (b"pass=plaintext-only\n", b"enc_pass=\n", b"enc_pass=not-a-hash\n"):
            with self.subTest(metadata=metadata):
                self.bundle([("customer.example_virtualmin", metadata, tarfile.REGTYPE)])
                with self.assertRaises(ValueError):
                    node.archive_credentials(self.archive, "customer.example")

    def test_native_database_credentials_are_staged_privately_from_exact_archive_metadata(self):
        metadata = (
            self.owner_metadata() + b"pass=original-domain-secret\nmysql_pass=separate-database-secret\n"
            b"mysql_enc_pass=stored-db-auth\ndisabled_oldmysql=saved-db-auth\n"
            b"unrelated_setting=not-a-credential\n"
        )
        self.bundle(
            [
                ("customer.example_unix", b"# original cron\n", tarfile.REGTYPE),
                ("customer.example_virtualmin", metadata, tarfile.REGTYPE),
            ]
        )
        cron, staged = self.archive.parent / "cron", self.archive.parent / "staged.json"
        surface = {"domain": "customer.example", "owner": "customer", "domain_id": "123"}
        node.stage_cron(self.archive, hashlib.sha256(self.archive.read_bytes()).hexdigest(), cron, staged, surface)
        payload = json.loads(staged.read_text())
        self.assertEqual(
            payload["native_credentials"],
            {
                "pass": "original-domain-secret",
                "mysql_pass": "separate-database-secret",
                "mysql_enc_pass": "stored-db-auth",
                "disabled_oldmysql": "saved-db-auth",
            },
        )
        self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
        self.assertNotIn("unrelated_setting", payload["native_credentials"])

    def test_absent_native_database_credentials_clear_placeholder_fields(self):
        credentials = node.native_credentials(
            b"dom=customer.example\nuser=customer\nenc_pass=$6$old$archive-hash\n",
            domain="customer.example",
            owner="customer",
        )
        self.assertEqual(credentials, {"pass": "", "mysql_pass": "", "mysql_enc_pass": "", "disabled_oldmysql": ""})

    def test_cleanup_removes_only_this_uuids_sensitive_artifacts_and_keeps_activation_marker(self):
        identity = "11111111-1111-4111-8111-111111111111"
        directory = self.archive.parent
        staging = directory / "staging"
        staging.mkdir()
        surface = {"domain": "customer.example", "owner": "customer", "domain_id": "123"}
        for suffix, content in (
            ("cron", b"secret cron"),
            ("json", json.dumps(surface).encode()),
            ("activation", b'{"state":"completed"}'),
        ):
            (directory / f"{identity}.{suffix}").write_bytes(content)
        derivative = staging / f"recovery-ssl-{identity}-base.tar.gz"
        derivative.write_bytes(b"sensitive cert")
        foreign = staging / "recovery-ssl-22222222-2222-4222-8222-222222222222-base.tar.gz"
        foreign.write_bytes(b"keep")
        with patch.object(node, "checked"):
            node.cleanup_staged(directory, staging, identity, surface)
            node.cleanup_staged(directory, staging, identity, surface)
        self.assertFalse((directory / f"{identity}.cron").exists())
        self.assertFalse((directory / f"{identity}.json").exists())
        self.assertFalse(derivative.exists())
        self.assertTrue(foreign.exists())
        self.assertTrue((directory / f"{identity}.activation").exists())
        with patch.object(node, "checked"), self.assertRaisesRegex(ValueError, "cleaned"):
            node.require_open_identity(directory, identity, surface)

    def test_held_verification_uses_native_disabled_shadow_check_and_rejects_active_cron(self):
        surface = {"domain": "customer.example", "owner": "customer", "domain_id": "123"}
        with patch.object(node, "checked"), patch.object(node, "run", return_value=b"# note\n") as run:
            node.verify_held(surface)
        payload = json.loads(run.call_args_list[0].kwargs["content"])
        self.assertEqual(payload["action"], "verify-held")
        with (
            patch.object(node, "checked"),
            patch.object(node, "run", side_effect=[b"proof", b"* * * * * /bin/true\n"]),
            self.assertRaisesRegex(ValueError, "cron"),
        ):
            node.verify_held(surface)
