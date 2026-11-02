"""Component archives cannot carry mailbox paths, unrelated cron, account sidecars or widened permissions."""

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
from copy import deepcopy
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

from tests.provisioning.test_component_migration_manifest import component_manifest


class ComponentArchiveTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-archive.py"
        spec = importlib.util.spec_from_file_location("component_archive", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        target = helper.with_name("praho-component-target-archive.py")
        spec = importlib.util.spec_from_file_location("component_target_archive", target)
        cls.target = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.target)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.operation_id = str(uuid4())
        self.raw = self.root / "raw.tar.gz"
        self.output = self.root / f"migration_{self.operation_id}.tar.gz"
        self.manifest = component_manifest()
        self.manifest["databases"] = []
        self.manifest["paths"][0]["bytes"] = len(b"selected website") + len(b"root secret")
        self.entries = ("public_html", "public_html/index.php", "public_html/root-private")
        self.cron = "*/5 * * * * /usr/bin/php /home/customer/public_html/job.php"
        self.manifest["writers"].append(
            {"kind": "cron_entry", "identity": "cron-site", "digest": hashlib.sha256(self.cron.encode()).hexdigest()}
        )

    @staticmethod
    def add(bundle, name, data, *, uid=1200, mode=0o640):
        entry = tarfile.TarInfo(name)
        entry.uid = entry.gid = uid
        entry.mode, entry.size = mode, len(data)
        bundle.addfile(entry, io.BytesIO(data))

    def native_archive(  # noqa: PLR0913 -- independent native archive fault-injection dimensions
        self,
        *,
        path="public_html/index.php",
        alias="www.example.test",
        domain_id="123456789",
        extra=None,
        web_directive="",
        logrotate=b"native logrotate policy",
    ):
        inner = io.BytesIO()
        with tarfile.open(fileobj=inner, mode="w") as bundle:
            directory = tarfile.TarInfo("public_html")
            directory.type, directory.uid, directory.gid, directory.mode = tarfile.DIRTYPE, 1200, 1200, 0o750
            bundle.addfile(directory)
            self.add(bundle, path, b"selected website")
            self.add(bundle, "public_html/root-private", b"root secret", uid=0, mode=0o600)
        with tarfile.open(self.raw, "w:gz") as bundle:
            metadata = (
                "id="
                + domain_id
                + "\ndom=example.test\nuser=customer\nunix=1\ndir=1\nweb=1\nssl=0\nlogrotate=1\nmysql=1\nmail=1\ndns=1\nwebmin=1\n"
                + "pass=retained-unix-plaintext\nmysql_user=retained_mail\nmysql_pass=retained-private-password\nmysql_enc_pass=retained-private-hash\n"
                + "disabled_oldmysql=retained-old-hash\nprovision_mysql=retained-remote-provider\n"
                + "postgres_pass=retained-postgres-password\nprovision_postgres=retained-postgres-provider\n"
                + "smtp_cloud=retained-smtp-provider\ndns_cloud_import=retained-dns-provider\nssl_everything=1\n"
            ).encode()
            for name, data in {
                "virtualmin": metadata,
                "virtualmin_admins": b"unrelated administrative identities",
                "virtualmin_users": b"mailbox accounts",
                "virtualmin_plan": b"unreviewed template",
                "unix": b"0 0 * * * /home/customer/Maildir/retained-job\n",
                "unix_url": b"private://old-user-database\n",
                "dir.tar": inner.getvalue(),
                "web": (
                    "<VirtualHost *:80>\nServerName example.test\nServerAlias "
                    + alias
                    + "\n"
                    + web_directive
                    + "\n</VirtualHost>\n"
                ).encode(),
                "web_alog": b"unselected access logs",
                "logrotate": logrotate,
            }.items():
                self.add(bundle, "./example.test_" + name, data)
            if extra is not None:
                self.add(bundle, "./example.test_" + extra, b"unclassified retained service")

    def sanitize(self):
        return self.module.sanitize_component_archive(
            self.raw,
            self.output,
            manifest=self.manifest,
            operation_id=self.operation_id,
            source_uid=1200,
            source_gid=1200,
            selected_cron=(self.cron,),
            database_dumps={},
            private_principals=[],
            expected_entries=self.entries,
        )

    def test_source_configuration_cannot_introduce_privileged_apache_programs(self):
        for directive in (
            'CustomLog "|/usr/bin/source-logger" combined',
            'ErrorLog "|/bin/source-logger"',
            "RewriteMap application prg:/usr/bin/source-map",
            "PerlRequire /root/source-handler.pl",
            'Define SOURCE_LOG "|/usr/bin/source-logger"',
        ):
            with self.subTest(directive=directive):
                self.output.unlink(missing_ok=True)
                self.native_archive(web_directive=directive)
                with self.assertRaises(ValueError):
                    self.sanitize()
                self.assertFalse(self.output.exists())

    def test_native_log_rotation_uses_destination_safe_policy_without_source_scripts(self):
        self.native_archive(logrotate=b"/source/log {\n prerotate\n /usr/bin/source-root-hook\n endscript\n}\n")
        self.sanitize()
        with tarfile.open(self.output) as archive:
            policy = archive.extractfile("example.test_logrotate").read()
        self.assertNotIn(b"source-root-hook", policy)
        self.assertNotIn(b"prerotate", policy)
        self.assertIn(b"weekly", policy)

    def test_only_selected_website_scope_and_original_file_permissions_cross_the_node_boundary(self):
        self.native_archive()
        result = self.sanitize()
        self.assertEqual(result["sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        with tarfile.open(self.output) as bundle:
            names = {member.name for member in bundle}
            self.assertTrue(all(member.uid == member.gid == 0 and member.mode == 0o600 for member in bundle))
            self.assertEqual(
                names,
                {
                    "example.test_" + name
                    for name in ("virtualmin", "dir.tar", "web", "unix", "logrotate", "virtualmin_components")
                },
            )
            self.assertEqual(bundle.extractfile("example.test_unix").read(), (self.cron + "\n").encode())
            metadata = bundle.extractfile("example.test_virtualmin").read()
            self.assertIn(b"mail=0\n", metadata)
            self.assertIn(b"dns=0\n", metadata)
            self.assertIn(b"webmin=0\n", metadata)
            self.assertNotIn(b"retained-private", metadata)
            self.assertNotIn(b"retained-unix-plaintext", metadata)
            self.assertNotIn(b"retained-postgres", metadata)
            self.assertNotIn(b"retained-smtp", metadata)
            self.assertNotIn(b"retained-dns", metadata)
            self.assertNotIn(b"ssl_everything=1", metadata)
            self.assertNotIn(b"retained_mail", metadata)
            self.assertNotIn(b"disabled_oldmysql", metadata)
            self.assertNotIn(b"provision_mysql", metadata)
            private = json.load(bundle.extractfile("example.test_virtualmin_components"))
        self.assertEqual(private["operation_id"], self.operation_id)
        entry = next(row for row in private["files"] if row["relative"] == "public_html/root-private")
        self.assertEqual((entry["uid"], entry["gid"], entry["mode"]), (0, 0, 0o600))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_a_mailbox_member_or_ancillary_web_alias_requires_preparation(self):
        for change in ({"path": "Maildir/message"}, {"alias": "mail.example.test"}):
            self.native_archive(**change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.sanitize()
            self.assertFalse(self.output.exists())

    def test_an_unreviewed_cron_entry_cannot_be_restored_on_the_destination(self):
        self.native_archive()
        self.cron = "0 0 * * * /home/customer/Maildir/retained-job"
        with self.assertRaises(ValueError):
            self.sanitize()
        self.assertFalse(self.output.exists())

    def test_native_identity_and_unknown_service_members_cannot_be_silently_rewritten(self):
        for change in ({"domain_id": "999999"}, {"extra": "mail"}, {"extra": "new_plugin"}):
            self.native_archive(**change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.sanitize()
            self.assertFalse(self.output.exists())

    def test_unapproved_private_database_login_never_enters_the_archive(self):
        self.native_archive()
        with self.assertRaises(ValueError):
            self.module.sanitize_component_archive(
                self.raw,
                self.output,
                manifest=self.manifest,
                operation_id=self.operation_id,
                source_uid=1200,
                source_gid=1200,
                selected_cron=(self.cron,),
                database_dumps={},
                private_principals=[{"user": "retained_mail", "host": "localhost"}],
                expected_entries=self.entries,
            )
        self.assertFalse(self.output.exists())

    def test_missing_empty_files_or_directories_are_detected_against_the_held_filesystem(self):
        self.native_archive()
        self.entries = (*self.entries, "public_html/empty-state")
        with self.assertRaisesRegex(ValueError, "closure"):
            self.sanitize()
        self.assertFalse(self.output.exists())

    def test_target_private_evidence_is_bound_to_checksum_uuid_and_approved_material_scope(self):
        self.native_archive()
        result = self.sanitize()
        private = self.target.read_component_archive(self.output, result["sha256"], self.operation_id, self.manifest)
        self.assertEqual(private["operation_id"], self.operation_id)
        self.assertEqual(private["source_uid"], 1200)
        self.assertEqual({row["relative"] for row in private["files"]}, set(self.entries))
        changed = deepcopy(self.manifest)
        changed["paths"][0]["inode"] += 1
        with self.assertRaises(ValueError):
            self.target.read_component_archive(self.output, result["sha256"], self.operation_id, changed)
        with self.assertRaises(ValueError):
            self.target.read_component_archive(self.output, "0" * 64, self.operation_id, self.manifest)
        with self.assertRaises(ValueError):
            self.target.read_component_archive(self.output, result["sha256"], str(uuid4()), self.manifest)
