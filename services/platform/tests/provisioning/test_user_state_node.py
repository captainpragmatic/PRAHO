"""Private user snapshots preserve originals without exporting credential fingerprints."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase

SCRIPT = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho_user_state.py"
PERL = SCRIPT.with_name("praho-user-state.pl")
spec = importlib.util.spec_from_file_location("user_state_node", SCRIPT)
assert spec is not None and spec.loader is not None
node = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = node
spec.loader.exec_module(node)

PASSWORD = "$6$private-canary$credential-for-this-test-only"
CRON = b"MAILTO=private-cron-canary\n@daily echo private-command-canary\n"
AGING = {"change": "20500", "min": "2", "max": "80", "warn": "8", "inactive": "40", "expire": "20900", "flag": ""}


def state(*, password=PASSWORD, present=True, content=CRON):
    return {
        "password": password,
        "aging": dict(AGING),
        "shell": "/bin/bash",
        "mail_enabled": True,
        "cron": {"present": present, "content_b64": base64.b64encode(content).decode()},
    }


def snapshot_document():
    operation = str(uuid4())
    identity = {
        "operation_id": operation,
        "archive_name": f"migration_{operation}.tar.gz",
        "domain": "customer.example",
        "domain_id": "123",
        "owner": "customer",
    }
    original = state()
    return {
        "version": 1,
        "identity": identity,
        "phase": "captured",
        "domains": [{"domain": "customer.example", "domain_id": "123", "parent_id": None, "home": "/home/customer"}],
        "users": [
            {
                "login": "customer",
                "canonical_login": "customer",
                "role": "owner",
                "domain_id": "123",
                "uid": 1001,
                "gid": 1001,
                "home": "/home/customer",
                "states": {"original": original, "frozen": None},
            },
            {
                "login": "reader@customer.example",
                "canonical_login": "reader@customer.example",
                "role": "mailbox",
                "domain_id": "123",
                "uid": 1002,
                "gid": 1001,
                "home": "/home/customer/homes/reader",
                "states": {"original": state(password="!!" + PASSWORD), "frozen": None},
            },
            {
                "login": "reader-customer.example",
                "canonical_login": "reader@customer.example",
                "role": "companion",
                "domain_id": "123",
                "uid": 1002,
                "gid": 1001,
                "home": "/home/customer/homes/reader",
                "states": {"original": state(present=False, content=b""), "frozen": None},
            },
            {
                "login": "web-manager",
                "canonical_login": "web-manager",
                "role": "web",
                "domain_id": "123",
                "uid": 1001,
                "gid": 1001,
                "home": "/home/customer/public_html/private",
                "states": {"original": state(present=True, content=b""), "frozen": None},
            },
        ],
    }


def frozen_document(document):
    frozen = copy.deepcopy(document)
    frozen["phase"] = "frozen"
    for user in frozen["users"]:
        user["states"]["frozen"] = state(password="!" + user["states"]["original"]["password"], content=b"# held\n")
    return frozen


class SnapshotFixture(SimpleTestCase):
    def setUp(self):
        self.document = snapshot_document()
        self.identity = node.SnapshotIdentity(**self.document["identity"])

    def decode(self, document=None):
        return node.decode_snapshot(json.dumps(document or self.document).encode(), expected=self.identity)


class UserStateSchemaTests(SnapshotFixture):
    def test_disabled_empty_password_child_and_frozen_aging_are_preserved_exactly(self):
        document = copy.deepcopy(self.document)
        document["domains"].append(
            {
                "domain": "owned-child.example",
                "domain_id": "124",
                "parent_id": "123",
                "home": "/home/customer/domains/owned-child.example",
            }
        )
        document["users"].append(
            {
                "login": "child-ftp",
                "canonical_login": "child-ftp",
                "role": "ftp",
                "domain_id": "124",
                "uid": 1003,
                "gid": 1001,
                "home": "/home/customer/domains/owned-child.example/homes/ftp",
                "states": {
                    "original": state(password="", content=b"# exact non-UTF8 cron comment: \xff\n"),
                    "frozen": None,
                },
            }
        )
        document["users"][0]["states"]["original"]["password"] = "*"
        frozen = frozen_document(document)
        frozen["users"][0]["states"]["frozen"]["aging"]["expire"] = "1"
        frozen["users"][0]["states"]["frozen"]["mail_enabled"] = False
        self.assertEqual(json.loads(self.decode(document).private_bytes()), document)
        self.assertEqual(json.loads(self.decode(frozen).private_bytes()), frozen)

    def test_non_scalar_fields_and_surrogate_credentials_refuse_with_fixed_errors(self):
        for field, value in (("role", []), ("role", {}), ("home", "/home/customer/\nprivate")):
            with self.subTest(field=field, kind=type(value).__name__):
                document = copy.deepcopy(self.document)
                document["users"][0][field] = value
                with self.assertRaises(node.UserStateError):
                    self.decode(document)
        document = copy.deepcopy(self.document)
        document["users"][0]["states"]["original"]["password"] = "\ud800private-canary"
        with self.assertRaises(node.UserStateError):
            self.decode(document)
        self.assertEqual(str(node.UserStateError(PASSWORD)), "invalid_user_state")

    def test_constructed_snapshot_cannot_export_a_private_digest_as_public_roster(self):
        snapshot = self.decode()
        nonce = str(uuid4())
        forged = replace(snapshot, _roster=PASSWORD.encode(), _user_count=999)
        self.assertEqual(node.public_projection(forged, nonce=nonce), node.public_projection(snapshot, nonce=nonce))

    def test_exact_credentials_aging_and_each_login_cron_survive_private_roundtrip(self):
        snapshot = self.decode()
        self.assertEqual(json.loads(snapshot.private_bytes()), self.document)
        self.assertNotIn(PASSWORD, repr(snapshot))
        self.assertEqual(len(json.loads(snapshot.private_bytes())["users"]), 4)
        self.assertEqual(self.decode(frozen_document(self.document)).phase, "frozen")

    def test_public_roster_and_receipt_do_not_depend_on_any_private_state(self):
        nonce = str(uuid4())
        first = self.decode()
        changed = copy.deepcopy(self.document)
        for user in changed["users"]:
            user["states"]["original"] = state(password="*private-other-canary", content=b"# another secret\n")
            user["states"]["original"]["aging"]["expire"] = "1"
            user["states"]["original"]["mail_enabled"] = False
        public = node.public_projection(first, nonce=nonce)
        self.assertEqual(public, node.public_projection(self.decode(changed), nonce=nonce))
        self.assertEqual(public["user_count"], 4)
        self.assertEqual(public["uid_count"], 2)
        encoded = json.dumps(public)
        for secret in (PASSWORD, "!!" + PASSWORD, CRON.decode(), json.dumps(AGING), first.private_bytes().decode()):
            self.assertNotIn(secret, encoded)
            self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(), encoded)
        self.assertEqual(
            set(public), {"version", "action", "nonce", "identity", "phase", "user_count", "uid_count", "roster_sha256"}
        )

    def test_public_request_returns_only_action_nonce_bound_projection(self):
        nonce = str(uuid4())
        request = {
            "action": "project",
            "nonce": nonce,
            "expected": self.document["identity"],
            "snapshot": self.document,
        }
        receipt = node.project_request(json.dumps(request).encode())
        self.assertTrue(receipt.startswith("USER_STATE_RESULT="))
        result = json.loads(base64.b64decode(receipt.partition("=")[2], validate=True))
        self.assertEqual(result, node.public_projection(self.decode(), nonce=nonce))
        request["action"] = "activate"
        with self.assertRaisesRegex(node.UserStateError, "invalid_action"):
            node.project_request(json.dumps(request).encode())

    def test_different_archive_operation_or_source_identity_cannot_adopt_snapshot(self):
        for key, value in (
            ("operation_id", str(uuid4())),
            ("archive_name", "virtualmin_backup_" + "a" * 32 + ".tar.gz"),
            ("domain_id", "456"),
            ("owner", "other"),
        ):
            with self.subTest(field=key):
                changed = copy.deepcopy(self.document)
                changed["identity"][key] = value
                with self.assertRaises(node.UserStateError):
                    self.decode(changed)

    def test_duplicate_unknown_and_oversized_data_refuse_without_echoing_content(self):
        encoded = json.dumps(self.document).encode()
        for payload in (b'{"version":1,"version":1}', b"{" + PASSWORD.encode(), b" " * (node.MAX_SNAPSHOT_BYTES + 1)):
            with self.subTest(size=len(payload)), self.assertRaises(node.UserStateError) as failure:
                node.decode_snapshot(payload, expected=self.identity)
            self.assertNotIn(PASSWORD, str(failure.exception))
        changed = copy.deepcopy(self.document)
        changed["password_hash"] = PASSWORD
        with self.assertRaises(node.UserStateError):
            self.decode(changed)
        self.assertGreater(len(encoded), 0)

    def test_invalid_aging_cron_and_unowned_identity_values_refuse(self):
        changes = (
            lambda d: d["users"][0]["states"]["original"]["aging"].update(flag="reserved"),
            lambda d: d["users"][0]["states"]["original"]["aging"].update(expire=-1),
            lambda d: d["users"][0]["states"]["original"]["cron"].update(present=False),
            lambda d: d["users"][0]["states"]["original"]["cron"].update(content_b64="bad$$"),
            lambda d: d["users"][0].update(uid=True),
            lambda d: d["users"][0].update(home="/home/foreign"),
            lambda d: d["users"][0].update(domain_id="999"),
            lambda d: d["users"][1].update(role="plugin"),
            lambda d: d["users"][1].update(uid=1001),
            lambda d: d["users"][2].update(canonical_login="foreign@elsewhere.example"),
            lambda d: d["users"].append(copy.deepcopy(d["users"][0])),
            lambda d: d["domains"].append(copy.deepcopy(d["domains"][0])),
        )
        for index, change in enumerate(changes):
            with self.subTest(change=index):
                changed = copy.deepcopy(self.document)
                change(changed)
                with self.assertRaises(node.UserStateError):
                    self.decode(changed)

    def test_frozen_profiles_require_every_actual_login_locked_and_no_runnable_cron(self):
        for field, value in (("password", PASSWORD), ("cron", state()["cron"])):
            with self.subTest(field=field):
                changed = frozen_document(self.document)
                changed["users"][2]["states"]["frozen"][field] = value
                with self.assertRaises(node.UserStateError):
                    self.decode(changed)


class UserStateStorageTests(SnapshotFixture):
    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "private"
        self.store = node.SnapshotStore(self.root)

    def path(self, phase="captured"):
        return self.root / self.identity.domain_id / self.identity.operation_id / f"{phase}.json"

    def test_store_creation_flushes_its_parent_before_a_snapshot_can_be_used(self):
        new_root = self.root.parent / "another-private-root"
        actual = node.os.fsync
        flushed = []

        def sync(descriptor):
            flushed.append(os.fstat(descriptor).st_ino)
            actual(descriptor)

        with patch.object(node.os, "fsync", side_effect=sync):
            node.SnapshotStore(new_root)
        self.assertIn(new_root.parent.stat().st_ino, flushed)

    def test_constructed_snapshot_cannot_persist_unvalidated_private_bytes(self):
        forged = replace(self.decode(), _encoded=PASSWORD.encode())
        with self.assertRaises(node.UserStateError):
            self.store.save(forged)
        self.assertFalse(self.path().exists())

    def test_ready_and_retry_proofs_flush_file_then_directory_without_changing_original(self):
        snapshot = self.decode()
        actual = node.os.fsync
        flushed = []

        def sync(descriptor):
            kind = "file" if stat.S_ISREG(os.fstat(descriptor).st_mode) else "directory"
            flushed.append(kind)
            if kind == "directory" and flushed[-2:] == ["file", "directory"]:
                raise OSError("owned simulated durability failure")
            actual(descriptor)

        with patch.object(node.os, "fsync", side_effect=sync), self.assertRaises(node.UserStateError):
            self.store.save(snapshot)
        self.assertEqual(self.path().read_bytes(), snapshot.private_bytes())
        before = self.path().stat()
        flushed.clear()

        def retry_sync(descriptor):
            flushed.append("file" if stat.S_ISREG(os.fstat(descriptor).st_mode) else "directory")
            actual(descriptor)

        with patch.object(node.os, "fsync", side_effect=retry_sync):
            self.assertFalse(self.store.save(snapshot))
        self.assertEqual(flushed[-2:], ["file", "directory"])
        self.assertEqual(self.path().stat().st_mtime_ns, before.st_mtime_ns)

    def test_nonregular_snapshot_refuses_instead_of_waiting_for_a_fifo_writer(self):
        self.store.save(self.decode())
        self.path().unlink()
        os.mkfifo(self.path(), 0o600)
        program = """import importlib.util,json,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('private_user_state',sys.argv[1]);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
try:m.SnapshotStore(Path(sys.argv[2])).load(m.SnapshotIdentity(**json.loads(sys.argv[3])),'captured')
except m.UserStateError:raise SystemExit(0)
raise SystemExit(2)
"""
        result = subprocess.run(  # noqa: S603 -- fixed Python script and this test's owned private fixture.
            [sys.executable, "-c", program, str(SCRIPT), str(self.root), json.dumps(self.document["identity"])],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        self.assertEqual(result.returncode, 0)

    def test_save_is_private_durable_identity_immutable_and_exact_replay_is_read_only(self):
        snapshot = self.decode()
        self.assertTrue(self.store.save(snapshot))
        before = self.path().stat()
        self.assertFalse(self.store.save(snapshot))
        after = self.path().stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o600)
        self.assertEqual(self.store.load(self.identity, "captured").private_bytes(), snapshot.private_bytes())
        changed = copy.deepcopy(self.document)
        changed["users"][0]["states"]["original"]["password"] = "changed-private-canary"
        with self.assertRaisesRegex(node.UserStateError, "immutable_snapshot"):
            self.store.save(self.decode(changed))
        self.assertEqual(self.path().read_bytes(), snapshot.private_bytes())

    def test_frozen_state_never_replaces_or_changes_the_original_snapshot(self):
        frozen = self.decode(frozen_document(self.document))
        with self.assertRaises(node.UserStateError):
            self.store.save(frozen)
        original = self.decode()
        self.store.save(original)
        self.assertTrue(self.store.save(frozen))
        self.assertEqual(self.path().read_bytes(), original.private_bytes())
        changed = frozen_document(self.document)
        changed["users"][0]["states"]["original"]["aging"]["expire"] = "2"
        with self.assertRaises(node.UserStateError):
            self.store.save(self.decode(changed))

    def test_unowned_modes_symlinks_hardlinks_and_foreign_root_refuse(self):
        self.store.save(self.decode())
        self.path().chmod(0o640)
        with self.assertRaises(node.UserStateError):
            self.store.load(self.identity, "captured")
        self.path().chmod(0o600)
        other = self.path().with_name("foreign.json")
        os.link(self.path(), other)
        with self.assertRaises(node.UserStateError):
            self.store.load(self.identity, "captured")
        other.unlink()
        self.path().unlink()
        self.path().symlink_to(other)
        with self.assertRaises(node.UserStateError):
            self.store.load(self.identity, "captured")
        self.root.chmod(0o750)
        with self.assertRaises(node.UserStateError):
            node.SnapshotStore(self.root)
        self.root.chmod(0o700)
        with patch.object(node.os, "geteuid", return_value=os.geteuid() + 1), self.assertRaises(node.UserStateError):
            node.SnapshotStore(self.root)

    def test_symlinked_scope_directory_cannot_redirect_a_private_write(self):
        foreign = self.root.parent / "foreign"
        foreign.mkdir(mode=0o700)
        (self.root / self.identity.domain_id).symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(node.UserStateError):
            self.store.save(self.decode())
        self.assertEqual(list(foreign.iterdir()), [])


class UserStatePerlBoundaryTests(SimpleTestCase):
    def test_perl_projection_entrypoint_refuses_an_unowned_unstaged_source_tree(self):
        result = subprocess.run(  # noqa: S603 -- fixed read-only adapter, no caller-selected executable.
            ["/usr/bin/perl", str(PERL), "project"], input=PASSWORD, capture_output=True, text=True, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("USER_STATE_RESULT=", result.stdout)
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        self.assertIn("USER_STATE_ERROR=", result.stderr)
