"""Source cleanup removes only a captured inode closure through private quarantine."""

import importlib.util
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class ComponentFileRetirementTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-file-retire.py"
        spec = importlib.util.spec_from_file_location("component_file_retire", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name).resolve()
        self.home = self.base / "home"
        self.home.mkdir(mode=0o755)
        self.selected = self.home / "public_html"
        self.selected.mkdir()
        (self.selected / "nested").mkdir()
        (self.selected / "nested/app.php").write_text("selected application")
        (self.selected / "index.php").write_text("selected entrypoint")
        (self.home / "Maildir").mkdir()
        self.mail = self.home / "Maildir/retained-message"
        self.mail.write_text("retained mail must survive")
        self.home_identity = self.home.stat()
        self.mail_identity = self.mail.stat()
        self.operation, self.boot = str(uuid4()), str(uuid4())
        self.options = {"state_dir": self.base / "state", "owner_uid": os.geteuid(), "boot_id": self.boot}
        self.quarantine = self.base / "quarantine"

    def capture(self):
        return self.module.capture(self.home, ("public_html",), "123456789", self.operation, "a" * 64, **self.options)

    def retire(self, receipt):
        return self.module.retire(receipt, quarantine_dir=self.quarantine, **self.options)

    def assert_mail_untouched(self):
        self.assertEqual(self.mail.read_text(), "retained mail must survive")
        self.assertEqual(
            (self.mail.stat().st_ino, self.mail.stat().st_mode), (self.mail_identity.st_ino, self.mail_identity.st_mode)
        )
        self.assertEqual(
            (self.home.stat().st_ino, self.home.stat().st_mode), (self.home_identity.st_ino, self.home_identity.st_mode)
        )

    def test_exact_captured_tree_is_retired_without_changing_home_or_mail(self):
        (self.selected / "entry-link").symlink_to("index.php")
        os.link(self.selected / "index.php", self.selected / "second-entry.php")
        receipt = self.capture()
        self.assertLess(len(str(receipt)), 2048)
        self.assertTrue(Path(receipt["capture_path"]).is_file())
        result = self.retire(receipt)
        self.assertEqual(result["phase"], "retired")
        self.assertFalse(self.selected.exists())
        self.assert_mail_untouched()
        self.assertEqual(self.retire(receipt), result)

    def test_changed_root_or_added_child_refuses_before_any_namespace_move(self):
        receipt = self.capture()
        (self.selected / "unreviewed-new-file").write_text("do not delete")
        with self.assertRaisesRegex(ValueError, "changed|capture|closure"):
            self.retire(receipt)
        self.assertEqual((self.selected / "unreviewed-new-file").read_text(), "do not delete")
        self.assert_mail_untouched()

    def test_root_symlink_substitution_never_follows_retained_mail(self):
        receipt = self.capture()
        self.selected.rename(self.home / "original-website")
        self.selected.symlink_to("Maildir", target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.retire(receipt)
        self.assertTrue(self.selected.is_symlink())
        self.assert_mail_untouched()

    def test_foreign_root_racing_the_atomic_rename_is_quarantined_but_never_deleted(self):
        receipt = self.capture()
        original = self.module._rename

        def swapped(*args, **kwargs):
            self.selected.rename(self.home / "saved-website")
            self.selected.mkdir()
            (self.selected / "foreign-data").write_text("preserve unexpected inode")
            return original(*args, **kwargs)

        with patch.object(self.module, "_rename", side_effect=swapped), self.assertRaises((ValueError, OSError)):
            self.retire(receipt)
        foreign = self.quarantine / self.operation / "root-000000/foreign-data"
        self.assertEqual(foreign.read_text(), "preserve unexpected inode")
        self.assertEqual((self.home / "saved-website/index.php").read_text(), "selected entrypoint")
        self.assert_mail_untouched()

    def test_new_quarantine_entry_is_not_chmod_chowned_or_deleted(self):
        receipt = self.capture()
        descriptor = os.open(self.selected, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        original = self.module._rename
        identity = {}

        def inserted(*args, **kwargs):
            result = original(*args, **kwargs)
            fd = os.open("foreign-data", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640, dir_fd=descriptor)
            os.write(fd, b"preserved late entry")
            identity["stat"] = os.fstat(fd)
            os.close(fd)
            return result

        with (
            patch.object(self.module, "_rename", side_effect=inserted),
            self.assertRaisesRegex(ValueError, "changed|closure"),
        ):
            self.retire(receipt)
        foreign = self.quarantine / self.operation / "root-000000/foreign-data"
        self.assertEqual(foreign.read_text(), "preserved late entry")
        self.assertEqual(
            (foreign.stat().st_uid, foreign.stat().st_mode), (identity["stat"].st_uid, identity["stat"].st_mode)
        )
        self.assert_mail_untouched()

    def test_interrupted_deletion_never_replays_or_adopts_missing_names(self):
        receipt = self.capture()
        original = self.module._unlink

        def interrupted(*args, **kwargs):
            original(*args, **kwargs)
            raise TimeoutError("Lost deletion completion")

        with patch.object(self.module, "_unlink", side_effect=interrupted), self.assertRaises(TimeoutError):
            self.retire(receipt)
        with patch.object(self.module, "_unlink") as unlink, self.assertRaisesRegex(ValueError, "interrupted"):
            self.retire(receipt)
        unlink.assert_not_called()
        self.assert_mail_untouched()

    def test_completed_receipt_cannot_delete_a_reused_source_namespace(self):
        receipt = self.capture()
        self.retire(receipt)
        self.selected.mkdir()
        (self.selected / "new-website").write_text("a different website")
        with self.assertRaisesRegex(ValueError, "reused|changed"):
            self.retire(receipt)
        self.assertEqual((self.selected / "new-website").read_text(), "a different website")
        self.assert_mail_untouched()
