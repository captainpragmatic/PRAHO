"""Only an independently prepared website schedule may move; retained owner jobs stay untouched."""

import hashlib
import importlib.util
import tempfile
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class ComponentCronFenceTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-cron-fence.py"
        spec = importlib.util.spec_from_file_location("component_cron_fence", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cron = self.root / "cron.d"
        self.cron.mkdir()
        self.path = self.cron / "praho-component-123456789"
        self.line = "*/5 * * * * /usr/bin/php /home/customer/public_html/job.php"
        self.original = (
            "# Dedicated website schedule\n*/5 * * * * customer /usr/bin/php /home/customer/public_html/job.php\n"
        )
        self.path.write_text(self.original)
        self.path.chmod(0o644)
        self.operation = str(uuid4())
        self.boot_id = str(uuid4())

    def fence(self, operation=None):
        return self.module.CronFileFence(
            "123456789",
            operation or self.operation,
            "customer",
            (hashlib.sha256(self.line.encode()).hexdigest(),),
            cron_dir=self.cron,
            state_dir=self.root / "receipts",
            boot_id=self.boot_id,
        )

    def test_only_the_exact_reviewed_website_schedule_is_removed_and_restored(self):
        retained = self.cron / "retained-mail"
        retained.write_text("* * * * * customer /home/customer/Maildir/job\n")
        fence = self.fence()
        self.assertEqual(fence.selected_cron(), (self.line,))
        fence.apply()
        fence.apply()
        fence.verify()
        self.assertFalse(self.path.exists())
        self.assertEqual(retained.read_text(), "* * * * * customer /home/customer/Maildir/job\n")
        self.assertEqual(fence.selected_cron(), (self.line,))
        fence.release()
        fence.release()
        self.assertEqual(self.path.read_text(), self.original)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)

    def test_unreviewed_entries_environment_or_other_owners_need_preparation(self):
        for addition in (
            "* * * * * customer /home/customer/Maildir/job\n",
            "MAILTO=retained@example.test\n",
            "* * * * * other /usr/bin/job\n",
        ):
            self.path.write_text(self.original + addition)
            with self.subTest(addition=addition), self.assertRaises(ValueError):
                self.fence().apply()
            self.assertEqual(self.path.read_text(), self.original + addition)

    def test_committed_schedule_retirement_removes_private_copy_without_restoring_source_jobs(self):
        fence = self.fence()
        fence.apply()
        fence.retire()
        self.assertFalse(self.path.exists())
        self.assertFalse(fence.saved.exists())
        fence.retire()
        with self.assertRaises(ValueError):
            fence.release()

    def test_replaced_schedule_and_other_operation_cannot_be_overwritten_on_release(self):
        fence = self.fence()
        fence.apply()
        self.path.write_text("# Another actor's schedule\n")
        with self.assertRaises(ValueError):
            fence.release()
        self.assertEqual(self.path.read_text(), "# Another actor's schedule\n")
        with self.assertRaises(ValueError):
            self.fence(str(uuid4())).release()

    def test_symlinks_and_lost_receipts_never_authorize_foreign_schedule_restoration(self):
        self.path.unlink()
        self.path.symlink_to(self.root / "retained")
        with self.assertRaises(ValueError):
            self.fence().apply()
        self.path.unlink()
        self.path.write_text(self.original)
        fence = self.fence()
        fence.apply()
        fence.journal.path.unlink()
        with self.assertRaises(ValueError):
            fence.release()
        self.assertFalse(self.path.exists())

    def test_lost_rename_receipt_is_reconciled_from_exact_private_saved_bytes(self):
        fence = self.fence()
        fence.apply()
        with fence.journal.locked():
            state = fence.journal.read()
            self.assertEqual(state["phase"], "held")
            state["phase"] = "removing"
            fence.journal.write(state)
        fence.apply()
        fence.verify()
        fence.release()
        self.assertEqual(self.path.read_text(), self.original)

    def test_lost_compensation_publication_receipt_preserves_exact_owned_schedule(self):
        fence = self.fence()
        fence.apply()
        publish = self.module.os.link

        def lost_receipt(source, destination):
            publish(source, destination)
            raise OSError("Lost the publication response")

        with patch.object(self.module.os, "link", side_effect=lost_receipt), self.assertRaises(OSError):
            fence.release()
        self.assertEqual(self.path.stat().st_ino, fence.saved.stat().st_ino)
        self.assertEqual(self.path.stat().st_nlink, 2)
        fence.release()
        self.assertEqual(self.path.read_text(), self.original)
        self.assertFalse(fence.saved.exists())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o644)

    def test_a_new_attempt_can_fence_after_complete_owned_compensation(self):
        first = self.fence()
        first.apply()
        first.release()
        second = self.fence(str(uuid4()))
        second.apply()
        second.verify()
        with self.assertRaises(ValueError):
            first.release()
        second.release()
        self.assertEqual(self.path.read_text(), self.original)
