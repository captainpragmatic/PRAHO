"""Selected native paths exclude mail, escaped links, shared inodes and open writers."""

import importlib.util
import os
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

HELPER = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-paths.py"


class ComponentPathScopeTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        spec = importlib.util.spec_from_file_location("component_paths", HELPER)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name).resolve()
        (self.home / "public_html").mkdir()
        (self.home / "Maildir").mkdir()
        (self.home / "public_html/app.php").write_text("website")
        (self.home / "Maildir/message").write_text("retained private message")

    def test_only_selected_content_is_counted_and_included(self):
        scope = self.module.scan_paths(self.home, ("public_html",))
        self.assertEqual(scope["bytes"], len("website"))
        self.assertEqual(scope["files"], ("public_html/app.php",))
        self.assertEqual(len(scope["tree_digest"]), 64)
        self.assertNotIn("Maildir/message", scope["files"])

    def test_link_into_retained_mail_is_refused(self):
        for hard in (False, True):
            alias = self.home / "public_html/mail-link"
            if hard:
                os.link(self.home / "Maildir/message", alias)
            else:
                alias.symlink_to("../Maildir/message")
            with self.subTest(hard=hard), self.assertRaisesRegex(ValueError, "outside|shared"):
                self.module.scan_paths(self.home, ("public_html",))
            alias.unlink()

    def test_internal_links_and_hardlinks_within_selected_scope_are_preserved(self):
        (self.home / "public_html/current").symlink_to("app.php")
        os.link(self.home / "public_html/app.php", self.home / "public_html/hardlink")
        scope = self.module.scan_paths(self.home, ("public_html",))
        self.assertEqual(scope["bytes"], len("website"))
        self.assertEqual(set(scope["files"]), {"public_html/app.php", "public_html/current", "public_html/hardlink"})

    def test_entire_home_traversal_and_reserved_roots_are_refused(self):
        for selected in (".", "Maildir", "../outside", "public_html/../Maildir", "/etc", ".ssh"):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                self.module.scan_paths(self.home, (selected,))

    def test_scope_detects_preopened_selected_file_even_after_rename(self):
        path = self.home / "public_html/app.php"
        with path.open("ab") as opened:
            info = os.fstat(opened.fileno())
            scope = self.module.scan_paths(self.home, ("public_html",))
            path.rename(self.home / "public_html/renamed.php")
            self.assertIn((info.st_dev, info.st_ino), scope["inodes"])
            self.assertNotIn(
                (self.home / "Maildir/message").stat().st_ino, {inode for _device, inode in scope["inodes"]}
            )

    def test_nested_selected_roots_and_symlinked_ancestors_are_refused(self):
        (self.home / "public_html/uploads").mkdir()
        with self.assertRaises(ValueError):
            self.module.scan_paths(self.home, ("public_html", "public_html/uploads"))
        (self.home / "application").symlink_to("public_html", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.module.scan_paths(self.home, ("application/uploads",))
