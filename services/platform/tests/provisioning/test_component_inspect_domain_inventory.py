"""The retained-domain inventory waits out Webmin's own in-progress writes, and refuses anything else it can't classify (#886).

Webmin's save_domain locks a domain file with `<id>.lock` and writes it through `<id>.webmintmp.<pid>.<n>`, renamed over
the original. Either name beside the domain files means a write is in progress, not an unknown file.
"""

import importlib.util
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase


class RetainedDomainInventoryTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-inspect.py"
        spec = importlib.util.spec_from_file_location("component_source_inventory", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()  # macOS: /var is a symlink, which _fields refuses
        for identifier, owner in (("101", "shop"), ("102", "shop"), ("103", "other")):
            (self.root / identifier).write_text(f"id={identifier}\nuser={owner}\ndom={identifier}.test\nweb=1\n")
        root = patch.object(self.module, "DOMAIN_ROOT", self.root)
        root.start()
        self.addCleanup(root.stop)

    def owned(self):
        return sorted(domain["id"] for domain in self.module._related_domains("shop"))

    def test_the_owners_domains_are_listed(self):
        with patch.object(self.module.time, "sleep") as sleep:
            self.assertEqual(self.owned(), ["101", "102"])
        sleep.assert_not_called()

    def test_a_webmin_lock_that_clears_is_waited_out(self):
        for transient in ("102.lock", "102.webmintmp.4242.0"):
            with self.subTest(transient=transient):
                (self.root / transient).write_text("")

                def write_finishes(_seconds, name=transient):
                    (self.root / name).unlink(missing_ok=True)

                with patch.object(self.module.time, "sleep", side_effect=write_finishes) as sleep:
                    self.assertEqual(self.owned(), ["101", "102"])
                sleep.assert_called_once()

    def test_a_write_that_never_finishes_refuses_as_busy_within_its_bound(self):
        (self.root / "101.lock").write_text("")
        with patch.object(self.module.time, "sleep") as sleep, self.assertRaisesRegex(ValueError, "being written"):
            self.owned()
        self.assertEqual(sleep.call_count, self.module.DOMAIN_WRITE_ATTEMPTS - 1)

    def test_any_other_name_still_refuses_at_once(self):
        for unknown in ("notes.txt", "101.bak", "lock", "abc.lock"):
            with self.subTest(unknown=unknown):
                (self.root / unknown).write_text("")
                with patch.object(self.module.time, "sleep") as sleep, self.assertRaisesRegex(ValueError, "unclassified"):
                    self.owned()
                sleep.assert_not_called()
                (self.root / unknown).unlink()
