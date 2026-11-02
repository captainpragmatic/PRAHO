"""An owned website ingress hold leaves native backup metadata and retained names untouched."""

import hashlib
import importlib.util
import tempfile
from pathlib import Path
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class ComponentWebFenceTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-web-fence.py"
        spec = importlib.util.spec_from_file_location("component_web_fence", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.operation = str(uuid4())
        self.boot = str(uuid4())
        self.site = self.root / "etc/apache2/sites-available/example.test.conf"
        self.site.parent.mkdir(parents=True)
        (self.root / "etc/apache2/conf-enabled").mkdir()
        domains = self.root / "etc/webmin/virtual-server/domains"
        domains.mkdir(parents=True)
        (domains / "123456789").write_text("id=123456789\ndom=example.test\nweb=1\nssl=1\n")
        self.original = "<VirtualHost 127.0.0.1:80>\nServerName example.test\nServerAlias www.example.test mail.example.test webmail.example.test\nDocumentRoot /home/customer/public_html\n</VirtualHost>\n"
        self.site.write_text(self.original)
        self.path = self.root / "etc/apache2/conf-enabled/praho-z-component-123456789.conf"
        self.commands = []

    def execute(self, arguments):
        self.commands.append(arguments)
        if arguments[0] == "curl":
            return (
                "HTTP/1.1 503 Service Unavailable\r\nX-PRAHO-Component-Hold: " + self.operation + "\r\n"
                if self.path.exists()
                else "HTTP/1.1 200 OK\r\n"
            )
        return ""

    def fence(self, operation=None):
        return self.module.WebIngressFence(
            "123456789",
            operation or self.operation,
            "example.test",
            ("example.test", "www.example.test"),
            hashlib.sha256(self.original.encode()).hexdigest(),
            root=self.root,
            boot_id=self.boot,
            execute=self.execute,
        )

    def test_holds_only_approved_names_without_modifying_native_backup_inputs(self):
        fence = self.fence()
        fence.apply()
        fence.apply()
        fence.verify()
        self.assertEqual(self.site.read_text(), self.original)

        body = self.path.read_text()
        self.assertIn("ServerName ${PRAHO_COMPONENT_", body)
        self.assertIn("ServerAlias ${PRAHO_COMPONENT_", body)
        self.assertNotIn("ServerName example.test", body)
        self.assertNotIn("ServerAlias www.example.test", body)
        self.assertIn(" example.test\n", body)
        self.assertIn(" www.example.test\n", body)
        self.assertNotIn("mail.example.test", body)
        self.assertNotIn("DocumentRoot", body)
        self.assertIn(self.operation, body)
        fence.release()
        fence.release()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.site.read_text(), self.original)

    def test_source_ingress_retires_only_after_web_absence_while_native_domain_remains(self):
        fence = self.fence()
        fence.apply()
        metadata = self.root / "etc/webmin/virtual-server/domains/123456789"
        metadata.write_text("id=123456789\ndom=example.test\nweb=0\nssl=0\nmail=1\ndns=1\nunix=1\n")
        metadata.chmod(0o600)
        self.site.unlink()
        fence.retire_after_web_absence("")
        self.assertTrue(metadata.exists())
        self.assertFalse(self.path.exists())
        fence.retire_after_web_absence("")
        self.site.write_text("# foreign website after cleanup\n")
        with self.assertRaisesRegex(ValueError, "changed|reused|website"):
            fence.retire_after_web_absence("")
        self.assertEqual(self.site.read_text(), "# foreign website after cleanup\n")

    def test_changed_native_vhost_or_unreceipted_guard_is_not_overwritten(self):
        self.site.write_text(self.original + "# another actor\n")
        with self.assertRaises(ValueError):
            self.fence().apply()
        self.assertFalse(self.path.exists())
        self.site.write_text(self.original)
        self.path.write_text("# foreign maintenance rule\n")
        with self.assertRaises(ValueError):
            self.fence().apply()
        self.assertEqual(self.path.read_text(), "# foreign maintenance rule\n")

    def test_other_attempt_and_changed_owned_guard_cannot_release_current_ingress(self):
        fence = self.fence()
        fence.apply()
        with self.assertRaises(ValueError):
            self.fence(str(uuid4())).release()
        self.path.write_text(self.path.read_text() + "# changed by another actor\n")
        with self.assertRaises(ValueError):
            fence.release()
        self.assertTrue(self.path.exists())

    def test_disk_configuration_alone_is_not_proof_of_effective_maintenance(self):
        fence = self.fence()
        self.execute = lambda _arguments: "HTTP/1.1 200 OK\r\n"
        fence.execute = self.execute
        fence.bindings.execute = self.execute
        with self.assertRaises(ValueError):
            fence.apply()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.site.read_text(), self.original)

    def test_forward_activation_requires_exact_changed_native_config_and_same_owned_hold(self):
        fence = self.fence()
        fence.apply()
        self.site.write_text(self.original + "# native enable callback\n")
        with self.assertRaises(ValueError):
            fence.release()
        changed = hashlib.sha256(self.site.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            fence.release_after_native_change("f" * 64)
        self.assertTrue(self.path.exists())
        fence.release_after_native_change(changed)
        fence.release_after_native_change(changed)
        self.assertFalse(self.path.exists())
        with self.assertRaises(ValueError):
            fence.release_after_native_change("e" * 64)

    def test_domain_absence_retires_owned_maintenance_without_opening_a_restored_application(self):
        fence = self.fence()
        fence.apply()
        with self.assertRaisesRegex(ValueError, "absent"):
            fence.retire_after_domain_absence()
        self.assertTrue(self.path.exists())
        self.site.unlink()
        (self.root / "etc/webmin/virtual-server/domains/123456789").unlink()
        fence.retire_after_domain_absence()
        self.assertFalse(self.path.exists())
        self.assertFalse(fence.certificates.exists())
        fence.retire_after_domain_absence()
        self.path.write_text("# subsequent foreign frontend\n")
        with self.assertRaises(ValueError):
            fence.retire_after_domain_absence()
        self.assertEqual(self.path.read_text(), "# subsequent foreign frontend\n")
