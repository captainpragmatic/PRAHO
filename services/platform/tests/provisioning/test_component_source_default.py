"""An imported hold cannot silently create or refresh the node's global default frontend."""

import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase


class ComponentSourceDefaultTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-default.py"
        spec = importlib.util.spec_from_file_location("component_source_default", path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.conf = self.root / "etc/apache2/conf-enabled"
        self.conf.mkdir(parents=True)
        (self.root / "etc/apache2/sites-enabled").mkdir()
        self.default = self.conf / "praho-default-site.conf"
        self.default.write_text("ServerName praho-default.invalid\n")
        self.policy = self.module.apache.ApacheBindings(self.root, owner_uid=self.module.os.geteuid())
        self.policy.state.mkdir(mode=0o700, parents=True)
        self.policy.refresh()
        self.enterContext(patch.object(self.policy, "probe_addresses", return_value=["127.0.0.1"]))

    def check(self, status="404"):
        return self.module.qualify_default(self.root, policy=self.policy, execute=lambda _arguments: status)

    def test_qualified_default_is_probed_without_modifying_any_config_or_receipt(self):
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(self.check(), [])
        self.assertEqual({path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}, before)

    def test_missing_unverified_or_stale_default_requires_explicit_preparation_without_refresh(self):
        self.assertTrue(self.check(status="200"))
        self.default.unlink()
        self.assertTrue(self.check())
        self.assertFalse(self.default.exists())
        self.default.write_text("ServerName praho-default.invalid\n")
        site = self.root / "etc/apache2/sites-enabled/other.conf"
        site.write_text("<VirtualHost 192.0.2.77:80>\nServerName other.example.test\n</VirtualHost>\n")
        old = self.policy.configuration.read_bytes()
        self.assertTrue(self.check())
        self.assertEqual(self.policy.configuration.read_bytes(), old)

    def test_older_neutral_renderer_is_not_silently_replaced_by_a_component_hold(self):
        old = self.policy.configuration.read_bytes() + b"# older renderer policy\n"
        self.policy.configuration.write_bytes(old)
        receipt = json.loads(self.policy.metadata.read_text())
        receipt["sha256"] = hashlib.sha256(old).hexdigest()
        self.policy.metadata.write_text(json.dumps(receipt))
        self.assertEqual(self.policy.current(), self.policy.observed())
        self.assertTrue(self.check())
        self.assertEqual(self.policy.configuration.read_bytes(), old)
