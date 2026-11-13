"""quotaon -p exits 1 when the quota class is on (quota-tools 4.09 on Ubuntu 26.04); the printed state decides.

Both native helpers read it. Treating exit 1 as a failed operation refused every node whose quotas were enabled.
PHP 8.5 reports EDQUOT as a silent short write, so the requalification probe proves the stop independently.
"""

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from django.conf import settings
from django.test import SimpleTestCase

FILES = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"quota_class_state_{name}", FILES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _answer(returncode: int, stdout: str):
    return patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode, stdout, ""))


class QuotaClassStateTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.helpers = [_load("praho_quota_native"), _load("praho_hosting_node")]

    def test_quota_on_is_read_from_the_printed_state_whatever_quotaon_exits_with(self):
        for helper in self.helpers:
            with self.subTest(helper=helper.__name__):
                with _answer(1, "user quota on / (/dev/sda1) is on\n"):
                    self.assertTrue(helper._quota_class_on("user", "-u"))
                with _answer(0, "group quota on / (/dev/sda1) is off\n"):
                    self.assertFalse(helper._quota_class_on("group", "-g"))
                with _answer(1, "group quota on / (/dev/sda1) is on\n"):
                    self.assertFalse(helper._quota_class_on("user", "-u"))  # the other class's line is not proof

    def test_any_other_exit_still_fails(self):
        for helper in self.helpers:
            with (
                self.subTest(helper=helper.__name__),
                _answer(2, "user quota on / (/dev/sda1) is on\n"),
                self.assertRaises(ValueError),
            ):
                helper._quota_class_on("user", "-u")


class PhpRequalificationProbeTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.node = _load("praho_hosting_node")

    IDENTIFIER = 2147000001

    def probe(self, *, used_kib, free_bytes):
        php_writes = []

        def native(argv, **_kwargs):
            if argv[0] == "/usr/bin/perl":
                return json.dumps({"uid": self.IDENTIFIER, "gid": self.IDENTIFIER})
            if "/usr/bin/php8.5" in argv:
                php_writes.append(argv)
            return str(self.IDENTIFIER)

        quota = ModuleType("praho_quota_native")
        empty = SimpleNamespace(hard=0, soft=0, space=0, inodes=0, inode_hard=0, inode_soft=0)
        used = SimpleNamespace(hard=64, soft=64, space=used_kib * 1024, inodes=1, inode_hard=0, inode_soft=0)
        quota._kernel_quota = Mock(side_effect=lambda *_a, **_k: used if php_writes else empty)
        quota._set_kernel_quota = Mock()
        with (
            TemporaryDirectory() as directory,
            patch.dict(sys.modules, {"praho_quota_native": quota}),
            patch.object(self.node, "REQUALIFICATION_ROOT", Path(directory).resolve() / "probe"),
            patch.object(self.node, "STATE", Path(directory).resolve()),
            patch.object(self.node, "_run", side_effect=native),
            patch.object(self.node, "_read", return_value="{}"),
            patch.object(self.node, "_write"),
            patch.object(self.node, "_reserved_probe_id", return_value=self.IDENTIFIER),
            patch.object(self.node, "_probe_cleanup"),
            patch.object(self.node.os, "chown"),
            patch.object(self.node.os, "statvfs", return_value=SimpleNamespace(f_bavail=free_bytes, f_frsize=1)),
        ):
            self.node._isolated_requalification_probe({"source": "/dev/fixture", "uuid": "u"}, 3)
        return php_writes[0]

    def test_a_silent_short_write_at_the_cap_on_a_roomy_disk_is_the_denial(self):
        program = self.probe(used_kib=64, free_bytes=10 * 1024**3)[-2]
        chunk = int(re.search(r"str_repeat\('x',(\d+)\)", program).group(1))
        self.assertIn(f"$n!=={chunk}", program)
        self.assertNotIn("quota exceeded", program)  # PHP 8.5 reports no message; requiring one refused every node

    def test_the_php_writer_steps_close_enough_to_the_cap_to_prove_it(self):
        # A chunk the size of the cap is refused whole, leaving usage at 0, so the probe called every node unqualified.
        program = self.probe(used_kib=64, free_bytes=10 * 1024**3)[-2]
        chunk = int(re.search(r"str_repeat\('x',(\d+)\)", program).group(1))
        rounds = int(re.search(r"\$i<(\d+)", program).group(1))
        self.assertLessEqual(chunk, self.node.REQUALIFICATION_CAP_SLACK_KIB * 1024)
        self.assertGreater(chunk * rounds, self.node.REQUALIFICATION_LIMIT_KIB * 1024)

    def test_a_short_write_well_below_the_cap_is_not_a_quota_stop(self):
        with self.assertRaisesRegex(ValueError, "quota stop"):
            self.probe(used_kib=4, free_bytes=10 * 1024**3)

    def test_a_short_write_on_a_nearly_full_disk_proves_nothing(self):
        with self.assertRaisesRegex(ValueError, "quota stop"):
            self.probe(used_kib=64, free_bytes=1024)
