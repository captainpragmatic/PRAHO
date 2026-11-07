"""quotaon -p exits 1 when the quota class is on (quota-tools 4.09 on Ubuntu 26.04); the printed state decides.

Both native helpers read it. Treating exit 1 as a failed operation refused every node whose quotas were enabled.
"""

import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import patch

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
