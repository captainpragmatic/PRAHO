"""The Platform runs the Ansible it pins, whatever PATH its worker was started with."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.infrastructure.ansible_service import AnsibleService

SERVICE = "apps.infrastructure.ansible_service"


class AnsibleControllerLookupTests(SimpleTestCase):
    def setUp(self) -> None:
        # A systemd unit starts the venv's python by absolute path; PATH stays the system default.
        self.which = self.enterContext(patch(f"{SERVICE}.shutil.which", return_value=None))
        self.enterContext(patch(f"{SERVICE}.os.path.exists", return_value=False))
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "python").touch()
        self.enterContext(patch("sys.executable", str(self.root / "python")))

    def _tool(self, name: str = "ansible-playbook", mode: int = 0o755) -> Path:
        tool = self.root / name
        tool.write_text("#!/bin/sh\n")
        tool.chmod(mode)
        return tool

    def _resolved(self) -> str:
        try:
            return AnsibleService()._ansible_path
        except RuntimeError as error:
            return f"refused: {error}"

    def test_the_interpreters_own_ansible_is_used_when_path_lacks_it(self) -> None:
        tool = self._tool()
        self.assertTrue(tool.is_file())
        self.assertEqual(self._resolved(), str(tool))

    def test_the_pinned_ansible_wins_over_another_on_path(self) -> None:
        tool = self._tool()
        self.which.return_value = "/usr/bin/ansible-playbook"
        self.assertEqual(self._resolved(), str(tool))

    def test_a_non_executable_file_next_to_the_interpreter_is_not_used(self) -> None:
        self._tool(mode=0o644)
        self.which.return_value = "/opt/tools/ansible-playbook"
        self.assertEqual(self._resolved(), "/opt/tools/ansible-playbook")

    def test_without_any_ansible_the_service_still_refuses(self) -> None:
        self.assertEqual(self._resolved(), "refused: ansible-playbook not found. Please install Ansible.")
