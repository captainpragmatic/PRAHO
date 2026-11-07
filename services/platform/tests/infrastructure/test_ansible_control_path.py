"""Ansible control paths and SSH transition diagnostics survive native unit sandboxing."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult, AnsibleService, failure_detail
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment
from tests.infrastructure.test_security_hardening import enrolled_node


class AnsibleControlPathTests(TestCase):
    def test_ansible_home_supplies_missing_or_empty_control_path(self) -> None:
        for empty in (False, True):
            with self.subTest(empty=empty), patch.dict(os.environ, {"ANSIBLE_HOME": "/run/x/ansible"}, clear=False):
                os.environ.pop("ANSIBLE_SSH_CONTROL_PATH_DIR", None)
                if empty:
                    os.environ["ANSIBLE_SSH_CONTROL_PATH_DIR"] = ""
                self.assertEqual(os.environ["ANSIBLE_HOME"], "/run/x/ansible")
                self.assertFalse(os.environ.get("ANSIBLE_SSH_CONTROL_PATH_DIR"))

                environment = AnsibleService._build_ansible_env()

                self.assertEqual(environment.get("ANSIBLE_SSH_CONTROL_PATH_DIR"), "/run/x/ansible/cp")

    def test_explicit_control_path_is_preserved(self) -> None:
        with patch.dict(
            os.environ,
            {"ANSIBLE_HOME": "/run/x/ansible", "ANSIBLE_SSH_CONTROL_PATH_DIR": "/run/custom/cp"},
            clear=False,
        ):
            self.assertEqual(os.environ["ANSIBLE_HOME"], "/run/x/ansible")
            self.assertEqual(os.environ["ANSIBLE_SSH_CONTROL_PATH_DIR"], "/run/custom/cp")

            environment = AnsibleService._build_ansible_env()

            self.assertEqual(environment.get("ANSIBLE_SSH_CONTROL_PATH_DIR"), "/run/custom/cp")

    def test_no_home_leaves_control_path_absent(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANSIBLE_HOME", None)
            os.environ.pop("ANSIBLE_SSH_CONTROL_PATH_DIR", None)
            self.assertNotIn("ANSIBLE_HOME", os.environ)
            self.assertNotIn("ANSIBLE_SSH_CONTROL_PATH_DIR", os.environ)

            environment = AnsibleService._build_ansible_env()

            self.assertNotIn("ANSIBLE_SSH_CONTROL_PATH_DIR", environment)

    def test_run_playbook_passes_control_path_to_process(self) -> None:
        deployment = _create_deployment("completed", external_node_id="fixture-vm")
        deployment.ssh_host_keys = enrolled_node().ssh_host_keys
        deployment.ssh_port = 9876
        deployment.save(update_fields=["ssh_host_keys", "ssh_port"])
        service = object.__new__(AnsibleService)
        service.timeout = 30
        service._ansible_path = "/usr/bin/ansible-playbook"
        service._ssh_manager = MagicMock()
        captured: dict[str, str] = {}

        def execute(command: list[str], environment: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
            captured.update(environment)
            return subprocess.CompletedProcess(command, returncode=0, stdout="", stderr="")

        with TemporaryDirectory() as directory:
            key_file = Path(directory) / "key"
            key_file.write_text("fixture-private-key")
            service._ssh_manager.get_private_key_file.return_value = Ok(key_file)
            with (
                patch.dict(os.environ, {"ANSIBLE_HOME": "/run/x/ansible"}, clear=False),
                patch.object(AnsibleService, "_execute_process", side_effect=execute),
                patch.object(AnsibleService, "_wait_for_ssh", return_value=Ok(True)),
                patch.object(AnsibleService, "_ensure_ssh_policy", return_value=Ok(True)),
                patch("apps.infrastructure.ansible_service.recover_connection_port", return_value=9876),
                patch.object(service, "_build_vars", return_value={}),
            ):
                os.environ.pop("ANSIBLE_SSH_CONTROL_PATH_DIR", None)
                self.assertEqual(os.environ["ANSIBLE_HOME"], "/run/x/ansible")
                self.assertNotIn("ANSIBLE_SSH_CONTROL_PATH_DIR", os.environ)
                self.assertEqual(deployment.ipv4_address, "1.2.3.4")
                self.assertTrue(deployment.ssh_host_keys)
                self.assertTrue(key_file.is_file())

                result = service.run_playbook(deployment, "virtualmin.yml")

        self.assertTrue(result.is_ok(), result)
        self.assertTrue(result.unwrap().success)
        self.assertEqual(captured.get("ANSIBLE_SSH_CONTROL_PATH_DIR"), "/run/x/ansible/cp")

    def test_ssh_transition_failure_includes_only_first_fatal_detail(self) -> None:
        service = object.__new__(AnsibleService)
        deployment = _create_deployment("completed", external_node_id="fixture-vm")
        self.assertEqual(deployment.status, "completed")
        self.assertEqual(deployment.external_node_id, "fixture-vm")
        prefix = "Node SSH transition failed; inspect the retained snapshot and verified port"
        error = (
            "[ERROR]: Task failed: Unable to create local directories "
            "'/home/praho/.ansible/cp': [Errno 13] Permission denied"
        )
        fatal = "fatal: [1.2.3.4]: FAILED! =>"
        yaml_failure = (
            f"{fatal}\n"
            "    ansible_facts:\n"
            "        discovered_interpreter_python: /usr/bin/python3\n"
            "    changed: false\n"
            "    cmd: some command\n"
            "    msg: the real reason\n"
            "PLAY RECAP\n"
        )
        inline = 'fatal: [1.2.3.4]: FAILED! => {"msg": "Permission denied"}'
        missing_role = "[ERROR]: the role 'x' was not found in /run/x/ansible/roles"
        cases: tuple[tuple[str, str, str], ...] = (
            (
                f"TASK [SSH policy]\n  {error}\n[ERROR]: ignored second failure",
                "[ERROR]: ignored stderr failure",
                error,
            ),
            (yaml_failure, "", f"{fatal} msg: the real reason"),
            (f"{inline}\nfatal: [other]: FAILED! => ignored", "", inline),
            ("", missing_role, missing_role),
            ("", "Playbook timed out after 1800 seconds", "Playbook timed out after 1800 seconds"),
            (f"[ERROR]: {'x' * 400}\n[ERROR]: ignored", "", ("[ERROR]: " + "x" * 400)[:300]),
            ("PLAY RECAP\nnode: failed=1", "", ""),
            (yaml_failure, f"  {missing_role}\n[ERROR]: ignored second failure", missing_role),
            (f"{fatal}\nPLAY RECAP\n    msg: unrelated", "", fatal),
            (f"{fatal}\n\n\tchanged: false\n\tmsg: tabbed reason", "", f"{fatal} msg: tabbed reason"),
            ("", "\n  \n  controller could not start\nignored second line", "controller could not start"),
        )
        for stdout, stderr, detail in cases:
            with self.subTest(stdout=stdout, stderr=stderr):
                failure = AnsibleResult(False, "ssh-hardening.yml", stdout, stderr, 2)
                self.assertFalse(failure.success)
                self.assertEqual(failure.stdout, stdout)
                self.assertEqual(failure.stderr, stderr)
                with patch.object(service, "run_playbook", return_value=Ok(failure)):
                    result = service._ensure_ssh_policy(deployment, operator_public_keys=("snapshot",))

                self.assertTrue(result.is_err())
                self.assertEqual(result.unwrap_err(), f"{prefix}: {detail}" if detail else prefix)


class FailureDetailTests(TestCase):
    def test_the_fatal_task_wins_over_leading_stderr_warnings(self) -> None:
        warnings = "[DEPRECATION WARNING]: INJECT_FACTS_AS_VARS default to `True` is deprecated."
        fatal = 'fatal: [1.2.3.4]: FAILED! => {"msg": "the real reason"}'
        self.assertEqual(failure_detail(f"TASK [x]\n{fatal}\n", warnings), fatal)
        # Without a recognisable failure line the stderr text is kept, as before.
        self.assertEqual(failure_detail("PLAY RECAP\n", "  controller died\n"), "controller died")
        self.assertEqual(failure_detail("", ""), "")

    def test_a_2_19_task_error_keeps_its_origin_and_the_fatal_result(self) -> None:
        # ansible-core 2.19 prints a generic [ERROR] first; the task and the command's stderr follow it.
        stdout = (
            "TASK [Install Virtualmin] ******\n"
            "[ERROR]: Task failed: Module failed: non-zero return code\n"
            "Origin: /x/playbooks/virtualmin.yml:120:7\n"
            "\n"
            "120     - name: Install Virtualmin\n"
            "         ^ column 7\n"
            "\n"
            'fatal: [1.2.3.4]: FAILED! => {"changed": true, "rc": 1, "stderr": "E: Unable to locate package x"}\n'
            "PLAY RECAP\n"
        )
        detail = failure_detail(stdout, "[DEPRECATION WARNING]: noise")
        self.assertIn("[ERROR]: Task failed: Module failed: non-zero return code", detail)
        self.assertIn("Origin: /x/playbooks/virtualmin.yml:120:7", detail)
        self.assertIn("E: Unable to locate package x", detail)
        self.assertNotIn("noise", detail)
        self.assertLessEqual(len(failure_detail(stdout.replace("package x", "x" * 5000), "")), 1500)

    def test_a_yaml_fatal_result_keeps_its_indented_stderr(self) -> None:
        stdout = (
            "[ERROR]: Task failed: Module failed: non-zero return code\n"
            "Origin: /x/playbooks/virtualmin.yml:63:7\n"
            "fatal: [node]: FAILED! =>\n"
            "    changed: false\n"
            "    rc: 1\n"
            "    stderr: |-\n"
            "        AssertionError: Tenant or unknown homes exist\n"
            "PLAY RECAP\n"
        )
        detail = failure_detail(stdout, "")
        self.assertIn("AssertionError: Tenant or unknown homes exist", detail)
        self.assertNotIn("PLAY RECAP", detail)

    def test_a_long_echoed_command_does_not_crowd_out_the_stderr(self) -> None:
        script = "\n".join(f"            line {n} of the inline script" for n in range(200))
        stdout = (
            "[ERROR]: Task failed: Module failed: non-zero return code\n"
            "fatal: [node]: FAILED! =>\n"
            "    changed: false\n"
            "    cmd:\n"
            "    - /usr/bin/python3\n"
            "    - -c\n"
            "    - |-\n"
            f"{script}\n"
            "    msg: non-zero return code\n"
            "    rc: 1\n"
            "    stderr: |-\n"
            "        Traceback (most recent call last):\n"
            "        AssertionError: Tenant or unknown homes exist: lost+found\n"
            "    stderr_lines: []\n"
        )
        detail = failure_detail(stdout, "")
        self.assertIn("AssertionError: Tenant or unknown homes exist: lost+found", detail)
        self.assertNotIn("inline script", detail)

    def test_the_end_of_a_long_stderr_is_kept(self) -> None:
        noise = "    W: a repository warning that repeats\n" * 14
        stdout = (
            "fatal: [node]: FAILED! =>\n"
            "    msg: non-zero return code\n"
            "    rc: 100\n"
            "    stderr: |-\n"
            + noise.replace("    W:", "        W:")
            + "        E: Unable to locate package php8.5-fpm\n"
        )
        detail = failure_detail(stdout, "")
        self.assertIn("E: Unable to locate package php8.5-fpm", detail)
        self.assertIn("rc: 100", detail)

    def test_several_long_fields_each_keep_their_end(self) -> None:
        def field(name: str, end: str) -> str:
            return f"    {name}: |-\n" + "        filler text that is not the reason\n" * 30 + f"        {end}\n"

        stdout = (
            "[ERROR]: Task failed: Module failed: non-zero return code\n"
            "Origin: /x/playbooks/virtualmin.yml:63:7\n"
            "fatal: [node]: FAILED! =>\n"
            + field("msg", "MSG-END")
            + "    rc: 1\n"
            + field("stderr", "STDERR-END")
            + field("stdout", "STDOUT-END")
        )
        detail = failure_detail(stdout, "")
        for end in ("MSG-END", "STDERR-END", "STDOUT-END", "rc: 1", "virtualmin.yml:63:7"):
            self.assertIn(end, detail)
        self.assertLessEqual(len(detail), 1500)

    def test_a_reason_given_only_on_stdout_is_kept(self) -> None:
        stdout = (
            "fatal: [node]: FAILED! =>\n"
            "    cmd: [/usr/bin/check]\n"
            "    msg: non-zero return code\n"
            "    rc: 3\n"
            "    stderr: ''\n"
            "    stdout: the disk layout is unsupported\n"
            "    stdout_lines: [the disk layout is unsupported]\n"
        )
        detail = failure_detail(stdout, "")
        self.assertIn("the disk layout is unsupported", detail)
        self.assertNotIn("/usr/bin/check", detail)
        # A huge stdout is bounded and does not push out msg or rc.
        flood = stdout.replace("the disk layout is unsupported", "x" * 5000)
        bounded = failure_detail(flood, "")
        self.assertIn("rc: 3", bounded)
        self.assertLessEqual(len(bounded), 1500)
