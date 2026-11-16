"""A failed retirement run keeps the node's own reason, redacted and bounded (#880)."""

from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult
from apps.provisioning import component_bridge_cleanup as cleanup

NODE_FAILURE = (
    "TASK [Run component action] ****\n"
    'fatal: [backup_target]: FAILED! => {"changed": true, "rc": 1, "stderr": "Traceback (most recent call last):\\n'
    "ValueError: Native component evidence is unreadable or exceeds its qualification bound\\n"
    'password=hunter2-secret"}\n'
)


class RetirementFailureDetailTests(SimpleTestCase):
    def run_failed(self, function, server_attribute):
        bridge = SimpleNamespace(**{server_attribute: object()})
        failed = AnsibleResult(success=False, playbook="virtualmin_component.yml", stdout=NODE_FAILURE * 20,
                               stderr="", return_code=2)
        with (
            patch.object(cleanup, "_retirement_variables", return_value={}),
            patch.object(cleanup, "_target_artifact_variables", return_value={}),
            patch.object(cleanup, "source_retirement_refusal", return_value=None),
            patch.object(cleanup, "target_artifact_retirement_refusal", return_value=None),
            patch("apps.infrastructure.ansible_service.AnsibleService.run_server_playbook", return_value=Ok(failed)),
            self.assertRaises(ValueError) as raised,
        ):
            function(bridge, "token")
        return str(raised.exception)

    def test_a_failed_source_retirement_says_why(self):
        message = self.run_failed(cleanup._retire_source, "source_server")
        self.assertTrue(message.startswith("Source component retirement is uncertain"))
        self.assertIn("Native component evidence is unreadable", message)

    def test_a_failed_target_retirement_says_why(self):
        message = self.run_failed(cleanup._retire_target_artifacts, "target_server")
        self.assertTrue(message.startswith("Private target staging retirement is uncertain"))
        self.assertIn("Native component evidence is unreadable", message)

    def test_the_reason_is_redacted_and_fits_the_bridge_record(self):
        message = self.run_failed(cleanup._retire_source, "source_server")
        self.assertNotIn("hunter2", message)
        self.assertLessEqual(len(message), cleanup.MAX_FAILURE_DETAIL + 200)
        self.assertLess(len(message), 4096)  # The lab diagnostic only prints a bridge error up to this size.


class ComponentFailureReceiptTests(SimpleTestCase):
    """The component task runs with no_log, so its output reaches Platform censored; only this receipt gets out."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import importlib.util  # noqa: PLC0415
        from pathlib import Path  # noqa: PLC0415

        from django.conf import settings  # noqa: PLC0415

        cls.files = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks"
        spec = importlib.util.spec_from_file_location("component_action_receipt", cls.files / "files/praho-component-action.py")
        cls.action = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.action)

    def test_the_receipt_keeps_only_the_authored_reason(self):
        error = RuntimeError("Source native retirement step is uncertain: helper stderr password=hunter2")
        self.assertEqual(
            self.action.failure_receipt(error),
            {"type": "RuntimeError", "reason": "Source native retirement step is uncertain"},
        )

    def test_the_receipt_carries_a_retirement_step_and_changed_part_names(self):
        error = ValueError("Retained source services changed during component retirement: dns")
        error.retirement_step, error.retained_changed = "export", ["dns"]
        receipt = self.action.failure_receipt(error)
        self.assertEqual((receipt["step"], receipt["changed"]), ("export", ["dns"]))

    def test_unexpected_attributes_are_dropped(self):
        error = ValueError("x")
        error.retirement_step, error.retained_changed = "rm -rf /", ["a b", "dns"]
        receipt = self.action.failure_receipt(error)
        self.assertNotIn("step", receipt)
        self.assertNotIn("changed", receipt)

    def test_the_playbook_returns_the_receipt_and_still_fails(self):
        import yaml  # noqa: PLC0415

        play = yaml.safe_load((self.files / "virtualmin_component.yml").read_text())[0]
        blocks = [task for task in play["tasks"] if "rescue" in task]
        self.assertEqual(len(blocks), 1)
        rescue = blocks[0]["rescue"]
        self.assertIn("PRAHO_COMPONENT_FAILURE=", rescue[0]["ansible.builtin.debug"]["msg"])
        self.assertIn("ansible.builtin.fail", rescue[-1])

    def test_platform_reads_the_receipt_from_censored_output(self):
        import base64  # noqa: PLC0415
        import json  # noqa: PLC0415

        receipt = {"failure": {"type": "ValueError", "reason": "Native component evidence is unreadable",
                               "step": "export"}}
        censored = (
            "fatal: [backup_target]: FAILED! => {\"censored\": \"the output has been hidden due to the fact that"
            " 'no_log: true' was specified for this result\"}\n"
            "ok: [backup_target] => {\"msg\": \"PRAHO_COMPONENT_FAILURE="
            + base64.b64encode(json.dumps(receipt).encode()).decode() + "\"}\n"
        )
        failed = AnsibleResult(success=False, playbook="virtualmin_component.yml", stdout=censored, stderr="",
                               return_code=2)
        reason = cleanup._failure_reason(Ok(failed))
        self.assertIn("ValueError: Native component evidence is unreadable", reason)
        self.assertIn("step export", reason)
        self.assertNotIn("censored", reason)


class LongSecretRedactionTests(SimpleTestCase):
    def test_a_long_secret_is_redacted_before_the_detail_is_shortened(self):
        from apps.infrastructure.ansible_service import redacted_failure_detail  # noqa: PLC0415

        stdout = (
            'fatal: [node]: FAILED! => {"msg": "' + "m" * 400 + '", "password": "S3CRET' + "y" * 600 + '"}\n'
        )
        for detail in (redacted_failure_detail(stdout, ""), cleanup._failure_reason(Ok(AnsibleResult(
            success=False, playbook="x.yml", stdout=stdout, stderr="", return_code=2
        )))):
            self.assertNotIn("S3CRET", detail)
            self.assertNotIn("y" * 20, detail)

    def test_a_yaml_block_secret_is_redacted_whole(self):
        from apps.infrastructure.ansible_service import redacted_failure_detail  # noqa: PLC0415

        stdout = (
            "fatal: [node]: FAILED! =>\n"
            "    msg: non-zero return code\n"
            "    rc: 1\n"
            "    stderr: |-\n"
            "        the real reason\n"
            "        password: |-\n"
            "            hunter2-continuation\n"
            "            second-secret-line\n"
            "        after the secret\n"
        )
        detail = redacted_failure_detail(stdout, "")
        self.assertNotIn("hunter2", detail)
        self.assertNotIn("second-secret-line", detail)
        self.assertIn("the real reason", detail)
        self.assertIn("rc: 1", detail)
        self.assertIn("after the secret", detail)


class YamlValueShapeTests(SimpleTestCase):
    def test_every_indented_value_under_a_sensitive_key_is_redacted(self):
        from apps.infrastructure.ansible_service import redacted_failure_detail  # noqa: PLC0415

        for name, lines in (
            ("list", ["        password:", "          - hunter2-list"]),
            ("mapping", ["        credential:", "          inner: hunter2-map"]),
            ("quoted block", ["        'password': |-", "            hunter2-quoted"]),
            ("list item key", ["        - password: |-", "            hunter2-item"]),
            ("commented header", ["        password: |-  # rotated", "            hunter2-comment"]),
            ("indentless sequence", ["        password:", "        - hunter2-indentless"]),
            ("quoted key with a space", ['        "database password": |-', "            hunter2-spaced"]),
            ("wrapped plain value", ["        password: hunter2-first-part", "          hunter2-second-part"]),
        ):
            stdout = "\n".join(
                ["fatal: [node]: FAILED! =>", "    rc: 1", "    stderr: |-", "        the real reason", *lines,
                 "        after the secret", ""]
            )
            with self.subTest(shape=name):
                detail = redacted_failure_detail(stdout, "")
                self.assertNotIn("hunter2", detail)
                self.assertIn("after the secret", detail)


class ComponentFailureLogTests(SimpleTestCase):
    def test_a_censored_component_failure_logs_its_receipt(self):
        import base64  # noqa: PLC0415
        import json  # noqa: PLC0415
        import subprocess  # noqa: PLC0415

        from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415

        receipt = {"failure": {"type": "ValueError", "reason": "Native component evidence is unreadable"}}
        stdout = (
            'fatal: [backup_target]: FAILED! => {"censored": "the output has been hidden"}\n'
            'ok: [backup_target] => {"msg": "PRAHO_COMPONENT_FAILURE='
            + base64.b64encode(json.dumps(receipt).encode()).decode() + '"}\n'
        )
        with self.assertLogs("apps.infrastructure.ansible_service", level="ERROR") as logs:
            AnsibleService._log_imported_outcome(
                "virtualmin_component.yml", subprocess.CompletedProcess([], 2, stdout, "")
            )
        self.assertTrue(any("ValueError: Native component evidence is unreadable" in line for line in logs.output))
