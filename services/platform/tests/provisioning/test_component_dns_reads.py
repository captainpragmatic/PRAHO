"""The retained-services digest reads DNS; one dropped query must not fail a whole source retirement (#880)."""

import importlib.util
import subprocess
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.test import SimpleTestCase


class ComponentDnsReadTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-inspect.py"
        spec = importlib.util.spec_from_file_location("component_dns_reads", path)
        cls.inspection = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.inspection)

    def answers(self, outcomes):
        """Each dig call takes the next (returncode, stdout); `dig +short` exits 9 when a query times out."""
        queue = list(outcomes)
        calls = []

        def run(arguments, **_kwargs):
            calls.append(arguments)
            code, stdout = queue.pop(0) if queue else (0, "")
            return subprocess.CompletedProcess(arguments, code, stdout, "")

        return patch.object(self.inspection.subprocess, "run", side_effect=run), calls

    def test_one_timed_out_query_is_retried(self):
        runner, calls = self.answers([(9, ";; connection timed out; no servers could be reached\n"), (0, "10 mx.example.test.\n")])
        with runner:
            records = self.inspection._dns("example.test", local=True)
        self.assertEqual(records["mx"], ["10 mx.example.test."])
        self.assertEqual(calls[0], calls[1])

    def test_a_query_that_keeps_timing_out_still_fails(self):
        runner, calls = self.answers([(9, "")] * self.inspection.DNS_QUERY_ATTEMPTS)
        with runner, self.assertRaisesRegex(ValueError, "unreadable"):
            self.inspection._dns("example.test", local=True)
        self.assertEqual(len(calls), self.inspection.DNS_QUERY_ATTEMPTS)

    def test_an_empty_answer_is_an_answer_and_is_not_retried(self):
        runner, calls = self.answers([(0, "")])
        with runner:
            records = self.inspection._dns("example.test", local=True)
        self.assertEqual(records["mx"], [])
        self.assertEqual(calls[0][-2:], ["example.test", "MX"])
        self.assertNotEqual(calls[1][-1], "MX")
