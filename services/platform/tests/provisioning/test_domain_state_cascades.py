"""Suspending or enabling a customer domain also reaches its account name (ADR-0061 P1.5).

The account name is a sub-server of the customer domain. `disable-domain` without `subservers`
leaves it serving the customer's site while the customer domain shows the disabled page (lab S3,
reproved for P1.5 on Virtualmin 8.3: a plain disable lists only the parent as disabled). Every
`disable-domain` and `enable-domain` PRAHO sends carries the flag, built by one helper, and a scan
fails on any call that bypasses it, in the provisioning package and in the node scripts.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from apps.common.types import Ok
from apps.provisioning.virtualmin_domain_state import DOMAIN_STATE_PROGRAMS, domain_state_params
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from tests.provisioning.test_cov_provisioning_services_creation import VirtualminServiceCoverageCase

PLATFORM = Path(__file__).resolve().parents[2]
PROVISIONING = PLATFORM / "apps" / "provisioning"
NODE_SCRIPTS = PLATFORM / "infrastructure" / "ansible" / "playbooks"


class HelperTests(SimpleTestCase):
    def test_the_parameters_name_the_domain_and_its_sub_servers(self) -> None:
        self.assertEqual(
            domain_state_params("customer.example.com"), {"domain": "customer.example.com", "subservers": ""}
        )


class LifecycleCascadeTests(VirtualminServiceCoverageCase):
    def test_suspend_and_unsuspend_reach_the_account_name(self) -> None:
        self.payloads["disable-domain"] = {"status": "success", "message": "disabled"}
        self.payloads["enable-domain"] = {"status": "success", "message": "enabled"}
        account = self._account()
        self.assertIs(self.provisioning.suspend_account(account, "billing hold").unwrap(), True)
        self.assertIs(self.provisioning.unsuspend_account(account).unwrap(), True)

        sent = [request for request in self.requests if request["program"] in DOMAIN_STATE_PROGRAMS]
        self.assertEqual([request["program"] for request in sent], ["disable-domain", "enable-domain"])
        for request in sent:
            self.assertIn("subservers", request)


class MigrationCascadeTests(TestCase):
    def test_the_migrations_domain_state_commands_reach_the_account_name(self) -> None:
        sent: list[tuple[str, dict[str, Any]]] = []

        class Gateway:
            def call(self, program: str, params: dict[str, Any], **_: object) -> object:
                sent.append((program, params))
                return Ok(SimpleNamespace(success=True, data={"status": "success"}, raw_response=""))

        migration = SimpleNamespace(account=SimpleNamespace(domain="customer.example.com"))
        with patch.object(VirtualminMigrationService, "_gateway", staticmethod(lambda server: Gateway())):
            service = VirtualminMigrationService()
            for program in ("disable-domain", "enable-domain", "list-domains"):
                service._command(migration, object(), program)  # type: ignore[arg-type]  # a stand-in

        self.assertEqual(sent[0][1], {"domain": "customer.example.com", "subservers": ""})
        self.assertEqual(sent[1][1], {"domain": "customer.example.com", "subservers": ""})
        self.assertEqual(sent[2][1], {"domain": "customer.example.com"}, "other programs are unchanged")


class NoCallBypassesTheHelperTests(SimpleTestCase):
    """A new call site cannot forget the flag: a literal params dict for these programs fails here."""

    def test_no_python_call_builds_domain_state_parameters_by_hand(self) -> None:
        offenders: list[str] = []
        for path in sorted(PROVISIONING.rglob("*.py")):
            if "tests" in path.parts or path.name == "virtualmin_domain_state.py":
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                # gateway.call("disable-domain", {...}) or an operation record {"operation": "...", "params": {...}}
                if isinstance(node, ast.Call) and len(node.args) >= 2:  # program and params
                    program, params = node.args[0], node.args[1]
                    if (
                        isinstance(program, ast.Constant)
                        and program.value in DOMAIN_STATE_PROGRAMS
                        and isinstance(params, ast.Dict)
                    ):
                        offenders.append(f"{path.relative_to(PLATFORM)}:{node.lineno}")
                if isinstance(node, ast.Dict):
                    fields = {
                        key.value: value
                        for key, value in zip(node.keys, node.values, strict=True)
                        if isinstance(key, ast.Constant)
                    }
                    operation, params = fields.get("operation"), fields.get("params")
                    if (
                        isinstance(operation, ast.Constant)
                        and operation.value in DOMAIN_STATE_PROGRAMS
                        and isinstance(params, ast.Dict)
                    ):
                        offenders.append(f"{path.relative_to(PLATFORM)}:{node.lineno}")
        self.assertEqual(offenders, [], "build disable-domain / enable-domain parameters with domain_state_params()")

    def test_every_node_script_call_carries_subservers(self) -> None:
        pattern = re.compile(r"virtualmin\s+(disable|enable)-domain\b[^\n]*")
        offenders = [
            f"{path.relative_to(PLATFORM)}: {match.group(0).strip()}"
            for path in sorted(NODE_SCRIPTS.rglob("*"))
            if path.is_file() and path.suffix in {".sh", ".yml", ".j2"}
            for match in pattern.finditer(path.read_text())
            if "--subservers" not in match.group(0) and not match.group(0).lstrip().startswith("#")
        ]
        self.assertEqual(offenders, [])
