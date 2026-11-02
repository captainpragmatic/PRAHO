"""Selected website DNS changes never broaden into mail, TXT, aliases or foreign addresses."""

import importlib.util
import json
import tempfile
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.conf import settings
from django.test import SimpleTestCase


class ComponentNativeRoutingTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        helper = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-component-routing.py"
        spec = importlib.util.spec_from_file_location("component_native_routing", helper)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.network = {
            "source_ipv4": "192.0.2.10",
            "target_ipv4": "192.0.2.20",
            "source_ipv6": "2001:db8::10",
            "target_ipv6": "2001:db8::20",
        }
        self.records = [
            {
                "name": "example.test.",
                "type": "SOA",
                "values": ["ns.example.test.", "hostmaster.example.test.", "12", "60", "60", "60", "60"],
            },
            {"name": "example.test.", "type": "A", "values": ["192.0.2.10"], "ttl": 600},
            {"name": "example.test.", "type": "AAAA", "values": ["2001:db8::10"], "ttl": 600},
            {"name": "www.example.test.", "type": "CNAME", "values": ["example.test."], "ttl": 600},
            {"name": "example.test.", "type": "MX", "values": ["10", "mail.example.test."]},
            {"name": "mail.example.test.", "type": "A", "values": ["192.0.2.10"]},
            {"name": "example.test.", "type": "TXT", "values": ["v=spf1 mx -all"]},
        ]

    def plan(self):
        return self.module.plan_records("example.test", self.records, self.network)

    def test_dual_stack_move_changes_only_exact_selected_address_values_and_retry_is_noop(self):
        original = deepcopy(self.records)
        plan = self.plan()
        self.assertEqual(plan["mode"], "source_dns_updated")
        self.assertEqual(
            plan["operations"], [{"index": 1, "value": "192.0.2.20"}, {"index": 2, "value": "2001:db8::20"}]
        )
        for operation in plan["operations"]:
            self.records[operation["index"]]["values"] = [operation["value"]]
        self.assertEqual(self.records[3:], original[3:])
        self.assertEqual(self.plan()["operations"], [])
        self.assertEqual(self.plan()["retained_digest"], plan["retained_digest"])

    def test_missing_target_ipv6_removes_only_old_selected_aaaa(self):
        self.network["target_ipv6"] = ""
        self.assertEqual(self.plan()["operations"], [{"index": 1, "value": "192.0.2.20"}, {"index": 2, "value": ""}])

    def test_new_target_ipv6_uses_existing_selected_record_ttl(self):
        del self.records[2]
        plan = self.plan()
        self.assertEqual(
            plan["operations"][-1],
            {"create": {"name": "example.test.", "type": "AAAA", "ttl": 600, "values": ["2001:db8::20"]}},
        )

    def test_foreign_proxy_address_or_external_alias_requires_operator_without_any_mutation(self):
        for index, value in ((1, "198.51.100.55"), (2, "2001:db8::99"), (3, "proxy.external.test.")):
            with self.subTest(index=index):
                changed = deepcopy(self.records)
                changed[index]["values"] = [value]
                plan = self.module.plan_records("example.test", changed, self.network)
                self.assertEqual(plan["mode"], "operator_dns_required")
                self.assertEqual(plan["operations"], [])

    def test_native_serial_changes_are_allowed_but_retained_mail_and_spf_changes_are_not(self):
        digest = self.plan()["retained_digest"]
        self.records[0]["values"][2] = "13"
        self.assertEqual(self.plan()["retained_digest"], digest)
        self.records[-1]["values"] = ["v=spf1 a -all"]
        self.assertNotEqual(self.plan()["retained_digest"], digest)

    def test_committed_bridge_keeps_current_mail_password_rotation_and_all_selected_holds_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source.json").write_text(
                json.dumps({"domain": "example.test", "source": "192.0.2.10", "target": "192.0.2.20"})
            )
            node = MagicMock()
            node.directory.return_value = root
            node.bound_manifest.side_effect = lambda manifest, _operation: manifest
            bridge = SimpleNamespace(NodeBridge=MagicMock(return_value=node))
            steps = {name: MagicMock() for name in ("web", "cron", "database", "paths")}
            steps["web"]._state.return_value = {"phase": "held"}
            source = SimpleNamespace(
                operation="exact-operation",
                request={"domain": "example.test"},
                retained=MagicMock(return_value="c" * 64),
                build=MagicMock(return_value=steps),
                coordinator=SimpleNamespace(
                    _steps=MagicMock(side_effect=AssertionError("Old immutable shadow digest"))
                ),
            )
            state = {"context": {"retained_digest": "a" * 64}}
            with (
                patch.object(
                    self.module.importlib.util,
                    "spec_from_file_location",
                    return_value=SimpleNamespace(loader=MagicMock()),
                ),
                patch.object(self.module.importlib.util, "module_from_spec", return_value=bridge),
            ):
                self.assertEqual(self.module.verify_bridged_source(source, state, self.network), "c" * 64)
            source.coordinator._steps.assert_not_called()
            steps["web"]._original.assert_called_once()
            steps["web"]._owned.assert_called_once_with({"phase": "held"})
            node.verify.assert_called_once_with("exact-operation")
            for name in ("cron", "database", "paths"):
                steps[name].verify.assert_called_once()
