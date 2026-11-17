"""Platform's transport for a billing hold during migration activation (#776, plan revision 3 item 4).

Native: the bridge's activate carries bridge_billing_hold and returns the node's exact hold outcome. Component: the
lease-bound target transport carries billing_hold on target_activate, admits target_billing_hold, and checks both
receipts. The orchestration that decides when to hold (7B) only calls these.
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from typing import Any
from unittest.mock import Mock, patch
from uuid import uuid4

from django.utils import timezone

from apps.common.types import Ok, Retriability, retriability_of
from apps.infrastructure.ansible_service import AnsibleResult, AnsibleService
from apps.provisioning import component_target_transport as transport
from apps.provisioning import migration_bridge_service as bridge
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase
from tests.provisioning.test_migration_bridge_service import BridgeServiceCase

TARGET_ID = "987654321"


def hold_request() -> dict[str, Any]:
    return {"token": str(uuid4()), "generation": 3, "installation": str(uuid4())}


def outcome(hold: dict[str, Any], domain: str, domain_id: str, **change: Any) -> dict[str, Any]:
    held = {
        "outcome": "held",
        "identity": {"domain_id": domain_id, "domain": domain, "installation": hold["installation"]},
        "token": hold["token"],
        "generation": hold["generation"],
        "held_digest": "d" * 64,
    }
    return {**held, **change}


def not_held(hold: dict[str, Any], domain: str, domain_id: str, **change: Any) -> dict[str, Any]:
    result = outcome(hold, domain, domain_id)
    del result["held_digest"]
    return {**result, "outcome": "not_held", "reason": "refused", "code": "global_privilege", **change}


class NativeActivationHoldTests(BridgeServiceCase):
    def setUp(self) -> None:
        super().setUp()
        self.migration.cutover_committed_at = timezone.now()
        self.hold = hold_request()
        self.answer: Any = None

        def activate(deployment, playbook, variables, **kwargs):
            if variables["bridge_action"] != "activate":
                return self._answer(deployment, playbook, variables, **kwargs)
            payload = {"billing_hold": self.answer} if "bridge_billing_hold" in variables else ""
            body = {"identity": str(self.migration.pk), "action": "activate", "payload": payload}
            return Ok(Mock(success=True, stdout="BRIDGE_RESULT=" + base64.b64encode(json.dumps(body).encode()).decode()))

        self.runner.run_playbook.side_effect = activate

    def test_the_hold_travels_with_activate_and_its_outcome_comes_back(self) -> None:
        for answer in (
            outcome(self.hold, self.account.domain, "1001"),
            not_held(self.hold, self.account.domain, "1001"),
            not_held(self.hold, self.account.domain, "1001", reason="uncertain", code=None),
        ):
            with self.subTest(outcome=answer["outcome"], reason=answer.get("reason")):
                self.answer = answer
                self.assertEqual(bridge.activate_target(self.migration, enabled=True, billing_hold=self.hold), Ok(answer))
                self.assertEqual(self._variables()["bridge_billing_hold"], self.hold)

    def test_without_a_hold_activation_is_unchanged(self) -> None:
        self.assertEqual(bridge.activate_target(self.migration, enabled=True), Ok("activated"))
        self.assertNotIn("bridge_billing_hold", self._variables())

    def test_an_outcome_for_another_hold_or_target_is_uncertain(self) -> None:
        domain = self.account.domain
        for answer in (
            None,
            outcome(self.hold, domain, "1001", token=str(uuid4())),
            outcome(self.hold, domain, "1001", generation=4),
            outcome(self.hold, "another.test", "1001"),
            outcome(self.hold, domain, "not-an-id"),
            outcome(self.hold, domain, "1001", held_digest="short"),
            outcome(self.hold, domain, "1001", extra=1),
            not_held(self.hold, domain, "1001", reason="maybe"),
            not_held(self.hold, domain, "1001", code="something_new"),
            not_held(self.hold, domain, "1001", code=["global_privilege"]),
        ):
            with self.subTest(answer=answer):
                self.answer = answer
                result = bridge.activate_target(self.migration, enabled=True, billing_hold=self.hold)
                self.assertTrue(result.is_err(), result)
                self.assertIs(retriability_of(result), Retriability.UNKNOWN)

    def test_a_known_target_domain_id_binds_the_outcome(self) -> None:
        self.migration.barrier_state = {**self.migration.barrier_state, "target_domain_id": "1001"}
        self.answer = outcome(self.hold, self.account.domain, "2002")
        self.assertTrue(bridge.activate_target(self.migration, enabled=True, billing_hold=self.hold).is_err())

    def test_an_inexact_hold_request_never_reaches_the_node(self) -> None:
        for bad in ({**self.hold, "generation": 0}, {**self.hold, "token": "x"}, {"token": self.hold["token"]}):
            with self.subTest(bad=bad):
                self.runner.run_playbook.reset_mock()
                result = bridge.activate_target(self.migration, enabled=True, billing_hold=bad)
                self.assertIs(retriability_of(result), Retriability.NOT_RETRIABLE)
                self.runner.run_playbook.assert_not_called()


class ComponentActivationHoldTests(ComponentAdmissionTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.migration = self.start(self.approve(self.review()))
        # fsm-bypass: a sealed, committed target about to be activated by its leased worker.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="activating",
            cutover_committed_at=timezone.now(),
            archive_sha256="a" * 64,
            barrier_state={
                "component_source_sealed": True,
                "component_target_sealed": True,
                "component_target_receipt_sha256": "b" * 64,
                "target_domain_id": TARGET_ID,
            },
        )
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        self.migration.refresh_from_db()
        self.token = uuid4()
        self.assertTrue(self.migration.acquire_lease(self.token, timedelta(minutes=5)))
        self.migration.refresh_from_db()
        self.hold = hold_request()
        self.receipt: dict[str, Any] = {}

    def variables(self, action: str, **terms: Any) -> dict[str, Any]:
        return transport.target_operation_variables(self.migration, self.token, action, **terms)

    def node(self):
        def run(_service, server, playbook, variables, **kwargs):
            encoded = base64.b64encode(json.dumps(self.receipt).encode()).decode()
            return Ok(AnsibleResult(True, playbook, f"PRAHO_COMPONENT_RESULT={encoded}", "", 0))

        return patch.object(AnsibleService, "run_server_playbook", autospec=True, side_effect=run)

    def active(self, action: str, **extra: Any) -> dict[str, Any]:
        return {
            "operation_id": str(self.migration.pk),
            "action": action,
            "phase": "active",
            "target_domain_id": TARGET_ID,
            **extra,
        }

    def test_activate_carries_the_hold_top_level_and_is_admitted(self) -> None:
        values = self.variables("target_activate", enabled=True, billing_hold=self.hold)
        self.assertEqual(values["component_operation"]["billing_hold"], self.hold)
        self.assertNotIn("billing_hold", values["component_request"])
        self.assertIsNone(transport.target_operation_refusal(self.target, values))
        without = self.variables("target_activate", enabled=True)
        self.assertNotIn("billing_hold", without["component_operation"])
        self.assertIsNone(transport.target_operation_refusal(self.target, without))

    def test_an_inexact_hold_is_refused_at_admission(self) -> None:
        values = self.variables("target_activate", enabled=True, billing_hold=self.hold)
        for bad in ({**self.hold, "generation": True}, {**self.hold, "extra": 1}, "hold"):
            with self.subTest(bad=bad):
                tampered = json.loads(json.dumps(values))
                tampered["component_operation"]["billing_hold"] = bad
                self.assertIsNotNone(transport.target_operation_refusal(self.target, tampered))
        with self.assertRaises(ValueError):
            self.variables("target_policy", enabled=True, billing_hold=self.hold)

    def test_the_activation_receipt_returns_the_exact_hold_outcome(self) -> None:
        domain = self.migration.component_approval.review.manifest["source"]["domain"]
        self.receipt = self.active("target_activate", billing_hold=outcome(self.hold, domain, TARGET_ID))
        with self.node():
            received = transport.run_target_operation(
                self.migration, self.token, "target_activate", enabled=True, billing_hold=self.hold
            )
        self.assertEqual(received["billing_hold"]["outcome"], "held")
        for wrong in (
            outcome(self.hold, domain, "123"),
            outcome(self.hold, domain, TARGET_ID, token=str(uuid4())),
            not_held(self.hold, domain, TARGET_ID, reason="maybe"),
        ):
            with self.subTest(wrong=wrong), self.node(), self.assertRaises(ValueError):
                self.receipt = self.active("target_activate", billing_hold=wrong)
                transport.run_target_operation(
                    self.migration, self.token, "target_activate", enabled=True, billing_hold=self.hold
                )
        self.receipt = self.active("target_activate")  # The hold was sent, but no outcome came back.
        with self.node(), self.assertRaises(ValueError):
            transport.run_target_operation(
                self.migration, self.token, "target_activate", enabled=True, billing_hold=self.hold
            )

    def test_platform_records_and_clears_a_hold_through_the_lease_bound_transport(self) -> None:
        record = {"token": self.hold["token"], "generation": 3, "held_digest": "d" * 64}
        for value in (record, None):
            with self.subTest(record=value):
                values = self.variables("target_billing_hold", billing_hold=value)
                self.assertEqual(values["component_operation"]["billing_hold"], value)
                self.assertIsNone(transport.target_operation_refusal(self.target, values))
                self.receipt = self.active("target_billing_hold", billing_hold=value)
                with self.node():
                    received = transport.run_target_operation(
                        self.migration, self.token, "target_billing_hold", billing_hold=value
                    )
                self.assertEqual(received["billing_hold"], value)
        self.receipt = self.active("target_billing_hold", billing_hold=None)
        with self.node(), self.assertRaises(ValueError):
            transport.run_target_operation(self.migration, self.token, "target_billing_hold", billing_hold=record)
        with self.assertRaises(ValueError):
            self.variables("target_billing_hold")  # Neither a record nor an explicit clear.
        with self.assertRaises(ValueError):
            self.variables("target_billing_hold", billing_hold={**record, "held_digest": "short"})
