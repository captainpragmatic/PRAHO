"""Platform's side of the database write hold: one playbook run per action, a receipt bound to its request (#776).

Only the SSH boundary is replaced: the gateway, the transport and the receipt decoding run as in production.
"""

from __future__ import annotations

import base64
import importlib.util
import inspect
import json
import sys
from typing import Any
from unittest.mock import patch
from uuid import UUID, uuid4

from django.conf import settings
from django.test import TestCase

from apps.common.types import Ok
from apps.infrastructure.ansible_service import AnsibleResult, AnsibleService
from apps.provisioning import database_hold_gateway as gateway
from apps.provisioning.virtualmin_models import VirtualminServer

INSTALLATION = UUID("12345678-1234-1234-1234-123456789abc")
DIGEST = "a" * 64


def _helper():
    path = settings.BASE_DIR / "infrastructure/ansible/playbooks/files/praho_database_hold.py"
    spec = importlib.util.spec_from_file_location("database_hold_node_defaults", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class GatewayFixture(TestCase):
    def setUp(self) -> None:
        self.server = VirtualminServer.objects.create(name="Hold node", hostname="hold-node.example.net")
        self.identity = gateway.HoldIdentity(
            server_id=self.server.pk, domain_id="42", domain="shop.test", installation=INSTALLATION
        )
        self.token = uuid4()
        self.calls: list[tuple[str, dict[str, Any], int]] = []

    def node(self, *receipts: object, success: bool = True):
        """Each run prints the next receipt, the way the playbook does."""
        outputs = iter(receipts)

        def run(_service, server, playbook, variables, *, timeout_seconds):
            self.assertEqual(server.pk, self.server.pk)
            self.calls.append((playbook, variables, timeout_seconds))
            receipt = next(outputs)
            text = receipt if isinstance(receipt, str) else json.dumps(receipt)
            marker = "PRAHO_DATABASE_HOLD_RESULT=" + base64.b64encode(text.encode()).decode()
            return Ok(AnsibleResult(success, playbook, marker, "", 0 if success else 2))

        return patch.object(AnsibleService, "run_server_playbook", autospec=True, side_effect=run)

    def wire_identity(self) -> dict[str, str]:
        return {"domain_id": "42", "domain": "shop.test", "installation": str(INSTALLATION)}

    def ok(self, action: str, **fields: Any) -> dict[str, Any]:
        receipt = {
            "outcome": "ok",
            "action": action,
            "identity": self.wire_identity(),
            "token": str(self.token),
            "generation": 3,
            "phase": {"probe": "probed", "hold": "held", "release": "released", "verify": "verified"}.get(
                action, "fenced"
            ),
            "held_digest": DIGEST if action in {"probe", "hold"} else None,
            "sessions_remaining": [],
            "drift": [],
        }
        return {**receipt, **fields}

    def refused(self, action: str, code: str, **fields: Any) -> dict[str, Any]:
        receipt = {
            "outcome": "refused",
            "action": action,
            "identity": self.wire_identity(),
            "token": str(self.token) if action in {"probe", "hold", "fence"} else None,
            "generation": 3 if action != "fence" else None,
            "code": code,
            "detail": f"{code}: shop@localhost on shop_db",
        }
        return {**receipt, **fields}

    def uncertain(self, result) -> None:
        self.assertTrue(result.is_err(), result)
        self.assertEqual(result.unwrap_err().code, "uncertain")


class RequestTests(GatewayFixture):
    def test_each_action_sends_exactly_the_helpers_request_shape(self) -> None:
        receipts = [
            self.ok("probe"),
            self.ok("hold"),
            self.ok("release", token=None),
            self.ok("verify", token=None),
            self.ok("fence", generation=0),
        ]
        with self.node(*receipts):
            gateway.probe(self.identity, token=self.token, generation=3)
            gateway.hold(self.identity, token=self.token, generation=3)
            gateway.release(self.identity, generation=3)
            gateway.verify(self.identity, generation=3)
            gateway.fence(self.identity, token=self.token)
        identity = self.wire_identity()
        token = str(self.token)
        self.assertEqual(
            [variables for _playbook, variables, _timeout in self.calls],
            [
                {
                    "hold_action": "probe",
                    "hold_request": {"action": "probe", "identity": identity, "token": token, "generation": 3},
                },
                {
                    "hold_action": "hold",
                    "hold_request": {"action": "hold", "identity": identity, "token": token, "generation": 3},
                },
                {"hold_action": "release", "hold_request": {"action": "release", "identity": identity, "generation": 3}},
                {"hold_action": "verify", "hold_request": {"action": "verify", "identity": identity, "generation": 3}},
                {"hold_action": "fence", "hold_request": {"action": "fence", "identity": identity, "token": token}},
            ],
        )
        self.assertEqual({playbook for playbook, _variables, _timeout in self.calls}, {"virtualmin_database_hold.yml"})

    def test_the_helper_accepts_every_request_the_gateway_sends(self) -> None:
        receipts = [self.ok("probe"), self.ok("hold"), self.ok("release"), self.ok("verify"), self.ok("fence")]
        with self.node(*receipts):
            gateway.probe(self.identity, token=self.token, generation=3)
            gateway.hold(self.identity, token=self.token, generation=3)
            gateway.release(self.identity, generation=3)
            gateway.verify(self.identity, generation=3)
            gateway.fence(self.identity, token=self.token)
        helper = _helper()
        for _playbook, variables, _timeout in self.calls:
            request = variables["hold_request"]
            parsed = helper.DatabaseHold._request(request)
            self.assertEqual(
                parsed,
                (variables["hold_action"], self.wire_identity(), request.get("token"), request.get("generation")),
            )

    def test_every_timeout_outlasts_the_helpers_lock_waits_and_drain(self) -> None:
        defaults = inspect.signature(_helper().DatabaseHold.__init__).parameters
        locks = 4 * defaults["lock_seconds"].default  # Migration, both component fences, then the hold lock.
        drain = defaults["drain_seconds"].default
        for action, timeout in gateway.TIMEOUTS.items():
            with self.subTest(action=action):
                # 60s for the SSH connection, the copy and the scope's SQL around the waits.
                self.assertGreater(timeout, locks + (drain if action == "hold" else 0) + 60)


class ReceiptTests(GatewayFixture):
    def test_a_hold_receipt_becomes_a_typed_receipt(self) -> None:
        with self.node(self.ok("hold", phase="holding", sessions_remaining=[12, 13])):
            result = gateway.hold(self.identity, token=self.token, generation=3)
        self.assertEqual(
            result.unwrap(),
            gateway.HoldReceipt(
                action="hold",
                identity=self.identity,
                token=self.token,
                generation=3,
                phase="holding",
                held_digest=DIGEST,
                sessions_remaining=(12, 13),
                drift=(),
            ),
        )

    def test_release_and_verify_echo_the_journals_token_or_none(self) -> None:
        with self.node(self.ok("release", token=None), self.ok("verify", drift=["not_held"], token=str(self.token))):
            released = gateway.release(self.identity, generation=3).unwrap()
            verified = gateway.verify(self.identity, generation=3).unwrap()
        self.assertIsNone(released.token)
        self.assertEqual((verified.token, verified.drift), (self.token, ("not_held",)))

    def test_fence_reports_the_journals_generation(self) -> None:
        with self.node(self.ok("fence", generation=0)):
            self.assertEqual(gateway.fence(self.identity, token=self.token).unwrap().generation, 0)

    def test_a_named_node_refusal_is_returned_as_itself(self) -> None:
        with self.node(self.refused("hold", "global_privilege")):
            result = gateway.hold(self.identity, token=self.token, generation=3)
        self.assertEqual(
            result.unwrap_err(), gateway.HoldRefusal("global_privilege", "global_privilege: shop@localhost on shop_db")
        )

    def test_every_closed_refusal_code_is_accepted(self) -> None:
        self.assertEqual(len(gateway.NODE_REFUSALS), 20)
        for code in gateway.NODE_REFUSALS:
            with self.subTest(code=code), self.node(self.refused("verify", code)):
                self.assertEqual(gateway.verify(self.identity, generation=3).unwrap_err().code, code)


class UncertainTests(GatewayFixture):
    """Anything but an exact receipt for this request is a lost response: the caller verifies before deciding."""

    def test_a_failed_or_unreadable_run(self) -> None:
        with self.node(self.ok("hold"), success=False):
            self.uncertain(gateway.hold(self.identity, token=self.token, generation=3))
        with self.node("not json"):
            self.uncertain(gateway.hold(self.identity, token=self.token, generation=3))

    def test_a_receipt_for_another_request(self) -> None:
        other = {"domain_id": "43", "domain": "shop.test", "installation": str(INSTALLATION)}
        for change in (
            {"action": "probe"},
            {"identity": other},
            {"identity": {**self.wire_identity(), "installation": str(uuid4())}},
            {"token": str(uuid4())},
            {"generation": 4},
        ):
            with self.subTest(change=change), self.node({**self.ok("hold"), **change}):
                self.uncertain(gateway.hold(self.identity, token=self.token, generation=3))
        with self.subTest(change="refusal for another token"), self.node(
            self.refused("hold", "lock_busy", token=str(uuid4()))
        ):
            self.uncertain(gateway.hold(self.identity, token=self.token, generation=3))

    def test_a_receipt_outside_the_closed_shape(self) -> None:
        for change in (
            {"extra": 1},
            {"phase": "released"},
            {"phase": "holding"},  # Holding with no session left is not a state the helper reports.
            {"sessions_remaining": [12]},  # Held with a session left, likewise.
            {"held_digest": "short"},
            {"sessions_remaining": ["12"]},
            {"sessions_remaining": [-1]},
            {"drift": "not_held"},
            {"generation": True},
            {"outcome": "maybe"},
        ):
            with self.subTest(change=change), self.node(self.ok("hold", **change)):
                self.uncertain(gateway.hold(self.identity, token=self.token, generation=3))
        missing = self.ok("hold")
        del missing["drift"]
        with self.node(missing):
            self.uncertain(gateway.hold(self.identity, token=self.token, generation=3))

    def test_an_unknown_refusal_code_or_a_refusal_with_extra_terms(self) -> None:
        for receipt in (
            self.refused("hold", "something_new"),
            self.refused("hold", "uncertain"),  # Only the gateway names a lost response.
            {**self.refused("hold", "lock_busy"), "phase": "held"},
        ):
            with self.subTest(receipt=receipt), self.node(receipt):
                self.uncertain(gateway.hold(self.identity, token=self.token, generation=3))

    def test_the_transport_rejects_a_request_outside_the_actions(self) -> None:
        with self.assertRaises(ValueError):
            gateway._run(self.identity, "drop", {})

    def test_no_run_reaches_the_node_with_an_unsaved_or_unknown_server(self) -> None:
        identity = gateway.HoldIdentity(server_id=uuid4(), domain_id="42", domain="shop.test", installation=INSTALLATION)
        with self.node(self.ok("hold")) as boundary, self.assertRaises(VirtualminServer.DoesNotExist):
            gateway.hold(identity, token=self.token, generation=3)
        boundary.assert_not_called()
