"""Native activation with a billing hold (#776, plan revision 3 item 4): compare, hold, then unlock and enable.

The bridge runs against a fake target: Virtualmin, cron, the SQL account and the hold helper. Only the order and
the outcomes are under test; the hold helper itself is qualified in test_database_hold_node and the lab.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch
from uuid import uuid4

from django.test import SimpleTestCase

from tests.provisioning import test_bridge_node as bridge

BRIDGE_ID, DOMAIN = bridge.BRIDGE_ID, bridge.DOMAIN

INSTALLATION = "12345678-1234-1234-1234-123456789abc"
USAGE = "GRANT USAGE ON *.* TO `shop`@`localhost` IDENTIFIED BY PASSWORD '*AB12'"
ORIGINAL = [USAGE, "GRANT ALL PRIVILEGES ON `shop\\_db`.* TO `shop`@`localhost`"]
HELD = [USAGE, "GRANT SELECT, DELETE, DROP ON `shop\\_db`.* TO `shop`@`localhost`"]
DIGEST = "d" * 64
HOLD_HELPER = bridge.HELPER.with_name("praho_database_hold.py")


def grants_sha(lines: list[str]) -> str:
    cleaned = [line.replace(" IDENTIFIED BY PASSWORD '*AB12'", "") for line in lines]
    return hashlib.sha256("\n".join(sorted(cleaned)).encode()).hexdigest()


class Target:
    """The target node: domains, cron, one SQL account and the hold helper's journal."""

    def __init__(self, test: SimpleTestCase) -> None:
        self.test = test
        self.events: list[str] = []
        self.disabled = {DOMAIN}
        self.cron = ""
        self.locked = True  # The restore left the account locked; activation unlocks it.
        self.grants = list(ORIGINAL)
        self.hold_outcome = "held"
        self.undo_fails: str | None = None
        self.foreign_hold = False  # Another token already holds this generation.
        self.held = False
        # Virtualmin suspends MySQL by changing the password; the enable callback puts the original back.
        self.authentication = "0" * 41

    def execute(self, argv: list[str]) -> str:
        if "--multiline" in argv:
            return "    Username for mysql: shop\n    Password for mysql: owner-db-pass\n"
        if argv[:2] == ["virtualmin", "list-domains"]:
            if "--disabled" in argv:
                return "\n".join(sorted(self.disabled))
            return "1001" if "--id-only" in argv else "shop"
        if argv[:2] == ["virtualmin", "enable-domain"]:
            self.events.append("enable")
            self.authentication = "*AB12"
            self.disabled.discard(argv[argv.index("--domain") + 1])
        if argv[:3] == ["crontab", "-u", "shop"]:
            if argv[-1] == "-l":
                return self.cron
            if argv[-1] != "-r":
                self.cron = Path(argv[-1]).read_text()
        if argv[0] == "mysql":
            return self.sql(argv[-1])

        return ""

    def sql(self, statement: str) -> str:
        if statement.startswith("ALTER USER"):
            self.locked = statement.endswith("LOCK") and not statement.endswith("UNLOCK")
            self.events.append("lock" if self.locked else "unlock")
            return ""
        if "account_locked" in statement:
            return "true" if self.locked else "false"
        if "plugin" in statement:
            return "mysql_native_password"
        if "authentication_string" in statement:
            return self.authentication
        if statement.startswith("SHOW GRANTS"):
            self.events.append("grants")
            return "\n".join(self.grants)
        raise AssertionError(statement)

    def run_hold(self, request: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0911 -- One answer per helper action.
        action = request["action"]
        self.events.append(action)
        self.test.assertEqual(request["identity"], {"domain_id": "1001", "domain": DOMAIN, "installation": INSTALLATION})
        echo = {key: request.get(key) for key in ("action", "identity", "token", "generation")}
        if action == "release" and self.foreign_hold:
            self.test.assertEqual(request.get("token"), self.test.token)
            return {**echo, "outcome": "refused", "code": "generation_conflict", "detail": "another token"}
        if action == self.undo_fails:
            return {**echo, "outcome": "refused", "code": "operator_inspection_required", "detail": "shop@localhost"}
        if action == "hold":
            if self.hold_outcome == "refused":
                return {**echo, "outcome": "refused", "code": "global_privilege", "detail": "backup@localhost"}
            if self.hold_outcome == "uncertain":
                self.grants = list(HELD)  # The revoke landed, then the response was lost.
                raise ValueError("the hold helper exited non-zero")
            self.grants = list(HELD)
            self.held = True
            phase, sessions = ("holding", [12]) if self.hold_outcome == "partial" else ("held", [])
            return {**echo, "outcome": "ok", "phase": phase, "held_digest": DIGEST, "sessions_remaining": sessions, "drift": []}
        if action == "verify":
            if self.held:
                # A partial hold's recorded session is still there, as the helper's verify reports it.
                sessions = [12] if self.hold_outcome == "partial" else []
                return {**echo, "outcome": "ok", "token": request.get("token"), "phase": "verified", "held_digest": DIGEST,
                        "sessions_remaining": sessions, "drift": []}
            return {**echo, "outcome": "ok", "phase": "verified", "held_digest": None, "sessions_remaining": [],
                    "drift": ["not_held"]}
        if action == "fence":
            return {**echo, "outcome": "ok", "generation": 0, "phase": "fenced", "held_digest": None,
                    "sessions_remaining": [], "drift": []}
        if action == "release":
            self.grants, self.held = list(ORIGINAL), False
            return {**echo, "outcome": "ok", "phase": "released", "held_digest": None, "sessions_remaining": [],
                    "drift": []}
        raise AssertionError(action)


class BillingHoldActivationTests(SimpleTestCase):
    def setUp(self) -> None:
        bridge.BridgeNodeTests.setUp(self)
        self.node.hold_helper = HOLD_HELPER
        self.target = Target(self)
        self.node.execute = self.target.execute
        self.node.run_hold = self.target.run_hold
        self.token = str(uuid4())
        self.hold = {"token": self.token, "generation": 3, "installation": INSTALLATION}
        cron = "*/5 * * * * /bin/true\n"
        self.node.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        incoming = self.node.directory(BRIDGE_ID) / "activation.incoming"
        incoming.write_text(cron)
        incoming.chmod(0o600)
        self.record = {
            "enabled": [{"name": DOMAIN, "enabled": True}],
            "accounts": [
                {
                    "user": "shop",
                    "host": "localhost",
                    "locked": False,
                    "plugin": "mysql_native_password",
                    "auth_sha": hashlib.sha256(b"*AB12").hexdigest(),
                    "grants_sha": grants_sha(ORIGINAL),
                }
            ],
            "databases": [],
            "has_crontab": True,
            "crontab_sha": hashlib.sha256(cron.encode().rstrip(b"\n")).hexdigest(),
            "active_sha": hashlib.sha256(cron.encode()).hexdigest(),
        }
        self.node.stage_activation(BRIDGE_ID, DOMAIN, "shop", self.record)

    def activate(self, hold: dict[str, Any] | None = None) -> Any:
        return self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", self.record, billing_hold=hold or self.hold)

    def test_grants_are_compared_then_held_before_anything_is_unlocked_or_enabled(self) -> None:
        payload = self.activate()
        self.assertEqual(
            payload["billing_hold"],
            {
                "outcome": "held",
                "identity": {"domain_id": "1001", "domain": DOMAIN, "installation": INSTALLATION},
                "token": self.token,
                "generation": 3,
                "held_digest": DIGEST,
            },
        )
        events = self.target.events
        self.assertLess(events.index("grants"), events.index("hold"))
        self.assertLess(events.index("hold"), events.index("unlock"))
        self.assertLess(events.index("unlock"), events.index("enable"))
        # The final check verifies the held digest, after the unlock, instead of the original grants.
        self.assertGreater(len(events) - 1 - events[::-1].index("verify"), events.index("enable"))
        self.assertEqual(self.target.grants, HELD)
        self.assertFalse(self.target.locked)
        self.assertEqual(self.target.disabled, set())

    def test_without_a_hold_request_activation_is_unchanged(self) -> None:
        payload = self.node.activate_target(BRIDGE_ID, DOMAIN, "shop", self.record)
        self.assertNotIn("hold", self.target.events)
        self.assertFalse(payload)
        self.assertEqual(self.target.grants, ORIGINAL)

    def test_a_refused_partial_or_uncertain_hold_is_undone_then_activation_completes(self) -> None:
        for outcome, code in (("refused", "global_privilege"), ("partial", None), ("uncertain", None)):
            with self.subTest(outcome=outcome):
                self.setUp()
                self.target.hold_outcome = outcome
                payload = self.activate()
                hold = payload["billing_hold"]
                self.assertEqual((hold["outcome"], hold["reason"], hold["code"]), ("not_held", outcome, code))
                self.assertEqual((hold["token"], hold["generation"]), (self.token, 3))
                events = self.target.events
                after = events[events.index("hold") + 1 :]
                self.assertEqual([e for e in after if e in {"fence", "release", "verify"}][:3], ["fence", "release", "verify"])
                self.assertLess(events.index("release"), events.index("unlock"))
                self.assertEqual(self.target.grants, ORIGINAL)
                self.assertFalse(self.target.locked)

    def test_a_hold_receipt_for_another_domain_is_uncertain_and_undone(self) -> None:
        real = self.target.run_hold

        def elsewhere(request):
            receipt = real(request)
            if request["action"] == "hold":
                receipt["identity"] = {**receipt["identity"], "domain_id": "2002"}
            return receipt

        self.node.run_hold = elsewhere
        hold = self.activate()["billing_hold"]
        self.assertEqual((hold["outcome"], hold["reason"]), ("not_held", "uncertain"))
        self.assertIn("release", self.target.events)

    def test_another_tokens_hold_is_kept_and_activation_stops_locked(self) -> None:
        self.target.hold_outcome = "refused"
        self.target.foreign_hold = True
        with self.assertRaises(ValueError):
            self.activate()
        self.assertTrue(self.target.locked)
        self.assertNotIn("unlock", self.target.events)

    def test_a_refused_fence_is_never_followed_by_a_release(self) -> None:
        self.target.hold_outcome = "refused"
        self.target.undo_fails = "fence"
        with self.assertRaises(ValueError):
            self.activate()
        self.assertNotIn("release", self.target.events)

    def test_an_undo_that_does_not_complete_stops_activation_with_everything_still_locked(self) -> None:
        for step in ("fence", "release"):
            with self.subTest(step=step):
                self.setUp()
                self.target.hold_outcome = "refused"
                self.target.undo_fails = step
                with self.assertRaises(ValueError):
                    self.activate()
                self.assertTrue(self.target.locked)
                self.assertNotIn("unlock", self.target.events)
                self.assertNotIn("enable", self.target.events)

    def test_original_grants_that_differ_stop_activation_before_any_hold(self) -> None:
        self.target.grants = [USAGE, "GRANT SELECT ON `shop\\_db`.* TO `shop`@`localhost`"]
        with self.assertRaisesRegex(ValueError, "grants"):
            self.activate()
        self.assertNotIn("hold", self.target.events)
        self.assertNotIn("unlock", self.target.events)

    def test_a_held_digest_that_changes_before_the_final_check_fails_activation(self) -> None:
        real = self.target.run_hold

        def drifted(request):
            receipt = real(request)
            if request["action"] == "verify" and "enable" in self.target.events:
                receipt["drift"] = ["regranted:shop@localhost:shop\\_db"]
            return receipt

        self.node.run_hold = drifted
        with self.assertRaisesRegex(ValueError, "hold"):
            self.activate()

    def test_a_completed_activation_replays_its_hold_outcome_without_acting_again(self) -> None:
        first = self.activate()
        self.target.events.clear()
        self.assertEqual(self.activate(), first)
        self.assertEqual(self.target.events, [])

    def test_the_hold_request_is_exact(self) -> None:
        for bad in (
            {"token": self.token, "generation": 3},
            {**self.hold, "generation": 0},
            {**self.hold, "generation": True},
            {**self.hold, "token": "not-a-uuid"},
            {**self.hold, "installation": "x"},
            {**self.hold, "extra": 1},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.module.billing_hold_request(json.dumps(bad))
        self.assertIsNone(self.module.billing_hold_request(""))
        self.assertEqual(self.module.billing_hold_request(json.dumps(self.hold)), self.hold)

    def test_the_entrypoint_passes_the_hold_and_prints_its_outcome(self) -> None:
        printed = []
        environment = {
            "PRAHO_BRIDGE_ID": BRIDGE_ID,
            "PRAHO_BRIDGE_ACTION": "activate",
            "PRAHO_BRIDGE_DOMAIN": DOMAIN,
            "PRAHO_BRIDGE_OWNER": "shop",
            "PRAHO_BARRIER_RECORD": json.dumps(self.record),
            "PRAHO_BRIDGE_BILLING_HOLD": json.dumps(self.hold),
        }
        node = Mock(**{"activate_target.return_value": {"billing_hold": {"outcome": "held"}}})
        with (
            patch.dict(os.environ, environment),
            patch.object(self.module, "NodeBridge", return_value=node),
            patch("builtins.print", side_effect=printed.append),
        ):
            self.module.main()
        node.activate_target.assert_called_once_with(
            BRIDGE_ID, DOMAIN, "shop", self.record, enabled=None, billing_hold=self.hold
        )
        result = json.loads(base64.b64decode(printed[0].removeprefix("BRIDGE_RESULT=")))
        self.assertEqual(result["payload"], {"billing_hold": {"outcome": "held"}})

    def test_a_held_owner_is_probed_with_a_read_not_a_write(self) -> None:
        probes = []

        def probe(argv, **options):
            probes.append(argv[-1])
            return subprocess.CompletedProcess(argv, 0, "1\n", "")

        self.record["databases"] = ["shop_db"]
        incoming = self.node.directory(BRIDGE_ID) / "activation.incoming"
        incoming.write_text("*/5 * * * * /bin/true\n")
        incoming.chmod(0o600)
        (self.node.directory(BRIDGE_ID) / "activation.json").unlink()
        self.node.stage_activation(BRIDGE_ID, DOMAIN, "shop", self.record)
        with patch.object(self.module.subprocess, "run", side_effect=probe):
            self.assertEqual(self.activate()["billing_hold"]["outcome"], "held")
        self.assertEqual(probes, ["SELECT 1"])
