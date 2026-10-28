"""Normal moves and recovery restore the same disabled, Unix-quiesced target."""

import base64
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

from django.test import SimpleTestCase

from apps.common.types import Ok
from apps.common.validators import SecureInputValidator
from apps.provisioning import migration_target_hold as hold
from apps.provisioning.virtualmin_pair_restore import PairStepResult
from apps.provisioning.virtualmin_validators import VirtualminValidator


class _ScriptedTokens:
    """A secrets stand-in whose token_urlsafe() returns scripted tokens and records the sizes asked for."""

    def __init__(self, tokens: list[str]) -> None:
        self._tokens = iter(tokens)
        self.requested: list[int] = []

    def token_urlsafe(self, nbytes: int) -> str:
        self.requested.append(nbytes)
        return next(self._tokens)


class HeldTargetRestoreTests(SimpleTestCase):
    def setUp(self):
        self.identity = uuid4()
        self.migration = SimpleNamespace(
            pk=self.identity,
            status="restoring",
            barrier_state={},
            target_server=SimpleNamespace(node_deployment=object()),
            account=SimpleNamespace(
                domain="customer.example",
                virtualmin_username="customer",
                template_name="Default",
                get_recovery_seed=lambda: "seed",
                disk_quota_mb=10,
                bandwidth_quota_mb=20,
            ),
            pre_migration_snapshot={"status": "active"},
        )
        self.archives = [{"archive_name": f"migration_{self.identity}.tar.gz", "checksum_sha256": "a" * 64}]
        self.service = Mock(backup_timeout=60)
        self.events = []

        def move(migration, token, status, **fields):
            self.events.append(("move", status))
            migration.status = status
            for name, value in fields.items():
                setattr(migration, name, value)

        def store(migration, token, state):
            migration.barrier_state = state

        self.service._move.side_effect = move
        self.service._store_barrier_state.side_effect = store
        self.service._domain.return_value = {"username": "customer", "enabled": False, "attributes": {"ID": "123"}}

    def test_placeholder_and_original_credentials_are_held_until_native_unix_proof(self):
        def node(migration, action):
            self.events.append(("node", action))
            self.assertEqual(migration.barrier_state["target_domain_id"], "123")
            self.assertEqual(migration.barrier_state["held_archives"], self.archives)

        with (
            patch.object(hold, "run_held_target_node", side_effect=node),
            patch.object(hold, "run_pair_step", return_value=Ok(PairStepResult("ok", "completed", True, ()))) as pair,
        ):
            hold.restore_held_target(self.service, self.migration, uuid4(), self.archives)
        calls = self.service._command.call_args_list
        self.assertEqual([call.args[2] for call in calls], ["create-domain", "disable-domain"])
        self.assertGreaterEqual(len(calls[0].kwargs["pass"]), 48)
        self.assertEqual(self.events[-2:], [("node", "verify-held"), ("move", "verifying")])
        self.assertTrue(self.migration.barrier_state["held_restore_complete"])
        variables = pair.call_args.args[1]
        self.assertTrue(variables["pair_recovery"])
        self.assertEqual(variables["pair_base_archive"], self.archives[0]["archive_name"])
        self.assertEqual(variables["chain_domain_id"], "123")

    def test_placeholder_password_always_passes_the_parameter_validator(self):
        # Every Virtualmin parameter is checked against SecureInputValidator's injection heuristics,
        # and a random token containing "--" reads as an SQL comment: Virtualmin Lab CI saw two held
        # restores fail definitively with "Invalid input detected". A rejected candidate is drawn again.
        rejected = "aA1--" + "b" * 59
        accepted = "cC2_" + "d" * 60
        tokens = _ScriptedTokens([rejected, accepted])
        # The gateway validates every parameter exactly like this before any request is sent
        self.service._command.side_effect = lambda _migration, _server, _program, **params: (
            VirtualminValidator.validate_virtualmin_params(params)
        )
        with (
            patch.object(hold, "secrets", tokens),
            patch.object(hold, "run_held_target_node"),
            patch.object(hold, "run_pair_step", return_value=Ok(PairStepResult("ok", "completed", True, ()))),
            self.assertNoLogs("apps.common.validators", level="WARNING"),
        ):
            hold.restore_held_target(self.service, self.migration, uuid4(), self.archives)
        create = self.service._command.call_args_list[0]
        self.assertEqual(create.args[2], "create-domain")
        self.assertEqual(create.kwargs["pass"], accepted)
        self.assertIsNone(SecureInputValidator.first_malicious_pattern(create.kwargs["pass"]))
        self.assertEqual(tokens.requested, [48, 48])

    def test_placeholder_that_never_passes_the_validator_creates_nothing(self):
        tokens = _ScriptedTokens(["aA1--" + "b" * 59] * 1000)
        with (
            patch.object(hold, "secrets", tokens),
            patch.object(hold, "run_held_target_node") as node,
            patch.object(hold, "run_pair_step", return_value=Ok(PairStepResult("ok", "completed", True, ()))),
            self.assertRaisesRegex(RuntimeError, "passes parameter validation"),
        ):
            hold.restore_held_target(self.service, self.migration, uuid4(), self.archives)
        self.service._command.assert_not_called()
        node.assert_not_called()

    def test_failed_unix_proof_never_marks_restore_complete_or_moves_to_verifying(self):
        def node(migration, action):
            if action == "verify-held":
                raise RuntimeError("shadow unlocked")

        with (
            patch.object(hold, "run_held_target_node", side_effect=node),
            patch.object(hold, "run_pair_step", return_value=Ok(PairStepResult("ok", "completed", True, ()))),
            self.assertRaisesRegex(RuntimeError, "shadow unlocked"),
        ):
            hold.restore_held_target(self.service, self.migration, uuid4(), self.archives)
        self.assertFalse(self.migration.barrier_state.get("held_restore_complete"))
        self.assertEqual(self.migration.status, "restoring")

    def test_recorded_target_identity_is_reused_without_recreating_the_domain(self):
        self.migration.barrier_state = {"target_domain_id": "123", "held_archives": self.archives}
        with (
            patch.object(hold, "run_held_target_node"),
            patch.object(hold, "run_pair_step", return_value=Ok(PairStepResult("ok", "completed", True, ()))),
        ):
            hold.restore_held_target(self.service, self.migration, uuid4(), self.archives)
        self.service._command.assert_not_called()

    def test_replay_refuses_a_target_with_another_recorded_identity(self):
        self.migration.barrier_state = {"target_domain_id": "456", "held_archives": self.archives}
        with patch.object(hold, "run_held_target_node") as node, self.assertRaisesRegex(ValueError, "identity"):
            hold.restore_held_target(self.service, self.migration, uuid4(), self.archives)
        self.service._command.assert_not_called()
        node.assert_not_called()

    def test_node_variables_prefer_shared_archive_and_cleanup_needs_no_retained_archive(self):
        self.migration.barrier_state = {
            "target_domain_id": "123",
            "held_archives": self.archives,
            "recovery_archives": [{"archive_name": "wrong", "checksum_sha256": "b" * 64}],
        }
        with patch("apps.infrastructure.ansible_service.AnsibleService") as runner:
            runner.return_value.run_playbook.return_value = Ok(SimpleNamespace(success=True))
            hold.run_held_target_node(self.migration, "verify-held")
            variables = runner.return_value.run_playbook.call_args.args[2]
            self.assertEqual(variables["recovery_archive"], self.archives[0]["archive_name"])
            self.migration.barrier_state.pop("held_archives")
            self.migration.barrier_state.pop("recovery_archives")
            hold.cleanup_held_target(self.migration)
        self.assertEqual(runner.return_value.run_playbook.call_args.args[2]["recovery_action"], "cleanup")

    def test_policy_rpc_validates_current_enabled_proof_after_archive_secrets_are_retired(self):
        self.migration.barrier_state = {"target_domain_id": "123"}
        proof = {"domain_id": "123", "owner": "customer", "enabled": False}
        stdout = "PRAHO_POLICY_RESULT=" + base64.b64encode(json.dumps(proof).encode()).decode()
        with patch("apps.infrastructure.ansible_service.AnsibleService") as runner:
            runner.return_value.run_playbook.return_value = Ok(SimpleNamespace(success=True, stdout=stdout))
            hold.run_held_target_node(self.migration, "reconcile_policy", enabled=False)
            call = runner.return_value.run_playbook.call_args
            self.assertEqual(call.args[2]["recovery_enabled"], False)
            self.assertEqual(call.kwargs["timeout_seconds"], 300)
            with self.assertRaisesRegex(RuntimeError, "proof"):
                hold.run_held_target_node(self.migration, "reconcile_policy", enabled=True)
