"""The hold playbook runs only for the request the open episode stands for: transport admission."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase

from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.database_hold_gateway import HoldIdentity
from apps.provisioning.database_overage_admission import database_hold_transport_refusal
from apps.settings.models import SystemSetting
from tests.provisioning.database_overage_fixtures import make_overage_account
from tests.provisioning.test_database_overage_models import _episode

PLAYBOOK = "virtualmin_database_hold.yml"


class _Admission:
    def setUp(self):
        self.fixture = make_overage_account("admit")
        self.episode = _episode(self.fixture)
        self.flag = SystemSetting.objects.create(
            key="provisioning.database_overage_enabled",
            value=True,
            default_value=False,
            data_type="boolean",
            category="provisioning",
        )
        self.identity = HoldIdentity(
            server_id=self.fixture.server.pk,
            domain_id=self.episode.domain_id,
            domain=self.episode.domain,
            installation=self.episode.installation,
        )

    def holding(self):
        self.episode.start_hold(token=uuid4(), generation=self.episode.hold_generation + 1)
        self.episode.save()

    def held(self):
        self.holding()
        self.episode.confirm_held(digest="5e" * 32)
        self.episode.save()

    def releasing(self):
        self.held()
        self.episode.start_release("waived")
        self.episode.save()

    def values(self, action, identity=None, **terms):
        """The playbook variables exactly as the gateway sends them."""
        wire = (identity or self.identity).wire()
        return {"hold_action": action, "hold_request": {"action": action, "identity": wire, **terms}}

    def hold_terms(self):
        return {"token": str(self.episode.hold_token), "generation": self.episode.hold_generation}

    def refusal(self, values, server=None):
        return database_hold_transport_refusal(server or self.fixture.server, values)


class DatabaseHoldTransportAdmissionTests(_Admission, TestCase):
    def test_the_hold_the_episode_decided_on_is_admitted(self):
        self.holding()
        self.assertIsNone(self.refusal(self.values("hold", **self.hold_terms())))

    def test_a_hold_for_another_token_or_generation_is_refused(self):
        self.holding()
        self.assertEqual(self.episode.hold_generation, 1)
        for terms in (
            {"token": str(uuid4()), "generation": self.episode.hold_generation},
            {"token": str(self.episode.hold_token), "generation": self.episode.hold_generation + 1},
            {"token": str(self.episode.hold_token), "generation": str(self.episode.hold_generation)},
            {"token": str(self.episode.hold_token), "generation": True},  # equal to 1, but not a generation
            {"token": "not-a-uuid", "generation": self.episode.hold_generation},
        ):
            with self.subTest(terms=terms):
                self.assertIsNotNone(self.refusal(self.values("hold", **terms)))

    def test_a_hold_is_refused_unless_the_episode_is_holding(self):
        terms = {"token": str(uuid4()), "generation": 1}
        self.assertIsNotNone(self.refusal(self.values("hold", **terms)))  # still in grace
        self.held()
        self.assertIsNotNone(self.refusal(self.values("hold", **self.hold_terms())))

    def test_a_hold_is_refused_with_the_flag_off(self):
        self.holding()
        SystemSetting.objects.filter(pk=self.flag.pk).update(value=False)
        self.assertIsNotNone(self.refusal(self.values("hold", **self.hold_terms())))

    def test_a_hold_for_another_domain_server_or_installation_is_refused(self):
        self.holding()
        other_server = make_overage_account("elsewhere").server
        for identity, server in (
            (HoldIdentity(self.identity.server_id, "17002", self.identity.domain, self.identity.installation), None),
            (HoldIdentity(self.identity.server_id, self.identity.domain_id, "other.test", self.identity.installation), None),
            (HoldIdentity(self.identity.server_id, self.identity.domain_id, self.identity.domain, uuid4()), None),
            (self.identity, other_server),
        ):
            with self.subTest(identity=identity, server=server):
                self.assertIsNotNone(self.refusal(self.values("hold", identity, **self.hold_terms()), server))

    def test_a_request_with_other_terms_is_refused(self):
        self.holding()
        values = self.values("hold", **self.hold_terms())
        for change in (
            {"hold_action": "verify"},
            {"hold_action": "drop"},
            {"hold_request": {**values["hold_request"], "scope": "all"}},
            {"hold_request": {**values["hold_request"], "action": "release"}},
            {"hold_request": {**values["hold_request"], "identity": {**values["hold_request"]["identity"], "x": 1}}},
            {"hold_request": "hold"},
        ):
            with self.subTest(change=change):
                self.assertIsNotNone(self.refusal({**values, **change}))
        self.assertIsNotNone(self.refusal(None))

    def test_verify_is_admitted_while_holding_or_held_for_the_current_generation(self):
        self.holding()
        self.assertIsNone(self.refusal(self.values("verify", generation=self.episode.hold_generation)))
        self.episode.confirm_held(digest="5e" * 32)
        self.episode.save()
        self.assertIsNone(self.refusal(self.values("verify", generation=self.episode.hold_generation)))
        self.assertIsNotNone(self.refusal(self.values("verify", generation=self.episode.hold_generation - 1)))

    def test_fence_and_release_are_admitted_only_while_releasing_the_episodes_hold(self):
        self.held()
        fence = self.values("fence", token=str(self.episode.hold_token))
        release = self.values("release", generation=self.episode.hold_generation)
        self.assertIsNotNone(self.refusal(fence))
        self.assertIsNotNone(self.refusal(release))
        self.episode.start_release("waived")
        self.episode.save()
        SystemSetting.objects.filter(pk=self.flag.pk).update(value=False)  # a rollback releases with the flag off
        self.assertIsNone(self.refusal(fence))
        self.assertIsNone(self.refusal(release))
        self.assertIsNotNone(self.refusal(self.values("fence", token=str(uuid4()))))
        self.assertIsNotNone(self.refusal(self.values("release", generation=self.episode.hold_generation + 1)))

    def test_a_held_episodes_token_is_fenced_only_to_reconcile_drift(self):
        self.held()
        fence = self.values("fence", token=str(self.episode.hold_token))
        self.assertIsNotNone(self.refusal(fence))
        self.episode.needs_reconcile = True
        self.episode.save()
        self.assertIsNone(self.refusal(fence))
        self.assertIsNotNone(self.refusal(self.values("fence", token=str(uuid4()))))

    def test_nothing_is_admitted_for_a_closed_episode(self):
        self.releasing()
        generation = self.episode.hold_generation
        self.episode.confirm_released_to_closed()
        self.episode.save()
        self.assertIsNotNone(self.refusal(self.values("release", generation=generation)))
        self.assertIsNotNone(self.refusal(self.values("verify", generation=generation)))

    def test_probe_is_never_admitted(self):
        self.holding()  # nothing in the over-allowance flow probes; the playbook is not a free read
        self.assertIsNotNone(self.refusal(self.values("probe", **self.hold_terms())))


class DatabaseHoldTransportWiringTests(_Admission, TestCase):
    """Both ways the shared runner reaches a node check the hold request before any connection."""

    def test_the_server_runner_refuses_an_unbound_hold_request(self):
        self.holding()
        with patch("apps.provisioning.hosting_node_execution.hosting_transport_allowed", return_value=True):
            bound = AnsibleService._server_playbook_authority(
                self.fixture.server, PLAYBOOK, self.values("hold", **self.hold_terms()), None
            )
            unbound = AnsibleService._server_playbook_authority(
                self.fixture.server, PLAYBOOK, self.values("hold", token=str(uuid4()), generation=1), None
            )
        self.assertTrue(bound.is_ok(), bound)
        self.assertTrue(unbound.is_err())

    def test_the_deployment_runner_refuses_an_unbound_hold_request(self):
        self.holding()
        deployment = SimpleNamespace(ipv4_address="192.0.2.10", virtualmin_server=self.fixture.server)
        result = AnsibleService().run_playbook(
            deployment, PLAYBOOK, self.values("hold", token=str(uuid4()), generation=1), timeout_seconds=30
        )
        self.assertTrue(result.is_err())
        self.assertIn("database hold", result.unwrap_err())
        no_server = AnsibleService().run_playbook(
            SimpleNamespace(ipv4_address="192.0.2.10", virtualmin_server=None),
            PLAYBOOK,
            self.values("hold", **self.hold_terms()),
            timeout_seconds=30,
        )
        self.assertTrue(no_server.is_err())


class EpisodeBlocksTests(_Admission, TestCase):
    """A hold or a release on its way to the node is the account's operation: others wait for it."""

    def busy(self, **kwargs):
        from apps.provisioning.hosting_limit_execution import _account_busy  # noqa: PLC0415
        from apps.provisioning.virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415

        account = self.fixture.account
        return account_has_active_operation(account, **kwargs), _account_busy(account)

    def test_holding_and_releasing_block_the_account_grace_and_held_do_not(self):
        self.assertEqual(self.busy(), (False, False))
        self.holding()
        self.assertEqual(self.busy(), (True, True))
        self.assertEqual(self.busy(ignore_episode_id=self.episode.pk)[0], False)  # the hold's own re-send
        self.assertEqual(self.busy(ignore_episode_id=uuid4())[0], True)
        self.episode.confirm_held(digest="5e" * 32)
        self.episode.save()
        self.assertEqual(self.busy(), (False, False))  # held for days: the account goes on with its life
        self.episode.start_release("waived")
        self.episode.save()
        self.assertEqual(self.busy(), (True, True))
        self.episode.confirm_released_to_closed()
        self.episode.save()
        self.assertEqual(self.busy(), (False, False))

    def test_a_quota_operation_already_running_settles_while_a_release_waits_for_it(self):
        from apps.provisioning.hosting_limit_execution import _account_busy  # noqa: PLC0415

        self.releasing()
        account = self.fixture.account
        self.assertTrue(_account_busy(account))  # no new quota operation starts
        self.assertFalse(_account_busy(account, ignore_job_id=uuid4()))  # the one that owns the account finishes
        # The quota child of a restore or migration the release waits for finishes too.
        self.assertFalse(_account_busy(account, parent={"job_id": str(uuid4())}))
        self.assertFalse(_account_busy(account, parent={"migration_id": str(uuid4())}))

    def test_another_accounts_episode_never_blocks(self):
        other = make_overage_account("neighbour")
        neighbour = _episode(other)
        neighbour.start_hold(token=uuid4(), generation=1)
        neighbour.save()
        self.assertEqual(self.busy(), (False, False))
