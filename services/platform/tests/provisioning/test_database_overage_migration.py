"""A database overage episode across a migration of its account (plan 7B.3, revision 3 item 4)."""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.provisioning.database_overage_migration import (
    activation_hold,
    record_activation_hold,
    suspend_for_migration,
)
from apps.provisioning.database_overage_models import DatabaseOverageEpisode
from apps.provisioning.virtualmin_migration_service import MigrationDeferredError, VirtualminMigrationService
from apps.provisioning.virtualmin_usage_models import AccountUsageState, UsageInterval
from apps.settings.models import SystemSetting
from tests.provisioning.database_hold_fake import HELD_DIGEST, FakeNode
from tests.provisioning.database_overage_fixtures import make_overage_account
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase
from tests.provisioning.test_database_overage_models import _episode
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


def _flag_on() -> None:
    SystemSetting.objects.create(
        key="provisioning.database_overage_enabled",
        value=True,
        default_value=False,
        data_type="boolean",
        category="provisioning",
    )


class _Episode:
    def make_episode(self, account) -> DatabaseOverageEpisode:
        now = timezone.now()
        return DatabaseOverageEpisode.objects.create(
            account=account,
            service=account.service,
            service_id_snapshot=account.service_id,
            customer_id_snapshot=account.service.customer_id,
            owner_scope=uuid4(),
            server_id=account.server_id,
            domain_id="17001",
            domain=account.domain,
            installation=uuid4(),
            opened_at=now - timedelta(days=20),
            deadline_at=now - timedelta(days=6),
        )

    def hold(self, episode: DatabaseOverageEpisode) -> DatabaseOverageEpisode:
        episode.start_hold(token=uuid4(), generation=episode.hold_generation + 1)
        episode.confirm_held(digest=HELD_DIGEST)
        episode.save()
        return episode

    def current(self) -> DatabaseOverageEpisode:
        return DatabaseOverageEpisode.objects.get(pk=self.episode.pk)


class NativeMigrationEpisodeTests(_Episode, MigrationTestBase):
    """A whole-domain move: suspended at the start, released before the move, unsuspended at the end."""

    def setUp(self) -> None:
        super().setUp()
        _flag_on()
        self.episode = self.make_episode(self.account)
        self.node = FakeNode()
        patcher = patch("apps.provisioning.database_overage_tasks._gateway", side_effect=self.node.module)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_episode_in_grace_is_suspended_for_the_move_and_resumes_after_it(self) -> None:
        migration = self._start()
        episode = self.current()
        self.assertEqual((episode.suspended_for, episode.suspended_migration_id), ("migration", migration.pk))
        self.assertFalse(episode.hold_follows_migration)
        migration = self._run(migration)
        self.assertEqual(migration.status, "completed")
        episode = self.current()
        self.assertEqual((episode.state, episode.suspended_for, episode.suspended_migration_id), ("grace", "", None))
        self.assertEqual(self.node.actions(), [])

    def test_a_held_episode_is_released_before_the_barrier_and_comes_back_due(self) -> None:
        self.hold(self.episode)
        self.node.journal[self.current().hold_generation] = self.current().hold_token
        migration = self._start()
        self.assertEqual((self.current().state, self.current().release_purpose), ("releasing", "migration"))
        self.assertTrue(self.current().hold_follows_migration)
        released_before = []
        barrier = VirtualminMigrationService._quiesce

        def quiesce(service: Any, migration: Any, token: Any) -> None:
            released_before.append(self.current().state)
            barrier(service, migration, token)

        with patch.object(VirtualminMigrationService, "_quiesce", new=quiesce):
            migration = self._run(migration)
        self.assertEqual(released_before, ["grace"])  # the barrier never sees the hold
        self.assertEqual(self.node.actions(), ["fence", "release"])
        self.assertEqual(migration.status, "completed")
        episode = self.current()
        self.assertEqual((episode.state, episode.suspended_for, episode.hold_follows_migration), ("grace", "", False))
        self.assertLess(episode.deadline_at, timezone.now())  # due: the next hold decision holds it again

    def test_a_release_that_does_not_complete_refuses_the_migration(self) -> None:
        self.hold(self.episode)
        self.node.release_answer = "uncertain"
        migration = self._run(self._start())
        self.assertEqual(migration.status, "failed", migration.error_detail)
        self.assertIn("not released", migration.error_detail)
        episode = self.current()
        # Still releasing, for the sweep to finish; no longer suspended for a migration that ended.
        self.assertEqual(
            (episode.state, episode.suspended_for, episode.suspended_migration_id), ("releasing", "", None)
        )

    def test_a_hold_in_flight_refuses_the_start(self) -> None:
        self.episode.start_hold(token=uuid4(), generation=1)
        self.episode.save()
        result = VirtualminMigrationService().start_migration(self.account, self.target, initiated_by=self.staff)
        self.assertTrue(result.is_err())
        self.assertIsNone(self.current().suspended_migration_id)


class SuspensionTests(_Episode, TestCase):
    def setUp(self) -> None:
        self.fixture = make_overage_account("suspend")
        self.episode = _episode(self.fixture)

    def test_an_episode_suspended_for_another_migration_refuses(self) -> None:
        suspend_for_migration(self.fixture.account, uuid4())
        with self.assertRaisesMessage(ValueError, "another migration"):
            suspend_for_migration(self.fixture.account, uuid4())


class ActivationHoldTests(_Episode, TestCase):
    """A cutover's activation holds the target again, when the episode was held at the start."""

    def setUp(self) -> None:
        _flag_on()
        self.fixture = make_overage_account("activate")
        self.target = make_overage_account("target").server
        self.episode = self.hold(_episode(self.fixture))
        DatabaseOverageEpisode.objects.filter(pk=self.episode.pk).update(deadline_at=timezone.now() - timedelta(days=1))
        self.migration = SimpleNamespace(
            pk=uuid4(),
            account_id=self.fixture.account.pk,
            target_server_id=self.target.pk,
            barrier_state={"target_domain_id": 28001},
        )
        self.installation = uuid4()
        UsageInterval.objects.create(
            account=make_overage_account("neighbour").account,
            owner_scope=uuid4(),
            server=self.target,
            server_id_snapshot=self.target.pk,
            started_at=timezone.now() - timedelta(days=1),
            domain_id="5",
            installation=self.installation,
        )
        suspend_for_migration(self.fixture.account, self.migration.pk)
        episode = self.current()
        episode.confirm_released_to_grace()  # released before the move
        episode.save()

    def test_the_target_hold_is_persisted_with_the_target_identity_before_it_is_asked(self) -> None:
        old_generation = self.current().hold_generation
        hold = activation_hold(self.migration)
        episode = self.current()
        self.assertEqual(episode.state, "holding")
        self.assertEqual(
            (episode.server_id, episode.domain_id, episode.installation),
            (self.target.pk, "28001", self.installation),
        )
        self.assertEqual(
            hold,
            {
                "token": str(episode.hold_token),
                "generation": old_generation + 1,
                "installation": str(self.installation),
            },
        )
        self.assertEqual(activation_hold(self.migration), hold)  # a retried activation resends the same hold

    def test_a_held_outcome_holds_the_episode_on_the_target(self) -> None:
        hold = activation_hold(self.migration)
        self.assertEqual(record_activation_hold(self.migration, hold, self.outcome(hold, "held")), "held")
        episode = self.current()
        self.assertEqual((episode.state, episode.held_digest, episode.suspended_for), ("held", HELD_DIGEST, ""))

    def test_a_target_that_did_not_keep_the_hold_leaves_the_episode_due_for_staff(self) -> None:
        hold = activation_hold(self.migration)
        outcome = self.outcome(hold, "not_held")
        self.assertEqual(record_activation_hold(self.migration, hold, outcome), "not_held")
        episode = self.current()
        self.assertEqual((episode.state, episode.suspended_for), ("grace", ""))
        self.assertIsNotNone(episode.hold_refused_at)
        self.assertIn("refused: shared_username", episode.last_error)

    def test_an_outcome_for_another_hold_settles_nothing(self) -> None:
        hold = activation_hold(self.migration)
        other = {**hold, "generation": hold["generation"] + 1}
        self.assertEqual(record_activation_hold(self.migration, other, self.outcome(other, "held")), "superseded")
        self.assertEqual(self.current().state, "holding")

    def test_no_target_hold_when_the_episode_was_not_held_or_the_flag_is_off(self) -> None:
        DatabaseOverageEpisode.objects.filter(pk=self.episode.pk).update(hold_follows_migration=False)
        self.assertIsNone(activation_hold(self.migration))
        DatabaseOverageEpisode.objects.filter(pk=self.episode.pk).update(hold_follows_migration=True)
        SystemSetting.objects.filter(key="provisioning.database_overage_enabled").update(value=False)
        self.assertIsNone(activation_hold(self.migration))
        self.assertEqual(self.current().state, "grace")

    def test_an_unknown_target_installation_holds_after_the_move_instead(self) -> None:
        UsageInterval.objects.all().delete()
        self.assertIsNone(activation_hold(self.migration))
        episode = self.current()
        self.assertEqual((episode.state, episode.server_id), ("grace", self.fixture.server.pk))
        self.assertIn("not known yet", episode.last_error)

    def activate(self, answers: list[Any], *, meanwhile: Any = None) -> list[Any]:
        """Run the native cutover activation with every node step faked; the guard keeps its real transaction."""
        from contextlib import contextmanager  # noqa: PLC0415

        from django.db import transaction  # noqa: PLC0415

        from apps.common.types import Ok  # noqa: PLC0415

        @contextmanager
        def guard(migration, token):
            if meanwhile is not None:
                meanwhile()  # between the committed decision and the guard's locks
            with transaction.atomic():
                yield self.fixture.account

        sent: list[Any] = []

        def activate(migration, *, enabled=None, billing_hold=None):
            sent.append(billing_hold)
            answer = answers.pop(0)
            if answer == "activated":
                return Ok("activated")
            return answer if not isinstance(answer, str) else Ok(self.outcome(billing_hold, answer))

        migration = SimpleNamespace(
            **vars(self.migration),
            contract="cutover",
            cutover_committed_at=timezone.now(),
            account=self.fixture.account,
            target_server=self.target,
        )
        module = "apps.provisioning"
        with (
            patch(f"{module}.virtualmin_migration_service.destination_refusal", return_value=None),
            patch(f"{module}.hosting_limit_execution.ensure_managed_limits", return_value=Ok(None)),
            patch(f"{module}.migration_enabled_state.activation_guard", side_effect=guard),
            patch(f"{module}.migration_enabled_state.current_policy", return_value=SimpleNamespace(enabled=True)),
            patch(f"{module}.migration_enabled_state.converge_before_release", return_value=None),
            patch(f"{module}.migration_enabled_state.record_activation", return_value=None),
            patch(f"{module}.migration_target_hold.run_held_target_node", return_value=None),
            patch(f"{module}.migration_bridge_service.activate_target", side_effect=activate),
            patch.object(VirtualminMigrationService, "_move", return_value=None),
            patch.object(VirtualminMigrationService, "_release_target_hold", return_value=None),
        ):
            while answers:
                try:
                    VirtualminMigrationService()._activate(migration, uuid4())
                except MigrationDeferredError:
                    continue
        return sent

    def test_a_cutover_activation_carries_the_hold_and_records_its_outcome(self) -> None:
        sent = self.activate(["held"])
        episode = self.current()
        self.assertEqual(
            sent,
            [
                {
                    "token": str(episode.hold_token),
                    "generation": episode.hold_generation,
                    "installation": str(self.installation),
                }
            ],
        )
        self.assertEqual((episode.state, episode.server_id), ("held", self.target.pk))

    def test_a_lost_activation_reply_resends_the_same_hold(self) -> None:
        from apps.common.types import Err, Retriability  # noqa: PLC0415

        lost = Err("The activation's billing hold is uncertain: no reply", retriability=Retriability.UNKNOWN)
        sent = self.activate([lost, "held"])
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0], sent[1])  # the decision survived the guard's rollback
        self.assertEqual(self.current().state, "held")

    def test_a_sweep_between_activation_retries_leaves_the_migrations_hold_alone(self) -> None:
        from apps.common.types import Err, Retriability  # noqa: PLC0415
        from apps.provisioning.database_overage_tasks import _advance  # noqa: PLC0415

        node = FakeNode()
        lost = Err("no reply", retriability=Retriability.UNKNOWN)

        def sweep():
            if self.current().state == "holding":
                self.assertEqual(_advance(self.episode.pk, node.module(), at=timezone.now()), "suspended")

        sent = self.activate([lost, "held"], meanwhile=sweep)
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(node.actions(), [])
        self.assertEqual(self.current().state, "held")

    def test_an_extension_between_the_decision_and_the_activation_drops_the_hold(self) -> None:
        from apps.provisioning.database_overage_staff import extend_episode  # noqa: PLC0415
        from apps.users.models import User  # noqa: PLC0415

        staff = User.objects.create_user(email="ops2@example.test", password="x", is_staff=True, staff_role="admin")

        def extend():
            extend_episode(self.episode.pk, user=staff, days=3, reason="customer is cleaning up the shop database")

        sent = self.activate(["activated"], meanwhile=extend)
        self.assertEqual(sent, [None])
        self.assertEqual(self.current().state, "releasing")

    def test_an_extension_after_the_source_release_keeps_the_target_writable(self) -> None:
        from apps.provisioning.database_overage_staff import extend_episode  # noqa: PLC0415
        from apps.users.models import User  # noqa: PLC0415

        staff = User.objects.create_user(email="ops@example.test", password="x", is_staff=True, staff_role="admin")
        extend_episode(self.episode.pk, user=staff, days=3, reason="customer is cleaning up the shop database")
        self.assertIsNone(activation_hold(self.migration))  # the extended deadline decides, not the carried flag
        self.assertEqual(self.current().state, "grace")
        self.assertFalse(self.current().hold_follows_migration)

    @staticmethod
    def outcome(hold: dict[str, Any], result: str) -> dict[str, Any]:
        common = {"identity": {}, "token": hold["token"], "generation": hold["generation"], "outcome": result}
        if result == "held":
            return {**common, "held_digest": HELD_DIGEST}
        return {**common, "reason": "refused", "code": "shared_username"}


class IdentityRebindTests(_Episode, TestCase):
    """After a move, the next hold decision takes the identity the collector reported on the new node."""

    def test_an_episode_in_grace_follows_the_account_to_its_new_node(self) -> None:
        from apps.provisioning.database_overage_service import _current_identity  # noqa: PLC0415

        fixture = make_overage_account("moved")
        episode = _episode(fixture)
        target = make_overage_account("newnode").server
        account = fixture.account
        account.server = target
        AccountUsageState.objects.filter(account=account).update(server_id_snapshot=target.pk, domain_id="")
        self.assertFalse(_current_identity(episode, account))  # not collected there yet
        installation = uuid4()
        AccountUsageState.objects.filter(account=account).update(domain_id="31", installation=installation)
        self.assertTrue(_current_identity(episode, account))
        self.assertEqual((episode.server_id, episode.domain_id, episode.installation), (target.pk, "31", installation))


class ComponentMigrationEpisodeTests(_Episode, ComponentAdmissionTestBase):
    """A component review records the source grants: never while a hold has revoked some of them."""

    def setUp(self) -> None:
        super().setUp()
        self.episode = self.make_episode(self.account)

    def test_a_held_account_is_refused_review_and_start_until_staff_extend_or_waive(self) -> None:
        approval = self.approve(self.review())
        self.hold(self.episode)
        with self.assertRaisesMessage(ValidationError, "database write hold"):
            self.review()
        self.events.clear()
        with self.assertRaisesMessage(ValidationError, "database write hold"):
            self.start(approval)
        self.assertEqual(self.events, [])  # refused before either node is asked anything
        self.assertEqual((self.current().state, self.current().suspended_for), ("held", ""))

    def test_an_episode_in_grace_is_suspended_by_the_start(self) -> None:
        migration = self.start(self.approve(self.review()))
        episode = self.current()
        self.assertEqual((episode.state, episode.suspended_migration_id), ("grace", migration.pk))
        self.assertFalse(episode.hold_follows_migration)
