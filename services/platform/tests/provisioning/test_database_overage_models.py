"""A database over-allowance episode: its states, the paths between them, and what can't bypass them."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone
from django_fsm import ConcurrentTransition, TransitionNotAllowed

from apps.provisioning.database_overage_models import DatabaseOverageEpisode
from tests.provisioning.database_overage_fixtures import make_overage_account

OPEN = {"grace", "holding", "held", "releasing"}


def _episode(fixture, **fields) -> DatabaseOverageEpisode:
    now = timezone.now()
    return DatabaseOverageEpisode.objects.create(
        account=fixture.account,
        service=fixture.service,
        service_id_snapshot=fixture.service.pk,
        customer_id_snapshot=fixture.customer.pk,
        owner_scope=fixture.usage.owner_scope,
        server_id=fixture.server.pk,
        domain_id=fixture.usage.domain_id,
        domain=fixture.account.domain,
        installation=fixture.installation,
        opened_at=now,
        deadline_at=now + timedelta(days=14),
        **fields,
    )


class DatabaseOverageEpisodeGraphTests(TestCase):
    def test_the_transition_graph_is_exactly_the_planned_one(self):
        """Once a hold may exist, closed is reachable only through releasing, or node_gone on a deleted node."""
        field = DatabaseOverageEpisode._meta.get_field("state")
        graph: dict[str, set[tuple[str, str]]] = {}
        for transition in field.get_all_transitions(DatabaseOverageEpisode):
            graph.setdefault(transition.name, set()).add((transition.source, transition.target))
        expected = {
            "start_hold": {("grace", "holding")},
            "confirm_held": {("holding", "held")},
            "start_rehold": {("held", "holding")},  # reconcile after drift, never through a release
            "start_release": {("holding", "releasing"), ("held", "releasing")},
            "confirm_released_to_grace": {("releasing", "grace")},
            "confirm_released_to_closed": {("releasing", "closed")},
            "close": {("grace", "closed")},
            "node_gone": {(state, "closed") for state in OPEN},
        }
        self.assertEqual(graph, expected)
        into_closed = {source for edges in graph.values() for source, target in edges if target == "closed"}
        self.assertEqual(into_closed, OPEN)
        for name, edges in graph.items():
            if name != "node_gone":
                for source, target in edges:
                    if target == "closed":
                        self.assertIn(source, {"grace", "releasing"}, name)


class DatabaseOverageEpisodeTransitionTests(TestCase):
    def setUp(self):
        self.fixture = make_overage_account()

    def test_a_new_episode_is_in_grace_with_its_identity_snapshots(self):
        episode = _episode(self.fixture)
        episode.refresh_from_db()
        self.assertEqual(episode.state, "grace")
        self.assertEqual(episode.domain_id, "17001")
        self.assertEqual(episode.installation, self.fixture.installation)
        self.assertEqual(episode.server_id, self.fixture.server.pk)
        self.assertEqual(episode.hold_generation, 0)

    def test_the_state_cannot_be_written_around_the_transitions(self):
        episode = _episode(self.fixture)
        episode.start_hold(token=uuid4(), generation=1)
        episode.confirm_held(digest="sha256:held")
        episode.save()
        with self.assertRaises(AttributeError):
            episode.state = "closed"
        values = {field.attname: getattr(episode, field.attname) for field in episode._meta.concrete_fields}
        closed = DatabaseOverageEpisode(**{**values, "state": "closed", "close_reason": "waived"})
        for write in (
            lambda: DatabaseOverageEpisode.objects.filter(pk=episode.pk).update(state="closed"),
            lambda: DatabaseOverageEpisode.objects.bulk_update([episode], ["state"]),
            lambda: DatabaseOverageEpisode.objects.filter(pk=episode.pk).update(revision=0),
            lambda: DatabaseOverageEpisode.objects.bulk_update([episode], ["last_error"]),
            lambda: DatabaseOverageEpisode.objects.bulk_create(
                [DatabaseOverageEpisode(**{**values, "state": "grace"})], None, False, True, ["state"], ["id"]
            ),
            lambda: DatabaseOverageEpisode.objects.bulk_create(
                [closed], update_conflicts=True, unique_fields=["id"], update_fields=["state", "close_reason"]
            ),
            # A held row upserted back to grace would skip its release just the same.
            lambda: DatabaseOverageEpisode.objects.bulk_create(
                [DatabaseOverageEpisode(**{**values, "state": "grace"})], update_conflicts=True, unique_fields=["id"], update_fields=["state"]
            ),
        ):
            with self.subTest(write=write), self.assertRaises(ValidationError):
                write()
        episode.refresh_from_db()
        self.assertEqual(episode.state, "held")

    def test_an_episode_is_born_in_grace(self):
        for state in ("holding", "held", "releasing", "closed"):
            with self.subTest(state=state), self.assertRaises(ValidationError):
                _episode(self.fixture, state=state, close_reason="waived" if state == "closed" else "")
        self.assertFalse(DatabaseOverageEpisode.objects.exists())

    def test_a_release_returns_to_grace_or_closes_by_its_purpose(self):
        for purpose, state in (
            ("extend", "grace"),
            ("migration", "grace"),
            ("hold_refused", "grace"),
            ("hold_withdrawn", "grace"),
            ("under_allowance", "closed"),
            ("waived", "closed"),
            ("ownership_changed", "closed"),
            ("flag_rollback", "closed"),
        ):
            with self.subTest(purpose=purpose):
                DatabaseOverageEpisode.objects.filter(account=self.fixture.account).delete()
                episode = _episode(self.fixture)
                episode.start_hold(token=uuid4(), generation=1)
                episode.confirm_held(digest="sha256:held")
                episode.start_release(purpose)
                episode.save()
                wrong = episode.confirm_released_to_closed if state == "grace" else episode.confirm_released_to_grace
                with self.assertRaises(TransitionNotAllowed):
                    wrong()
                (episode.confirm_released_to_grace if state == "grace" else episode.confirm_released_to_closed)()
                episode.save()
                episode.refresh_from_db()
                self.assertEqual(episode.state, state)
                self.assertEqual(episode.close_reason, purpose if state == "closed" else "")
                self.assertEqual(episode.release_purpose, "")

    def test_a_release_needs_a_known_purpose(self):
        episode = _episode(self.fixture)
        episode.start_hold(token=uuid4(), generation=1)
        with self.assertRaises(ValueError):
            episode.start_release("because")

    def test_grace_closes_only_for_a_reason_that_needs_no_release(self):
        episode = _episode(self.fixture)
        with self.assertRaises(ValueError):
            episode.close("extend")
        episode.close("under_allowance")
        episode.save()
        episode.refresh_from_db()
        self.assertEqual((episode.state, episode.close_reason), ("closed", "under_allowance"))
        self.assertIsNotNone(episode.closed_at)

    def test_node_gone_closes_only_an_episode_whose_account_was_terminated(self):
        episode = _episode(self.fixture)
        episode.start_hold(token=uuid4(), generation=1)
        episode.confirm_held(digest="sha256:held")
        episode.save()
        with self.assertRaises(TransitionNotAllowed):
            episode.node_gone()
        episode.account = None  # a deleted account row is no proof the node domain was deleted
        with self.assertRaises(TransitionNotAllowed):
            episode.node_gone()
        episode.account = self.fixture.account
        self.fixture.account.status = "terminated"
        self.fixture.account.save(update_fields=["status"])
        episode.node_gone()
        episode.save()
        episode.refresh_from_db()
        self.assertEqual((episode.state, episode.close_reason), ("closed", "node_deleted"))

    def test_holding_records_the_token_and_generation_and_held_the_digest(self):
        episode = _episode(self.fixture)
        token = uuid4()
        episode.start_hold(token=token, generation=3)
        episode.confirm_held(digest="sha256:held")
        episode.save()
        episode.refresh_from_db()
        self.assertEqual((episode.hold_token, episode.hold_generation, episode.held_digest), (token, 3, "sha256:held"))

    def test_a_rehold_takes_a_newer_generation_and_settles_the_drift_once_held(self):
        episode = _episode(self.fixture)
        episode.start_hold(token=uuid4(), generation=3)
        episode.confirm_held(digest="sha256:held")
        episode.needs_reconcile = True
        with self.assertRaises(ValueError):
            episode.start_rehold(token=uuid4(), generation=3)
        token = uuid4()
        episode.start_rehold(token=token, generation=4)
        self.assertEqual((episode.state, episode.hold_token, episode.hold_generation), ("holding", token, 4))
        self.assertTrue(episode.needs_reconcile)  # until the node confirms the new hold
        episode.confirm_held(digest="sha256:again")
        self.assertFalse(episode.needs_reconcile)

    def test_a_generation_never_goes_back(self):
        episode = _episode(self.fixture, hold_generation=4)
        with self.assertRaises(ValueError):
            episode.start_hold(token=uuid4(), generation=4)

    def test_a_new_episode_continues_the_accounts_generations(self):
        """The node journal outlives an episode, so a later episode never reuses a generation."""
        first = _episode(self.fixture)
        first.start_hold(token=uuid4(), generation=4)
        first.start_release("waived")
        first.save()
        first.confirm_released_to_closed()
        first.save()
        second = _episode(self.fixture)
        with self.assertRaises(ValueError):
            second.start_hold(token=uuid4(), generation=4)
        second.start_hold(token=uuid4(), generation=5)

    def test_a_stale_copy_cannot_save_over_a_newer_hold(self):
        """A worker holding an old copy loses, even when the state has come back round to where it was."""
        episode = _episode(self.fixture)
        episode.start_hold(token=uuid4(), generation=1)
        episode.save()
        stale = DatabaseOverageEpisode.objects.get(pk=episode.pk)
        fresh = DatabaseOverageEpisode.objects.get(pk=episode.pk)
        fresh.start_release("hold_refused")
        fresh.save()
        fresh.confirm_released_to_grace()
        fresh.save()
        newer = uuid4()
        fresh.start_hold(token=newer, generation=2)
        fresh.save()
        stale.refresh_from_db(fields=["last_error"])  # a partial reload doesn't make the rest of the copy current
        stale.confirm_held(digest="sha256:old")
        with self.assertRaises(ConcurrentTransition), transaction.atomic():
            stale.save()
        episode.refresh_from_db()
        self.assertEqual((episode.state, episode.hold_token, episode.hold_generation), ("holding", newer, 2))

    def test_a_copy_read_without_its_revision_cannot_save(self):
        """With no baseline there is nothing to fence against, so the save refuses rather than writes."""
        episode = _episode(self.fixture)
        for loaded in (
            DatabaseOverageEpisode.objects.defer("revision").get(pk=episode.pk),
            DatabaseOverageEpisode.objects.only("id", "state", "last_error").get(pk=episode.pk),
        ):
            with self.subTest(deferred=loaded.get_deferred_fields()):
                DatabaseOverageEpisode.objects.filter(pk=episode.pk).update(needs_reconcile=True)
                loaded.last_error = "from a copy without a baseline"
                with self.assertRaises(ConcurrentTransition), transaction.atomic():
                    loaded.save()
                episode.refresh_from_db()
                self.assertEqual(episode.last_error, "")

    def test_a_queryset_write_also_outdates_earlier_copies(self):
        episode = _episode(self.fixture)
        DatabaseOverageEpisode.objects.filter(pk=episode.pk).update(needs_reconcile=True)
        episode.last_error = "from an older copy"
        with self.assertRaises(ConcurrentTransition), transaction.atomic():
            episode.save()
        episode.refresh_from_db()
        self.assertTrue(episode.needs_reconcile)

    def test_save_options_are_taken_by_keyword_only(self):
        episode = _episode(self.fixture)
        with self.assertRaises(TypeError):
            episode.save(False, False, None, ["last_error"])


class DatabaseOverageEpisodeConstraintTests(TestCase):
    def setUp(self):
        self.fixture = make_overage_account()

    def test_an_account_has_at_most_one_open_episode(self):
        first = _episode(self.fixture)
        with self.assertRaises(IntegrityError), transaction.atomic():
            _episode(self.fixture)
        first.close("waived")
        first.save()
        _episode(self.fixture)  # a closed episode doesn't count
        self.assertEqual(DatabaseOverageEpisode.objects.filter(account=self.fixture.account).count(), 2)

    def test_a_migration_suspension_names_its_migration(self):
        for fields in ({"suspended_for": "migration"}, {"suspended_migration_id": uuid4()}):
            with self.subTest(fields=fields), self.assertRaises(IntegrityError), transaction.atomic():
                _episode(self.fixture, **fields)
        _episode(self.fixture, suspended_for="migration", suspended_migration_id=uuid4())

    def test_only_a_closed_episode_has_a_close_reason(self):
        with self.assertRaises(IntegrityError), transaction.atomic():
            _episode(self.fixture, close_reason="waived")
