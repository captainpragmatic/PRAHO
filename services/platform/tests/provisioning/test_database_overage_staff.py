"""Staff extend and waive, and the release-all rollback, on database overage episodes."""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.management import CommandError, call_command
from django.db.models import QuerySet
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Err
from apps.provisioning.database_overage_models import DatabaseOverageEpisode
from apps.provisioning.database_overage_staff import extend_episode, waive_episode
from apps.provisioning.database_overage_tasks import _release
from apps.users.models import User
from tests.provisioning.database_hold_fake import HELD_DIGEST, FakeNode, HoldRefusal
from tests.provisioning.database_overage_fixtures import make_overage_account


class _Staff:
    def setUp(self):
        self.fixture = make_overage_account("staff")
        self.staff = User.objects.create_user("manager@example.test", "fixture-password", is_staff=True)
        self.now = timezone.now().replace(microsecond=0)
        self.episode = DatabaseOverageEpisode.objects.create(
            account=self.fixture.account,
            service=self.fixture.service,
            service_id_snapshot=self.fixture.service.pk,
            customer_id_snapshot=self.fixture.customer.pk,
            owner_scope=self.fixture.usage.owner_scope,
            server_id=self.fixture.server.pk,
            domain_id=self.fixture.usage.domain_id,
            domain=self.fixture.account.domain,
            installation=self.fixture.installation,
            opened_at=self.now - timedelta(days=15),
            deadline_at=self.now - timedelta(days=1),
        )
        self.node = FakeNode()
        patcher = patch("apps.provisioning.database_overage_tasks._gateway", side_effect=lambda: self.node and self.node.module())
        patcher.start()
        self.addCleanup(patcher.stop)

    def hold(self):
        """A hold the node really has: its journal carries the episode's token."""
        self.episode.refresh_from_db()
        token, generation = uuid4(), self.episode.hold_generation + 1
        identity = self.node.module().HoldIdentity(
            server_id=self.episode.server_id,
            domain_id=self.episode.domain_id,
            domain=self.episode.domain,
            installation=self.episode.installation,
        )
        self.assertTrue(self.node.hold(identity, token=token, generation=generation).is_ok())
        self.node.calls.clear()
        self.episode.start_hold(token=token, generation=generation)
        self.episode.confirm_held(digest=HELD_DIGEST)
        self.episode.save()

    def current(self) -> DatabaseOverageEpisode:
        self.episode.refresh_from_db()
        return self.episode

    def audit(self, action) -> AuditEvent:
        return AuditEvent.objects.get(
            content_type=ContentType.objects.get_for_model(DatabaseOverageEpisode),
            object_id=str(self.episode.pk),
            action=action,
        )


class DatabaseOverageExtendTests(_Staff, TestCase):
    def test_extending_moves_the_deadline_from_now_when_it_has_passed(self):
        extend_episode(self.episode.pk, user=self.staff, days=5, reason="Customer is migrating data", at=self.now)
        self.assertEqual(self.current().deadline_at, self.now + timedelta(days=5))
        event = self.audit("database_overage_extended")
        self.assertEqual((event.user_id, event.new_values["reason"], event.new_values["days"]), (self.staff.pk, "Customer is migrating data", 5))

    def test_extending_a_hold_releases_it_into_a_write_window(self):
        self.hold()
        extend_episode(self.episode.pk, user=self.staff, days=2, reason="Write window to OPTIMIZE a table", at=self.now)
        self.assertEqual((self.current().state, self.current().release_purpose), ("releasing", "extend"))

    def test_extending_clears_a_refused_hold_for_another_try(self):
        DatabaseOverageEpisode.objects.filter(pk=self.episode.pk).update(hold_refused_at=self.now, last_error="x")
        extend_episode(self.episode.pk, user=self.staff, days=1, reason="Grants were fixed on the node", at=self.now)
        self.assertIsNone(self.current().hold_refused_at)

    def test_extension_bounds_and_reason_are_required(self):
        for days, reason in ((0, "A proper reason"), (31, "A proper reason"), (3, "short")):
            with self.subTest(days=days, reason=reason), self.assertRaises(ValidationError):
                extend_episode(self.episode.pk, user=self.staff, days=days, reason=reason, at=self.now)


class DatabaseOverageWaiveTests(_Staff, TestCase):
    def test_waiving_a_grace_episode_closes_it(self):
        waive_episode(self.episode.pk, user=self.staff, reason="Billing agreed to waive this", at=self.now)
        self.assertEqual((self.current().state, self.current().close_reason), ("closed", "waived"))
        self.assertEqual(self.audit("database_overage_waived").user_id, self.staff.pk)

    def test_waiving_a_hold_goes_through_its_release(self):
        self.hold()
        waive_episode(self.episode.pk, user=self.staff, reason="Billing agreed to waive this", at=self.now)
        self.assertEqual((self.current().state, self.current().release_purpose), ("releasing", "waived"))

    def test_a_closed_episode_cannot_be_waived_or_extended(self):
        waive_episode(self.episode.pk, user=self.staff, reason="Billing agreed to waive this", at=self.now)
        for action in (
            lambda: waive_episode(self.episode.pk, user=self.staff, reason="Again, for the record", at=self.now),
            lambda: extend_episode(self.episode.pk, user=self.staff, days=1, reason="Again, for the record", at=self.now),
        ):
            with self.subTest(action=action), self.assertRaises(ValidationError):
                action()


class ReleaseAllCommandTests(_Staff, TestCase):
    def test_release_all_drains_every_hold_to_closed(self):
        self.hold()
        out = StringIO()
        call_command("release_database_holds", "--all", stdout=out)
        episode = self.current()
        self.assertEqual((episode.state, episode.close_reason), ("closed", "flag_rollback"))
        self.assertEqual(self.node.actions(), ["fence", "release"])
        self.assertEqual(self.node.journal, {})  # the node's hold is gone, not just the episode's record
        self.assertIn("1 released", out.getvalue())

    def test_release_all_also_closes_an_episode_released_for_a_write_window(self):
        self.hold()
        extend_episode(self.episode.pk, user=self.staff, days=2, reason="Write window to OPTIMIZE a table", at=self.now)
        call_command("release_database_holds", "--all", stdout=StringIO())
        episode = self.current()
        self.assertEqual((episode.state, episode.close_reason), ("closed", "flag_rollback"))

    def test_release_all_keeps_its_purpose_through_a_failed_release(self):
        self.hold()
        extend_episode(self.episode.pk, user=self.staff, days=2, reason="Write window to OPTIMIZE a table", at=self.now)
        self.node.release_answer = "uncertain"
        with self.assertRaises(CommandError):
            call_command("release_database_holds", "--all", stdout=StringIO())
        self.assertEqual(self.current().release_purpose, "flag_rollback")
        self.node.release_answer = "released"
        call_command("release_database_holds", "--all", stdout=StringIO())
        self.assertEqual((self.current().state, self.current().close_reason), ("closed", "flag_rollback"))

    def test_release_all_counts_a_release_a_concurrent_sweep_finished_as_done(self):
        other = make_overage_account("concurrent")
        second = DatabaseOverageEpisode.objects.create(
            account=other.account,
            service=other.service,
            service_id_snapshot=other.service.pk,
            customer_id_snapshot=other.customer.pk,
            owner_scope=other.usage.owner_scope,
            server_id=other.server.pk,
            domain_id=other.usage.domain_id,
            domain=other.account.domain,
            opened_at=self.now,
            deadline_at=self.now,
        )
        second.start_hold(token=uuid4(), generation=1)
        second.confirm_held(digest=HELD_DIGEST)
        second.save()
        self.hold()
        for episode in (self.episode, second):
            extend_episode(episode.pk, user=self.staff, days=2, reason="Write window to OPTIMIZE a table", at=self.now)
        original, raced = self.node.release, []

        def a_sweep_finishes_the_other_release_meanwhile(identity, *, generation):
            if not raced:
                raced.append(True)
                pending = DatabaseOverageEpisode.objects.filter(state="releasing").exclude(domain=identity.domain)
                for episode_id in pending.values_list("pk", flat=True):
                    _release(episode_id, self.node.module(), at=self.now)  # the regular sweep, concurrently
            return original(identity, generation=generation)

        self.node.release = a_sweep_finishes_the_other_release_meanwhile
        out = StringIO()
        call_command("release_database_holds", "--all", stdout=out)  # no CommandError: nothing is left held
        self.assertIn("0 pending", out.getvalue())
        for episode in (self.episode, second):
            episode.refresh_from_db()
            self.assertEqual((episode.state, episode.close_reason), ("closed", "flag_rollback"))

    def test_release_all_counts_its_own_release_finished_by_a_concurrent_sweep(self):
        self.hold()
        original, raced = self.node.release, []

        def the_sweep_finishes_this_very_release(identity, *, generation):
            answer = original(identity, generation=generation)
            if not raced:
                raced.append(True)
                _release(self.episode.pk, self.node.module(), at=self.now)  # the sweep settles it first
            return answer

        self.node.release = the_sweep_finishes_this_very_release
        out = StringIO()
        call_command("release_database_holds", "--all", stdout=out)
        self.assertIn("1 released, 0 pending", out.getvalue())
        self.assertEqual(self.current().close_reason, "flag_rollback")

    def test_release_all_rechecks_after_its_own_request_fails(self):
        self.hold()
        original = self.node.release

        def the_sweep_wins_and_this_request_is_lost(identity, *, generation):
            self.node.release = original
            _release(self.episode.pk, self.node.module(), at=self.now)  # the sweep releases and closes it
            return Err(HoldRefusal("uncertain", "uncertain"))

        self.node.release = the_sweep_wins_and_this_request_is_lost
        out = StringIO()
        call_command("release_database_holds", "--all", stdout=out)
        self.assertIn("1 released, 0 pending", out.getvalue())

    def test_release_all_locks_the_account_before_the_episode_every_time(self):
        self.hold()
        order: list[str] = []
        original = QuerySet.select_for_update

        def record(queryset, *args, **kwargs):
            order.append(queryset.model.__name__)
            return original(queryset, *args, **kwargs)

        with patch.object(QuerySet, "select_for_update", autospec=True, side_effect=record):
            call_command("release_database_holds", "--all", stdout=StringIO())
        account, episode = "VirtualminAccount", "DatabaseOverageEpisode"
        locks = [name for name in order if name in {account, episode}]
        # Marked as the rollback's, the release's decision, its recorded answer, and the close. Whatever moves the
        # episode into releasing or decides a release holds the account row first; the answer locks the episode
        # alone, and nothing locks the account after the episode.
        self.assertEqual(locks, [account, episode, account, episode, episode, account, episode])

    def test_release_all_needs_the_flag_and_leaves_a_server_record_gone_pending(self):
        with self.assertRaises(CommandError):
            call_command("release_database_holds")
        self.hold()
        DatabaseOverageEpisode.objects.update(server_id=uuid4())
        with self.assertRaises(CommandError):
            call_command("release_database_holds", "--all")
        self.assertEqual(self.current().state, "releasing")


class DatabaseOverageStaffPageTests(_Staff, TestCase):
    def setUp(self):
        super().setUp()
        self.staff.staff_role = "manager"
        self.staff.save(update_fields=["staff_role"])
        self.client.force_login(self.staff)
        self.url = reverse("provisioning:service_database_overage", kwargs={"pk": self.fixture.service.pk})

    def test_the_page_shows_the_actions_to_a_manager_only(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'hx-confirm="', count=2)  # extend and waive both ask first
        self.assertContains(response, self.episode.get_state_display())
        support = User.objects.create_user("support@example.test", "fixture-password", is_staff=True, staff_role="support")
        self.client.force_login(support)
        self.assertNotContains(self.client.get(self.url), 'hx-confirm="')  # support reads, without the forms

    def test_extend_and_waive_from_the_page(self):
        response = self.client.post(
            self.url, {"action": "extend", "days": "3", "reason": "Customer asked for time", **self.form_fields()}
        )
        self.assertEqual(response.status_code, 302)
        self.assertGreater(self.current().deadline_at, timezone.now() + timedelta(days=2))
        response = self.client.post(
            self.url, {"action": "waive", "reason": "Billing agreed to waive this", **self.form_fields()}
        )
        self.assertEqual((response.status_code, self.current().state), (302, "closed"))

    def test_a_form_for_an_episode_that_moved_on_is_refused(self):
        stale = {"episode": str(self.episode.pk), "revision": str(self.episode.revision)}
        DatabaseOverageEpisode.objects.filter(pk=self.episode.pk).update(needs_reconcile=True)  # it changed
        response = self.client.post(self.url, {"action": "waive", "reason": "Billing agreed to waive this", **stale})
        self.assertEqual((response.status_code, self.current().state), (400, "grace"))
        self.current().close("waived")
        self.episode.save()
        newer = DatabaseOverageEpisode.objects.create(
            account=self.fixture.account,
            service=self.fixture.service,
            service_id_snapshot=self.fixture.service.pk,
            customer_id_snapshot=self.fixture.customer.pk,
            owner_scope=self.fixture.usage.owner_scope,
            server_id=self.fixture.server.pk,
            domain_id="17001",
            domain=self.fixture.account.domain,
            opened_at=self.now,
            deadline_at=self.now + timedelta(days=14),
        )
        self.client.post(self.url, {"action": "waive", "reason": "Billing agreed to waive this", **stale})
        newer.refresh_from_db()
        self.assertEqual(newer.state, "grace")  # a form shown for the old episode never acts on the new one

    def test_an_htmx_submission_shows_why_it_was_refused(self):
        response = self.client.post(
            self.url,
            {"action": "extend", "days": "3", "reason": "too short", **self.form_fields()},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "at least 10 characters")

    def form_fields(self):
        episode = self.current()
        return {"episode": str(episode.pk), "revision": str(episode.revision)}

    def test_a_refused_action_says_why(self):
        response = self.client.post(
            self.url, {"action": "extend", "days": "45", "reason": "Customer asked for time", **self.form_fields()}
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.current().deadline_at, self.now - timedelta(days=1))
