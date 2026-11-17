"""An episode across the account's life: a change of owner, and the account's termination."""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.customers.models import Customer
from apps.provisioning.database_overage_admission import on_account_terminated
from apps.provisioning.database_overage_models import DatabaseOverageEpisode
from apps.provisioning.database_overage_tasks import sweep_database_overages
from apps.provisioning.hosted_zone_ownership import fence_service_ownership
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.provisioning.database_overage_fixtures import make_overage_account
from tests.provisioning.test_database_overage_models import _episode


class _Lifecycle:
    def setUp(self):
        self.fixture = make_overage_account("life")
        self.episode = _episode(self.fixture)
        self.buyer = Customer.objects.create(
            name="buyer", customer_type="company", status="active", primary_email="buyer@example.test"
        )

    def current(self) -> DatabaseOverageEpisode:
        return DatabaseOverageEpisode.objects.get(pk=self.episode.pk)

    def held(self):
        self.episode.start_hold(token=uuid4(), generation=1)
        self.episode.confirm_held(digest="5e" * 32)
        self.episode.save()

    def sell_service(self):
        service = Service.objects.get(pk=self.fixture.service.pk)
        service.customer = self.buyer
        service.save()

    def closed_events(self):
        return list(
            AuditEvent.objects.filter(object_id=str(self.episode.pk), action="database_overage_closed").values_list(
                "new_values", flat=True
            )
        )


class OwnershipChangeTests(_Lifecycle, TestCase):
    def test_an_episode_in_grace_closes_with_the_change_of_owner(self):
        self.sell_service()
        episode = self.current()
        self.assertEqual((episode.state, episode.close_reason), ("closed", "ownership_changed"))
        self.assertEqual([values["close_reason"] for values in self.closed_events()], ["ownership_changed"])

    def test_a_hold_refuses_the_change_until_staff_release_or_waive_it(self):
        self.held()
        with self.assertRaisesMessage(ValidationError, "database write hold"):
            self.sell_service()
        self.assertEqual(Service.objects.get(pk=self.fixture.service.pk).customer_id, self.fixture.customer.pk)
        self.assertEqual(self.current().state, "held")
        for state_change in ("start_release",):
            episode = self.current()
            getattr(episode, state_change)("waived")
            episode.save()
            with self.assertRaisesMessage(ValidationError, "database write hold"):
                self.sell_service()  # releasing is still a hold on the node

    def test_an_episode_suspended_for_a_migration_refuses_even_in_grace(self):
        DatabaseOverageEpisode.objects.filter(pk=self.episode.pk).update(
            suspended_for="migration", suspended_migration_id=uuid4()
        )
        with self.assertRaisesMessage(ValidationError, "database write hold"):
            self.sell_service()
        self.assertEqual(self.current().state, "grace")

    def test_moving_the_account_to_another_service_is_an_ownership_change_too(self):
        spare = self.spare_service()
        self.held()
        account = VirtualminAccount.objects.get(pk=self.fixture.account.pk)
        account.service = spare
        with self.assertRaisesMessage(ValidationError, "database write hold"):
            account.save()
        self.assertEqual(VirtualminAccount.objects.get(pk=account.pk).service_id, self.fixture.service.pk)

    def spare_service(self) -> Service:
        return Service.objects.create(
            customer=self.buyer,
            service_plan=self.fixture.service.service_plan,
            currency=self.fixture.service.currency,
            service_name="spare.example.test",
            domain="spare.example.test",
            username="sparefixture",
            status="active",
            price=10,
        )

    def test_a_bulk_upsert_cannot_move_an_account_around_the_ownership_fence(self):
        self.held()
        account = VirtualminAccount.objects.get(pk=self.fixture.account.pk)
        account.service = self.spare_service()
        with self.assertRaises(ValidationError):
            VirtualminAccount.objects.bulk_create(
                [account], update_conflicts=True, update_fields=["service"], unique_fields=["id"]
            )
        self.assertEqual(VirtualminAccount.objects.get(pk=account.pk).service_id, self.fixture.service.pk)
        self.assertEqual(self.current().state, "held")
        with self.assertRaises(ValidationError):  # however the field names are given
            VirtualminAccount.objects.bulk_create(
                [account], update_conflicts=True, update_fields=iter(["service"]), unique_fields=["id"]
            )
        account = VirtualminAccount.objects.get(pk=self.fixture.account.pk)
        account.status = "suspended"
        VirtualminAccount.objects.bulk_create(  # an upsert that leaves the owner alone still works
            [account], update_conflicts=True, update_fields=iter(["status"]), unique_fields=["id"]
        )
        self.assertEqual(VirtualminAccount.objects.get(pk=account.pk).status, "suspended")

    def test_a_save_that_keeps_the_owner_changes_nothing(self):
        self.held()
        service = Service.objects.get(pk=self.fixture.service.pk)
        service.service_name = "renamed"
        service.save()
        self.assertEqual(self.current().state, "held")
        with fence_service_ownership({self.fixture.service.pk: self.fixture.customer.pk}, using="default"):
            pass  # the fence ran, and the owner stayed
        self.assertEqual(self.current().state, "held")


class TerminationTests(_Lifecycle, TestCase):
    def terminate(self):
        account = VirtualminAccount.objects.get(pk=self.fixture.account.pk)
        account.status = "terminated"
        with self.captureOnCommitCallbacks(execute=True):
            account.save()

    def test_a_terminated_account_closes_its_episode_whatever_its_state(self):
        self.held()
        self.terminate()
        episode = self.current()
        self.assertEqual((episode.state, episode.close_reason), ("closed", "node_deleted"))
        self.assertEqual([values["close_reason"] for values in self.closed_events()], ["node_deleted"])

    def test_a_failing_close_never_reaches_the_termination_and_the_sweep_closes_it(self):
        self.held()
        with patch(
            "apps.provisioning.database_overage_admission.close_for_terminated_account",
            side_effect=RuntimeError("database gone away"),
        ):
            self.terminate()
        self.assertEqual(VirtualminAccount.objects.get(pk=self.fixture.account.pk).status, "terminated")
        self.assertEqual(self.current().state, "held")
        sweep_database_overages()
        self.assertEqual((self.current().state, self.current().close_reason), ("closed", "node_deleted"))

    def test_a_terminated_account_written_around_the_signal_is_closed_by_the_sweep(self):
        VirtualminAccount.objects.filter(pk=self.fixture.account.pk).update(status="terminated")
        sweep_database_overages()
        self.assertEqual((self.current().state, self.current().close_reason), ("closed", "node_deleted"))

    def test_another_status_change_leaves_the_episode_alone(self):
        account = VirtualminAccount.objects.get(pk=self.fixture.account.pk)
        account.status = "suspended"
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            account.save()
        self.assertFalse([callback for callback in callbacks if "close_overage" in callback.__qualname__])
        self.assertEqual(self.current().state, "grace")
        on_account_terminated(account.pk)  # asked anyway: only a terminated account closes its episode
        self.assertEqual(self.current().state, "grace")
