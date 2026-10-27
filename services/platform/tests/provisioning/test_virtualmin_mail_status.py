"""The public mail projection rechecks tenant binding and never repairs readiness."""

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from freezegun import freeze_time

from apps.customers.models import Customer
from apps.provisioning import virtualmin_mail_status as public
from apps.provisioning.virtualmin_mail_models import VirtualminMailConfiguration
from apps.users.models import CustomerMembership, User
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_account_hostname_models import _account
from tests.provisioning.test_virtualmin_mail_models import MailModelFixture


class MailStatusProjectionTests(MailModelFixture, TestCase):
    def setUp(self):
        self.enterContext(patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"))
        super().setUp()
        self.actor = User.objects.create_user(email="mail-status-viewer@example.test", password="Read-test123!")
        self.customer = self.account.service.customer
        force_status(self.customer, "active")
        self.membership = CustomerMembership.objects.create(user=self.actor, customer=self.customer, role="viewer")

    def read(self, actor=None):
        return public.cached_mail_status(
            self.account.service_id, customer_id=self.customer.pk, actor=self.actor if actor is None else actor
        )

    def test_a_cached_user_cannot_outlive_current_database_revocation(self):
        User.objects.filter(pk=self.actor.pk).update(is_active=False)
        self.assertTrue(self.actor.is_active)
        self.assertEqual(self.read().unwrap_err(), "mail_status_forbidden")
        self.assertFalse(VirtualminMailConfiguration.objects.exists())

    def test_missing_actor_is_refused_instead_of_receiving_system_authority(self):
        self.assertEqual(
            public.cached_mail_status(self.account.service_id, customer_id=self.customer.pk, actor=None).unwrap_err(),
            "mail_status_forbidden",
        )

    def test_revocation_during_projection_does_not_publish_the_earlier_authorized_snapshot(self):
        original = public._operation

        def revoke(configuration, customer_id):
            projected = original(configuration, customer_id)
            CustomerMembership.objects.filter(pk=self.membership.pk).update(is_active=False)
            return projected

        with patch.object(public, "_operation", side_effect=revoke):
            self.assertEqual(self.read().unwrap_err(), "mail_status_forbidden")

    def test_customer_transfer_during_projection_does_not_publish_a_previous_tenants_snapshot(self):
        other = Customer.objects.create(name="Mail projection new customer", status="active")
        original = public._operation

        def transfer(configuration, customer_id):
            projected = original(configuration, customer_id)
            self.account.service.customer = other
            self.account.service.save(update_fields=["customer"])
            return projected

        with patch.object(public, "_operation", side_effect=transfer):
            self.assertEqual(self.read().unwrap_err(), "mail_status_not_found")

    def test_account_relink_during_projection_does_not_publish_its_name_to_the_old_service(self):
        replacement = _account(self.server, "relinked-mail.example.test")
        destination = replacement.service
        replacement.delete()
        original = public._operation
        service_id = self.account.service_id

        def relink(configuration, customer_id):
            projected = original(configuration, customer_id)
            self.account.service = destination
            self.account.save(update_fields=["service"])
            return projected

        with patch.object(public, "_operation", side_effect=relink):
            result = public.cached_mail_status(service_id, customer_id=self.customer.pk, actor=self.actor)
        self.assertEqual(result.unwrap_err(), "mail_status_not_found")

    def test_a_retired_or_foreign_target_name_is_never_offered_as_current_connection_info(self):
        self.name.target_server = None
        self.name.save(update_fields=["target_server"])
        self.assertIsNone(self.read().unwrap()["account_name"])
        self.name.target_server = self.server
        self.name.retired_at = timezone.now()
        self.name.save(update_fields=["target_server", "retired_at"])
        self.assertIsNone(self.read().unwrap()["account_name"])

    def test_time_expiry_only_changes_the_projection_and_preserves_recorded_hosted_enrollment(self):
        configuration = self.prepared()
        configuration.enable_hosted()
        configuration.save()
        original = dict(configuration.readiness)
        with freeze_time(timezone.now() + timedelta(hours=2)):
            status = self.read().unwrap()
        self.assertEqual((status["mode"], status["enrolled"], status["verification"]), ("hosted", True, "stale"))
        configuration.refresh_from_db()
        self.assertEqual(configuration.mode, "hosted")
        self.assertEqual(configuration.readiness, original)
