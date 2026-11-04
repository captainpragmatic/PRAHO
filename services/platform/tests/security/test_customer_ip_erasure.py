"""Customer erasure also protects observations belonging to other active members."""

from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.audit.services import GDPRDeletionService, GDPRExportService
from apps.customers.erasure_guard import CustomerErasedError
from apps.customers.models import Customer
from apps.security.addresses import pack_address
from apps.security.customer_ips import record_recent_customer_ip
from apps.security.models import CustomerIPObservation
from apps.users.models import CustomerMembership, User


@override_settings(CROWDSEC_CUSTOMER_IP_OBSERVATIONS_ENABLED=True)
class CustomerObservationErasureTests(TransactionTestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email="erasure-owner@example.test", password="fixture-password")
        self.member = User.objects.create_user(email="erasure-member@example.test", password="fixture-password")
        self.customer = Customer.objects.create(name="Individual", customer_type="individual")
        CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner")
        CustomerMembership.objects.create(user=self.member, customer=self.customer, role="billing")

    def observation(self, customer=None):
        family, address = pack_address("198.51.100.9")
        return CustomerIPObservation(
            user=self.member, customer=customer or self.customer, address_family=family, address=address
        )

    def erase(self):
        result = GDPRDeletionService._anonymize_user_data(self.owner)
        self.assertTrue(result.is_ok(), result)
        self.assertIsNotNone(Customer.all_objects.get(pk=self.customer.pk).anonymized_at)

    def test_erasure_deletes_observations_of_other_active_members(self):
        self.observation().save()
        self.erase()
        self.assertFalse(CustomerIPObservation.objects.exists())
        self.assertTrue(User.objects.get(pk=self.member.pk).is_active)

    def test_other_member_login_skips_erased_customer_but_keeps_live_memberships(self):
        live = Customer.objects.create(name="Live company", customer_type="company")
        CustomerMembership.objects.create(user=self.member, customer=live, role="billing")
        self.erase()
        result = record_recent_customer_ip(user_id=self.member.pk, ip="198.51.100.9")
        self.assertTrue(result.healthy)
        self.assertEqual(result.customer_count, 1)
        self.assertEqual(list(CustomerIPObservation.objects.values_list("customer_id", flat=True)), [live.pk])

    def test_stale_save_cannot_reinsert_deleted_observation(self):
        stale = self.observation()
        stale.save()
        self.erase()
        with self.assertRaises(CustomerErasedError):
            stale.save()
        self.assertFalse(CustomerIPObservation.objects.exists())

    def test_bulk_insert_cannot_bypass_customer_erasure(self):
        Customer.all_objects.filter(pk=self.customer.pk).update(anonymized_at=timezone.now())
        with self.assertRaises(IntegrityError), transaction.atomic():
            CustomerIPObservation.objects.bulk_create([self.observation()])
        self.assertFalse(CustomerIPObservation.objects.exists())

    def test_queryset_refresh_cannot_bypass_customer_erasure(self):
        row = self.observation()
        row.save()
        Customer.all_objects.filter(pk=self.customer.pk).update(anonymized_at=timezone.now())
        with self.assertRaises(IntegrityError), transaction.atomic():
            CustomerIPObservation.objects.filter(pk=row.pk).update(last_seen_at=timezone.now())

    def test_bulk_upsert_cannot_refresh_erased_customer(self):
        self.observation().save()
        Customer.all_objects.filter(pk=self.customer.pk).update(anonymized_at=timezone.now())
        with self.assertRaises(IntegrityError), transaction.atomic():
            CustomerIPObservation.objects.bulk_create(
                [self.observation()],
                update_conflicts=True,
                update_fields=["last_seen_at"],
                unique_fields=["user", "customer", "address_family", "address"],
            )

    def test_bulk_retarget_cannot_move_observation_to_erased_customer(self):
        live = Customer.objects.create(name="Live", customer_type="company")
        row = self.observation(live)
        row.save()
        Customer.all_objects.filter(pk=self.customer.pk).update(anonymized_at=timezone.now())
        row.customer = self.customer
        with self.assertRaises(IntegrityError), transaction.atomic():
            CustomerIPObservation.objects.bulk_update([row], ["customer"])
        row.refresh_from_db()
        self.assertEqual(row.customer_id, live.pk)

    def test_export_omits_preexisting_erased_customer_observations(self):
        self.observation().save()
        Customer.all_objects.filter(pk=self.customer.pk).update(anonymized_at=timezone.now())
        exported = GDPRExportService._collect_user_data(self.member, {"include_audit_logs": True})
        self.assertEqual(exported["recent_customer_ip_observations"], [])

    def test_database_guard_reverses_and_restores_without_rewriting_existing_history(self):
        executor = MigrationExecutor(connection)
        leaves = executor.loader.graph.leaf_nodes("security")
        try:
            executor.migrate([("security", "0003_merge_actions_observations")])
            Customer.all_objects.filter(pk=self.customer.pk).update(anonymized_at=timezone.now())
            CustomerIPObservation.objects.bulk_create([self.observation()])
        finally:
            MigrationExecutor(connection).migrate(leaves)
        self.assertEqual(CustomerIPObservation.objects.count(), 1)
        another = self.observation()
        another.address_family, another.address = pack_address("198.51.100.10")
        with self.assertRaises(IntegrityError), transaction.atomic():
            CustomerIPObservation.objects.bulk_create([another])
