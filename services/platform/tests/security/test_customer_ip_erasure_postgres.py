"""Independent PostgreSQL connections prove customer-root erasure ordering."""

from contextlib import ExitStack
from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.db import IntegrityError, connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.audit.services import GDPRDeletionService
from apps.customers.models import Customer
from apps.security import customer_ips
from apps.security.addresses import pack_address
from apps.security.models import CustomerIPObservation
from apps.users.models import CustomerMembership, User
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker


@skipUnless(connection.vendor == "postgresql", "Independent customer-root waits require PostgreSQL")
@override_settings(CROWDSEC_CUSTOMER_IP_OBSERVATIONS_ENABLED=True)
class CustomerObservationErasurePostgreSQLTests(TransactionTestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email="customer-owner-race@example.test")
        self.member = User.objects.create_user(email="customer-member-race@example.test")
        self.customer = Customer.objects.create(name="Individual", customer_type="individual", marketing_consent=False)
        CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner")
        CustomerMembership.objects.create(user=self.member, customer=self.customer, role="billing")

    def record(self):
        return customer_ips.record_recent_customer_ip(user_id=self.member.pk, ip="198.51.100.9")

    def erase(self):
        return GDPRDeletionService._anonymize_user_data(User.objects.get(pk=self.owner.pk))

    def test_erasure_wins_and_other_members_recorder_waits_then_skips_customer(self):
        self.assertTrue(self.record().healthy)
        with ExitStack() as workers:
            with transaction.atomic():
                blocker = backend_pid()
                self.assertTrue(self.erase().is_ok())
                pid, pending = workers.enter_context(database_worker(self.record))
                wait_for_blocker(pid, blocker, pending, table=Customer._meta.db_table)
            result = pending.result(timeout=5)
        self.assertTrue(result.healthy)
        self.assertEqual(result.customer_count, 0)
        self.assertFalse(CustomerIPObservation.objects.exists())

    def test_other_members_recorder_wins_and_erasure_waits_then_deletes_its_row(self):
        entered, release = Event(), Event()
        write = customer_ips._write_observations

        def hold(*args):
            write(*args)
            entered.set()
            if not release.wait(10):
                raise AssertionError("Recorder was not released")

        with patch.object(customer_ips, "_write_observations", side_effect=hold), ExitStack() as workers:
            recorder_pid, recorder = workers.enter_context(database_worker(self.record))
            try:
                self.assertTrue(entered.wait(10))
                erase_pid, erased = workers.enter_context(database_worker(self.erase))
                wait_for_blocker(erase_pid, recorder_pid, erased, table=Customer._meta.db_table)
            finally:
                release.set()
            self.assertTrue(recorder.result(timeout=5).healthy)
            self.assertTrue(erased.result(timeout=5).is_ok())
        self.assertFalse(CustomerIPObservation.objects.exists())

    def test_bulk_insert_waits_for_erasure_then_database_guard_refuses_it(self):
        family, address = pack_address("198.51.100.9")

        def bulk_insert():
            try:
                CustomerIPObservation.objects.bulk_create(
                    [
                        CustomerIPObservation(
                            user_id=self.member.pk, customer_id=self.customer.pk, address_family=family, address=address
                        )
                    ]
                )
            except IntegrityError:
                return "refused"
            return "written"

        with ExitStack() as workers:
            with transaction.atomic():
                blocker = backend_pid()
                Customer.all_objects.select_for_update().get(pk=self.customer.pk)
                Customer.all_objects.filter(pk=self.customer.pk).update(anonymized_at=timezone.now())
                pid, pending = workers.enter_context(database_worker(bulk_insert))
                wait_for_blocker(pid, blocker, pending, table=CustomerIPObservation._meta.db_table, operation="INSERT")
            self.assertEqual(pending.result(timeout=5), "refused")
        self.assertFalse(CustomerIPObservation.objects.exists())

    def test_erasure_locks_full_customer_union_before_marketing_subset(self):
        company = Customer.objects.create(name="Company", customer_type="company", marketing_consent=True)
        CustomerMembership.objects.create(user=self.owner, customer=company, role="billing")
        CustomerMembership.objects.create(user=self.member, customer=company, role="billing")

        def lock_company():
            with transaction.atomic():
                Customer.all_objects.select_for_update(nowait=True).get(pk=company.pk)
            return True

        with ExitStack() as workers:
            with transaction.atomic():
                blocker = backend_pid()
                Customer.all_objects.select_for_update().get(pk=self.customer.pk)
                erase_pid, erased = workers.enter_context(database_worker(self.erase))
                wait_for_blocker(erase_pid, blocker, erased, table=Customer._meta.db_table)
                with database_worker(lock_company) as (_, company_lock):
                    self.assertTrue(company_lock.result(timeout=5), "Later company root must not be locked first")
            self.assertTrue(erased.result(timeout=5).is_ok())
