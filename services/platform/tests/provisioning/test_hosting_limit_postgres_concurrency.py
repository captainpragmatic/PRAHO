"""Real READ COMMITTED waits and the financial/native lock boundary."""

from threading import Event
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TransactionTestCase

from apps.customers.models import Customer
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.models import Service, ServicePlan, VirtualminAccount
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.helpers.task_queue import quiet_task_queue
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class HostingLimitPostgresConcurrencyTests(TransactionTestCase):
    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Hosting allowance lock acceptance requires PostgreSQL")
        quiet_task_queue(self)
        VirtualminTaskTestBase.setUp(self)

    def assign(self):
        with transaction.atomic():
            return request_service_plan_change(
                service=self.service,
                target_plan_id=self.plan.pk,
                expected_revision=1,
                submission_id=uuid4(),
                reason="Explicit assignment",
                authority={"kind": "staff_resource_override"},
            ).revision

    def test_creation_pins_committed_plan_snapshot_without_waiting_for_catalog_edit(self):
        self.plan.disk_space_gb = 5
        self.plan.save(update_fields=["disk_space_gb", "updated_at"])
        cached_plan = ServicePlan.objects.get(pk=self.plan.pk)
        start = Event()

        def create():
            if not start.wait(10):
                raise AssertionError("Plan writer never reached its locked boundary")
            service = Service.objects.create(
                customer=self.customer,
                service_plan=cached_plan,
                currency=self.currency,
                service_name="Committed plan snapshot",
                username="waiting_plan",
                price=10,
            )
            return ServiceHostingLimits.objects.get(service=service).disk_allowance_mib

        writer = backend_pid()
        with database_worker(create) as (pid, pending):
            with transaction.atomic():
                self.plan.disk_space_gb = 20
                self.plan.save(update_fields=["disk_space_gb", "updated_at"])
                self.assertEqual(cached_plan.disk_space_gb, 5)
                start.set()
                try:
                    allowance = pending.result(timeout=2)
                except TimeoutError:
                    wait_for_blocker(pid, writer, pending, table="provisioning_service_plans")
                    self.fail("Initial snapshot blocks an unrelated Service insertion on a shared catalog row")
                self.assertEqual(allowance, 5120)
            # The later catalog commit applies only to future snapshots.
            self.assertEqual(pending.result(timeout=10), 5120)

    def test_creation_uses_a_fresh_committed_plan_read_instead_of_cached_relation(self):
        self.plan.disk_space_gb = 5
        self.plan.save(update_fields=["disk_space_gb", "updated_at"])
        cached_plan = ServicePlan.objects.get(pk=self.plan.pk)
        ServicePlan.objects.filter(pk=self.plan.pk).update(disk_space_gb=20)
        service = Service.objects.create(
            customer=self.customer,
            service_plan=cached_plan,
            currency=self.currency,
            service_name="Fresh plan snapshot",
            username="fresh_plan",
            price=10,
        )
        self.assertEqual(cached_plan.disk_space_gb, 5)
        self.assertEqual(ServiceHostingLimits.objects.get(service=service).disk_allowance_mib, 20480)

    def test_owner_transfer_is_rechecked_after_an_observed_service_wait(self):
        other = Customer.objects.create(name="New owner", customer_type="company", status="active")
        start = Event()

        def assign_after_transfer():
            if not start.wait(10):
                raise AssertionError("Owner writer never reached its locked boundary")
            try:
                self.assign()
            except ValidationError:
                return "refused"
            return "accepted"

        writer = backend_pid()
        with database_worker(assign_after_transfer) as (pid, pending):
            with transaction.atomic():
                Service.objects.filter(pk=self.service.pk).update(customer=other)
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_services")
            self.assertEqual(pending.result(timeout=10), "refused")
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 2)

    def test_assignment_commits_while_an_independent_transaction_holds_account(self):
        start = Event()

        def assign_while_native_lane_is_held():
            if not start.wait(10):
                raise AssertionError("Native account holder never reached its boundary")
            return self.assign()

        with database_worker(assign_while_native_lane_is_held) as (_, pending), transaction.atomic():
            VirtualminAccount.objects.select_for_update(of=("self",), no_key=True).get(pk=self.account.pk)
            start.set()
            # This must commit BEFORE the Account transaction releases. A
            # hidden Account FK or lock in the financial path would block.
            self.assertEqual(pending.result(timeout=10), 2)
