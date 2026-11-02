"""Shared configuration protects edits while unrelated foreign-key references commit."""

from datetime import timedelta
from threading import Event
from time import monotonic
from unittest import skipUnless
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.domains.services import DomainReconciliationService
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_tasks import provision_virtualmin_account
from tests.common.postgres_locking import database_worker, wait_for_blocker
from tests.provisioning import test_virtualmin_tasks as fixtures


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL deferred FK checks at COMMIT")
class ConfigurationRowLockTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.enterContext(patch("django_q.tasks.async_task"))
        fixtures.VirtualminTaskTestBase.setUp(self)
        # The public provisioning validator refuses a literal "test" DNS label.
        self.service.domain = "configuration.example.com"
        self.service.save(update_fields=["domain", "updated_at"])
        self.other = Customer.objects.create(name="Independent buyer", primary_email="independent@example.test")

    def _assert_reference_and_edit(self, operation, table, reference, edit) -> None:
        entered, release = Event(), Event()
        statements = []

        def held():
            def observe(execute, sql, params, many, context):
                result = execute(sql, params, many, context)
                if not entered.is_set() and table in sql and "FOR " in sql:
                    statements.append(sql)
                    entered.set()
                    assert release.wait(15)
                return result

            with connection.execute_wrapper(observe):
                return operation()

        with database_worker(held) as (owner, operation_result):
            try:
                self.assertTrue(entered.wait(10), f"Operation never locked its configuration: {operation_result.result(timeout=1) if operation_result.done() else 'still running'}")
                with database_worker(reference) as (pid, pending):
                    deadline = monotonic() + 5
                    sample = None
                    while not pending.done() and monotonic() < deadline:
                        with connection.cursor() as cursor:
                            cursor.execute("SELECT pg_stat_clear_snapshot()")
                            cursor.execute("SELECT pg_blocking_pids(%s), query FROM pg_stat_activity WHERE pid=%s", [pid, pid])
                            sample = cursor.fetchone()
                        if sample and owner in sample[0]:
                            self.fail(f"Unrelated FK reference cannot COMMIT: {sample!r}")
                        Event().wait(0.01)
                    self.assertIsNotNone(pending.result(timeout=5))
                # Configuration still cannot be edited while the operation is paused.
                with database_worker(edit) as (pid, pending):
                    wait_for_blocker(pid, owner, pending, table=table, operation="UPDATE")
                    release.set()
                    self.assertEqual(pending.result(timeout=20), 1)
                self.assertIn("FOR NO KEY UPDATE", statements[0])
            finally:
                release.set()
            self.assertIsNotNone(operation_result.result(timeout=25))

    def test_service_plan_allows_other_customer_service_commit_but_blocks_edits(self) -> None:
        self._assert_reference_and_edit(
            lambda: provision_virtualmin_account({"service_id": self.service.pk, "domain": self.service.domain}),
            ServicePlan._meta.db_table,
            lambda: Service.objects.create(customer=self.other, service_plan=self.plan, currency=self.currency,
                                           service_name="independent.example.test", username="independent", price=10),
            lambda: ServicePlan.objects.filter(pk=self.plan.pk).update(name="Edited after operation"),
        )

    def test_tld_allows_other_customer_domain_commit_but_blocks_edits(self) -> None:
        tld = TLD.objects.create(extension="test", description="Test", registration_price_cents=100,
                                 renewal_price_cents=100, transfer_price_cents=100)
        registrar = Registrar.objects.create(name="test-registrar", display_name="Test registrar")
        domain = Domain.objects.create(name="expired.test", tld=tld, registrar=registrar, customer=self.customer,
                                       status="active", expires_at=timezone.now() - timedelta(days=60))
        self._assert_reference_and_edit(
            lambda: DomainReconciliationService._expire_post_grace_domains(timezone.now()),
            TLD._meta.db_table,
            lambda: Domain.objects.create(name="independent.test", tld=tld, registrar=registrar, customer=self.other),
            lambda: TLD.objects.filter(pk=tld.pk).update(grace_period_days=90),
        )
        domain.refresh_from_db()
        self.assertEqual(domain.status, "expired")
