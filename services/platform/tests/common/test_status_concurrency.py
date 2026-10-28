"""Exercise real row-lock races on PostgreSQL and the same ordering contract on SQLite."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event
from types import SimpleNamespace
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection, connections, transaction
from django.test import RequestFactory, TransactionTestCase, override_settings
from django.utils import timezone
from django_q.models import OrmQ

from apps.billing.models import Currency
from apps.common.status_models import SystemCheckState
from apps.common.status_observations import Observation, claim_check, finish_check
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.scheduled_backups import continue_after_completed_backup, schedule_customer_backup
from apps.provisioning.virtualmin_backup_service import backup_storage_configuration
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from config.settings.test import LOCMEM_TEST_CACHE


class StatusConcurrencyTests(TransactionTestCase):
    @override_settings(CACHES=LOCMEM_TEST_CACHE)
    def test_status_read_failures_preserve_the_callers_transaction(self) -> None:
        from apps.common import system_status as status  # noqa: PLC0415
        from apps.common.context_processors import setup_attention  # noqa: PLC0415

        def failed_read():
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM missing_status_read_fixture")

        SystemCheckState.objects.create(check_key="status_refresh", input_identity="a" * 64)
        cache.set(status.CACHE_KEY, status.StatusSnapshot([status.SubsystemStatus("Email", status.StatusLevel.GREEN, "Verified", key="email")], input_identity="a" * 64))
        request = RequestFactory().get("/settings/setup/")
        request.user = SimpleNamespace(is_authenticated=True, is_superuser=True)
        with transaction.atomic(), patch.object(status, "runtime_input_identity", side_effect=failed_read):
            self.assertEqual(status.get_cached_status().results[0].level, status.StatusLevel.AMBER)
            self.assertEqual(SystemCheckState.objects.count(), 1)
        with transaction.atomic(), patch("apps.settings.setup_checklist.get_setup_report", side_effect=failed_read):
            self.assertTrue(setup_attention(request)["setup_status_unavailable"])
            self.assertEqual(SystemCheckState.objects.count(), 1)

    def _due_account(self, suffix: str) -> VirtualminAccount:
        customer = Customer.objects.create(name=suffix, customer_type="company", primary_email=f"{suffix}@hosting.test")
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name=suffix, plan_type="shared_hosting", price_monthly=10)
        service = Service.objects.create(customer=customer, service_plan=plan, currency=currency, service_name=suffix,
                                         domain=f"{suffix}.hosting.test", username=suffix, billing_cycle="monthly", price=10, status="active")
        server = VirtualminServer.objects.create(name=suffix, hostname=f"{suffix}.hosting.test", api_username="root", encrypted_api_password=b"")
        account = VirtualminAccount.objects.create(service=service, server=server, domain=service.domain, virtualmin_username=suffix,
                                                   encrypted_password=b"", status="active", praho_customer_id=customer.pk, praho_service_id=service.pk)
        VirtualminAccount.objects.filter(pk=account.pk).update(created_at=timezone.now() - timedelta(days=2))
        return account

    def test_tick_and_completion_admit_exactly_one_job_and_queue_message(self) -> None:
        completed_account = self._due_account("completed")
        target = self._due_account("eligible")
        completed = VirtualminProvisioningJob.objects.create(account=completed_account, server=completed_account.server,
                                                             operation="backup_domain", status="completed", parameters={"initiated_by": "scheduled_platform_backup"},
                                                             result={"status": "completed", "checksum_sha256": "a" * 64, "s3_info": {"metadata_key": "virtualmin-backups/current/metadata.json", "storage_identity": backup_storage_configuration().identity}})
        with patch("apps.provisioning.scheduled_backups.backup_configuration", return_value=(True, "0 0 * * *")), patch("apps.provisioning.scheduled_backups.server_transport_ready", return_value=Ok(None)):
            if connection.vendor == "postgresql":
                barrier = Barrier(2)

                def trigger(source):
                    try:
                        barrier.wait(timeout=5)
                        if source == "completion":
                            continue_after_completed_backup(completed)
                        else:
                            schedule_customer_backup()
                    finally:
                        connections.close_all()

                with ThreadPoolExecutor(max_workers=2) as pool:
                    list(pool.map(trigger, ("completion", "tick")))
            else:
                continue_after_completed_backup(completed)
                schedule_customer_backup()
        pending = VirtualminProvisioningJob.objects.filter(operation="backup_domain", status="pending")
        self.assertEqual(pending.count(), 1)
        self.assertEqual(pending.get().account_id, target.pk)
        backup_messages = [row.task for row in OrmQ.objects.all() if row.task.get("func") == "apps.provisioning.virtualmin_tasks.run_virtualmin_backup"]
        self.assertEqual(len(backup_messages), 1)
        self.assertEqual(backup_messages[0]["args"], (str(pending.get().pk),))

    def test_completion_waiting_past_lease_expiry_is_rejected(self) -> None:
        claim = claim_check("expiry", identity="a" * 64, lease_time=timedelta(milliseconds=200))
        assert claim is not None
        if connection.vendor == "postgresql":
            started = Event()

            def publish():
                try:
                    started.set()
                    return finish_check(claim, identity="a" * 64, observation=Observation("green", "connected"))
                finally:
                    connections.close_all()

            with ThreadPoolExecutor(max_workers=1) as pool:
                with transaction.atomic():
                    SystemCheckState.objects.select_for_update().get(pk=claim.state_id)
                    pending = pool.submit(publish)
                    self.assertTrue(started.wait(timeout=5))
                    Event().wait(timeout=0.4)
                self.assertFalse(pending.result(timeout=5))
        else:
            SystemCheckState.objects.filter(pk=claim.state_id).update(lease_until=timezone.now() - timedelta(seconds=1))
            self.assertFalse(finish_check(claim, identity="a" * 64, observation=Observation("green", "connected")))
        row = SystemCheckState.objects.get(pk=claim.state_id)
        self.assertIsNone(row.last_success_at)

    def test_competing_claims_have_exactly_one_owner(self) -> None:
        SystemCheckState.objects.create(check_key="race", input_identity="a" * 64)
        if connection.vendor == "postgresql":
            barrier = Barrier(2)

            def attempt():
                try:
                    barrier.wait(timeout=5)
                    return claim_check("race", identity="a" * 64)
                finally:
                    connections.close_all()

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: attempt(), range(2)))
        else:
            results = [claim_check("race", identity="a" * 64), claim_check("race", identity="a" * 64)]
        self.assertEqual(sum(result is not None for result in results), 1)
        row = SystemCheckState.objects.get(check_key="race")
        self.assertEqual(row.sequence, 1)
        self.assertIsNotNone(row.claim_token)

    def test_obsolete_completion_cannot_overwrite_replacement(self) -> None:
        first = claim_check("race", identity="a" * 64)
        assert first is not None
        SystemCheckState.objects.filter(pk=first.state_id).update(lease_until=timezone.now() - timedelta(seconds=1))
        replacement = claim_check("race", identity="a" * 64)
        assert replacement is not None
        if connection.vendor == "postgresql":
            barrier = Barrier(2)

            def publish(item):
                claim, level = item
                try:
                    barrier.wait(timeout=5)
                    return finish_check(claim, identity="a" * 64, observation=Observation(level, "observed"))
                finally:
                    connections.close_all()

            with ThreadPoolExecutor(max_workers=2) as pool:
                accepted = list(pool.map(publish, ((first, "green"), (replacement, "red"))))
        else:
            accepted = [finish_check(first, identity="a" * 64, observation=Observation("green", "observed")),
                        finish_check(replacement, identity="a" * 64, observation=Observation("red", "observed"))]
        self.assertEqual(accepted, [False, True])
        row = SystemCheckState.objects.get(check_key="race")
        self.assertEqual(row.level, "red")
        self.assertIsNone(row.last_success_at)
