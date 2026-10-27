"""Account names at the account's lifecycle boundaries (ADR-0061 P1.7).

First the safety net: with `dns.account_hostnames_enabled` off, the create, suspend and migration
paths behave exactly as before, with no name row, no node call and no DNS call. Then each boundary
with it on: a finished create ensures the name on the account's node, a migration puts the name
back on its target before activating, and a terminated or deleted account retires its name.
"""

from __future__ import annotations

from decimal import Decimal
from itertools import count
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch
from uuid import uuid4

from django.utils import timezone

from apps.billing.models import Currency
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.infrastructure.dns_gateway import _DNS_PROVIDER_REGISTRY, register_dns_gateway
from apps.provisioning import account_hostname_lifecycle as lifecycle
from apps.provisioning import account_hostname_service as service
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.settings.services import SettingsService
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_cov_provisioning_services_creation import VirtualminServiceCoverageCase

_domains = count(1)


def _distinct_account(server: Any) -> VirtualminAccount:
    """One more account, with its own customer and service, so several names can share a sweep."""
    n = next(_domains)
    domain = f"sweep{n}.example.test"
    customer = Customer.objects.create(name=domain, customer_type="individual", primary_email=f"owner@{domain}")
    currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    plan = ServicePlan.objects.create(name=f"plan {domain}", plan_type="shared_hosting", price_monthly=Decimal("10"))
    service_row = Service.objects.create(
        customer=customer,
        currency=currency,
        service_plan=plan,
        service_name=domain,
        domain=domain,
        username=f"sweep{n}",
        billing_cycle="monthly",
        price=Decimal("10"),
        status="active",
    )
    return VirtualminAccount.objects.create(
        domain=domain, server=server, virtualmin_username=f"sweep{n}", service=service_row, status="active"
    )


ZONE = "praho-sites.net"
ZONE_ID = "0123456789abcdef0123456789abcdef"


def _configure(*, enabled: bool) -> None:
    for key, value in (
        ("dns.account_hostname_zone", ZONE),
        ("dns.account_hostname_zone_id", ZONE_ID),
        ("dns.account_zone_api_token", "token-value"),
    ):
        SettingsService.update_setting(key, value).unwrap()
    SettingsService.update_setting("dns.account_hostnames_enabled", enabled).unwrap()


class LifecycleCase(VirtualminServiceCoverageCase):
    def setUp(self) -> None:
        super().setUp()
        self.payloads["disable-domain"] = {"status": "success", "message": "disabled"}
        self.payloads["enable-domain"] = {"status": "success", "message": "enabled"}
        previous = _DNS_PROVIDER_REGISTRY.get(service.DNS_PROVIDER)
        register_dns_gateway(service.DNS_PROVIDER, FakeDnsGateway)
        self.addCleanup(lambda: register_dns_gateway(service.DNS_PROVIDER, previous) if previous else None)
        FakeDnsGateway.reset({ZONE_ID: ZONE})
        self.node_calls: list[str] = []
        ensure = patch.object(
            service,
            "ensure_node_account_name",
            lambda account, server, *, enabled, operation_owner=False: (
                self.node_calls.append(f"ensure enabled={enabled}") or Ok(None)
            ),
        )
        ensure.start()
        self.addCleanup(ensure.stop)


class FeatureOffChangesNothingTests(LifecycleCase):
    def test_create_suspend_and_unsuspend_make_no_name_and_no_dns_or_node_call(self) -> None:
        _configure(enabled=False)
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            account = self.provisioning.create_virtualmin_account(self._creation()).unwrap()
            self.provisioning.suspend_account(account, "billing hold").unwrap()
            self.provisioning.unsuspend_account(account).unwrap()
        enqueue.assert_not_called()
        self.assertFalse(AccountHostname.objects.exists())
        self.assertEqual(FakeDnsGateway.calls, [])
        self.assertEqual(self.node_calls, [])

    def test_the_task_and_the_recreate_hook_do_nothing_while_off(self) -> None:
        _configure(enabled=False)
        account = self._account()
        self.assertEqual(lifecycle.ensure_account_name(str(account.pk)), {"outcome": "disabled"})
        self.assertEqual(lifecycle.ensure_on_recreated_node(account, self.server, enabled=False), Ok(None))
        self.assertFalse(AccountHostname.objects.exists())
        self.assertEqual(self.node_calls, [])


class AccountReadyTests(LifecycleCase):
    def test_a_finished_create_enqueues_the_name_once_it_commits(self) -> None:
        _configure(enabled=True)
        with patch("django_q.tasks.async_task") as enqueue:
            with self.captureOnCommitCallbacks(execute=False) as pending:
                account = self.provisioning.create_virtualmin_account(self._creation()).unwrap()
                enqueue.assert_not_called()
            for callback in pending:
                callback()
        enqueue.assert_called_once_with(
            lifecycle.ENSURE_TASK, str(account.pk), timeout=lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS
        )

    def test_the_task_allocates_the_name_points_it_at_the_node_and_serves_it(self) -> None:
        _configure(enabled=True)
        account = self._account()
        VirtualminAccount.objects.filter(pk=account.pk).update(provisioned_at=timezone.now())
        self.server.__class__.objects.filter(pk=self.server.pk).update(ipv4_address="95.217.0.10")
        outcome = lifecycle.ensure_account_name(str(account.pk))
        hostname = AccountHostname.objects.get(account=account)
        self.assertEqual(hostname.target_server, self.server)
        self.assertEqual(self.node_calls, ["ensure enabled=True"])
        self.assertEqual(outcome, {"outcome": "skipped:certificate_not_ready"})

    def test_a_suspended_account_gets_its_name_disabled(self) -> None:
        _configure(enabled=True)
        account = self._account()
        VirtualminAccount.objects.filter(pk=account.pk).update(status="suspended", provisioned_at=timezone.now())
        lifecycle.ensure_account_name(str(account.pk))
        self.assertEqual(self.node_calls, ["ensure enabled=False"])

    def test_the_target_server_is_set_once_and_never_moved_by_the_task(self) -> None:
        _configure(enabled=True)
        account = self._account()
        other = self.server.__class__.objects.create(name="Other", hostname="vm-other.example.com")
        hostname = service.allocate_account_hostname(account)
        AccountHostname.objects.filter(pk=hostname.pk).update(target_server=other)
        lifecycle.ensure_account_name(str(account.pk))
        hostname.refresh_from_db()
        self.assertEqual(hostname.target_server, other, "only a cutover or a recovery moves it")


class MigrationTargetTests(LifecycleCase):
    def test_a_legacy_move_puts_the_name_on_the_target_disabled_before_activation(self) -> None:
        _configure(enabled=True)
        account = self._account()
        service.allocate_account_hostname(account)
        target = self.server.__class__.objects.create(name="Target", hostname="vm-target.example.com")
        order: list[str] = []
        migration = SimpleNamespace(
            contract="legacy",
            account=account,
            target_server=target,
            pre_migration_snapshot={"remote": {"username": account.virtualmin_username, "attributes": {}}},
        )
        migrator = VirtualminMigrationService()
        with (
            patch.object(
                migrator,
                "_domain",
                lambda server, domain: {"username": account.virtualmin_username, "enabled": False, "attributes": {}},
            ),
            patch.object(migrator, "_move", lambda migration, token, state, **kw: order.append(f"move {state}")),
            patch.object(
                service,
                "ensure_node_account_name",
                lambda account, server, *, enabled, operation_owner=False: (
                    order.append(f"ensure {server.hostname} enabled={enabled} owner={operation_owner}") or Ok(None)
                ),
            ),
        ):
            migrator._verify(migration, uuid4())  # type: ignore[arg-type]  # a stand-in migration
        self.assertEqual(order, ["ensure vm-target.example.com enabled=False owner=True", "move activating"])

    def test_the_recreate_hook_hands_back_what_the_node_now_serves(self) -> None:
        # The cutover gates its next step on this outcome (ADR-0061 P2.4), so it must not be dropped.
        _configure(enabled=True)
        account = self._account()
        service.allocate_account_hostname(account)
        served = service.EnsureOutcome(created=True, enabled=False, linked=True, certificate_installed=True)
        with patch.object(service, "ensure_node_account_name", return_value=Ok(served)):
            self.assertEqual(lifecycle.ensure_on_recreated_node(account, self.server, enabled=False), Ok(served))


class TerminationTests(LifecycleCase):
    def _named_account(self) -> tuple[VirtualminAccount, AccountHostname]:
        _configure(enabled=True)
        account = self._account()
        return account, service.allocate_account_hostname(account)

    def test_a_terminated_account_retires_its_name_once_it_commits(self) -> None:
        account, hostname = self._named_account()
        with self.captureOnCommitCallbacks(execute=True):
            account.status = "terminated"
            account.save(update_fields=["status", "updated_at"])
        hostname.refresh_from_db()
        self.assertIsNotNone(hostname.retired_at)

    def test_a_deleted_account_row_retires_its_name_and_keeps_the_label_taken(self) -> None:
        account, hostname = self._named_account()
        with self.captureOnCommitCallbacks(execute=True):
            account.delete()
        hostname.refresh_from_db()
        self.assertIsNotNone(hostname.retired_at)
        self.assertIsNone(hostname.account_id)

    def test_suspension_does_not_retire_the_name(self) -> None:
        account, hostname = self._named_account()
        with self.captureOnCommitCallbacks(execute=True):
            account.status = "suspended"
            account.save(update_fields=["status", "updated_at"])
        hostname.refresh_from_db()
        self.assertIsNone(hostname.retired_at)

    def test_a_retirement_is_audited(self) -> None:
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        account, hostname = self._named_account()
        with self.captureOnCommitCallbacks(execute=True):
            account.status = "terminated"
            account.save(update_fields=["status", "updated_at"])
        events: Any = AuditEvent.objects.filter(object_id=str(hostname.pk)).values_list("action", flat=True)
        self.assertTrue(any("retired" in action for action in events), list(events))


class SweepTests(LifecycleCase):
    def setUp(self) -> None:
        super().setUp()
        # A name reconciled before has its certificate on its node; one that lost it is a node repair
        # (test_account_name_hardening.NodeRepairForReconciledNamesTests).
        ready = patch.object(service, "certificate_ready_on", return_value=True)
        ready.start()
        self.addCleanup(ready.stop)
        self.synced: list[str] = []
        sync = patch.object(
            service,
            "sync_account_hostname",
            lambda hostname, *, skip_locked=False: self.synced.append(hostname.label) or Ok("published"),
        )
        sync.start()
        self.addCleanup(sync.stop)

    def _named(self, **fields: Any) -> AccountHostname:
        account = _distinct_account(self.server)
        hostname = service.allocate_account_hostname(account)
        AccountHostname.objects.filter(pk=hostname.pk).update(target_server=self.server, **fields)
        hostname.refresh_from_db()
        return hostname

    def test_the_sweep_does_nothing_while_off(self) -> None:
        _configure(enabled=False)
        self._named()
        self.assertEqual(lifecycle.reconcile_account_names(), {"disabled": 1})
        self.assertEqual((self.synced, self.node_calls), ([], []))

    def test_a_name_never_reconciled_is_handed_to_its_own_task_not_run_inline(self) -> None:
        _configure(enabled=True)
        hostname = self._named()
        with patch("django_q.tasks.async_task") as enqueue:
            counts = lifecycle.reconcile_account_names()
        enqueue.assert_called_once_with(
            lifecycle.ENSURE_TASK, str(hostname.account_id), timeout=lifecycle.ACCOUNT_NAME_TASK_TIMEOUT_SECONDS
        )
        self.assertEqual((self.node_calls, self.synced), ([], []))
        self.assertEqual(counts["enqueued"], 1)

    def test_names_that_cannot_be_published_yet_never_starve_the_published_ones(self) -> None:
        _configure(enabled=True)
        for _ in range(3):
            self._named()  # never reconciled: their task cannot publish them (no certificate yet)
        published = self._named(last_reconciled_at=timezone.now() - timezone.timedelta(hours=25))
        with patch("django_q.tasks.async_task"), patch.object(lifecycle, "SWEEP_BATCH", 2):
            for _ in range(3):
                lifecycle.reconcile_account_names()
        self.assertIn(published.label, self.synced)

    def test_every_pass_moves_a_name_to_the_back_of_the_queue(self) -> None:
        _configure(enabled=True)
        hostname = self._named(last_reconciled_at=timezone.now() - timezone.timedelta(hours=25))
        with patch.object(service, "sync_account_hostname", return_value=Ok("skipped:certificate_not_ready")):
            lifecycle.reconcile_account_names()
        hostname.refresh_from_db()
        self.assertIsNotNone(hostname.last_swept_at)

    def test_one_name_raising_does_not_stop_the_others(self) -> None:
        _configure(enabled=True)
        first = self._named(last_reconciled_at=timezone.now() - timezone.timedelta(hours=25))
        second = self._named(last_reconciled_at=timezone.now() - timezone.timedelta(hours=26))

        def sync(hostname: AccountHostname, *, skip_locked: bool = False) -> Any:
            if hostname.pk == second.pk:
                raise ValueError("unexpected")
            self.synced.append(hostname.label)
            return Ok("published")

        with patch.object(service, "sync_account_hostname", sync):
            counts = lifecycle.reconcile_account_names()
        self.assertEqual(self.synced, [first.label])
        self.assertEqual(counts["failed"], 1)

    def test_a_fresh_name_is_left_alone_and_a_stale_one_is_synced_again(self) -> None:
        _configure(enabled=True)
        self._named(last_reconciled_at=timezone.now() - timezone.timedelta(hours=1))
        lifecycle.reconcile_account_names()
        self.assertEqual(self.synced, [])
        AccountHostname.objects.update(last_reconciled_at=timezone.now() - timezone.timedelta(hours=25))
        with patch("django_q.tasks.async_task") as enqueue:
            lifecycle.reconcile_account_names()
        self.assertEqual(len(self.synced), 1)
        enqueue.assert_not_called()  # a name reconciled before does not repeat its node step

    def test_the_sweep_passes_over_a_name_being_published_rather_than_wait(self) -> None:
        _configure(enabled=True)
        self._named(last_reconciled_at=timezone.now() - timezone.timedelta(hours=25))
        sync = Mock(return_value=Ok("published"))

        with patch.object(service, "sync_account_hostname", sync):
            lifecycle.reconcile_account_names()

        self.assertEqual([call.kwargs for call in sync.call_args_list], [{"skip_locked": True}])

    def test_an_account_in_an_operation_is_skipped(self) -> None:
        _configure(enabled=True)
        self._named()
        with patch("apps.provisioning.virtualmin_migration_models.account_has_active_operation", return_value=True):
            counts = lifecycle.reconcile_account_names()
        self.assertEqual((self.synced, counts["skipped"]), ([], 1))

    def test_one_run_handles_a_bounded_batch_oldest_first(self) -> None:
        _configure(enabled=True)
        self._named(last_reconciled_at=timezone.now() - timezone.timedelta(hours=25))
        with patch.object(lifecycle, "SWEEP_BATCH", 0):
            lifecycle.reconcile_account_names()
        self.assertEqual(self.synced, [])

    def test_the_sweep_is_scheduled_every_fifteen_minutes(self) -> None:
        from django_q.models import Schedule  # noqa: PLC0415

        from apps.provisioning.virtualmin_tasks import setup_virtualmin_scheduled_tasks  # noqa: PLC0415

        setup_virtualmin_scheduled_tasks()
        row = Schedule.objects.get(name="account-names-reconcile")
        self.assertEqual(
            (row.func, row.minutes), ("apps.provisioning.account_hostname_lifecycle.reconcile_account_names", 15)
        )
