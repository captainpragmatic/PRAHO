"""Account names after review: a name is always retired in the end, and nothing breaks what it hooks.

- A retire that fails (the provider down at a termination or a delete) is finished by the sweep;
  a sync that was already running when the name was retired never brings its records back.
- The lifecycle hooks never raise into the create or the termination they sit in: a failed
  settings read must not roll back a domain that was created.
- With the feature off, the daily certificate job does nothing at all.
- A name the sweep cannot publish yet gets its node step at most once an hour, not every 15 minutes.
- A retired name no longer holds its node, and allocation races resolve to the one row.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.db import DatabaseError
from django.utils import timezone

from apps.provisioning import account_hostname_lifecycle as lifecycle
from apps.provisioning import account_hostname_service as service
from apps.provisioning import account_name_certificates as certs
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_models import VirtualminAccount
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_account_hostname_lifecycle import (
    LifecycleCase,
    _configure,
    _distinct_account,
)
from tests.provisioning.test_account_hostname_service import ZONE_ID, AccountNameTestCase


class RetireFinishedTests(LifecycleCase):
    def _named(self) -> tuple[VirtualminAccount, AccountHostname]:
        _configure(enabled=True)
        account = _distinct_account(self.server)
        hostname = service.allocate_account_hostname(account)
        AccountHostname.objects.filter(pk=hostname.pk).update(
            target_server=self.server, records={"A": {"intended": "95.217.0.10", "applied": "95.217.0.10"}}
        )
        return account, hostname

    def test_a_retire_that_failed_at_termination_is_finished_by_the_sweep(self) -> None:
        account, hostname = self._named()
        with (
            patch.object(FakeDnsGateway, "delete_owned_records", return_value=service.Err("provider down")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            account.status = "terminated"
            account.save(update_fields=["status", "updated_at"])
        hostname.refresh_from_db()
        self.assertIsNone(hostname.retired_at, "the provider was down")

        lifecycle.reconcile_account_names()

        hostname.refresh_from_db()
        self.assertIsNotNone(hostname.retired_at)
        self.assertIn(f"delete {ZONE_ID} {service.owner_tag(hostname)}", FakeDnsGateway.calls)

    def test_a_retire_that_failed_at_a_delete_is_finished_by_the_sweep(self) -> None:
        account, hostname = self._named()
        with (
            patch.object(FakeDnsGateway, "delete_owned_records", return_value=service.Err("provider down")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            account.delete()
        hostname.refresh_from_db()
        self.assertEqual((hostname.account_id, hostname.retired_at), (None, None))

        lifecycle.reconcile_account_names()

        hostname.refresh_from_db()
        self.assertIsNotNone(hostname.retired_at)


class SyncAfterRetireTests(AccountNameTestCase):
    def test_a_sync_running_when_the_name_is_retired_leaves_no_record_behind(self) -> None:
        from apps.infrastructure.dns_gateway import _DNS_PROVIDER_REGISTRY, register_dns_gateway  # noqa: PLC0415
        from apps.settings.services import SettingsService  # noqa: PLC0415

        previous = _DNS_PROVIDER_REGISTRY.get(service.DNS_PROVIDER)
        register_dns_gateway(service.DNS_PROVIDER, FakeDnsGateway)
        self.addCleanup(lambda: register_dns_gateway(service.DNS_PROVIDER, previous) if previous else None)
        FakeDnsGateway.reset({ZONE_ID: "praho-sites.net"})
        SettingsService.update_setting("dns.account_hostnames_enabled", True).unwrap()
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=self.server)
        self.hostname.refresh_from_db()
        real_reconcile = FakeDnsGateway.reconcile_records

        def reconcile_then_retired(gateway: Any, zone_id: str, specs: Any, owner: str) -> Any:
            outcome = real_reconcile(gateway, zone_id, specs, owner)
            AccountHostname.objects.filter(pk=self.hostname.pk).update(retired_at=timezone.now(), records={})
            return outcome

        with (
            patch.object(service, "certificate_ready_on", return_value=True),
            patch.object(FakeDnsGateway, "reconcile_records", reconcile_then_retired),
        ):
            service.sync_account_hostname(self.hostname)

        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.records, {})
        self.assertEqual(FakeDnsGateway.published(self.hostname.fqdn), {})


class HooksNeverRaiseTests(LifecycleCase):
    def test_a_failed_settings_read_does_not_undo_a_created_domain(self) -> None:
        with patch.object(lifecycle.config, "account_hostnames_enabled", side_effect=DatabaseError("cache down")):
            result = self.provisioning.create_virtualmin_account(self._creation())

        self.assertTrue(result.is_ok(), result)
        self.assertNotIn("delete-domain", self._programs())

    def test_a_failed_lookup_does_not_break_a_termination(self) -> None:
        account = _distinct_account(self.server)
        with patch.object(lifecycle.AccountHostname.objects, "filter", side_effect=DatabaseError("db hiccup")):
            account.status = "terminated"
            account.save(update_fields=["status", "updated_at"])

        account.refresh_from_db()
        self.assertEqual(account.status, "terminated")


class FeatureOffCertificatesTests(LifecycleCase):
    def test_the_daily_certificate_job_does_nothing_while_off(self) -> None:
        _configure(enabled=False)
        with (
            patch.object(certs, "_dispatch") as dispatch,
            patch.object(certs, "get_dns_gateway") as dns,
        ):
            counts = certs.renew_due_certificates()

        dispatch.assert_not_called()
        dns.assert_not_called()
        self.assertEqual(counts, {"disabled": 1})


class NodeStepBackoffTests(LifecycleCase):
    def test_a_name_that_cannot_be_published_gets_its_node_step_at_most_hourly(self) -> None:
        _configure(enabled=True)
        hostname = service.allocate_account_hostname(_distinct_account(self.server))
        AccountHostname.objects.filter(pk=hostname.pk).update(target_server=self.server)
        with patch("django_q.tasks.async_task") as enqueue:
            lifecycle.reconcile_account_names()
            lifecycle.reconcile_account_names()
            self.assertEqual(enqueue.call_count, 1)
            AccountHostname.objects.filter(pk=hostname.pk).update(
                last_swept_at=timezone.now() - lifecycle.NODE_STEP_BACKOFF - timezone.timedelta(minutes=1)
            )
            lifecycle.reconcile_account_names()
        self.assertEqual(enqueue.call_count, 2)


class RetiredNameReleasesItsNodeTests(AccountNameTestCase):
    def test_a_retired_name_no_longer_holds_its_node(self) -> None:
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=self.server)
        self.hostname.refresh_from_db()

        service.retire_account_hostname(self.hostname).unwrap()

        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.target_server_id)


class AllocationRaceTests(AccountNameTestCase):
    def test_a_name_created_meanwhile_for_the_account_is_the_one_returned(self) -> None:
        # setUp allocated the account's name; a second allocation that read "none" before it existed
        # hits the account's uniqueness, and must return that row rather than draw labels for ever.
        created = service._create_name_row(self.account, "praho-sites.net")

        self.assertEqual(created.pk, self.hostname.pk)
