"""Hosting ownership changes serialize with account-name publishers without transferring DNS ownership."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, models, transaction
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings

from apps.audit.models import AuditEvent
from apps.customers.models import Customer
from apps.domains.dns_zone_import import make_record_data
from apps.domains.dns_zone_models import HostedZone, HostedZoneRecord
from apps.infrastructure.dns_zone_gateway import ProviderZoneRecord
from apps.provisioning import account_hostname_service as names
from apps.provisioning import hosted_zone_ownership as ownership
from apps.provisioning import managed_dns_service as managed
from apps.provisioning import service_views
from apps.provisioning.service_models import Service
from apps.provisioning.service_views import service_edit
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.users.models import User
from tests.domains.test_dns_zone_import_service import hosting_fixture
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_managed_customer_dns import MemoryZoneGateway


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class HostedZoneOwnershipTests(TestCase):
    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    def test_full_account_save_keeps_general_audit_without_inventing_a_server_move(self):
        self.account.set_password("ownership-audit-test-password")
        self.account.save()
        actions = list(AuditEvent.objects.filter(object_id=str(self.account.pk)).values_list("action", flat=True))
        self.assertEqual(actions.count("virtualmin_account_updated"), 1)
        self.assertNotIn("virtualmin_account_server_migrated", actions)
        self.assertNotIn("virtualmin_account_status_changed", actions)

    def setUp(self):
        self.account, self.hostname, _actor = hosting_fixture()
        self.service = self.account.service
        self.customer = self.service.customer
        self.other = Customer.objects.create(name="Next owner")
        self.third = Customer.objects.create(name="Third owner")
        self.zone = HostedZone.objects.create(
            customer=self.customer,
            service=self.service,
            account=self.account,
            account_hostname=self.hostname,
            name=self.account.domain,
            provider_account_id="a" * 32,
            provider_zone_id="b" * 32,
            current_revision=1,
            confirmed_revision=1,
            applied_revision=1,
            status="active",
        )

    def another_service(self, *, customer=None, suffix="next"):
        return Service.objects.create(
            customer=customer or self.customer,
            service_plan=self.service.service_plan,
            currency=self.service.currency,
            service_name="Next hosting",
            domain=f"{suffix}.example.net",
            username=suffix,
            price="10.00",
            status="active",
        )

    def test_fresh_transfer_remains_possible_and_independent_dns_customer_stays_put(self):
        self.service.customer = self.other
        self.service.save(update_fields=["customer", "updated_at"])
        self.service.refresh_from_db()
        self.zone.refresh_from_db()
        self.assertEqual(self.service.customer_id, self.other.pk)
        self.assertEqual(self.zone.customer_id, self.customer.pk)
        with transaction.atomic(), patch.object(managed, "get_zone_gateway") as provider:
            result = managed.sync_managed_locked(names.lock_for_publication(self.hostname.pk))
        self.assertTrue(result.is_err())
        provider.assert_not_called()

    def test_stale_service_edit_cannot_overwrite_an_ownership_change(self):
        stale = Service.objects.get(pk=self.service.pk)
        Service.objects.filter(pk=stale.pk).update(customer=self.other)
        stale.customer = self.third
        with self.assertRaises(ValidationError):
            stale.save()
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, self.other.pk)

    def test_unrelated_full_save_does_not_restore_a_cached_former_customer(self):
        stale = Service.objects.get(pk=self.service.pk)
        Service.objects.filter(pk=stale.pk).update(customer=self.other)
        stale.service_name = "Renamed hosting"
        stale.save()
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, self.other.pk)
        self.assertEqual(self.service.service_name, "Renamed hosting")

    def test_unrelated_explicit_save_does_not_take_the_ownership_fence(self):
        with patch(
            "apps.provisioning.hosted_zone_ownership.fence_service_ownership",
            side_effect=AssertionError("unrelated save fenced"),
        ):
            self.service.service_name = "Renamed"
            self.service.save(update_fields=["service_name"])
        self.service.refresh_from_db()
        self.assertEqual(self.service.service_name, "Renamed")

    def test_deferred_nonownership_save_preserves_current_customer(self):
        deferred = Service.objects.only("pk", "service_name").get(pk=self.service.pk)
        Service.objects.filter(pk=self.service.pk).update(customer=self.other)
        deferred.service_name = "Deferred rename"
        deferred.save()
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, self.other.pk)

    def test_ownership_expressions_are_refused_before_a_queryset_can_bypass_the_fence(self):
        with self.assertRaises(ValidationError):
            Service.objects.filter(pk=self.service.pk).update(customer_id=models.F("customer_id"))

    def test_bulk_customer_transfer_is_supported_but_stale_bulk_edits_are_atomic(self):
        fresh = Service.objects.get(pk=self.service.pk)
        fresh.customer = self.other
        fresh.service_name = "Bulk transferred"
        self.assertEqual(Service.objects.bulk_update([fresh], ["customer", "service_name"]), 1)
        stale = Service.objects.get(pk=self.service.pk)
        Service.objects.filter(pk=self.service.pk).update(customer=self.third)
        stale.customer = self.customer
        stale.service_name = "Must not land"
        with self.assertRaises(ValidationError):
            Service.objects.bulk_update([stale], ["customer", "service_name"])
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, self.third.pk)
        self.assertEqual(self.service.service_name, "Bulk transferred")

    def test_same_customer_account_relink_invalidates_old_managed_authority(self):
        replacement = self.another_service()
        self.account.service = replacement
        self.account.save(update_fields=["service"])
        with transaction.atomic(), patch.object(managed, "get_zone_gateway") as provider:
            result = managed.sync_managed_locked(names.lock_for_publication(self.hostname.pk))
        self.assertTrue(result.is_err())
        provider.assert_not_called()
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.service_id, self.service.pk)

    def test_stale_account_relink_is_rejected_without_restoring_the_former_service(self):
        stale = VirtualminAccount.objects.get(pk=self.account.pk)
        replacement = self.another_service()
        third = self.another_service(suffix="third")
        VirtualminAccount.objects.filter(pk=stale.pk).update(service=replacement)
        stale.service = third
        with self.assertRaises(ValidationError):
            stale.save()
        self.account.refresh_from_db()
        self.assertEqual(self.account.service_id, replacement.pk)

    def test_unrelated_account_full_save_preserves_a_concurrent_service_relink(self):
        stale = VirtualminAccount.objects.get(pk=self.account.pk)
        replacement = self.another_service()
        VirtualminAccount.objects.filter(pk=stale.pk).update(service=replacement)
        stale.status_message = "Only a monitoring update"
        stale.save()
        self.account.refresh_from_db()
        self.assertEqual(self.account.service_id, replacement.pk)
        self.assertEqual(self.account.status_message, "Only a monitoring update")

    def test_account_bulk_relink_respects_loaded_identity(self):
        stale = VirtualminAccount.objects.get(pk=self.account.pk)
        replacement = self.another_service()
        third = self.another_service(suffix="third")
        VirtualminAccount.objects.filter(pk=stale.pk).update(service=replacement)
        stale.service = third
        with self.assertRaises(ValidationError):
            VirtualminAccount.objects.bulk_update([stale], ["service"])

    def test_stale_staff_transfer_form_returns_conflict_and_current_owner(self):
        stale = Service.objects.get(pk=self.service.pk)
        Service.objects.filter(pk=stale.pk).update(customer=self.other)
        staff = User.objects.create_superuser(email="ownership-form-staff@example.net")
        request = RequestFactory().post(
            "/provisioning/services/edit/",
            {
                "customer_id": self.third.pk,
                "plan_id": self.service.service_plan_id,
                "domain": self.service.domain,
            },
        )
        request.user = staff
        request.session = {}
        request._messages = FallbackStorage(request)
        original = service_views.get_object_or_404

        def stale_service(model, *args, **kwargs):
            return stale if model is Service else original(model, *args, **kwargs)

        with patch.object(service_views, "get_object_or_404", side_effect=stale_service):
            response = service_edit(request, self.service.pk)
        self.assertEqual(response.status_code, 409)
        self.assertIn("changed", response.content.decode().lower())
        self.assertIn(self.other.name, response.content.decode())
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, self.other.pk)


_RACE_SECONDS = 15


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class HostedZoneOwnershipPostgresTests(TransactionTestCase):
    """Use independent connections and observed PostgreSQL lock waits, not timing guesses."""

    def setUp(self):
        if connection.vendor != "postgresql":
            self.skipTest("Ownership publication races require PostgreSQL row locks")
        self.enterContext(patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"))
        self.account, self.hostname, _actor = hosting_fixture()
        self.service = self.account.service
        self.customer = self.service.customer
        self.other = Customer.objects.create(name="Transferred owner")
        self.staff = User.objects.create_superuser(email="ownership-staff@example.net")
        self.zone = HostedZone.objects.create(
            customer=self.customer,
            service=self.service,
            account=self.account,
            account_hostname=self.hostname,
            name=self.account.domain,
            provider_account_id="a" * 32,
            provider_zone_id="b" * 32,
            current_revision=1,
            confirmed_revision=1,
            applied_revision=1,
            status="active",
        )
        data = make_record_data("A", str(self.account.server.ipv4_address))
        row = HostedZoneRecord.objects.create(
            zone=self.zone,
            name=self.zone.name,
            record_type="A",
            rdata=data,
            rdata_digest=managed.rdata_digest(data),
            ttl=300,
            managed_by="praho",
            managed_slot="apex:A",
            provider_record_id="owned-apex",
            desired_revision=1,
            applied_revision=1,
            applied_ttl=300,
            applied_rdata=data,
        )
        self.provider = MemoryZoneGateway()
        self.provider.records[row.provider_record_id] = ProviderZoneRecord(
            row.provider_record_id, managed.record_spec(row, ttl=300)
        )
        FakeDnsGateway.reset({"owned-zone": self.hostname.zone})
        self.enterContext(patch.object(names.config, "account_hostnames_enabled", return_value=True))
        self.enterContext(patch.object(names.config, "account_zone_id", return_value="owned-zone"))
        self.enterContext(patch.object(names, "_syncable", return_value=None))
        self.enterContext(patch.object(names, "_dns_gateway", return_value=FakeDnsGateway("fake-token")))
        self.enterContext(patch.object(managed, "get_zone_gateway", return_value=self.provider))

    def _thread(self, action, pids, ready, done):
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            ready.set()
            return action()
        finally:
            done.set()
            connection.close()

    def _waits_on_lock(self, pid, done):
        deadline = time.monotonic() + _RACE_SECONDS
        while time.monotonic() < deadline and not done.is_set():
            with connection.cursor() as cursor:
                cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s", [pid])
                row = cursor.fetchone()
            if row and row[0] == "Lock":
                return True
            done.wait(0.01)
        return False

    def _transfer_view(self):
        request = RequestFactory().post(
            "/provisioning/services/edit/",
            {
                "customer_id": self.other.pk,
                "plan_id": self.service.service_plan_id,
                "domain": self.service.domain,
            },
        )
        request.user = User.objects.get(pk=self.staff.pk)
        request.session = {}
        request._messages = FallbackStorage(request)
        return service_edit(request, self.service.pk).status_code

    def _publish(self):
        return names.sync_account_hostname(self.hostname)

    def _assert_old_zone_refused(self):
        self.provider.calls.clear()
        self.assertTrue(self._publish().is_err())
        self.assertEqual(self.provider.calls, [])
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.customer_id, self.customer.pk)

    def _publisher_blocks(self, action):
        inside, release = threading.Event(), threading.Event()
        original = self.provider.update_record

        def hold_provider(*args):
            inside.set()
            if not release.wait(_RACE_SECONDS):
                raise RuntimeError("Publisher proof was not released")
            return original(*args)

        with (
            patch.object(self.provider, "update_record", side_effect=hold_provider),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            pids, ready, done = [], threading.Event(), threading.Event()
            publisher = executor.submit(self._thread, self._publish, [], threading.Event(), threading.Event())
            try:
                self.assertTrue(inside.wait(_RACE_SECONDS))
                writer = executor.submit(self._thread, action, pids, ready, done)
                self.assertTrue(ready.wait(_RACE_SECONDS))
                self.assertTrue(
                    self._waits_on_lock(pids[0], done), "Ownership committed while its DNS publisher held the name"
                )
            finally:
                release.set()
            self.assertTrue(publisher.result(timeout=_RACE_SECONDS).is_ok())
            writer.result(timeout=_RACE_SECONDS)

    def test_real_service_edit_waits_for_the_publisher_then_invalidates_old_zone_authority(self):
        self._publisher_blocks(self._transfer_view)
        self.service.refresh_from_db()
        self.assertEqual(self.service.customer_id, self.other.pk)
        self._assert_old_zone_refused()

    def test_same_customer_account_relink_waits_for_the_publisher(self):
        replacement = Service.objects.create(
            customer=self.customer,
            service_plan=self.service.service_plan,
            currency=self.service.currency,
            service_name="Replacement",
            domain="replacement.example.net",
            price="10.00",
        )

        def relink():
            account = VirtualminAccount.objects.get(pk=self.account.pk)
            account.service = replacement
            account.save(update_fields=["service"])

        self._publisher_blocks(relink)
        self.account.refresh_from_db()
        self.assertEqual(self.account.service_id, replacement.pk)
        self._assert_old_zone_refused()

    def test_transfer_winning_the_name_lock_makes_waiting_publisher_refuse_without_customer_io(self):
        inside, release = threading.Event(), threading.Event()
        original = ownership._lock_account_names

        def hold_owner(*args):
            result = original(*args)
            inside.set()
            if not release.wait(_RACE_SECONDS):
                raise RuntimeError("Ownership proof was not released")
            return result

        with (
            patch.object(ownership, "_lock_account_names", side_effect=hold_owner),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            pids, ready, done = [], threading.Event(), threading.Event()
            transfer = executor.submit(self._thread, self._transfer_view, [], threading.Event(), threading.Event())
            try:
                self.assertTrue(inside.wait(_RACE_SECONDS))
                publisher = executor.submit(self._thread, self._publish, pids, ready, done)
                self.assertTrue(ready.wait(_RACE_SECONDS))
                self.assertTrue(self._waits_on_lock(pids[0], done), "Publisher bypassed the transfer's name lock")
            finally:
                release.set()
            self.assertEqual(transfer.result(timeout=_RACE_SECONDS), 302)
            self.assertTrue(publisher.result(timeout=_RACE_SECONDS).is_err())
        self.assertEqual(self.provider.calls, [])
