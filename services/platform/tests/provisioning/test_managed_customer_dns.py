"""Managed customer routing shares the account-name publication and TTL fence."""

from dataclasses import replace
from unittest.mock import patch

from django.db import transaction
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.domains.dns_zone_import import make_record_data
from apps.domains.dns_zone_models import HostedZone, HostedZoneRecord
from apps.domains.dns_zone_record_services import current_manifest
from apps.infrastructure.dns_agreement import Agreement
from apps.infrastructure.dns_zone_gateway import ProviderZoneRecord, ZoneIdentity, ZoneInventory
from apps.provisioning import account_hostname_service as service
from apps.provisioning import managed_dns_service as managed
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.service_models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_account_name_ttl import TtlCase


class MemoryZoneGateway:
    def __init__(self):
        self.records = {}
        self.calls = []
        self.stuck_ttl = None
        self.fail = False

    def read_zone(self, binding):
        return Ok(None)

    def list_records(self, binding):
        return Ok(ZoneInventory(ZoneIdentity(binding, "active", ()), tuple(self.records.values())))

    def get_record(self, binding, record_id, **kwargs):
        self.calls.append(("get", record_id))
        return Ok(self.records[record_id]) if record_id in self.records else Err("missing")

    def update_record(self, binding, record_id, spec):
        self.calls.append(("update", record_id))
        if self.fail:
            return Err("provider unavailable")
        value = ProviderZoneRecord(record_id, replace(spec, ttl=self.stuck_ttl or spec.ttl))
        self.records[record_id] = value
        return Ok(value)

    def create_record(self, binding, spec):
        record_id = "provider-" + spec.local_id
        return self.update_record(binding, record_id, spec)

    def delete_record(self, binding, record_id, **kwargs):
        self.calls.append(("delete", record_id))
        if self.fail:
            return Err("provider unavailable")
        self.records.pop(record_id, None)
        return Ok(None)


class ManagedCustomerDnsTests(TtlCase):
    def setUp(self):
        super().setUp()
        self.zone = HostedZone.objects.create(
            customer=self.account.service.customer,
            service=self.account.service,
            account=self.account,
            account_hostname=self.hostname,
            name=self.account.domain,
            provider_account_id="cf-account",
            provider_zone_id="cf-zone",
            current_revision=1,
            confirmed_revision=1,
            applied_revision=1,
            status="active",
            activation={"activated_at": timezone.now().isoformat()},
        )
        self.gateway = MemoryZoneGateway()
        self.enterContext(patch.object(managed, "get_zone_gateway", return_value=self.gateway))
        self.apex = self._record(self.zone.name, "A", str(self.server.ipv4_address), 1800)
        self.www = self._record("www." + self.zone.name, "CNAME", self.hostname.fqdn + ".", 7200)
        self._published()

    def _record(self, name, kind, text, ttl):
        data = make_record_data(kind, text, origin=self.zone.name)
        row = HostedZoneRecord.objects.create(
            zone=self.zone,
            name=name,
            record_type=kind,
            rdata=data,
            rdata_digest=managed.rdata_digest(data),
            ttl=ttl,
            managed_by="praho",
            managed_slot=f"{name}:{kind}",
        )
        self.gateway.records[str(row.pk)] = ProviderZoneRecord(str(row.pk), managed.record_spec(row, ttl=ttl))
        row.provider_record_id = str(row.pk)
        row.applied_rdata = data
        row.applied_ttl = ttl
        row.applied_revision = 1
        row.save()
        return row

    def test_www_cname_old_ttl_controls_the_complete_cache_wait(self):
        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("waiting"))
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.previous_ttl, 7200)
        self.assertEqual(self.gateway.records[str(self.www.pk)].spec.ttl, 60)
        self.assertEqual(self.gateway.records[str(self.apex.pk)].spec.ttl, 60)

    def test_provider_ttl_regression_can_reconfirm_without_changing_cutover_owner(self):
        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("waiting"))
        self.hostname.refresh_from_db()
        self.assertIsNotNone(self.hostname.ttl_confirmed_at)
        self.gateway.stuck_ttl = 7200
        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("waiting"))
        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.ttl_confirmed_at)
        self.gateway.stuck_ttl = None
        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("waiting"))

    def test_temporary_certificate_withdrawal_republishes_customer_www_cname(self):
        with patch.object(service, "certificate_ready_on", return_value=False):
            self.assertEqual(service.sync_account_hostname(self.hostname), Ok("withdrawn"))
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        self.www.refresh_from_db()
        self.assertFalse(self.www.desired_deleted)
        self.assertIn(self.www.provider_record_id, self.gateway.records)

    def test_managed_frontend_authorities_must_agree_before_cutover_completes(self):
        with patch(
            "apps.infrastructure.dns_agreement.routing_agreement", return_value=Agreement(False, detail="still source")
        ) as probe:
            result = managed.observe_routing(self.hostname).unwrap()
        self.assertFalse(result["agreed"])
        self.assertEqual(set(result["records"]), {self.zone.name, "www." + self.zone.name})
        self.assertEqual(probe.call_count, 2)

    def test_authority_result_is_discarded_if_target_changes_during_probe(self):
        target = VirtualminServer.objects.create(
            name="Later target", hostname="later.example.net", ipv4_address="95.217.0.30"
        )

        def change(_name, _ipv4, _ipv6):
            AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=target)
            return Agreement(True, ttl=60)

        with patch("apps.infrastructure.dns_agreement.routing_agreement", side_effect=change):
            result = managed.observe_routing(self.hostname)
        self.assertTrue(result.is_err())

    def test_managed_target_binding_advances_in_the_same_ownership_transaction(self):
        target = VirtualminServer.objects.create(
            name="Commit target", hostname="commit.example.net", ipv4_address="95.217.0.40"
        )
        with transaction.atomic():
            self.account.server = target
            self.account.save(update_fields=["server", "updated_at"])
            AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=target)
            name = service.lock_for_publication(self.hostname.pk)
            managed.advance_target_locked(name)
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.enrollment_binding["target_id"], str(target.pk))
        self.assertEqual(self.zone.enrollment_binding["ipv4"], "95.217.0.40")

    def test_provider_holdout_does_not_start_a_shared_confirmation_clock(self):
        self.gateway.stuck_ttl = 7200
        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("waiting"))
        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.ttl_confirmed_at)

    def test_restore_keeps_each_record_original_ttl(self):
        service.lower_account_hostname_ttl(self.hostname)
        self.assertEqual(service.restore_account_hostname_ttl(self.hostname), Ok("restored"))
        self.assertEqual(self.gateway.records[str(self.apex.pk)].spec.ttl, 1800)
        self.assertEqual(self.gateway.records[str(self.www.pk)].spec.ttl, 7200)
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.managed_ttl_evidence, {})

    def test_failed_restore_preserves_all_ttl_evidence(self):
        service.lower_account_hostname_ttl(self.hostname)
        self.gateway.fail = True
        self.assertTrue(service.restore_account_hostname_ttl(self.hostname).is_err())
        self.hostname.refresh_from_db()
        self.zone.refresh_from_db()
        self.assertEqual(self.hostname.previous_ttl, 7200)
        self.assertTrue(self.zone.managed_ttl_evidence)

    def test_routine_sync_keeps_lowered_customer_records(self):
        service.lower_account_hostname_ttl(self.hostname)
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        self.assertEqual(self.gateway.records[str(self.www.pk)].spec.ttl, 60)

    def test_termination_withdraws_only_managed_records_and_preserves_zone(self):
        customer_txt = HostedZoneRecord.objects.create(
            zone=self.zone,
            name=self.zone.name,
            record_type="TXT",
            rdata=make_record_data("TXT", '"keep"'),
            rdata_digest="customer",
            ttl=900,
            managed_by="imported",
            provider_record_id="customer-txt",
        )
        self.assertTrue(service.retire_account_hostname(self.hostname).is_ok())
        self.assertNotIn(str(self.apex.pk), self.gateway.records)
        self.assertNotIn(str(self.www.pk), self.gateway.records)
        self.assertTrue(HostedZone.objects.filter(pk=self.zone.pk).exists())
        customer_txt.refresh_from_db()
        self.assertFalse(customer_txt.desired_deleted)

    def test_stale_instance_sync_uses_the_committed_target_for_managed_apex(self):
        target = VirtualminServer.objects.create(name="Target", hostname="next.example.net", ipv4_address="95.217.0.20")
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=target)
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        self.assertEqual(self.gateway.records[str(self.apex.pk)].spec.rdata, "95.217.0.20")

    def test_a_transferred_service_does_not_publish_into_the_old_customers_zone(self):
        replacement = Customer.objects.create(name="Other tenant", company_name="Other", customer_type="company")
        Service.objects.filter(pk=self.account.service_id).update(customer=replacement)
        self.gateway.calls.clear()
        self.assertTrue(service.sync_account_hostname(self.hostname).is_err())
        self.assertEqual(self.gateway.calls, [])

    # A customer zone's state never keeps the account name in DNS (withdrawal) or alive (retirement).

    def _account_records(self):
        return [record for record in FakeDnsGateway.records.values() if record["name"] == self.hostname.fqdn]

    def _managed_rows(self):
        return list(self.zone.records.filter(managed_by="praho").order_by("pk"))

    def _withdraw(self):
        with patch.object(service, "certificate_ready_on", return_value=False):
            return service.sync_account_hostname(self.hostname)

    def _hold(self, state):
        if state == "deleting":
            HostedZone.objects.filter(pk=self.zone.pk).update(status="deleting")
        elif state == "moved":
            other = Customer.objects.create(name="Next tenant", company_name="Next", customer_type="company")
            Service.objects.filter(pk=self.account.service_id).update(customer=other)
        else:
            VirtualminAccount.objects.filter(pk=self.account.pk).update(domain="renamed.example.com")
        with transaction.atomic():
            locked = service.lock_for_publication(self.hostname.pk)
            self.assertTrue(managed._ownership(HostedZone.objects.get(pk=self.zone.pk), locked).is_err())
        self.assertTrue(self._account_records())
        self.assertTrue(self._managed_rows())
        self.assertTrue(all(row.provider_record_id in self.gateway.records for row in self._managed_rows()))
        self.manifest = current_manifest(self.zone)
        self.gateway.calls.clear()

    def _assert_held(self, reason):
        self.assertEqual(self._account_records(), [])
        for row in self._managed_rows():
            self.assertFalse(row.desired_deleted)
            self.assertIn(row.provider_record_id, self.gateway.records)
            self.assertEqual(row.evidence[managed.WITHDRAWAL_HELD]["reason"], reason)
        self.assertEqual(current_manifest(self.zone), self.manifest)
        self.assertFalse([call for call in self.gateway.calls if call[0] == "delete"])
        parked = AuditEvent.objects.filter(action="dns_zone_operation_parked", object_id=str(self.zone.pk))
        self.assertEqual(
            [event.new_values["code"] for event in parked],
            [managed.WITHDRAWAL_PARKED_CODE] if reason == "ownership_changed" else [],
        )

    def _assert_withdrawal_held(self, state, reason):
        self._hold(state)
        self.assertEqual(self._withdraw(), Ok("withdrawn"))
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.records, {})
        self._assert_held(reason)

    def _assert_retirement_held(self, state, reason):
        self._hold(state)
        self.assertEqual(service.retire_account_hostname(self.hostname), Ok(None))
        self.hostname.refresh_from_db()
        self.assertIsNotNone(self.hostname.retired_at)
        self._assert_held(reason)

    def test_withdrawal_leaves_a_deleting_zone_to_its_deletion_and_withdraws_the_name(self):
        self._assert_withdrawal_held("deleting", "zone_deleting")

    def test_withdrawal_parks_a_moved_service_zone_and_withdraws_the_name(self):
        self._assert_withdrawal_held("moved", "ownership_changed")

    def test_withdrawal_parks_a_renamed_domain_zone_and_withdraws_the_name(self):
        self._assert_withdrawal_held("renamed", "ownership_changed")

    def test_retirement_leaves_a_deleting_zone_to_its_deletion_and_retires_the_name(self):
        self._assert_retirement_held("deleting", "zone_deleting")

    def test_retirement_parks_a_moved_service_zone_and_retires_the_name(self):
        self._assert_retirement_held("moved", "ownership_changed")

    def test_retirement_parks_a_renamed_domain_zone_and_retires_the_name(self):
        self._assert_retirement_held("renamed", "ownership_changed")

    def test_a_parked_zone_is_audited_once_however_often_the_name_is_withdrawn(self):
        self._assert_withdrawal_held("moved", "ownership_changed")
        AccountHostname.objects.filter(pk=self.hostname.pk).update(records={"A": {"intended": "95.217.0.10"}})
        self.assertEqual(self._withdraw(), Ok("withdrawn"))
        self.assertEqual(service.retire_account_hostname(self.hostname), Ok(None))
        self._assert_held("ownership_changed")

    def test_a_refused_customer_slot_is_retried_after_the_name_itself_is_withdrawn(self):
        self.gateway.fail = True
        self.assertTrue(self._withdraw().is_err())
        self.assertEqual(self._account_records(), [])
        self.hostname.refresh_from_db()
        self.assertTrue(self.hostname.records, "the withdrawal stays due for the customer slot")
        self.assertTrue(any(row.provider_record_id in self.gateway.records for row in self._managed_rows()))
        self.gateway.fail = False
        self.assertEqual(self._withdraw(), Ok("withdrawn"))
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.records, {})
        self.assertFalse(any(row.provider_record_id for row in self._managed_rows()))
        self.assertEqual(self.gateway.records, {})

    def test_a_refused_customer_slot_keeps_the_name_unretired_until_it_is_withdrawn(self):
        self.gateway.fail = True
        self.assertTrue(service.retire_account_hostname(self.hostname).is_err())
        self.assertEqual(self._account_records(), [])
        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.retired_at)
        self.gateway.fail = False
        self.assertEqual(service.retire_account_hostname(self.hostname), Ok(None))
        self.hostname.refresh_from_db()
        self.assertIsNotNone(self.hostname.retired_at)
        self.assertFalse(any(row.provider_record_id for row in self._managed_rows()))

    def test_an_owned_uuid_record_recovers_an_ambiguous_create_without_repeating_post(self):
        self.apex.provider_record_id = ""
        self.apex.evidence = {"create_issued": True}
        self.apex.save(update_fields=["provider_record_id", "evidence"])
        self.gateway.calls.clear()
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        self.apex.refresh_from_db()
        self.assertEqual(self.apex.provider_record_id, str(self.apex.pk))

    def test_retirement_removes_a_create_that_landed_without_readback(self):
        self.gateway.records.pop(self.apex.provider_record_id)
        self.apex.provider_record_id, self.apex.evidence = "", {}
        self.apex.save(update_fields=["provider_record_id", "evidence"])
        original_create = self.gateway.create_record

        def lost_reply(binding, spec):
            original_create(binding, spec)
            return Err("UNKNOWN: provider accepted the POST but its reply was lost")

        with patch.object(self.gateway, "create_record", side_effect=lost_reply):
            self.assertTrue(service.sync_account_hostname(self.hostname).is_err())
        self.apex.refresh_from_db()
        self.assertEqual(self.apex.provider_record_id, "")
        self.assertTrue(self.apex.evidence["create_issued"])
        self.assertTrue(service.retire_account_hostname(self.hostname).is_ok())
        self.assertFalse(any(row.spec.owner_tag == self.apex.owner_tag for row in self.gateway.records.values()))

    def test_worker_crash_after_provider_post_does_not_allow_a_second_post(self):
        self.gateway.records.pop(self.apex.provider_record_id)
        self.apex.provider_record_id, self.apex.evidence = "", {}
        self.apex.save(update_fields=["provider_record_id", "evidence"])
        original_create = self.gateway.create_record
        calls = []

        def crash_after_post(binding, spec):
            calls.append(spec.local_id)
            if len(calls) == 1:
                original_create(binding, spec)
                raise RuntimeError("Worker died after the POST escaped")
            return Err("An identical record already exists")

        with patch.object(self.gateway, "create_record", side_effect=crash_after_post):
            with self.assertRaisesRegex(RuntimeError, "Worker died"):
                service.sync_account_hostname(self.hostname)
            self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        self.assertEqual(len(calls), 1)

    def test_ttl_restore_waits_for_customer_record_readback_and_retains_the_snapshot(self):
        service.lower_account_hostname_ttl(self.hostname)
        self.gateway.stuck_ttl = 60
        self.assertEqual(service.restore_account_hostname_ttl(self.hostname), Ok("waiting"))
        self.zone.refresh_from_db()
        self.hostname.refresh_from_db()
        self.assertTrue(self.zone.managed_ttl_evidence)
        self.assertEqual(self.hostname.previous_ttl, 7200)

    def test_removed_ipv6_keeps_its_cache_bound_and_does_not_return_on_restore(self):
        ipv6 = HostedZoneRecord.objects.get(zone=self.zone, record_type="AAAA")
        ipv6.ttl = 12000
        ipv6.applied_ttl = 12000
        ipv6.save()
        self.gateway.records[ipv6.provider_record_id] = ProviderZoneRecord(
            ipv6.provider_record_id, managed.record_spec(ipv6, ttl=12000)
        )
        service.lower_account_hostname_ttl(self.hostname)
        self.server.ipv6_address = ""
        self.server.save(update_fields=["ipv6_address"])
        service.sync_account_hostname(self.hostname)
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.previous_ttl, 12000)
        self.assertNotIn(ipv6.provider_record_id, self.gateway.records)
        self.assertEqual(service.restore_account_hostname_ttl(self.hostname), Ok("restored"))
        self.assertNotIn(ipv6.provider_record_id, self.gateway.records)

    def test_managed_ipv6_can_return_after_a_successful_ipv4_only_move_deleted_its_old_record(self):
        ipv6 = HostedZoneRecord.objects.get(zone=self.zone, record_type="AAAA")
        self.assertTrue(ipv6.evidence.get("create_issued"), "Exercise a record actually created by the publisher")
        self.server.ipv6_address = ""
        self.server.save(update_fields=["ipv6_address"])
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        ipv6.refresh_from_db()
        self.assertTrue(ipv6.desired_deleted)
        self.assertEqual(ipv6.provider_record_id, "")
        self.server.ipv6_address = "2a01:4f9:c010::99"
        self.server.save(update_fields=["ipv6_address"])
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        ipv6.refresh_from_db()
        self.assertFalse(ipv6.desired_deleted)
        self.assertEqual(self.gateway.records[ipv6.provider_record_id].spec.rdata, "2a01:4f9:c010::99")

    def test_unrestorable_provider_ttl_is_refused_before_lowering_or_customer_snapshot(self):
        for actual_ttl in (1, 30):
            with self.subTest(actual_ttl=actual_ttl):
                original = self.gateway.records[str(self.www.pk)]
                self.gateway.records[str(self.www.pk)] = replace(original, spec=replace(original.spec, ttl=actual_ttl))
                self.gateway.calls.clear()
                self.assertTrue(service.lower_account_hostname_ttl(self.hostname).is_err())
                self.assertFalse(any(call[0] in {"update", "delete"} for call in self.gateway.calls))
                self.zone.refresh_from_db()
                self.assertEqual(self.zone.managed_ttl_evidence, {})
