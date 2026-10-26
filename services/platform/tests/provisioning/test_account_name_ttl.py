"""Lowering and restoring an account name's TTL for a cutover (ADR-0061 P2.3).

Contract step 1: record what each record's TTL was, lower it, wait until every owned record
confirms the lower TTL, and restore the recorded value on cancellation or a pre-commit failure.
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone

from apps.common.types import Err, Ok, Retriability, retriability_of
from apps.provisioning import account_hostname_config as hostname_config
from apps.provisioning import account_hostname_service as service
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.settings.services import SettingsService
from tests.helpers.fake_dns_gateway import FakeDnsGateway
from tests.provisioning.test_account_hostname_service import AccountNameTestCase

ORIGINAL_TTL = 900


_ORIGINAL_RECONCILE = FakeDnsGateway.reconcile_records


def _stuck_low(gateway: FakeDnsGateway, zone_id: str, specs: list, owner_tag: str):
    """A provider that accepts a restore but keeps reporting the cutover TTL (propagation not done)."""
    outcome = _ORIGINAL_RECONCILE(gateway, zone_id, specs, owner_tag)
    outcome.applied = [
        dataclasses.replace(record, ttl=hostname_config.account_cutover_ttl_seconds()) for record in outcome.applied
    ]
    return outcome


def _stale_ttl(gateway: FakeDnsGateway, zone_id: str, specs: list, owner_tag: str):
    """A provider that accepts the change but keeps reporting the old TTL (propagation not done)."""
    outcome = _ORIGINAL_RECONCILE(gateway, zone_id, specs, owner_tag)
    outcome.applied = [dataclasses.replace(record, ttl=ORIGINAL_TTL) for record in outcome.applied]
    return outcome


class TtlCase(AccountNameTestCase):
    def setUp(self) -> None:
        super().setUp()
        SettingsService.update_setting("dns.account_record_ttl_seconds", ORIGINAL_TTL).unwrap()
        AccountHostname.objects.filter(pk=self.hostname.pk).update(target_server=self.server)
        self.hostname.refresh_from_db()
        self._ready = patch.object(service, "certificate_ready_on", return_value=True)
        self._ready.start()
        self.addCleanup(self._ready.stop)

    def _published(self, *, ipv6: bool = True) -> None:
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))
        self.hostname.refresh_from_db()
        # Fixture reality: the provider really holds the original TTL on every published record.
        self.assertEqual(self.hostname.records["A"]["applied_ttl"], ORIGINAL_TTL)
        if ipv6:
            self.assertEqual(self.hostname.records["AAAA"]["applied_ttl"], ORIGINAL_TTL)
        else:
            self.assertNotIn("AAAA", self.hostname.records)

    def _provider_ttls(self) -> dict[str, int]:
        return {r["type"]: r["ttl"] for r in FakeDnsGateway.records.values() if r["name"] == self.hostname.fqdn}


class LowerTests(TtlCase):
    def test_lowering_records_the_ttl_it_replaces_and_lowers_every_record(self) -> None:
        self._published()

        result = service.lower_account_hostname_ttl(self.hostname)

        self.assertEqual(result, Ok("converged"))
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.previous_ttl, ORIGINAL_TTL)
        self.assertIsNotNone(self.hostname.ttl_lowered_at)
        for record_type in ("A", "AAAA"):
            with self.subTest(record_type=record_type):
                self.assertEqual(self.hostname.records[record_type]["applied_ttl"], hostname_config.account_cutover_ttl_seconds())
                self.assertEqual(self._provider_ttls()[record_type], hostname_config.account_cutover_ttl_seconds())

    def test_the_configured_cutover_ttl_is_what_gets_published(self) -> None:
        SettingsService.update_setting("dns.cutover_ttl_seconds", 120).unwrap()
        self._published()

        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("converged"))

        self.assertEqual(self._provider_ttls(), {"A": 120, "AAAA": 120})

    def test_lowering_twice_keeps_the_first_ttl_as_the_one_to_restore(self) -> None:
        self._published()
        service.lower_account_hostname_ttl(self.hostname)

        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("converged"))

        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.previous_ttl, ORIGINAL_TTL, "the lowered value must not replace the original")

    def test_a_name_that_was_never_published_is_left_alone(self) -> None:
        result = service.lower_account_hostname_ttl(self.hostname)

        self.assertEqual(result, Ok("skipped:not_published"))
        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.previous_ttl)
        self.assertFalse([call for call in FakeDnsGateway.calls if call.startswith("reconcile")])

    def test_a_name_with_only_an_a_record_converges(self) -> None:
        self.server.ipv6_address = ""
        self.server.save(update_fields=["ipv6_address"])
        self._published(ipv6=False)

        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("converged"))

        self.assertEqual(self._provider_ttls(), {"A": hostname_config.account_cutover_ttl_seconds()})

    def test_a_provider_that_has_not_applied_the_lower_ttl_is_not_converged(self) -> None:
        self._published()

        with patch.object(FakeDnsGateway, "reconcile_records", _stale_ttl):
            result = service.lower_account_hostname_ttl(self.hostname)

        self.assertEqual(result, Ok("waiting"))
        self.hostname.refresh_from_db()
        self.assertFalse(service.ttl_is_lowered(self.hostname))
        self.assertEqual(self.hostname.previous_ttl, ORIGINAL_TTL)

    def test_a_lowering_that_never_confirms_fails_at_the_deadline(self) -> None:
        self._published()
        with patch.object(FakeDnsGateway, "reconcile_records", _stale_ttl):
            self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("waiting"))
            AccountHostname.objects.filter(pk=self.hostname.pk).update(
                ttl_lowered_at=timezone.now() - service.TTL_LOWER_DEADLINE - timedelta(seconds=1)
            )
            self.hostname.refresh_from_db()

            result = service.lower_account_hostname_ttl(self.hostname)

        self.assertIsInstance(result, Err)
        self.assertIs(retriability_of(result), Retriability.NOT_RETRIABLE)


class TtlPredicateTests(TtlCase):
    def test_every_record_must_confirm_before_the_name_counts_as_lowered(self) -> None:
        self._published()
        service.lower_account_hostname_ttl(self.hostname)
        self.hostname.refresh_from_db()
        self.assertTrue(service.ttl_is_lowered(self.hostname))

        records = self.hostname.records
        records["AAAA"]["applied_ttl"] = ORIGINAL_TTL
        AccountHostname.objects.filter(pk=self.hostname.pk).update(records=records)
        self.hostname.refresh_from_db()

        self.assertFalse(service.ttl_is_lowered(self.hostname), "one record still on the old TTL is not converged")


class RoutineSyncTests(TtlCase):
    def test_a_routine_sync_keeps_the_lowered_ttl_until_it_is_restored(self) -> None:
        self._published()
        service.lower_account_hostname_ttl(self.hostname)

        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))

        self.assertEqual(self._provider_ttls(), {"A": hostname_config.account_cutover_ttl_seconds(), "AAAA": hostname_config.account_cutover_ttl_seconds()})


class RestoreTests(TtlCase):
    def test_restoring_returns_every_record_and_clears_the_evidence(self) -> None:
        self._published()
        service.lower_account_hostname_ttl(self.hostname)

        result = service.restore_account_hostname_ttl(self.hostname)

        self.assertEqual(result, Ok("restored"))
        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.previous_ttl)
        self.assertIsNone(self.hostname.ttl_lowered_at)
        self.assertEqual(self._provider_ttls(), {"A": ORIGINAL_TTL, "AAAA": ORIGINAL_TTL})

    def test_restoring_keeps_its_evidence_until_the_provider_confirms(self) -> None:
        self._published()
        service.lower_account_hostname_ttl(self.hostname)

        with patch.object(FakeDnsGateway, "reconcile_records", _stuck_low):
            result = service.restore_account_hostname_ttl(self.hostname)

        self.assertEqual(result, Ok("waiting"))
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.previous_ttl, ORIGINAL_TTL, "a failed restore keeps its retry evidence")

    def test_mixed_record_ttls_are_restored_record_by_record(self) -> None:
        self._published()
        records = self.hostname.records
        records["A"]["applied_ttl"] = 900
        records["AAAA"]["applied_ttl"] = 1800
        AccountHostname.objects.filter(pk=self.hostname.pk).update(records=records)
        for record in FakeDnsGateway.records.values():
            if record["name"] == self.hostname.fqdn:
                record["ttl"] = 900 if record["type"] == "A" else 1800
        self.hostname.refresh_from_db()

        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("converged"))
        self.assertEqual(service.restore_account_hostname_ttl(self.hostname), Ok("restored"))

        self.assertEqual(self._provider_ttls(), {"A": 900, "AAAA": 1800})
        self.hostname.refresh_from_db()
        self.assertIsNone(self.hostname.previous_ttl)
        self.assertNotIn("previous_ttl", self.hostname.records["A"])

    def test_an_address_change_while_lowered_keeps_each_original_ttl(self) -> None:
        self._published()
        records = self.hostname.records
        records["A"]["applied_ttl"] = 900
        records["AAAA"]["applied_ttl"] = 1800
        AccountHostname.objects.filter(pk=self.hostname.pk).update(records=records)
        for record in FakeDnsGateway.records.values():
            if record["name"] == self.hostname.fqdn:
                record["ttl"] = 900 if record["type"] == "A" else 1800
        self.hostname.refresh_from_db()
        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("converged"))
        VirtualminServer.objects.filter(pk=self.server.pk).update(ipv4_address="95.217.0.11")
        self.server.refresh_from_db()
        self.assertEqual(service.sync_account_hostname(self.hostname), Ok("published"))

        self.assertEqual(service.restore_account_hostname_ttl(self.hostname), Ok("restored"))

        self.assertEqual(self._provider_ttls(), {"A": 900, "AAAA": 1800})

    def test_a_sync_that_races_the_restore_keeps_the_evidence(self) -> None:
        self._published()
        self.assertEqual(service.lower_account_hostname_ttl(self.hostname), Ok("converged"))
        original = service._apply_ttl

        def restore_then_race(hostname, ttl):
            result = original(hostname, ttl)
            service.sync_account_hostname(hostname)  # a routine sweep lowers it again, legitimately
            return result

        with patch.object(service, "_apply_ttl", side_effect=restore_then_race):
            result = service.restore_account_hostname_ttl(self.hostname)

        self.assertEqual(result, Ok("waiting"))
        self.hostname.refresh_from_db()
        self.assertEqual(self.hostname.previous_ttl, ORIGINAL_TTL)

    def test_restoring_a_name_that_was_not_lowered_does_nothing(self) -> None:
        self._published()
        before = dict(self._provider_ttls())

        self.assertEqual(service.restore_account_hostname_ttl(self.hostname), Ok("noop"))

        self.assertEqual(self._provider_ttls(), before)
