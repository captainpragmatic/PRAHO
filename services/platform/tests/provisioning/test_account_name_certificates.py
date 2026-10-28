"""A certificate per account name (ADR-0061 P1.10).

ACME is always the fake directory in `acme_fakes` and Cloudflare is always the faked HTTP layer from the
gateway tests: nothing reaches Let's Encrypt or a real zone.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import timedelta
from decimal import Decimal
from itertools import count
from typing import Any
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.core.cache import cache
from django.db import connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import Schedule
from freezegun import freeze_time

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.common.credential_vault import EncryptedCredential
from apps.common.types import Err, Ok
from apps.provisioning import account_name_certificates as certs
from apps.provisioning import virtualmin_tasks
from apps.provisioning.account_hostname_models import (
    AccountHostname,
    AccountNameCertificate,
    AccountNameCertificateBudget,
    AccountNameCertificateInstall,
)
from apps.provisioning.account_name_certificates import IssuanceStatus
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_full_customer
from tests.infrastructure.test_dns_gateway_cloudflare import SAFE_REQUEST, FakeCloudflare
from tests.infrastructure.test_dns_gateway_cloudflare import ZONE as CF_ZONE_ID
from tests.provisioning.acme_fakes import FakeAcme, SimulatedCrash

ZONE = "praho-sites.net"
_labels = count(1)
_servers = count(1)


def _write(key: str, value: object) -> None:
    result = SettingsService.update_setting(key, value)
    assert result.is_ok(), f"{key}: {result}"


def _server() -> VirtualminServer:
    n = next(_servers)
    return VirtualminServer.objects.create(
        name=f"cert-node-{n}", hostname=f"cert-node-{n}.example.test", api_username="api", status="active"
    )


def _hostname(server: VirtualminServer | None = None) -> AccountHostname:
    return AccountHostname.objects.create(label=f"c{next(_labels):07d}", zone=ZONE, target_server=server)


@contextmanager
def fakes(cloudflare: FakeCloudflare, acme: FakeAcme) -> Iterator[None]:
    """Cloudflare's HTTP layer and the ACME directory faked, the zone id pointed at the fake zone, no settle wait."""
    with ExitStack() as stack:
        stack.enter_context(patch(SAFE_REQUEST, cloudflare))
        stack.enter_context(patch.object(certs, "build_acme_client", acme))
        stack.enter_context(patch.object(certs.config, "account_zone_id", return_value=CF_ZONE_ID))
        stack.enter_context(patch.object(certs, "DNS_SETTLE_SECONDS", 0.0))
        yield


class CertificateTestCase(TestCase):
    def setUp(self) -> None:
        _write("dns.account_hostname_zone", ZONE)
        _write("dns.account_zone_api_token", "test-token-value")
        self.cloudflare = FakeCloudflare()
        self.acme = FakeAcme(self.cloudflare)
        self.server = _server()
        self.hostname = _hostname(self.server)
        patcher = fakes(self.cloudflare, self.acme)
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def row(self, hostname: AccountHostname | None = None) -> AccountNameCertificate:
        return AccountNameCertificate.objects.get(hostname=hostname or self.hostname)

    def issue(self, hostname: AccountHostname | None = None) -> certs.IssuanceOutcome:
        return certs.request_certificate(hostname or self.hostname)

    def reservations(self) -> int:
        # A slot is a new name's reservation; a renewal never takes or moves one.
        return AccountNameCertificate.objects.filter(hostname__zone=ZONE, attempt_reserved_at__isnull=False).count()


class IssuanceTests(CertificateTestCase):
    def test_a_name_is_issued_through_dns01_on_the_account_zone(self) -> None:
        outcome = self.issue()

        self.assertEqual(outcome.status, IssuanceStatus.ISSUED)
        row = self.row()
        self.assertEqual(row.attempt_status, AccountNameCertificate.AttemptStatus.ISSUED)
        self.assertTrue(row.has_valid_material())
        self.assertGreater(row.current_not_after, timezone.now() + timedelta(days=80))
        self.assertEqual(self.acme.place_calls, 1)
        # The fake only issues when the order's challenge value was published as an owned TXT record.
        self.assertEqual(self.acme.complete_calls, 1)

    def test_the_challenge_records_are_removed_once_the_order_is_done(self) -> None:
        self.issue()

        self.assertEqual([r for r in self.cloudflare.store.values() if r["type"] == "TXT"], [])
        self.assertGreaterEqual(self.cloudflare.count("POST"), 1)

    def test_the_certificate_and_its_key_live_in_the_vault_per_hostname(self) -> None:
        self.issue()

        row = self.row()
        fullchain = certs.vault_secret(row.current_certificate_ref)
        key = certs.vault_secret(row.current_key_ref)
        self.assertIn("BEGIN CERTIFICATE", fullchain or "")
        self.assertIn("BEGIN PRIVATE KEY", key or "")
        self.assertNotIn("BEGIN", row.current_certificate_ref + row.current_key_ref)
        self.assertTrue(
            EncryptedCredential.objects.filter(
                service_type="acme_account_key", service_identifier=self.hostname.fqdn
            ).exists()
        )
        self.assertIn(self.hostname.fqdn, row.current_certificate_ref)

    def test_the_certificate_is_for_the_stored_key(self) -> None:
        from cryptography import x509  # noqa: PLC0415
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

        self.issue()

        row = self.row()
        leaf = x509.load_pem_x509_certificate(
            certs.split_chain(certs.vault_secret(row.current_certificate_ref) or "")[0].encode()
        )
        key = serialization.load_pem_private_key(
            (certs.vault_secret(row.current_key_ref) or "").encode(), password=None
        )
        self.assertEqual(
            leaf.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
            key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo),
        )

    def test_valid_material_is_never_ordered_again(self) -> None:
        self.issue()

        again = self.issue()

        self.assertEqual(again.status, IssuanceStatus.ALREADY_VALID)
        self.assertEqual(self.acme.place_calls, 1)

    def test_a_retired_name_is_not_ordered(self) -> None:
        AccountHostname.objects.filter(pk=self.hostname.pk).update(retired_at=timezone.now())
        self.hostname.refresh_from_db()

        self.assertEqual(self.issue().status, IssuanceStatus.RETIRED)
        self.assertEqual(self.acme.place_calls, 0)

    def test_an_unconfigured_zone_orders_nothing(self) -> None:
        with patch.object(certs.config, "account_zone_api_token", return_value=""):
            outcome = self.issue()

        self.assertEqual(outcome.status, IssuanceStatus.NOT_CONFIGURED)
        self.assertEqual(self.acme.place_calls, 0)
        self.assertFalse(AccountNameCertificate.objects.filter(hostname=self.hostname).exists())

    def test_a_rejected_order_fails_the_attempt_and_waits_before_the_next(self) -> None:
        self.acme.reject_orders = True

        outcome = self.issue()

        self.assertEqual(outcome.status, IssuanceStatus.FAILED)
        row = self.row()
        self.assertEqual(row.attempt_status, AccountNameCertificate.AttemptStatus.FAILED)
        self.assertFalse(row.has_valid_material())
        self.assertEqual([r for r in self.cloudflare.store.values() if r["type"] == "TXT"], [])
        self.assertEqual(self.issue().status, IssuanceStatus.DEFERRED)
        self.assertEqual(self.acme.place_calls, 1)

    def test_a_failed_first_attempt_keeps_its_slot_for_the_retry(self) -> None:
        self.acme.reject_orders = True
        self.issue()
        row = self.row()
        row.retry_after = None
        row.save()
        self.acme.reject_orders = False

        outcome = self.issue()

        self.assertEqual(outcome.status, IssuanceStatus.ISSUED)
        self.assertEqual(self.reservations(), 1)

    def test_the_acme_directory_setting_chooses_the_server(self) -> None:
        _write("dns.account_acme_directory_url", "https://acme.test/directory")

        self.issue()

        self.assertEqual(self.acme.directory_urls, ["https://acme.test/directory"])


class CrashResumeTests(CertificateTestCase):
    def _lease_runs_out(self) -> None:
        """The dead worker's lease expires; until then everyone else is deferred (AttemptOwnershipTests)."""
        AccountNameCertificate.objects.filter(hostname=self.hostname).update(
            attempt_lease_until=timezone.now() - timedelta(seconds=1)
        )

    def test_a_crash_in_ordering_resumes_the_same_order(self) -> None:
        self.acme.crash_in_complete = True

        with self.assertRaises(SimulatedCrash):
            self.issue()
        crashed = self.row()
        self.assertEqual(crashed.attempt_status, AccountNameCertificate.AttemptStatus.ORDERING)
        stored_url = crashed.attempt_order_url
        self.assertTrue(stored_url)
        self._lease_runs_out()

        outcome = self.issue()

        self.assertEqual(outcome.status, IssuanceStatus.ISSUED)
        self.assertEqual(self.acme.place_calls, 1, "the second run must not order again")
        self.assertEqual(self.acme.load_calls, 1)
        self.assertEqual(self.reservations(), 1, "the second run must not reserve again")
        self.assertEqual(self.row().attempt_order_url, "")

    def test_a_crash_after_the_reservation_but_before_the_order_resumes_without_a_second_reservation(self) -> None:
        with patch.object(self.acme, "place_order", side_effect=SimulatedCrash), self.assertRaises(SimulatedCrash):
            self.issue()
        self.assertEqual(self.row().attempt_status, AccountNameCertificate.AttemptStatus.ORDERING)
        self.assertEqual(self.row().attempt_order_url, "")
        self._lease_runs_out()

        outcome = self.issue()

        self.assertEqual(outcome.status, IssuanceStatus.ISSUED)
        self.assertEqual(self.reservations(), 1)

    def test_challenge_records_left_by_a_crash_are_swept_but_a_live_orders_are_kept(self) -> None:
        self.acme.crash_in_complete = True
        with self.assertRaises(SimulatedCrash):
            self.issue()
        # The crash ran no cleanup in a real process; stand for that by publishing a stale record of a dead order.
        live_tag = certs.order_owner_tag(self.row().attempt_order_url)
        old = (timezone.now() - timedelta(hours=3)).isoformat()
        self.cloudflare.add(
            type="TXT",
            name="_acme-challenge.gone.praho-sites.net",
            content="stale",
            comment="praho:acme:deadbeefdeadbeef",
            created_on=old,
        )
        self.cloudflare.add(
            type="TXT", name="_acme-challenge.live.praho-sites.net", content="live", comment=live_tag, created_on=old
        )

        swept = certs.sweep_stale_challenge_records()

        self.assertEqual(swept, 1)
        comments = {r.get("comment") for r in self.cloudflare.store.values() if r["type"] == "TXT"}
        self.assertIn(live_tag, comments)
        self.assertNotIn("praho:acme:deadbeefdeadbeef", comments)


class RetryAfterTests(CertificateTestCase):
    def test_a_rate_limited_order_waits_for_retry_after_and_keeps_its_slot(self) -> None:
        self.acme.rate_limit_seconds = 900

        with freeze_time("2026-10-18 10:00:00") as clock:
            first = self.issue()
            self.assertEqual(first.status, IssuanceStatus.DEFERRED)
            self.assertEqual(self.row().retry_after, timezone.now() + timedelta(seconds=900))
            self.assertEqual(self.reservations(), 1)

            clock.tick(timedelta(seconds=600))
            self.acme.rate_limit_seconds = None
            still_waiting = self.issue()
            self.assertEqual(still_waiting.status, IssuanceStatus.DEFERRED)
            self.assertEqual(self.acme.place_calls, 0, "no request before Retry-After has passed")

            clock.tick(timedelta(seconds=400))
            done = self.issue()
            self.assertEqual(done.status, IssuanceStatus.ISSUED)
            self.assertEqual(self.reservations(), 1, "waiting out a delay never takes a second slot")


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "account-cert-budget"}}
)
class BudgetTests(CertificateTestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        _write("dns.account_cert_weekly_budget", 2)

    def test_the_budget_is_a_rolling_seven_day_count_of_new_names(self) -> None:
        names = [self.hostname, _hostname(self.server), _hostname(self.server)]
        with freeze_time("2026-10-18 10:00:00") as clock:
            outcomes = [self.issue(h).status for h in names]
            self.assertEqual(outcomes, [IssuanceStatus.ISSUED, IssuanceStatus.ISSUED, IssuanceStatus.BUDGET_EXHAUSTED])
            clock.tick(timedelta(days=6, hours=23))
            self.assertEqual(self.issue(names[2]).status, IssuanceStatus.BUDGET_EXHAUSTED)
            clock.tick(timedelta(hours=2))
            self.assertEqual(self.issue(names[2]).status, IssuanceStatus.ISSUED)

    def test_budget_exhaustion_leaves_the_name_unready_and_orders_nothing(self) -> None:
        for host in (_hostname(self.server), _hostname(self.server)):
            self.issue(host)
        orders = self.acme.place_calls

        outcome = self.issue()

        self.assertEqual(outcome.status, IssuanceStatus.BUDGET_EXHAUSTED)
        self.assertEqual(self.acme.place_calls, orders)
        self.assertFalse(certs.account_name_ready(self.hostname))
        self.assertFalse(AccountNameCertificate.objects.get(hostname=self.hostname).has_valid_material())

    def test_staff_are_alerted_at_eighty_percent_once_a_day(self) -> None:
        _write("dns.account_cert_weekly_budget", 5)
        hosts = [_hostname(self.server) for _ in range(5)]

        for host in hosts[:3]:
            self.issue(host)
        self.assertEqual(self._alerts(), 0, "3 of 5 is below 80%")
        self.issue(hosts[3])
        self.assertEqual(self._alerts(), 1, "4 of 5 is 80%")
        self.issue(hosts[4])
        self.assertEqual(self._alerts(), 1, "the same day alerts once")

    def test_an_exhausted_budget_alerts_staff(self) -> None:
        for host in (_hostname(self.server), _hostname(self.server)):
            self.issue(host)
        before = self._alerts()

        self.issue()

        self.assertEqual(self._alerts(), before + 1)
        self.assertTrue(
            AuditEvent.objects.filter(action="account_name_certificate_alert", description__contains="used up").exists()
        )

    def test_a_failed_alert_write_does_not_stop_the_reservation(self) -> None:
        _write("dns.account_cert_weekly_budget", 1)

        with patch.object(certs.AuditService, "log_event", side_effect=RuntimeError("audit down")):
            outcome = self.issue()

        self.assertEqual(outcome.status, IssuanceStatus.ISSUED, "1 of 1 is over 80%, so the alert ran and failed")
        self.assertEqual(self.reservations(), 1)
        self.assertEqual(self._alerts(), 0)

    def _alerts(self) -> int:
        return AuditEvent.objects.filter(action="account_name_certificate_alert").count()


class RenewalTests(CertificateTestCase):
    def setUp(self) -> None:
        super().setUp()
        _write("dns.account_cert_weekly_budget", 2)
        _write("dns.account_hostnames_enabled", True)  # The daily job does nothing while the feature is off
        self.install = patch.object(certs, "install_current_certificate", return_value=Ok(None))
        self.install_mock = self.install.start()
        self.addCleanup(self.install.stop)
        # The queue, run inline: each dispatched task runs as the cluster would run it, one after another.
        self.dispatched: list[tuple[str, tuple[str, ...]]] = []

        def run_inline(task: str, *args: str) -> None:
            self.dispatched.append((task, args))
            import_string(task)(*args)

        dispatch = patch.object(certs, "_dispatch", run_inline)
        dispatch.start()
        self.addCleanup(dispatch.stop)

    def _age(self, hostname: AccountHostname, days_left: int) -> None:
        """Let time pass for one name: its 90-day certificate now has ``days_left`` days, and was issued that long ago."""
        elapsed = timedelta(days=90 - days_left)
        AccountNameCertificate.objects.filter(hostname=hostname).update(
            current_not_after=timezone.now() + timedelta(days=days_left), attempt_reserved_at=timezone.now() - elapsed
        )

    def test_renewal_picks_only_names_near_expiry_and_consumes_no_budget(self) -> None:
        near, far, recent = self.hostname, _hostname(self.server), _hostname(self.server)
        for host in (near, far):
            self.issue(host)
        self._age(near, 10)
        self._age(far, 70)
        self.issue(recent)
        far_ref, orders = self.row(far).current_certificate_ref, self.acme.place_calls
        old_ref = self.row(near).current_certificate_ref

        counts = certs.renew_due_certificates()

        self.assertEqual(counts["renewals"], 1)
        self.assertEqual(self.acme.place_calls, orders + 1)
        self.assertNotEqual(self.row(near).current_certificate_ref, old_ref)
        self.assertEqual(self.row(far).current_certificate_ref, far_ref)
        # Budget 2 and one name issued inside the window: the renewal took nothing, so one slot is still free.
        self.assertEqual(self.issue(_hostname(self.server)).status, IssuanceStatus.ISSUED)
        self.assertEqual(self.issue(_hostname(self.server)).status, IssuanceStatus.BUDGET_EXHAUSTED)

    def test_a_renewal_with_the_budget_spent_still_goes_ahead(self) -> None:
        self.issue(self.hostname)
        self._age(self.hostname, 5)
        self.issue(_hostname(self.server))
        self.issue(_hostname(self.server))
        self.assertEqual(self.issue(_hostname(self.server)).status, IssuanceStatus.BUDGET_EXHAUSTED)

        outcome = certs.request_certificate(self.hostname, scheduled_renewal=True)

        self.assertEqual(outcome.status, IssuanceStatus.ISSUED)

    def test_only_the_scheduled_renewal_orders_while_valid_material_exists(self) -> None:
        self.issue()
        self._age(self.hostname, 10)

        self.assertEqual(self.issue().status, IssuanceStatus.ALREADY_VALID)
        self.assertEqual(self.acme.place_calls, 1)
        self.assertEqual(certs.request_certificate(self.hostname, scheduled_renewal=True).status, IssuanceStatus.ISSUED)
        self.assertEqual(self.acme.place_calls, 2)

    def test_a_scheduled_renewal_far_from_expiry_orders_nothing(self) -> None:
        self.issue()

        self.assertEqual(
            certs.request_certificate(self.hostname, scheduled_renewal=True).status, IssuanceStatus.ALREADY_VALID
        )
        self.assertEqual(self.acme.place_calls, 1)

    def test_a_renewal_left_ordering_keeps_the_old_certificate_in_force(self) -> None:
        self.issue()
        self._age(self.hostname, 10)
        certs.record_installation(
            self.hostname,
            self.server,
            certificate_ref=self.row().current_certificate_ref,
            not_after=self.row().current_not_after,
        )
        old = self.row()
        self.acme.rate_limit_seconds = 600

        outcome = certs.request_certificate(self.hostname, scheduled_renewal=True)

        self.assertEqual(outcome.status, IssuanceStatus.DEFERRED)
        row = self.row()
        self.assertEqual(row.attempt_status, AccountNameCertificate.AttemptStatus.ORDERING)
        self.assertEqual(row.current_certificate_ref, old.current_certificate_ref)
        self.assertTrue(row.has_valid_material())
        self.assertTrue(certs.account_name_ready(self.hostname))

    def test_a_renewal_that_failed_keeps_the_old_certificate_in_force(self) -> None:
        self.issue()
        self._age(self.hostname, 10)
        certs.record_installation(
            self.hostname,
            self.server,
            certificate_ref=self.row().current_certificate_ref,
            not_after=self.row().current_not_after,
        )
        old = self.row()
        self.acme.reject_orders = True

        outcome = certs.request_certificate(self.hostname, scheduled_renewal=True)

        self.assertEqual(outcome.status, IssuanceStatus.FAILED)
        row = self.row()
        self.assertEqual(row.attempt_status, AccountNameCertificate.AttemptStatus.FAILED)
        self.assertEqual(row.current_certificate_ref, old.current_certificate_ref)
        self.assertEqual(row.current_not_after, old.current_not_after)
        self.assertTrue(row.has_valid_material())
        self.assertTrue(certs.account_name_ready(self.hostname))

    def test_a_renewal_uses_a_new_key_and_leaves_the_key_in_force_alone(self) -> None:
        self.issue()
        self._age(self.hostname, 10)
        old_key = certs.vault_secret(self.row().current_key_ref)
        old_key_ref = self.row().current_key_ref

        certs.request_certificate(self.hostname, scheduled_renewal=True)

        self.assertNotEqual(self.row().current_key_ref, old_key_ref)
        self.assertEqual(certs.vault_secret(old_key_ref), old_key)

    def test_a_renewed_certificate_is_installed_where_the_old_one_is(self) -> None:
        self.issue()
        certs.record_installation(
            self.hostname,
            self.server,
            certificate_ref=self.row().current_certificate_ref,
            not_after=self.row().current_not_after,
        )
        self._age(self.hostname, 10)

        certs.renew_due_certificates()

        self.install_mock.assert_called_once()
        self.assertEqual(self.install_mock.call_args.args[1], self.server)

    def test_a_former_node_is_forgotten_not_reinstalled(self) -> None:
        self.issue()
        former = _server()
        old = self.row()
        for server in (self.server, former):
            certs.record_installation(
                self.hostname, server, certificate_ref=old.current_certificate_ref, not_after=old.current_not_after
            )
        self._age(self.hostname, 10)

        certs.renew_due_certificates()

        self.assertEqual([call.args[1] for call in self.install_mock.call_args_list], [self.server])
        self.assertFalse(AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=former).exists())

    def test_an_account_under_an_operation_keeps_every_install_row_untouched(self) -> None:
        self.issue()
        former = _server()
        old = self.row()
        for server in (self.server, former):
            certs.record_installation(
                self.hostname, server, certificate_ref=old.current_certificate_ref, not_after=old.current_not_after
            )
        self._age(self.hostname, 10)

        with patch.object(certs, "_name_under_operation", return_value=True):
            certs.renew_due_certificates()

        self.install_mock.assert_not_called()
        self.assertEqual(AccountNameCertificateInstall.objects.filter(hostname=self.hostname).count(), 2)

    def test_a_node_that_already_holds_the_current_certificate_is_not_reinstalled(self) -> None:
        self.issue()
        row = self.row()
        certs.record_installation(
            self.hostname, self.server, certificate_ref=row.current_certificate_ref, not_after=row.current_not_after
        )

        counts = certs.renew_due_certificates()

        self.assertEqual(counts["installs"], 0)
        self.install_mock.assert_not_called()

    def test_the_daily_task_does_not_install_on_a_node_that_has_no_install_record(self) -> None:
        self.issue()

        counts = certs.renew_due_certificates()

        self.assertEqual(counts["installs"], 0)
        self.install_mock.assert_not_called()

    def test_each_certificate_is_renewed_by_its_own_task(self) -> None:
        first, second = self.hostname, _hostname(self.server)
        for host in (first, second):
            self.issue(host)
            self._age(host, 10)

        certs.renew_due_certificates()

        renewals = sorted(args for task, args in self.dispatched if task == certs.RENEW_TASK)
        self.assertEqual(renewals, sorted([(str(first.pk), "renewal"), (str(second.pk), "renewal")]))

    def test_an_install_waits_while_another_node_step_holds_the_name(self) -> None:
        from apps.provisioning.account_name_lease import take_node_lease  # noqa: PLC0415

        self.issue()
        old = self.row()
        certs.record_installation(
            self.hostname, self.server, certificate_ref="acme_certificate:older", not_after=old.current_not_after
        )
        self.assertIsNotNone(take_node_lease(self.hostname))

        certs.renew_due_certificates()

        self.install_mock.assert_not_called()

    def test_the_sweep_runs_with_the_renewal(self) -> None:
        self.cloudflare.add(
            type="TXT",
            name="_acme-challenge.x.praho-sites.net",
            content="stale",
            comment="praho:acme:0123456789abcdef",
            created_on=(timezone.now() - timedelta(hours=5)).isoformat(),
        )

        counts = certs.renew_due_certificates()

        self.assertEqual(counts["swept"], 1)


class ReadinessTests(CertificateTestCase):
    def test_a_name_is_ready_only_with_unexpired_material_installed_on_its_intended_node(self) -> None:
        self.issue()
        row = self.row()
        self.assertFalse(certs.account_name_ready(self.hostname), "issued but not installed")

        certs.record_installation(
            self.hostname,
            self._other_server(),
            certificate_ref=row.current_certificate_ref,
            not_after=row.current_not_after,
        )
        self.assertFalse(certs.account_name_ready(self.hostname), "installed on another node")

        certs.record_installation(
            self.hostname, self.server, certificate_ref=row.current_certificate_ref, not_after=row.current_not_after
        )
        self.assertTrue(certs.account_name_ready(self.hostname))

        with freeze_time(row.current_not_after + timedelta(seconds=1)):
            self.assertFalse(certs.account_name_ready(self.hostname), "expired")

    def test_a_name_with_no_intended_node_is_not_ready(self) -> None:
        host = _hostname(None)
        certs.record_installation(
            host, self.server, certificate_ref="x:y", not_after=timezone.now() + timedelta(days=30)
        )

        self.assertFalse(certs.account_name_ready(host))

    def test_recording_an_installation_again_updates_the_one_row(self) -> None:
        later = timezone.now() + timedelta(days=60)
        certs.record_installation(
            self.hostname, self.server, certificate_ref="a:1", not_after=timezone.now() + timedelta(days=30)
        )
        certs.record_installation(self.hostname, self.server, certificate_ref="a:2", not_after=later)

        install = AccountNameCertificateInstall.objects.get(hostname=self.hostname, server=self.server)
        self.assertEqual((install.certificate_ref, install.not_after), ("a:2", later))

    def test_an_unissued_name_is_not_ready_whatever_the_attempt_says(self) -> None:
        self.acme.rate_limit_seconds = 600
        self.issue()

        self.assertEqual(self.row().attempt_status, AccountNameCertificate.AttemptStatus.ORDERING)
        self.assertFalse(certs.account_name_ready(self.hostname))

    def _other_server(self) -> VirtualminServer:
        return _server()


class NodeInstallTests(CertificateTestCase):
    def setUp(self) -> None:
        super().setUp()
        currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})[0]
        plan = ServicePlan.objects.create(
            name="Certificate owner", plan_type="shared_hosting", price_monthly=Decimal("10")
        )
        service = Service.objects.create(
            customer=create_full_customer(),
            service_plan=plan,
            currency=currency,
            service_name="customer.example",
            domain="customer.example",
            username="customer",
            price=Decimal("10"),
            status="active",
        )
        account = VirtualminAccount.objects.create(
            service=service, server=self.server, domain=service.domain, virtualmin_username="customer", status="active"
        )
        self.hostname.account = account
        self.hostname.save(update_fields=["account"])
        self.neutral = self.enterContext(
            patch.object(certs, "ensure_account_name_neutral", return_value=Ok("a" * 64), create=True)
        )
        self.prepared = self.enterContext(
            patch.object(certs, "prepare_account_name_neutral", return_value=Ok("a" * 64), create=True)
        )

    @contextmanager
    def managed_node(self) -> Iterator[None]:
        """Give servers a managed node deployment, the way a deployed node has one."""
        with patch.object(VirtualminServer, "node_deployment", MagicMock(), create=True):
            yield

    def served(self, fingerprint: str | None = None) -> MagicMock:
        """A play that worked, reporting the fingerprint of what the node now serves (the one in force by default)."""
        if fingerprint is None:
            fullchain = certs.vault_secret(self.row().current_certificate_ref) or ""
            leaf = x509.load_pem_x509_certificate(certs.split_chain(fullchain)[0].encode())
            fingerprint = ":".join(f"{byte:02X}" for byte in leaf.fingerprint(hashes.SHA256()))
        return MagicMock(success=True, stdout=f'"msg": "INSTALLED_FINGERPRINT={fingerprint}"')

    def test_the_stored_certificate_is_installed_through_the_playbook_vars_only(self) -> None:
        self.issue()
        runner = MagicMock()
        runner.return_value.run_playbook.return_value = Ok(self.served())

        with patch("apps.infrastructure.ansible_service.AnsibleService", runner), self.managed_node():
            result = certs.install_current_certificate(self.hostname, self.server)

        self.assertTrue(result.is_ok(), result)
        _deployment, playbook, variables = runner.return_value.run_playbook.call_args.args
        self.assertEqual(playbook, "virtualmin_install_account_cert.yml")
        self.assertEqual(variables["account_name"], self.hostname.fqdn)
        self.assertIn("BEGIN CERTIFICATE", variables["certificate_pem"])
        self.assertEqual(variables["certificate_pem"].count("BEGIN CERTIFICATE"), 1)
        self.assertEqual(variables["chain_pem"].count("BEGIN CERTIFICATE"), 1)
        self.assertIn("BEGIN PRIVATE KEY", variables["private_key_pem"])
        self.assertTrue(
            AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).exists()
        )

    def test_a_stored_pair_that_does_not_match_is_never_installed(self) -> None:
        self.issue()
        row = self.row()
        stranger = (
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            .decode()
        )
        _type, _sep, identifier = row.current_key_ref.partition(":")
        certs._vault_store(certs.CERT_KEY_TYPE, identifier, stranger, days=30)
        runner = MagicMock()
        runner.return_value.run_playbook.return_value = Ok(MagicMock(success=True))
        with patch("apps.infrastructure.ansible_service.AnsibleService", runner), self.managed_node():
            result = certs.install_current_certificate(self.hostname, self.server)

        self.assertTrue(result.is_err())
        self.assertIn("not for its stored key", result.unwrap_err())
        runner.return_value.run_playbook.assert_not_called()
        self.assertFalse(AccountNameCertificateInstall.objects.filter(hostname=self.hostname).exists())

    def test_an_install_is_recorded_only_when_the_node_serves_that_certificate(self) -> None:
        self.issue()
        for report in (self.served("00:11:22"), MagicMock(success=True, stdout="ok=4 changed=1")):
            with self.subTest(stdout=report.stdout):
                runner = MagicMock()
                runner.return_value.run_playbook.return_value = Ok(report)
                with patch("apps.infrastructure.ansible_service.AnsibleService", runner), self.managed_node():
                    result = certs.install_current_certificate(self.hostname, self.server)

                self.assertTrue(result.is_err())
                self.assertFalse(AccountNameCertificateInstall.objects.filter(hostname=self.hostname).exists())

    def test_a_failed_install_records_nothing(self) -> None:
        self.issue()
        runner = MagicMock()
        runner.return_value.run_playbook.return_value = Ok(MagicMock(success=False))

        with patch("apps.infrastructure.ansible_service.AnsibleService", runner), self.managed_node():
            result = certs.install_current_certificate(self.hostname, self.server)

        self.assertTrue(result.is_err())
        self.assertFalse(AccountNameCertificateInstall.objects.exists())

    def test_a_valid_native_install_is_not_recorded_if_the_neutral_tls_frontend_cannot_refresh(self) -> None:
        self.issue()
        runner = MagicMock()
        runner.return_value.run_playbook.return_value = Ok(self.served())
        with (
            patch("apps.infrastructure.ansible_service.AnsibleService", runner),
            patch.object(certs, "ensure_account_name_neutral", return_value=Err("neutral refresh failed")),
            self.managed_node(),
        ):
            result = certs.install_current_certificate(self.hostname, self.server)
        self.assertTrue(result.is_err())
        runner.return_value.run_playbook.assert_called_once()
        self.assertFalse(
            AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).exists()
        )

    def test_unproved_neutral_preflight_does_not_install_even_a_valid_certificate(self) -> None:
        self.issue()
        self.prepared.return_value = Err("neutral preflight failed")
        runner = MagicMock()
        runner.return_value.run_playbook.return_value = Ok(self.served())
        with patch("apps.infrastructure.ansible_service.AnsibleService", runner), self.managed_node():
            result = certs.install_current_certificate(self.hostname, self.server)
        self.assertTrue(result.is_err())
        runner.return_value.run_playbook.assert_not_called()

    def test_expired_native_leaf_does_not_prevent_installing_its_valid_replacement(self) -> None:
        self.issue()
        runner = MagicMock()
        runner.return_value.run_playbook.return_value = Ok(self.served())
        self.neutral.side_effect = lambda *args, **kwargs: (
            Ok("a" * 64) if runner.return_value.run_playbook.called else Err("native leaf expired")
        )
        with patch("apps.infrastructure.ansible_service.AnsibleService", runner), self.managed_node():
            result = certs.install_current_certificate(self.hostname, self.server)
        self.assertTrue(result.is_ok(), result)
        self.prepared.assert_called_once()
        self.neutral.assert_called_once()
        self.assertIn("expected_certificate_sha256", self.neutral.call_args.kwargs)
        self.assertTrue(AccountNameCertificateInstall.objects.filter(hostname=self.hostname, server=self.server).exists())

    def test_a_manually_registered_node_cannot_be_installed_on(self) -> None:
        self.issue()

        result = certs.install_current_certificate(self.hostname, self.server)

        self.assertTrue(result.is_err())

    def test_a_name_without_a_certificate_has_nothing_to_install(self) -> None:
        self.assertTrue(certs.install_current_certificate(self.hostname, self.server).is_err())

    def test_a_manually_registered_node_spends_no_budget_on_a_certificate_it_cannot_take(self) -> None:
        result = certs.ensure_certificate_on_node(self.hostname, self.server)

        self.assertFalse(result.ready)
        self.assertIsNone(result.issuance)
        self.assertEqual((self.acme.place_calls, self.reservations()), (0, 0))

    def test_ensure_on_a_node_reinstalls_the_stored_certificate_without_ordering(self) -> None:
        self.issue()
        orders = self.acme.place_calls
        with patch.object(certs, "install_current_certificate", return_value=Ok(None)) as install, self.managed_node():
            result = certs.ensure_certificate_on_node(self.hostname, self.server)

        self.assertEqual(self.acme.place_calls, orders)
        install.assert_called_once()
        self.assertFalse(result.ready, "installing is mocked, so no install row exists to be ready on")

    def test_ensure_on_a_node_that_already_has_the_certificate_does_nothing(self) -> None:
        self.issue()
        row = self.row()
        certs.record_installation(
            self.hostname, self.server, certificate_ref=row.current_certificate_ref, not_after=row.current_not_after
        )

        with patch.object(certs, "install_current_certificate") as install, self.managed_node():
            result = certs.ensure_certificate_on_node(self.hostname, self.server)

        install.assert_not_called()
        self.assertTrue(result.ready)

    def test_ensure_on_a_node_without_a_certificate_is_not_ready_and_says_why(self) -> None:
        self.acme.rate_limit_seconds = 600

        with self.managed_node():
            result = certs.ensure_certificate_on_node(self.hostname, self.server)

        self.assertFalse(result.ready)
        self.assertEqual(result.issuance.status, IssuanceStatus.DEFERRED)


class ScheduleRegistrationTests(CertificateTestCase):
    def test_the_renewal_is_registered_daily_and_setup_is_idempotent(self) -> None:
        first = virtualmin_tasks.setup_virtualmin_scheduled_tasks()
        second = virtualmin_tasks.setup_virtualmin_scheduled_tasks()

        self.assertEqual(first["account_name_certificates"], "created")
        self.assertEqual(second["account_name_certificates"], "updated")
        row = Schedule.objects.get(name="account-name-certificate-renewal")
        self.assertEqual(row.func, "apps.provisioning.virtualmin_tasks.renew_account_name_certificates")
        self.assertEqual((row.schedule_type, row.minutes), ("I", 24 * 60))
        self.assertEqual(Schedule.objects.filter(name="account-name-certificate-renewal").count(), 1)

    def test_the_task_wrapper_runs_the_renewal_and_never_raises(self) -> None:
        _write("dns.account_hostnames_enabled", True)
        result = virtualmin_tasks.renew_account_name_certificates()
        self.assertTrue(result["success"])
        self.assertIn("renewals", result)

        with patch.object(certs, "renew_due_certificates", side_effect=RuntimeError("boom")):
            failed = virtualmin_tasks.renew_account_name_certificates()
        self.assertEqual(failed, {"success": False, "error": "boom"})


class AttemptOwnershipTests(CertificateTestCase):
    """One worker per attempt; a worker that lost its lease changes nothing; a pair is checked before use."""

    def _crash_once(self) -> None:
        self.acme.crash_in_complete = True
        with self.assertRaises(SimulatedCrash):
            self.issue()

    def _expire_lease(self) -> None:
        AccountNameCertificate.objects.filter(hostname=self.hostname).update(
            attempt_lease_until=timezone.now() - timedelta(seconds=1)
        )

    def test_a_live_lease_defers_without_asking_the_ca(self) -> None:
        self._crash_once()
        calls = (self.acme.place_calls, self.acme.load_calls, self.acme.complete_calls)

        outcome = self.issue()

        self.assertIs(outcome.status, IssuanceStatus.DEFERRED)
        self.assertEqual((self.acme.place_calls, self.acme.load_calls, self.acme.complete_calls), calls)

    def test_an_expired_lease_is_taken_over_and_the_same_order_resumed(self) -> None:
        self._crash_once()
        attempt = self.row().attempt_id
        self._expire_lease()

        outcome = self.issue()

        self.assertIs(outcome.status, IssuanceStatus.ISSUED)
        self.assertEqual((self.acme.place_calls, self.acme.load_calls), (1, 1))
        self.assertIn(attempt, self.row().current_certificate_ref, "a takeover keeps the attempt and its key")

    def test_a_worker_that_lost_its_lease_changes_nothing(self) -> None:
        first = certs._claim_attempt(self.row_for_claim().pk, scheduled_renewal=False)
        assert isinstance(first, certs.AttemptClaim)
        self._expire_lease()
        second = certs._claim_attempt(self.row().pk, scheduled_renewal=False)
        assert isinstance(second, certs.AttemptClaim)

        outcome = certs._run_order(first)

        row = self.row()
        self.assertIs(outcome.status, IssuanceStatus.DEFERRED)
        self.assertEqual(row.attempt_token, second.token)
        self.assertEqual((row.attempt_order_url, row.current_certificate_ref), ("", ""))
        self.assertEqual(row.attempt_status, AccountNameCertificate.AttemptStatus.ORDERING)
        self.assertEqual(self.acme.complete_calls, 0, "the CA must not issue a certificate the worker would discard")

    def test_a_worker_fenced_during_the_exchange_puts_nothing_in_force_and_leaves_the_records(self) -> None:
        from tests.provisioning.acme_fakes import FakeAcme  # noqa: PLC0415

        row = self.row_for_claim()

        def taken_over_while_waiting(order: Any) -> bytes:
            self._expire_lease()
            assert isinstance(certs._claim_attempt(row.pk, scheduled_renewal=False), certs.AttemptClaim)
            return FakeAcme.complete(self.acme, order)

        with patch.object(self.acme, "complete", taken_over_while_waiting):
            outcome = self.issue()

        self.assertIs(outcome.status, IssuanceStatus.DEFERRED)
        self.assertEqual(self.row().current_certificate_ref, "")
        txt = [r for r in self.cloudflare.store.values() if r["type"] == "TXT"]
        self.assertTrue(txt, "the new holder still needs the shared order's challenge records")

    def test_a_fenced_failure_or_deferral_leaves_the_new_holder_alone(self) -> None:
        first = certs._claim_attempt(self.row_for_claim().pk, scheduled_renewal=False)
        assert isinstance(first, certs.AttemptClaim)
        self._expire_lease()
        second = certs._claim_attempt(self.row().pk, scheduled_renewal=False)
        assert isinstance(second, certs.AttemptClaim)

        certs._fail(first, "late failure")
        certs._defer(first, 60, "late deferral")

        row = self.row()
        self.assertEqual(row.attempt_status, AccountNameCertificate.AttemptStatus.ORDERING)
        self.assertEqual((row.attempt_token, row.retry_after), (second.token, None))

    def test_an_attempt_older_than_an_order_can_live_fails_without_asking_the_ca(self) -> None:
        self._crash_once()
        AccountNameCertificate.objects.filter(hostname=self.hostname).update(
            attempt_started_at=timezone.now() - certs.ATTEMPT_MAX_AGE - timedelta(minutes=1),
            attempt_lease_until=None,
        )
        calls = (self.acme.place_calls, self.acme.load_calls)

        outcome = self.issue()

        self.assertIs(outcome.status, IssuanceStatus.FAILED)
        self.assertEqual(self.row().attempt_order_url, "")
        self.assertEqual((self.acme.place_calls, self.acme.load_calls), calls)

    def test_a_certificate_for_another_key_is_never_put_in_force(self) -> None:
        from tests.provisioning.acme_fakes import issue_chain  # noqa: PLC0415

        stranger = certs._csr(
            ec.generate_private_key(ec.SECP256R1())
            .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            .decode(),
            self.hostname.fqdn,
        )
        with patch.object(self.acme, "complete", lambda order: issue_chain(stranger, 90).encode()):
            outcome = self.issue()

        self.assertIs(outcome.status, IssuanceStatus.FAILED)
        self.assertEqual(self.row().current_certificate_ref, "")

    def test_a_vault_read_error_never_replaces_a_key(self) -> None:
        vault = certs.get_credential_vault()
        with (
            patch.object(vault, "get_credential", return_value=Err("Credential expired 3 days ago")),
            patch.object(vault, "store_credential", wraps=vault.store_credential) as store,
            patch.object(certs, "get_credential_vault", return_value=vault),
        ):
            outcome = self.issue()

        self.assertIs(outcome.status, IssuanceStatus.DEFERRED)
        store.assert_not_called()

    def test_a_dns_refusal_that_retrying_cannot_cure_fails_the_attempt(self) -> None:
        from apps.common.types import Retriability  # noqa: PLC0415
        from apps.infrastructure.dns_gateway import ReconcileOutcome  # noqa: PLC0415

        refused = ReconcileOutcome()
        refused.error = "403 token cannot edit the zone"
        refused.retriability = Retriability.NOT_RETRIABLE
        with patch("apps.infrastructure.dns_gateway.CloudflareDnsGateway.reconcile_txt_values", return_value=refused):
            outcome = self.issue()

        self.assertIs(outcome.status, IssuanceStatus.FAILED)

    def test_a_renewal_inside_the_window_keeps_its_first_issuance_counted(self) -> None:
        _write("dns.account_cert_weekly_budget", 1)
        self.issue()
        AccountNameCertificate.objects.filter(hostname=self.hostname).update(
            current_not_after=timezone.now() + timedelta(days=5)
        )
        self.assertIs(certs.request_certificate(self.hostname, scheduled_renewal=True).status, IssuanceStatus.ISSUED)

        outcome = self.issue(_hostname(self.server))

        self.assertIs(outcome.status, IssuanceStatus.BUDGET_EXHAUSTED, "the week's one slot is still the first name's")

    def test_a_renewal_takes_no_slot_even_when_its_first_issuance_left_the_window(self) -> None:
        _write("dns.account_cert_weekly_budget", 1)
        self.issue()
        AccountNameCertificate.objects.filter(hostname=self.hostname).update(
            current_not_after=timezone.now() + timedelta(days=5),
            attempt_reserved_at=timezone.now() - timedelta(days=8),
        )
        reserved = self.row().attempt_reserved_at

        self.assertIs(certs.request_certificate(self.hostname, scheduled_renewal=True).status, IssuanceStatus.ISSUED)

        self.assertEqual(self.row().attempt_reserved_at, reserved)
        self.assertIs(self.issue(_hostname(self.server)).status, IssuanceStatus.ISSUED)

    def row_for_claim(self) -> AccountNameCertificate:
        AccountNameCertificateBudget.objects.get_or_create(zone=ZONE)
        return AccountNameCertificate.objects.get_or_create(hostname=self.hostname)[0]


class ConcurrentReservationTests(TransactionTestCase):
    """Two workers reserving the last slot get exactly one order. Row locks need PostgreSQL."""

    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("select_for_update row locking is a PostgreSQL behaviour")
        _write("dns.account_hostname_zone", ZONE)
        _write("dns.account_zone_api_token", "test-token-value")
        _write("dns.account_cert_weekly_budget", 1)

    def test_two_workers_reserving_the_last_slot_place_exactly_one_order(self) -> None:
        server = _server()
        first, second = _hostname(server), _hostname(server)
        cloudflare = FakeCloudflare()
        acme = FakeAcme(cloudflare)
        real_budget = certs.config.account_cert_weekly_budget
        ready = threading.Barrier(2)
        outcomes: list[certs.IssuanceOutcome] = []

        def slow_budget() -> int:
            # Read inside the reservation, after the count: a lock that is missing lets both workers pass here.
            threading.Event().wait(0.4)
            return real_budget()

        def worker(hostname: AccountHostname) -> None:
            try:
                ready.wait(timeout=10)
                outcomes.append(certs.request_certificate(hostname))
            finally:
                connection.close()

        with fakes(cloudflare, acme), patch.object(certs.config, "account_cert_weekly_budget", slow_budget):
            threads = [threading.Thread(target=worker, args=(h,)) for h in (first, second)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)

        self.assertEqual(sorted(o.status for o in outcomes), [IssuanceStatus.BUDGET_EXHAUSTED, IssuanceStatus.ISSUED])
        self.assertEqual(acme.place_calls, 1)
        self.assertEqual(AccountNameCertificateBudget.objects.filter(zone=ZONE).count(), 1)
