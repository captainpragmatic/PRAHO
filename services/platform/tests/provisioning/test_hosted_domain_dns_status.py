"""Persisted DNS observations have fenced writers and one outbox entry per real incident."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from io import StringIO
from unittest.mock import patch
from uuid import uuid4

from django.core.management import call_command
from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.customers.models import Customer
from apps.notifications.models import EmailLog, EmailTemplate
from apps.notifications.services import EmailResult
from apps.provisioning import hosted_domain_dns_config as dns_config
from apps.provisioning import hosted_domain_dns_service as dns_status
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.hosted_domain_dns_models import HostedDomainDnsStatus
from apps.provisioning.hosted_domain_dns_tasks import check_account_dns, dispatch_due_dns_checks
from apps.provisioning.service_models import Service, ServicePlan
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User


def account_fixture():
    customer = Customer.objects.create(name="DNS customer", primary_email="owner@example.com")
    Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    plan = ServicePlan.objects.create(name="DNS plan", price_monthly="10.00")
    service = Service.objects.create(
        customer=customer,
        service_plan=plan,
        currency_id="RON",
        service_name="DNS hosting",
        domain="customer.example",
        username="customer",
        price="10.00",
        status="active",
    )
    server = VirtualminServer.objects.create(
        name="private-node", hostname="private-node.example.net", ipv4_address="95.217.0.10"
    )
    account = VirtualminAccount.objects.create(
        service=service, server=server, domain=service.domain, virtualmin_username="customer", status="active"
    )
    name = AccountHostname.objects.create(
        account=account,
        target_server=server,
        label="a1b2c3d4",
        zone="accounts.example.net",
        records={"A": {"intended": server.ipv4_address, "applied": server.ipv4_address, "ttl": 300}},
    )
    return account, name, server


def report(**states):
    return {
        "version": 1,
        "dns_path": "external_dns",
        "components": {
            key: {
                "state": states.get(key, "healthy" if key not in {"mx", "dnssec"} else "not_applicable"),
                "code": "routing_matches" if key in {"apex", "www"} else "observed",
                "name": "customer.example",
                "record_type": "A",
                "checked_at": timezone.now().isoformat(),
                "ttl": 300,
                "evidence": {"private_address": "95.217.0.10", "private_node": "private-node.example.net"},
            }
            for key in ("apex", "www", "caa", "dnssec", "mx")
        },
    }


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class HostedDnsStatusTests(TestCase):
    def setUp(self):
        self.account, self.name, self.server = account_fixture()
        self.messages = []

        def queue(**kwargs):
            self.messages.append(kwargs)
            log = EmailLog.objects.create(
                customer=self.account.service.customer,
                to_addr="owner@example.com",
                template_key="hosting_dns_broken",
                subject="DNS changed",
                status="queued",
            )
            return EmailResult(success=True, email_log_id=str(log.pk))

        self.mail = patch("apps.notifications.services.EmailService.send_template_email", side_effect=queue).start()
        self.addCleanup(patch.stopall)
        self.audit = patch.object(dns_status, "_audit").start()

    def run_check(self, outcome):
        HostedDomainDnsStatus.objects.get_or_create(account=self.account)
        HostedDomainDnsStatus.objects.filter(account=self.account).update(
            next_check_at=timezone.now() - timedelta(seconds=1)
        )
        with patch.object(dns_status, "_probe", return_value=deepcopy(outcome)):
            result = check_account_dns(str(self.account.pk))
        return HostedDomainDnsStatus.objects.get(account=self.account), result

    def test_a_cached_read_is_offline_and_never_creates_a_status_row(self):
        with patch.object(dns_status, "_probe", side_effect=AssertionError("DNS on read")):
            value = dns_status.cached_status(self.account)
        self.assertEqual(value["state"], "unknown")
        self.assertFalse(HostedDomainDnsStatus.objects.exists())

    def test_request_recheck_is_durable_deduplicated_and_does_not_probe_or_dispatch_inline(self):
        with patch.object(dns_status, "_probe", side_effect=AssertionError("inline DNS")):
            first = dns_status.request_recheck(self.account)
            second = dns_status.request_recheck(self.account)
        self.assertTrue(first.is_ok(), first)
        self.assertTrue(first.unwrap()["queued"])
        self.assertFalse(second.unwrap()["queued"])
        row = HostedDomainDnsStatus.objects.get(account=self.account)
        self.assertIsNotNone(row.requested_at)
        self.assertIsNone(row.lease_token)
        self.assertTrue(dns_status.cached_status(self.account)["pending"])

    def test_service_level_recheck_rejects_a_viewer(self):
        user = User.objects.create_user(email="viewer@example.com", password=None)
        CustomerMembership.objects.create(user=user, customer=self.account.service.customer, role="viewer")
        result = dns_status.request_recheck(self.account, actor=user)
        self.assertTrue(result.is_err())
        self.assertFalse(HostedDomainDnsStatus.objects.exists())

    def test_recheck_during_cooldown_after_completion_reports_no_pending_work(self):
        dns_status.request_recheck(self.account)
        self.run_check(report())
        outcome = dns_status.request_recheck(self.account).unwrap()
        self.assertFalse(outcome["queued"])
        self.assertFalse(outcome["pending"])
        self.assertEqual(outcome["state"], "healthy")

    def test_runtime_monitoring_settings_take_effect_without_restarting_workers(self):
        SettingsService.update_setting("dns.hosted_checks_interval_seconds", 600).unwrap()
        SettingsService.update_setting("dns.hosted_checks_batch_size", 2).unwrap()
        SettingsService.update_setting("dns.hosted_recheck_cooldown_seconds", 120).unwrap()
        self.assertEqual(dns_config.interval_seconds(), 600)
        self.assertEqual(dns_config.batch_size(), 2)
        self.assertEqual(dns_config.recheck_cooldown_seconds(), 120)
        SettingsService.update_setting("dns.hosted_checks_enabled", False).unwrap()
        self.assertEqual(dispatch_due_dns_checks(), {"queued": 0})
        self.assertTrue(dns_status.request_recheck(self.account).is_err())
        self.assertEqual(dns_status.cached_status(self.account)["state"], "not_applicable")

    def test_disabling_monitoring_during_a_probe_prevents_publication_and_alerting(self):
        previous, _ = self.run_check(report())

        def disable(_target):
            SettingsService.update_setting("dns.hosted_checks_enabled", False).unwrap()
            return report(apex="broken")

        HostedDomainDnsStatus.objects.filter(account=self.account).update(next_check_at=timezone.now())
        with patch.object(dns_status, "_probe", side_effect=disable):
            outcome = check_account_dns(str(self.account.pk))
        self.assertEqual(outcome["action"], "excluded")
        previous.refresh_from_db()
        self.assertTrue(previous.healthy)
        self.assertFalse(self.messages)
        self.assertIsNone(previous.lease_token)

    def test_first_observed_failure_has_no_manufactured_healthy_baseline_or_email(self):
        row, _ = self.run_check(report(www="broken"))
        self.assertFalse(row.healthy)
        self.assertIsNotNone(row.first_failed_at)
        self.assertEqual(self.messages, [])

    def test_component_healthy_to_broken_alerts_even_with_an_unrelated_unknown_component(self):
        self.run_check(report(apex="unknown", www="healthy"))
        row, _ = self.run_check(report(apex="unknown", www="broken"))
        self.assertFalse(row.healthy)
        self.assertEqual(len(self.messages), 1)
        incident = row.incident_id
        first_log = row.alert_email_log_id
        self.assertIsNotNone(first_log)
        self.run_check(report(apex="unknown", www="broken", caa="broken"))
        row, _ = self.run_check(report(apex="unknown", www="unknown", caa="unknown"))
        self.assertIsNone(row.healthy)
        self.assertEqual(row.incident_id, incident)
        self.assertEqual(row.alert_email_log_id, first_log)
        self.assertEqual(len(self.messages), 1)
        self.assertTrue(self.messages[0]["async_send"])

    def test_an_unknown_component_cannot_borrow_another_components_healthy_baseline(self):
        self.run_check(report(www="unknown", apex="healthy"))
        self.run_check(report(www="broken", apex="healthy"))
        self.assertEqual(self.messages, [])

    def test_unknown_preserves_each_components_last_definitive_state(self):
        self.run_check(report())
        row, _ = self.run_check(report(www="unknown"))
        self.assertIsNone(row.healthy)
        self.assertEqual(row.component_history["www"]["state"], "healthy")
        self.run_check(report(www="broken"))
        self.assertEqual(len(self.messages), 1)

    def test_only_definitive_recovery_closes_an_incident_and_allows_the_next_email(self):
        self.run_check(report())
        first, _ = self.run_check(report(www="broken"))
        row, _ = self.run_check(report(www="unknown"))
        self.assertEqual(row.incident_id, first.incident_id)
        row, _ = self.run_check(report())
        self.assertIsNone(row.incident_id)
        self.assertIsNone(row.first_failed_at)
        row, _ = self.run_check(report(caa="broken"))
        self.assertNotEqual(row.incident_id, first.incident_id)
        self.assertEqual(len(self.messages), 2)

    def test_failed_delivery_with_a_durable_email_log_never_creates_a_second_message(self):
        self.run_check(report())
        log = EmailLog.objects.create(to_addr="owner@example.com", subject="DNS changed", status="failed")
        self.mail.side_effect = None
        self.mail.return_value = EmailResult(success=False, email_log_id=str(log.pk), error="provider unavailable")
        first, _ = self.run_check(report(www="broken"))
        self.run_check(report(www="broken"))
        self.assertEqual(first.alert_email_log_id, log.pk)
        self.assertEqual(self.mail.call_count, 1)

    def test_a_template_failure_without_an_email_log_retries_the_same_incident(self):
        self.run_check(report())
        queue = self.mail.side_effect
        self.mail.side_effect = None
        self.mail.return_value = EmailResult(success=False, error="template unavailable")
        row, _ = self.run_check(report(www="broken"))
        incident = row.incident_id
        self.assertTrue(row.notification_pending)
        self.mail.side_effect = queue
        row, _ = self.run_check(report(www="broken"))
        self.assertEqual(row.incident_id, incident)
        self.assertFalse(row.notification_pending)
        self.assertEqual(len(self.messages), 1)

    def test_public_status_omits_private_probe_data_and_node_identifiers(self):
        self.run_check(report())
        value = dns_status.cached_status(self.account)
        self.assertEqual(value["state"], "healthy")
        self.assertEqual(value["account_name"], self.name.fqdn)
        self.assertTrue(value["instructions"])
        text = json.dumps(value)
        for hidden in (
            self.server.ipv4_address,
            self.server.hostname,
            str(self.server.pk),
            "private_address",
            "evidence",
        ):
            self.assertNotIn(hidden, text)

    def test_cached_green_is_invalidated_immediately_when_target_changes_without_a_worker(self):
        self.run_check(report())
        VirtualminServer.objects.filter(pk=self.server.pk).update(ipv4_address="95.217.0.20")
        with patch.object(dns_status, "_probe", side_effect=AssertionError("DNS on read")):
            value = dns_status.cached_status(self.account)
        self.assertEqual(value["state"], "unknown")
        self.assertTrue(value["stale"])
        self.assertTrue(all(item["state"] != "healthy" for item in value["components"].values()))

    def transfer_customer(self):
        customer = Customer.objects.create(name="New owner", primary_email="new-owner@example.com")
        Service.objects.filter(pk=self.account.service_id).update(customer=customer)
        return customer

    def test_cached_green_is_invalidated_offline_when_canonical_customer_changes(self):
        self.run_check(report())
        self.transfer_customer()
        value = dns_status.cached_status(self.account)
        self.assertEqual(value["state"], "unknown")
        self.assertTrue(value["stale"])

    def test_cached_green_is_invalidated_when_account_is_relinked_to_another_service(self):
        self.run_check(report())
        service = self.account.service
        replacement = Service.objects.create(
            customer=service.customer,
            service_plan=service.service_plan,
            currency_id="RON",
            service_name="Replacement hosting",
            domain=service.domain,
            username="replacement",
            price="10.00",
            status="active",
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(service=replacement)
        self.assertEqual(dns_status.cached_status(self.account)["state"], "unknown")

    def test_customer_transfer_during_probe_discards_old_tenant_observations_and_alerts(self):
        previous, _ = self.run_check(report())

        def transfer(_target):
            self.transfer_customer()
            return report(apex="broken")

        HostedDomainDnsStatus.objects.filter(account=self.account).update(next_check_at=timezone.now())
        with patch.object(dns_status, "_probe", side_effect=transfer):
            outcome = check_account_dns(str(self.account.pk))
        self.assertEqual(outcome["action"], "stale")
        previous.refresh_from_db()
        self.assertTrue(previous.healthy)
        self.assertFalse(self.messages)

    def test_a_later_worked_to_broken_component_notifies_an_incident_that_has_never_emailed(self):
        first, _ = self.run_check(report(apex="broken", www="healthy"))
        incident = first.incident_id
        self.assertFalse(self.messages)
        second, _ = self.run_check(report(apex="broken", www="broken"))
        self.assertEqual(second.incident_id, incident)
        self.assertEqual(len(self.messages), 1)
        self.assertIn("www", self.messages[0]["context"]["dns_problems"])
        self.run_check(report(apex="broken", www="unknown"))
        self.run_check(report(apex="broken", www="broken"))
        self.assertEqual(len(self.messages), 1)

    def test_new_tenant_does_not_inherit_the_previous_tenants_healthy_baseline(self):
        self.run_check(report())
        self.transfer_customer()
        row, result = self.run_check(report(apex="broken"))
        self.assertEqual(result["action"], "broken")
        self.assertIsNotNone(row.incident_id)
        self.assertFalse(self.messages)

    def test_cached_green_is_invalidated_by_maintenance_or_termination(self):
        self.run_check(report())
        VirtualminAccount.objects.filter(pk=self.account.pk).update(restore_hold="half_restored")
        self.assertEqual(dns_status.cached_status(self.account)["state"], "unknown")
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="terminated", restore_hold="")
        value = dns_status.cached_status(self.account)
        self.assertEqual(value["state"], "not_applicable")
        self.assertFalse(value["pending"])

    def retained_bridge(self, *, expires=None, evidence=None):
        source = VirtualminServer.objects.create(name="former-source", hostname="former.example.net")
        migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=source,
            target_server=self.server,
            status="completed",
            cutover_committed_at=timezone.now(),
        )
        return MigrationBridge.objects.create(
            migration=migration,
            source_server=source,
            target_server=self.server,
            domain=self.account.domain,
            status="active",
            evidence={"expires_at": (expires or timezone.now() + timedelta(hours=48)).isoformat(), **(evidence or {})},
        )

    def test_live_bridge_retention_defers_dns_and_invalidates_cached_green_offline(self):
        self.run_check(report())
        self.retained_bridge()
        with patch.object(dns_status, "_probe", side_effect=AssertionError("DNS during retained bridge")):
            status = dns_status.cached_status(self.account)
            HostedDomainDnsStatus.objects.filter(account=self.account).update(next_check_at=timezone.now())
            outcome = check_account_dns(str(self.account.pk))
        self.assertEqual(status["state"], "unknown")
        self.assertTrue(status["stale"])
        self.assertEqual(outcome["action"], "maintenance")

    def test_expired_bridge_cannot_hide_a_dns_warning_or_revive_pre_bridge_green(self):
        self.run_check(report())
        bridge = self.retained_bridge()
        self.assertEqual(dns_status.cached_status(self.account)["state"], "unknown")
        bridge.evidence["expires_at"] = (timezone.now() - timedelta(seconds=1)).isoformat()
        bridge.save(update_fields=["evidence"])
        self.assertEqual(dns_status.cached_status(self.account)["state"], "unknown")
        _row, outcome = self.run_check(report(apex="broken"))
        self.assertEqual(outcome["action"], "broken")
        self.assertEqual(len(self.messages), 1)

    def test_source_fenced_and_failed_bridges_do_not_claim_working_traffic(self):
        self.run_check(report())
        bridge = self.retained_bridge(evidence={"source_fenced_control": {"attestation": "Provider instance off"}})
        _row, result = self.run_check(report(apex="broken"))
        self.assertEqual(result["action"], "broken")
        MigrationBridge.objects.filter(pk=bridge.pk).update(
            status="failed", evidence={"expires_at": (timezone.now() + timedelta(hours=48)).isoformat()}
        )
        _row, result = self.run_check(report(apex="broken"))
        self.assertEqual(result["action"], "broken")

    def test_bridge_activation_during_probe_discards_the_pre_maintenance_result(self):
        def retain_bridge(_target):
            self.retained_bridge()
            return report()

        with patch.object(dns_status, "_probe", side_effect=retain_bridge):
            result = check_account_dns(str(self.account.pk))
        self.assertEqual(result["action"], "stale")
        self.assertIsNone(HostedDomainDnsStatus.objects.get(account=self.account).checked_at)

    def test_a_result_from_a_previous_target_is_discarded(self):
        def move(_target):
            VirtualminServer.objects.filter(pk=self.server.pk).update(ipv4_address="95.217.0.20")
            return report()

        with patch.object(dns_status, "_probe", side_effect=move):
            result = check_account_dns(str(self.account.pk))
        self.assertEqual(result["action"], "stale")
        self.assertIsNone(HostedDomainDnsStatus.objects.get(account=self.account).checked_at)
        self.assertEqual(self.messages, [])

    def test_a_stale_worker_cannot_write_after_its_lease_is_reclaimed(self):
        def reclaim(_target):
            HostedDomainDnsStatus.objects.filter(account=self.account).update(lease_token=uuid4())
            return report()

        with patch.object(dns_status, "_probe", side_effect=reclaim):
            result = check_account_dns(str(self.account.pk))
        self.assertEqual(result["action"], "busy")
        self.assertIsNone(HostedDomainDnsStatus.objects.get(account=self.account).checked_at)

    def test_active_migrations_defer_checks_and_manual_rechecks(self):
        VirtualminMigration.objects.create(account=self.account, source_server=self.server, target_server=self.server)
        with patch.object(dns_status, "_probe", side_effect=AssertionError("probe during migration")):
            result = check_account_dns(str(self.account.pk))
            requested = dns_status.request_recheck(self.account)
        self.assertEqual(result["action"], "maintenance")
        self.assertTrue(requested.is_err())

    def test_expired_results_do_not_remain_green(self):
        self.run_check(report())
        HostedDomainDnsStatus.objects.filter(account=self.account).update(
            checked_at=timezone.now() - timedelta(hours=3)
        )
        self.assertEqual(dns_status.cached_status(self.account)["state"], "unknown")

    def test_empty_or_malformed_results_are_unknown_and_never_a_healthy_baseline(self):
        row, _ = self.run_check({"version": 1, "dns_path": "anything", "components": {}})
        self.assertIsNone(row.healthy)
        self.assertEqual(row.component_history, {})
        self.assertEqual(self.messages, [])

    def test_dispatch_is_bounded_and_repeated_dispatch_does_not_duplicate_active_claims(self):
        for _ in range(3):
            # Reuse the account's service setup while keeping account identities distinct.
            service = Service.objects.create(
                customer=self.account.service.customer,
                service_plan=self.account.service.service_plan,
                currency_id="RON",
                service_name="More DNS",
                username=f"user{_}",
                domain=f"more{_}.example",
                price="10.00",
                status="active",
            )
            account = VirtualminAccount.objects.create(
                service=service,
                server=self.server,
                domain=service.domain,
                virtualmin_username=f"user{_}",
                status="active",
            )
            AccountHostname.objects.create(
                account=account,
                target_server=self.server,
                label=f"b{_:07d}",
                zone=self.name.zone,
                records=deepcopy(self.name.records),
            )
        with (
            patch("apps.provisioning.hosted_domain_dns_tasks.config.batch_size", return_value=2),
            patch("apps.provisioning.hosted_domain_dns_tasks.async_task") as queued,
            self.captureOnCommitCallbacks(execute=True),
        ):
            first = dispatch_due_dns_checks()
            second = dispatch_due_dns_checks()
            third = dispatch_due_dns_checks()
        self.assertEqual((first["queued"], second["queued"], third["queued"]), (2, 2, 0))
        self.assertEqual(queued.call_count, 4)
        self.assertTrue(all(call.kwargs["timeout"] == 120 for call in queued.call_args_list))

    def test_expired_dispatch_claim_is_recovered_even_before_its_hourly_deadline(self):
        row = HostedDomainDnsStatus.objects.create(
            account=self.account,
            lease_token=uuid4(),
            lease_until=timezone.now() - timedelta(seconds=1),
            next_check_at=timezone.now() + timedelta(hours=1),
        )
        old = row.lease_token
        with patch("apps.provisioning.hosted_domain_dns_tasks.async_task"), self.captureOnCommitCallbacks(execute=True):
            outcome = dispatch_due_dns_checks()
        row.refresh_from_db()
        self.assertEqual(outcome["queued"], 1)
        self.assertNotEqual(row.lease_token, old)

    def test_an_enqueue_failure_leaves_durable_work_for_the_dispatcher(self):
        dns_status.request_recheck(self.account)
        with (
            patch("apps.provisioning.hosted_domain_dns_tasks.async_task", side_effect=RuntimeError("broker offline")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            dispatch_due_dns_checks()
        row = HostedDomainDnsStatus.objects.get(account=self.account)
        self.assertIsNone(row.lease_token)
        self.assertIsNotNone(row.requested_at)

    def test_dispatch_remains_asynchronous_even_when_django_q_defaults_to_sync(self):
        dns_status.request_recheck(self.account)
        with (
            patch("django_q.conf.Conf.SYNC", True),
            patch("django_q.tasks._sync") as synchronous,
            patch("django_q.tasks.get_broker") as broker,
            self.captureOnCommitCallbacks(execute=True),
        ):
            outcome = dispatch_due_dns_checks()
        self.assertEqual(outcome["queued"], 1)
        synchronous.assert_not_called()
        broker.return_value.enqueue.assert_called_once()


@override_settings(DISABLE_AUDIT_SIGNALS=True, AUDIT_CHAIN_ENABLED=False)
class HostedDnsTransactionBoundaryTests(TransactionTestCase):
    def setUp(self):
        self.account, _name, _server = account_fixture()
        self.audit_patch = patch.object(dns_status, "_audit")
        self.audit = self.audit_patch.start()
        self.addCleanup(self.audit_patch.stop)

    def run_check(self, outcome):
        HostedDomainDnsStatus.objects.get_or_create(account=self.account)
        HostedDomainDnsStatus.objects.filter(account=self.account).update(next_check_at=timezone.now())
        with patch.object(dns_status, "_probe", return_value=outcome):
            return check_account_dns(str(self.account.pk))

    def test_probe_network_runs_after_the_claim_transaction_has_closed(self):
        def probe(_target):
            self.assertFalse(connection.in_atomic_block, "DNS must not hold a database transaction open")
            return report()

        with patch.object(dns_status, "_probe", side_effect=probe), patch.object(dns_status, "_audit"):
            outcome = check_account_dns(str(self.account.pk))
        self.assertEqual(outcome["action"], "healthy")

    def test_seeded_templates_queue_one_real_outbox_row_after_incident_commit(self):
        call_command("setup_email_templates", stdout=StringIO())
        self.assertEqual(
            set(EmailTemplate.objects.filter(key="hosting_dns_broken").values_list("locale", flat=True)), {"ro", "en"}
        )
        self.run_check(report())

        def queued(*_args, **kwargs):
            self.assertFalse(connection.in_atomic_block)
            row = HostedDomainDnsStatus.objects.get(account=self.account)
            self.assertEqual(str(row.alert_email_log_id), kwargs["email_log_id"])
            self.assertEqual(EmailLog.objects.get(pk=row.alert_email_log_id).status, "queued")

        with (
            patch("django_q.tasks.async_task", side_effect=queued) as enqueue,
            patch("apps.notifications.services.EmailService._send_now", side_effect=AssertionError("inline SMTP")),
        ):
            self.run_check(report(apex="broken"))
            self.run_check(report(apex="broken"))
        self.assertEqual(enqueue.call_count, 1)
        self.assertEqual(EmailLog.objects.filter(template_key="hosting_dns_broken").count(), 1)

    def test_incident_rollback_does_not_publish_an_email_or_leave_an_outbox_row(self):
        call_command("setup_email_templates", stdout=StringIO())
        self.run_check(report())

        def refuse_audit(*_args, **_kwargs):
            self.assertTrue(connection.in_atomic_block)
            self.assertEqual(EmailLog.objects.filter(template_key="hosting_dns_broken").count(), 1)
            raise RuntimeError("audit persistence refused")

        self.audit.side_effect = refuse_audit
        with patch("django_q.tasks.async_task") as enqueue, self.assertRaisesRegex(RuntimeError, "audit persistence"):
            self.run_check(report(apex="broken"))
        self.assertEqual(enqueue.call_count, 0)
        self.assertFalse(EmailLog.objects.filter(template_key="hosting_dns_broken").exists())
        row = HostedDomainDnsStatus.objects.get(account=self.account)
        self.assertTrue(row.healthy)
        self.assertIsNone(row.incident_id)

    def test_expiry_during_outbox_rendering_rolls_back_result_and_email(self):
        call_command("setup_email_templates", stdout=StringIO())
        self.run_check(report())
        clock = [timezone.now()]
        notify = dns_status._notify

        def slow_render(*args):
            notify(*args)
            self.assertEqual(EmailLog.objects.filter(template_key="hosting_dns_broken").count(), 1)
            clock[0] += timedelta(seconds=dns_config.LEASE_SECONDS + 1)

        with (
            patch.object(dns_status.timezone, "now", side_effect=lambda: clock[0]),
            patch.object(dns_status, "_notify", side_effect=slow_render),
            patch("django_q.tasks.async_task") as enqueue,
        ):
            result = self.run_check(report(apex="broken"))
        self.assertEqual(result["action"], "busy")
        self.assertFalse(EmailLog.objects.filter(template_key="hosting_dns_broken").exists())
        enqueue.assert_not_called()
        self.assertTrue(HostedDomainDnsStatus.objects.get(account=self.account).healthy)

    def test_duplicate_workers_commit_only_one_incident_and_outbox_entry_on_postgres(self):
        if connection.vendor != "postgresql":
            self.skipTest("Concurrent row locks require PostgreSQL")
        call_command("setup_email_templates", stdout=StringIO())
        self.run_check(report())
        HostedDomainDnsStatus.objects.filter(account=self.account).update(next_check_at=timezone.now())
        claim, _ = dns_status.claim_check(str(self.account.pk))
        self.assertIsNotNone(claim)
        ready = threading.Barrier(2)

        def publish():
            close_old_connections()
            try:
                ready.wait(timeout=10)
                return dns_status.commit_check(claim, report(apex="broken"))
            finally:
                connection.close()

        with patch("django_q.tasks.async_task") as enqueue, ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(publish) for _ in range(2)]
            outcomes = [future.result(timeout=30) for future in futures]
        self.assertCountEqual(outcomes, ["broken", "busy"])
        self.assertEqual(enqueue.call_count, 1)
        self.assertEqual(EmailLog.objects.filter(template_key="hosting_dns_broken").count(), 1)

    def test_concurrent_dispatchers_enqueue_one_current_claim_on_postgres(self):
        if connection.vendor != "postgresql":
            self.skipTest("Concurrent row locks require PostgreSQL")
        HostedDomainDnsStatus.objects.create(account=self.account)
        ready = threading.Barrier(2)

        def dispatch():
            close_old_connections()
            try:
                ready.wait(timeout=10)
                return dispatch_due_dns_checks()["queued"]
            finally:
                connection.close()

        with (
            patch("apps.provisioning.hosted_domain_dns_tasks.async_task") as enqueue,
            ThreadPoolExecutor(max_workers=2) as workers,
        ):
            futures = [workers.submit(dispatch) for _ in range(2)]
            queued = [future.result(timeout=30) for future in futures]
        self.assertEqual(sum(queued), 1)
        self.assertEqual(enqueue.call_count, 1)
        current = HostedDomainDnsStatus.objects.get(account=self.account)
        self.assertEqual(enqueue.call_args.kwargs["lease_token"], str(current.lease_token))
