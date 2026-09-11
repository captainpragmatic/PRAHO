"""Intent persistence, crash recovery and PostgreSQL request serialization."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from importlib import import_module
from threading import Barrier, Event
from unittest import skipUnless
from unittest.mock import patch

from django.apps import apps
from django.core.cache import cache
from django.db import IntegrityError, close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Err, Ok
from apps.customers.models import Customer
from apps.domains.gateways import DomainInfoResult, RegistrarAPIError
from apps.domains.models import TLD, Domain, DomainOperation, Registrar
from apps.domains.operation_services import DomainOperationService, intent_digest
from apps.domains.services import DomainLifecycleService, DomainReconciliationService, DomainRegistrationConfig
from apps.domains.webhooks import RegistrarWebhookView
from config.settings.test import LOCMEM_TEST_CACHE
from tests.domains.test_registrar_contracts import CONTACT, FIXTURES, response


class IntentFixture:
    def setUp(self) -> None:
        cache.clear()
        self.registrar = Registrar.objects.create(name="gandi", api_endpoint="https://api.sandbox.gandi.net/v5")
        self.tld = TLD.objects.create(
            extension="com", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        self.customer = Customer.objects.create(name="Test Registrant", primary_email="test@example.net")
        self.expiry = datetime(2028, 1, 1, tzinfo=UTC)
        self.domain = Domain.objects.create(
            name="intent.com",
            registrar=self.registrar,
            tld=self.tld,
            customer=self.customer,
            status="active",
            registrar_domain_id="intent.com",
            expires_at=self.expiry,
        )
        self.info = DomainInfoResult("intent.com", "intent.com", "active", self.expiry, [])
        preflight = patch("apps.domains.services.DomainRegistrarGateway.get_domain_info", return_value=Ok(self.info))
        self.preflight = preflight.start()
        self.addCleanup(preflight.stop)


@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True, CACHES=LOCMEM_TEST_CACHE)
class DurableOperationTests(IntentFixture, TransactionTestCase):
    def test_same_token_replays_after_cache_loss_and_distinct_token_blocks(self) -> None:
        with patch(
            "apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"pending": True})
        ) as renew:
            first = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="paid:1")
            cache.clear()
            replay = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="paid:1")
            blocked = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="paid:2")
        self.assertTrue(first.is_ok())
        self.assertTrue(replay.is_ok())
        self.assertTrue(blocked.is_err())
        self.assertEqual(renew.call_count, 1)
        self.assertEqual(DomainOperation.objects.filter(domain=self.domain).count(), 1)
        operation = DomainOperation.objects.get(domain=self.domain)
        self.assertIsNotNone(operation.accepted_at)
        self.assertEqual(len(operation.intent_key), 64)
        self.assertNotIn("paid:1", operation.intent_key)

    def test_submitted_row_exists_before_renewal_http_and_response_loss_does_not_replay(self) -> None:
        def lose_response(*args, **kwargs):
            operation = DomainOperation.objects.get(domain=self.domain)
            self.assertEqual(operation.state, "submitted")
            self.assertIsNotNone(operation.submitted_at)
            self.assertFalse(connection.in_atomic_block)
            raise RuntimeError("response lost")

        with patch("apps.domains.services.DomainRegistrarGateway.renew_domain", side_effect=lose_response) as renew:
            self.assertTrue(
                DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="lost").is_err()
            )
            cache.clear()
            self.assertTrue(
                DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="lost").is_err()
            )
        self.assertEqual(renew.call_count, 1)
        self.assertEqual(DomainOperation.objects.get(domain=self.domain).state, "submitted")

    def test_response_persistence_failure_retains_precommitted_intent(self) -> None:
        with (
            patch(
                "apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"pending": True})
            ) as renew,
            patch.object(DomainOperationService, "record_response", side_effect=RuntimeError("db unavailable")),
        ):
            DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="persist")
            DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="persist")
        self.assertEqual(renew.call_count, 1)
        self.assertEqual(DomainOperation.objects.get(domain=self.domain).state, "submitted")

    def test_snapshot_comes_from_registrar_and_one_extension_is_consumed_once(self) -> None:
        local_drift = self.expiry - timedelta(days=365)
        Domain.objects.filter(pk=self.domain.pk).update(expires_at=local_drift)
        with patch("apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"pending": True})):
            DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="first")
        first = DomainOperation.objects.get(domain=self.domain)
        self.assertEqual(first.parameters["prev_expires_at"], self.expiry.isoformat())
        self.assertFalse(DomainOperationService.confirm_renewal(first, self.expiry))
        new_expiry = self.expiry + timedelta(days=365)
        self.assertTrue(DomainOperationService.confirm_renewal(first, new_expiry))
        second = DomainOperation(
            domain=self.domain, registrar=self.registrar, operation_type="renew", parameters=first.parameters
        )
        second.mark_submitted()
        second.save()
        self.assertFalse(DomainOperationService.confirm_renewal(second, new_expiry))
        self.assertFalse(DomainOperationService.confirm_renewal(second, new_expiry))
        second.refresh_from_db()
        self.assertEqual(second.state, "submitted")
        self.assertIsNotNone(second.review_required_at)

    def test_completed_token_replays_but_new_intent_can_extend_again(self) -> None:
        new_expiry = self.expiry + timedelta(days=365)
        with patch(
            "apps.domains.services.DomainRegistrarGateway.renew_domain",
            return_value=(True, {"new_expires_at": new_expiry}),
        ) as renew:
            self.assertTrue(
                DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="first").is_ok()
            )
            cache.clear()
            self.assertTrue(
                DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="first").is_ok()
            )
            self.info = DomainInfoResult("intent.com", "intent.com", "active", new_expiry, [])
            self.preflight.return_value = Ok(self.info)
            renew.return_value = (True, {"new_expires_at": new_expiry + timedelta(days=365)})
            self.assertTrue(
                DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="second").is_ok()
            )
        self.assertEqual(renew.call_count, 2)
        self.assertEqual(DomainOperation.objects.filter(state="completed").count(), 2)

    def test_enclosing_transaction_refuses_before_any_request_or_operation(self) -> None:
        with transaction.atomic(), patch("apps.domains.services.DomainRegistrarGateway.renew_domain") as renew:
            result = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="outer")
        self.assertTrue(result.is_err())
        self.assertIn("enclosing", result.unwrap_err())
        self.assertFalse(DomainOperation.objects.exists())
        self.preflight.assert_not_called()
        renew.assert_not_called()

    def test_preflight_failure_sends_no_renewal(self) -> None:
        self.preflight.return_value = Err(RegistrarAPIError("cannot read"))
        with patch("apps.domains.services.DomainRegistrarGateway.renew_domain") as renew:
            result = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="preflight")
        self.assertTrue(result.is_err())
        renew.assert_not_called()
        operation = DomainOperation.objects.get(domain=self.domain)
        self.assertIsNone(operation.submitted_at)
        self.assertEqual(operation.state, "failed")

    def test_failed_preflight_can_retry_same_paid_intent_without_duplicate_rows(self) -> None:
        self.preflight.return_value = Err(RegistrarAPIError("read unavailable"))
        with patch(
            "apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"pending": True})
        ) as renew:
            self.assertTrue(
                DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="paid").is_err()
            )
            renew.assert_not_called()
            self.preflight.return_value = Ok(self.info)
            self.assertTrue(
                DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="paid").is_ok()
            )
        self.assertEqual(DomainOperation.objects.count(), 1)
        self.assertEqual(renew.call_count, 1)

    def test_intent_unique_constraint_allows_unkeyed_legacy_rows(self) -> None:
        fields = {"domain": self.domain, "registrar": self.registrar, "operation_type": "renew"}
        DomainOperation.objects.create(**fields, intent_key=intent_digest("unique"))
        with self.assertRaises(IntegrityError), transaction.atomic():
            DomainOperation.objects.create(**fields, intent_key=intent_digest("unique"))
        DomainOperation.objects.create(**fields)
        DomainOperation.objects.create(**fields)
        self.assertEqual(DomainOperation.objects.count(), 3)

    def test_webhook_completion_and_late_202_preserve_completion(self) -> None:
        def webhook_then_accepted(*args, **kwargs):
            success, message = RegistrarWebhookView()._handle_domain_renewed(
                self.domain, {"expires_at": "2029-01-01T00:00:00Z"}, "127.0.0.1"
            )
            self.assertTrue(success, message)
            return True, {"pending": True}

        with patch("apps.domains.services.DomainRegistrarGateway.renew_domain", side_effect=webhook_then_accepted):
            DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="webhook")
        operation = DomainOperation.objects.get(domain=self.domain)
        self.assertEqual(operation.state, "completed")
        self.assertIsNotNone(operation.accepted_at)
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.expires_at, datetime(2029, 1, 1, tzinfo=UTC))

    def test_review_rows_are_scheduled_daily_and_do_not_starve_newer_work(self) -> None:
        op = DomainOperation(
            domain=self.domain,
            registrar=self.registrar,
            operation_type="renew",
            parameters={"prev_expires_at": self.expiry.isoformat()},
        )
        op.mark_submitted()
        op.save()
        DomainOperation.objects.filter(pk=op.pk).update(submitted_at=timezone.now() - timedelta(hours=73))
        with patch("apps.domains.gateways.gandi.GandiGateway.get_domain_info", return_value=Ok(self.info)) as get_info:
            DomainReconciliationService.reconcile()
            DomainReconciliationService.reconcile()
        self.assertEqual(get_info.call_count, 1)
        op.refresh_from_db()
        self.assertEqual(op.state, "submitted")
        self.assertIsNotNone(op.review_required_at)
        self.assertGreater(op.next_retry_at, timezone.now() + timedelta(hours=23))

    def test_migration_retains_acceptance_and_resurrects_timeout_without_inventing_keys(self) -> None:
        timeout = DomainOperation.objects.create(
            domain=self.domain,
            registrar=self.registrar,
            operation_type="renew",
            state="failed",
            error_message="unconfirmed after 72h — investigate at the registrar",
        )
        accepted = DomainOperation.objects.create(
            domain=self.domain,
            registrar=self.registrar,
            operation_type="register",
            registrar_operation_id="/v5/reference",
            state="failed",
        )
        rejected = DomainOperation.objects.create(
            domain=self.domain,
            registrar=self.registrar,
            operation_type="renew",
            state="failed",
            error_message="auth_failed",
        )
        migration = import_module("apps.domains.migrations.0009_domainoperation_durable_intent")
        with connection.schema_editor() as editor:
            migration.preserve_uncertain_operations(apps, editor)
        for operation in (timeout, accepted):
            operation.refresh_from_db()
            self.assertEqual(operation.state, "submitted")
            self.assertIsNone(operation.intent_key)
            self.assertIsNotNone(operation.review_required_at)
        self.assertIsNotNone(accepted.accepted_at)
        rejected.refresh_from_db()
        self.assertEqual(rejected.state, "failed")

    def test_stale_preflight_after_completed_intent_does_not_send_another_renewal(self) -> None:
        expiry = self.expiry + timedelta(days=365)
        with patch(
            "apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"new_expires_at": expiry})
        ) as renew:
            DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="first")
            result = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="stale")
        self.assertTrue(result.is_err())
        self.assertEqual(renew.call_count, 1)

    def test_rotld_contact_is_persisted_and_nameserver_failure_keeps_registration(self) -> None:
        registrar = Registrar.objects.create(
            name="rotld",
            api_endpoint="https://rest2-test.rotld.ro:6080",
            default_nameservers=["ns1.example.net", "ns2.example.net"],
        )
        tld = TLD.objects.create(
            extension="ro", registration_price_cents=1000, renewal_price_cents=1000, transfer_price_cents=1000
        )
        config = DomainRegistrationConfig(self.customer, "example.ro", tld, registrar, CONTACT)
        commands = []

        def transport(method, url, **kwargs):
            self.assertFalse(connection.in_atomic_block)
            command = kwargs["data"]["command"]
            commands.append(command)
            fixture = {
                "check-availability": "rotld_available",
                "contact-create": "rotld_contact",
                "domain-register": "rotld_register",
            }
            if command == "domain-register":
                operation = DomainOperation.objects.get(domain__name="example.ro", operation_type="register")
                self.assertEqual(operation.state, "submitted")
                self.assertEqual(operation.parameters["registrar_contact_id"], "CONTACT-EXAMPLE")
            if command == "domain-reset-ns":
                return response({"error": 1, "result_code": "10501", "data": {}})
            return response(FIXTURES[fixture[command]])

        with (
            patch.object(Registrar, "get_api_credentials", return_value=("test", "test")),
            patch("apps.domains.gateways.rotld.ROTLDGateway._api_request", side_effect=transport),
        ):
            result = DomainLifecycleService._execute_domain_registration(config)
            self.assertTrue(result.is_ok(), result)
            DomainOperationService.resume_registration_nameservers(result.unwrap())
        domain = result.unwrap()
        self.assertEqual(domain.status, "active")
        self.assertEqual(domain.nameservers, [])
        self.assertEqual(domain.operations.get(operation_type="register").state, "completed")
        self.assertEqual(domain.operations.get(operation_type="nameserver_update").state, "failed")
        self.assertEqual(commands, ["check-availability", "contact-create", "domain-register", "domain-reset-ns"])

    def test_lost_rotld_contact_response_retains_reviewable_registration_without_resubmitting(self) -> None:
        registrar = Registrar.objects.create(name="rotld", api_endpoint="https://rest2-test.rotld.ro:6080")
        config = DomainRegistrationConfig(self.customer, "example.ro", self.tld, registrar, CONTACT)
        with (
            patch.object(Registrar, "get_api_credentials", return_value=("test", "test")),
            patch(
                "apps.domains.gateways.rotld.ROTLDGateway._api_request",
                side_effect=[response(FIXTURES["rotld_available"]), response({"unexpected": "data"})],
            ) as send,
        ):
            self.assertTrue(DomainLifecycleService._execute_domain_registration(config).is_err())
            self.assertTrue(DomainLifecycleService._execute_domain_registration(config).is_err())
        self.assertEqual(send.call_count, 2)
        operation = DomainOperation.objects.get(domain__name="example.ro", operation_type="register")
        self.assertEqual(operation.state, "pending")
        self.assertTrue(operation.parameters["contact_dispatched"])
        self.assertIsNotNone(operation.review_required_at)
        self.assertIsNone(operation.submitted_at)

    def test_definite_contact_rejection_does_not_create_an_uncertainty_review(self) -> None:
        registrar = Registrar.objects.create(name="rotld", api_endpoint="https://rest2-test.rotld.ro:6080")
        config = DomainRegistrationConfig(self.customer, "example.ro", self.tld, registrar, CONTACT)
        with (
            patch.object(Registrar, "get_api_credentials", return_value=("test", "test")),
            patch(
                "apps.domains.gateways.rotld.ROTLDGateway._api_request",
                side_effect=[
                    response(FIXTURES["rotld_available"]),
                    response({"error": 1, "result_code": "50001", "data": {}}),
                ],
            ),
        ):
            result = DomainLifecycleService._execute_domain_registration(config)
        self.assertTrue(result.is_err())
        self.assertFalse(Domain.objects.filter(name="example.ro").exists())
        self.assertFalse(AuditEvent.objects.filter(action="domain_operation_review_required").exists())

    def test_interrupted_pending_renewal_resumes_the_same_intent(self) -> None:
        operation = DomainOperation.objects.create(
            domain=self.domain,
            registrar=self.registrar,
            operation_type="renew",
            intent_key=intent_digest("token:resume"),
            parameters={"years": 1},
        )
        with patch(
            "apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"pending": True})
        ) as renew:
            result = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="resume")
            replay = DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="resume")
        self.assertTrue(result.is_ok(), result)
        self.assertTrue(replay.is_ok(), replay)
        self.assertEqual(renew.call_count, 1)
        self.assertEqual(DomainOperation.objects.count(), 1)
        operation.refresh_from_db()
        self.assertEqual(operation.state, "submitted")
        self.assertEqual(operation.parameters["prev_expires_at"], self.expiry.isoformat())

    def test_duplicate_webhook_preserves_notice_counters_and_does_not_audit_again(self) -> None:
        self.domain.renewal_notices_sent = 14
        self.domain.save(update_fields=["renewal_notices_sent"])
        with patch("apps.domains.webhooks.DomainsAuditService.log_domain_event") as audit:
            success, message = RegistrarWebhookView()._handle_domain_renewed(
                self.domain, {"expires_at": self.expiry.isoformat()}, "127.0.0.1"
            )
        self.assertTrue(success, message)
        self.domain.refresh_from_db()
        self.assertEqual(self.domain.renewal_notices_sent, 14)
        audit.assert_not_called()


@skipUnless(connection.vendor == "postgresql", "Requires PostgreSQL row locks; exercised in Integration CI")
@override_settings(REGISTRAR_ADAPTERS_VERIFIED=True, CACHES=LOCMEM_TEST_CACHE)
class RegistrarIntentPostgresConcurrencyTests(IntentFixture, TransactionTestCase):
    def test_concurrent_distinct_intent_never_dispatches_while_first_is_in_flight(self) -> None:
        entered, release = Event(), Event()

        def registrar(*args, **kwargs):
            entered.set()
            if not release.wait(timeout=10):
                raise RuntimeError("test synchronization timed out")
            return True, {"pending": True}

        def first_request():
            close_old_connections()
            try:
                return DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="concurrent-first")
            finally:
                connection.close()

        with (
            patch("apps.domains.services.DomainRegistrarGateway.renew_domain", side_effect=registrar) as renew,
            ThreadPoolExecutor(max_workers=1) as pool,
        ):
            future = pool.submit(first_request)
            try:
                self.assertTrue(entered.wait(timeout=10))
                self.assertEqual(DomainOperation.objects.get(domain=self.domain).state, "submitted")
                result = DomainLifecycleService.process_domain_renewal(
                    self.domain, idempotency_token="concurrent-second"
                )
                self.assertTrue(result.is_err())
            finally:
                release.set()
            self.assertTrue(future.result(timeout=10).is_ok())
        self.assertEqual(renew.call_count, 1)

    def test_simultaneous_distinct_claims_are_serialized_by_the_domain_lock(self) -> None:
        first_creating, second_creating, release = Event(), Event(), Event()
        original_create = DomainOperation.objects.create
        calls = 0

        def create_operation(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                first_creating.set()
                if not release.wait(timeout=10):
                    raise RuntimeError("test synchronization timed out")
            else:
                second_creating.set()
            return original_create(**kwargs)

        def request(token):
            close_old_connections()
            try:
                return DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token=token)
            finally:
                connection.close()

        with (
            patch.object(DomainOperation.objects, "create", side_effect=create_operation),
            patch(
                "apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"pending": True})
            ) as renew,
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            first = pool.submit(request, "first")
            try:
                self.assertTrue(first_creating.wait(timeout=10))
                second = pool.submit(request, "second")
                self.assertFalse(second_creating.wait(timeout=0.5), "Second intent crossed the domain row lock")
            finally:
                release.set()
            results = [first.result(timeout=10), second.result(timeout=10)]
        self.assertEqual(sum(result.is_ok() for result in results), 1)
        self.assertEqual(DomainOperation.objects.count(), 1)
        self.assertEqual(renew.call_count, 1)

    def test_concurrent_resumption_of_same_pending_intent_dispatches_once(self) -> None:
        DomainOperation.objects.create(
            domain=self.domain,
            registrar=self.registrar,
            operation_type="renew",
            intent_key=intent_digest("token:resume"),
            parameters={"years": 1},
        )
        preflight_barrier = Barrier(2)

        def read_info(*args):
            preflight_barrier.wait(timeout=10)
            return Ok(self.info)

        def request():
            close_old_connections()
            try:
                return DomainLifecycleService.process_domain_renewal(self.domain, idempotency_token="resume")
            finally:
                connection.close()

        self.preflight.side_effect = read_info
        with (
            patch(
                "apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"pending": True})
            ) as renew,
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            results = list(pool.map(lambda _: request(), range(2)))
        self.assertTrue(any(result.is_ok() for result in results))
        self.assertEqual(renew.call_count, 1)
        self.assertEqual(DomainOperation.objects.count(), 1)
        self.assertEqual(DomainOperation.objects.get().state, "submitted")
