"""Nameserver ownership is per domain, not the registrar shared by its customers."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from threading import Event
from time import monotonic
from typing import Any
from unittest import skipUnless
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

from django.db import close_old_connections, connection, connections
from django.test import TransactionTestCase, override_settings

from apps.billing.models import Currency
from apps.common.types import Err, Ok, Retriability
from apps.customers.models import Customer
from apps.domains.gateways import NameserverUpdateResult, RegistrarAPIError, RegistrarErrorCode
from apps.domains.models import TLD, Domain, DomainOperation, Registrar
from apps.domains.services import DomainLifecycleService


@skipUnless(connection.vendor == "postgresql", "PostgreSQL row and deferred-FK locks are required")
@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class NameserverRegistrarLockConcurrencyTests(TransactionTestCase):
    def setUp(self) -> None:
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        registrar = Registrar.objects.create(name="gandi", display_name="Shared registrar", status="active")
        tld = TLD.objects.create(
            extension="test",
            description="Test",
            registration_price_cents=100,
            renewal_price_cents=100,
            transfer_price_cents=100,
        )
        self.domains: list[Domain] = []
        for index in range(2):
            customer = Customer.objects.create(
                name=f"Independent customer {index}",
                primary_email=f"customer-{index}@example.test",
                customer_type="individual",
            )
            self.domains.append(
                Domain.objects.create(
                    name=f"independent-{index}.test",
                    customer=customer,
                    registrar=registrar,
                    tld=tld,
                    status="active",
                    nameservers=["ns.old.example"],
                )
            )
        self.assertNotEqual(self.domains[0].customer_id, self.domains[1].customer_id)
        self.assertEqual(self.domains[0].registrar_id, self.domains[1].registrar_id)
        self.operation = self._prepare(self.domains[0])
        self.gateway = Mock()
        self.gateway.update_nameservers.return_value = Ok(NameserverUpdateResult(nameservers=["ns.new.example"]))
        gateway = patch("apps.domains.gateways.RegistrarGatewayFactory.create_gateway", return_value=self.gateway)
        gateway.start()
        self.addCleanup(gateway.stop)

    def _prepare(self, domain: Domain) -> DomainOperation:
        result = DomainLifecycleService.prepare_nameserver_update(domain, ["ns.new.example"], operation_id=uuid4())
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def _resume(self) -> UUID:
        result = DomainLifecycleService.resume_nameserver_update(DomainOperation.objects.get(pk=self.operation.pk))
        self.assertTrue(result.is_ok(), result)
        return result.unwrap().pk

    @staticmethod
    def _connected[T](operation: Callable[[], T], pids: list[int]) -> T:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SET lock_timeout = '15s'")
                cursor.execute("SET statement_timeout = '20s'")
                cursor.execute("SELECT pg_backend_pid()")
                pids.append(cursor.fetchone()[0])
            return operation()
        finally:
            connections.close_all()

    def _held_resume(self, entered: Event, release: Event) -> UUID:
        def observe(execute: Callable[..., Any], sql: str, params: Any, many: bool, context: Any) -> Any:
            result = execute(sql, params, many, context)
            if not entered.is_set() and 'FROM "domains"' in sql and "FOR UPDATE" in sql:
                self.assertIn(self.domains[0].pk, params)
                entered.set()
                self.assertTrue(release.wait(10), "Nameserver admission observer was not released")
            return result

        with connection.execute_wrapper(observe):
            return self._resume()

    def _completion_or_wait[T](self, future: Future[T], pids: list[int], owner: int) -> tuple[bool, str]:
        deadline, poll = monotonic() + 10, Event()
        last = None
        while monotonic() < deadline:
            if future.done():
                future.result()
                return True, ""
            if pids:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_stat_clear_snapshot()")
                    cursor.execute(
                        "SELECT wait_event_type, pg_blocking_pids(pid), query FROM pg_stat_activity WHERE pid = %s",
                        [pids[0]],
                    )
                    last = cursor.fetchone()
                if last and last[0] == "Lock" and owner in last[1]:
                    return False, f"pid={pids[0]}, wait_event_type={last[0]}, blockers={last[1]}, query={last[2]}"
            poll.wait(0.01)
        self.fail(f"No public completion or exact PostgreSQL lock wait: {last!r}")

    def test_public_prepare_and_resume_succeed_without_competition(self) -> None:
        self.assertEqual(self._resume(), self.operation.pk)
        other = self._prepare(self.domains[1])
        self.assertEqual(other.state, "pending")
        self.assertEqual(other.registrar_id, self.operation.registrar_id)
        self.gateway.update_nameservers.assert_called_once_with(self.domains[0].name, ["ns.new.example"])
        self.domains[1].refresh_from_db()
        self.assertEqual(self.domains[1].nameservers, ["ns.old.example"])

    def test_resume_does_not_block_an_unrelated_customers_intent_commit(self) -> None:
        entered, release = Event(), Event()
        owner_pids: list[int] = []
        preparing_pids: list[int] = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            resuming = executor.submit(self._connected, lambda: self._held_resume(entered, release), owner_pids)
            try:
                self.assertTrue(entered.wait(10), "Public resume did not lock its domain")
                preparing = executor.submit(self._connected, lambda: self._prepare(self.domains[1]), preparing_pids)
                completed, wait = self._completion_or_wait(preparing, preparing_pids, owner_pids[0])
                self.assertTrue(
                    completed,
                    f"Another Customer's nameserver intent waits on admission backend {owner_pids[0]}: {wait}",
                )
                other = DomainOperation.objects.get(pk=preparing.result(timeout=5).pk)
                self.assertEqual(other.domain_id, self.domains[1].pk)
                self.assertEqual(other.parameters["binding"]["customer_id"], str(self.domains[1].customer_id))
                self.assertEqual(other.state, "pending")
            finally:
                release.set()
                resuming.result(timeout=15)
        self.gateway.update_nameservers.assert_called_once_with(self.domains[0].name, ["ns.new.example"])

    def test_duplicate_resume_waits_for_its_domain_and_submits_once(self) -> None:
        entered, release = Event(), Event()
        owner_pids: list[int] = []
        duplicate_pids: list[int] = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            resuming = executor.submit(self._connected, lambda: self._held_resume(entered, release), owner_pids)
            try:
                self.assertTrue(entered.wait(10), "Public resume did not lock its domain")
                duplicate = executor.submit(self._connected, self._resume, duplicate_pids)
                completed, wait = self._completion_or_wait(duplicate, duplicate_pids, owner_pids[0])
                self.assertFalse(completed, "Duplicate resume did not wait for the exact domain owner")
                self.assertIn('query=SELECT "domains"."id"', wait)
            finally:
                release.set()
                self.assertEqual(resuming.result(timeout=15), self.operation.pk)
            self.assertEqual(duplicate.result(timeout=15), self.operation.pk)
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.state, "completed")
        self.gateway.update_nameservers.assert_called_once_with(self.domains[0].name, ["ns.new.example"])

    def test_unknown_submission_is_retained_without_replay(self) -> None:
        self.gateway.update_nameservers.return_value = Err(
            RegistrarAPIError("Unconfirmed response", code=RegistrarErrorCode.INTERNAL_ERROR),
            retriability=Retriability.UNKNOWN,
        )
        first = DomainLifecycleService.resume_nameserver_update(self.operation)
        self.assertTrue(first.is_err(), first)
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.state, "submitted")
        self.assertIsNone(self.operation.accepted_at)
        self.assertEqual(self._resume(), self.operation.pk)
        self.gateway.update_nameservers.assert_called_once_with(self.domains[0].name, ["ns.new.example"])
        self.domains[0].refresh_from_db()
        self.assertEqual(self.domains[0].nameservers, ["ns.old.example"])
