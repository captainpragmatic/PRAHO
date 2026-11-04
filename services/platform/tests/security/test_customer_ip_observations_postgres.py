"""Real PostgreSQL commit and erasure races for optional post-authentication history."""

from __future__ import annotations

from contextlib import ExitStack
from datetime import timedelta
from threading import Event
from unittest import skipUnless
from unittest.mock import patch

from django.core.cache import cache
from django.db import connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.db.models import QuerySet
from django.test import Client, TransactionTestCase, override_settings
from django.utils import timezone

from apps.audit.services import GDPRDeletionService
from apps.customers.models import Customer
from apps.security import customer_ips
from apps.security.models import CustomerIPObservation, SecuritySource
from apps.security.tasks import prune_security_history
from apps.users.models import CustomerMembership, PortalSession, User
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@skipUnless(connection.vendor == "postgresql", "Independent row-lock and deferred-COMMIT proof requires PostgreSQL")
@override_settings(
    CROWDSEC_CUSTOMER_IP_OBSERVATIONS_ENABLED=True,
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class CustomerIPObservationPostgreSQLTests(HMACTestMixin, TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.password = "Fixture-password-123!"
        self.user = User.objects.create_user(email="observation-race@example.test", password=self.password)
        self.original_email = self.user.email
        self.customer = Customer.objects.create(name="Observation customer", customer_type="company", status="active")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_active=True)

    def login(self):
        self.client = Client()
        return self.portal_post(
            "/api/users/login/",
            {"email": self.original_email, "password": self.password, "client_ip": "198.51.100.29"},
        )

    def test_deferred_foreign_key_commit_failure_does_not_undo_the_successful_session(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT condeferrable, condeferred FROM pg_constraint "
                "WHERE conrelid = 'security_customer_ip_observation'::regclass AND contype = 'f'"
            )
            self.assertEqual(cursor.fetchall(), [(True, True), (True, True)])
        write = customer_ips._write_observations
        reached_after_invalid_write = []

        def break_deferred_constraint(*args):
            write(*args)
            CustomerIPObservation.objects.update(customer_id=0)
            reached_after_invalid_write.append(True)

        with patch.object(customer_ips, "_write_observations", side_effect=break_deferred_constraint):
            response = self.login()
        self.assertEqual(reached_after_invalid_write, [True], "The INSERT/UPDATE succeeded; only COMMIT must fail")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json()["security_observation"], {"enabled": True, "recorded": False, "degraded": True}
        )
        self.assertTrue(PortalSession.objects.filter(pk=response.json()["session_id"], user=self.user).exists())
        self.assertFalse(CustomerIPObservation.objects.exists())

    def test_erasure_commits_before_waiting_login_and_observations_stay_erased(self) -> None:
        self.assertEqual(self.login().status_code, 200)
        self.assertTrue(CustomerIPObservation.objects.exists())
        with ExitStack() as workers:
            with transaction.atomic():
                blocker = backend_pid()
                User.objects.select_for_update().get(pk=self.user.pk)
                erased = GDPRDeletionService._anonymize_user_data(self.user)
                self.assertTrue(erased.is_ok(), erased)
                login_pid, login = workers.enter_context(database_worker(self.login))
                self.assertNotEqual(login_pid, blocker)
                wait_for_blocker(login_pid, blocker, login, table=User._meta.db_table)
            response = login.result(timeout=10)
        self.assertEqual(response.status_code, 401, response.content)
        self.assertFalse(CustomerIPObservation.objects.exists())
        self.assertFalse(User.objects.get(pk=self.user.pk).is_active)

    def test_observation_commits_before_waiting_erasure_and_is_then_deleted(self) -> None:
        entered, release = Event(), Event()
        write = customer_ips._write_observations

        def hold_observation(*args):
            write(*args)
            entered.set()
            if not release.wait(10):
                raise AssertionError("Observation owner was not released")

        def erase():
            return GDPRDeletionService._anonymize_user_data(User.objects.get(pk=self.user.pk))

        with patch.object(customer_ips, "_write_observations", side_effect=hold_observation), ExitStack() as workers:
            login_pid, login = workers.enter_context(database_worker(self.login))
            try:
                self.assertTrue(entered.wait(10), "Login did not reach the separately committed recorder")
                self.assertTrue(
                    PortalSession.objects.filter(user=self.user).exists(), "Authentication already committed"
                )
                erase_pid, erased = workers.enter_context(database_worker(erase))
                self.assertNotEqual(login_pid, erase_pid)
                wait_for_blocker(erase_pid, login_pid, erased, table=User._meta.db_table)
            finally:
                release.set()
            response = login.result(timeout=10)
            self.assertTrue(erased.result(timeout=10).is_ok())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json()["security_observation"], {"enabled": True, "recorded": True, "degraded": False}
        )
        self.assertFalse(CustomerIPObservation.objects.exists())
        self.assertFalse(User.objects.get(pk=self.user.pk).is_active)

    def test_optional_recorder_times_out_while_the_exact_user_lock_remains_held(self) -> None:
        with ExitStack() as workers, transaction.atomic():
            blocker = backend_pid()
            User.objects.select_for_update().get(pk=self.user.pk)
            recorder_pid, pending = workers.enter_context(
                database_worker(
                    lambda: customer_ips.record_recent_customer_ip(user_id=self.user.pk, ip="198.51.100.29")
                )
            )
            wait_for_blocker(recorder_pid, blocker, pending, table=User._meta.db_table)
            result = pending.result(timeout=5)
            self.assertFalse(result.healthy)
            self.assertEqual(result.reason, "unavailable")
            self.assertFalse(CustomerIPObservation.objects.exists())

    def test_observation_migration_reverses_without_losing_enrolled_sources(self) -> None:
        executor = MigrationExecutor(connection)
        initial_leaves = executor.loader.graph.leaf_nodes("security")
        initial_tables = {name for name in connection.introspection.table_names() if name.startswith("security_")}
        source = SecuritySource.objects.create(
            kind="portal",
            transport="local",
            hostname="portal.example.test",
            installation_id="11111111-2222-4333-8444-555555555555",
            configuration_digest="a" * 64,
        )
        try:
            MigrationExecutor(connection).migrate([("security", "0001_initial")])
            self.assertNotIn("security_customer_ip_observation", connection.introspection.table_names())
            self.assertTrue(SecuritySource.objects.filter(pk=source.pk).exists())
        finally:
            MigrationExecutor(connection).migrate(initial_leaves)
        self.assertTrue(initial_tables <= set(connection.introspection.table_names()))
        self.assertIn("security_customer_ip_observation", connection.introspection.table_names())
        with connection.cursor() as cursor:
            constraints = connection.introspection.get_constraints(cursor, "security_customer_ip_observation")
        self.assertTrue(constraints["security_customer_ip_identity"]["unique"])
        self.assertTrue(constraints["security_customer_ip_family"]["check"])
        self.assertTrue(constraints["security_customer_ip_recent"]["index"])
        self.assertTrue(SecuritySource.objects.filter(pk=source.pk).exists())

    def test_retention_rechecks_age_after_an_independent_login_commits_a_refresh(self) -> None:
        self.assertEqual(self.login().status_code, 200)
        CustomerIPObservation.objects.update(last_seen_at=timezone.now() - timedelta(days=8))
        original_delete = QuerySet.delete
        pruner_pid = backend_pid()
        writer_pids = []

        def refresh_after_selection(queryset):
            if queryset.model is CustomerIPObservation and queryset.exists():
                with database_worker(
                    lambda: customer_ips.record_recent_customer_ip(user_id=self.user.pk, ip="198.51.100.29")
                ) as (writer_pid, pending):
                    writer_pids.append(writer_pid)
                    self.assertNotEqual(writer_pid, pruner_pid)
                    self.assertTrue(pending.result(timeout=5).healthy)
            return original_delete(queryset)

        with patch.object(QuerySet, "delete", refresh_after_selection):
            pruned = prune_security_history()
        self.assertEqual(len(writer_pids), 1)
        self.assertEqual(CustomerIPObservation.objects.count(), 1)
        self.assertEqual(pruned["observations"], 0)
