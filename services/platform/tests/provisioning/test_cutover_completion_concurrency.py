"""Completion fences an IP edit without deadlocking an existing DNS publisher's FK checks."""

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.infrastructure.dns_agreement import Agreement
from apps.provisioning import managed_dns_service as managed
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning import test_hosted_zone_ownership as ownership_fixtures

WAIT_SECONDS = 15


@override_settings(
    DISABLE_AUDIT_SIGNALS=True,
    AUDIT_CHAIN_ENABLED=False,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class CutoverCompletionServerLockTests(TransactionTestCase):
    _thread = ownership_fixtures.HostedZoneOwnershipPostgresTests._thread
    _waits_on_lock = ownership_fixtures.HostedZoneOwnershipPostgresTests._waits_on_lock
    _publish = ownership_fixtures.HostedZoneOwnershipPostgresTests._publish

    def setUp(self):
        ownership_fixtures.HostedZoneOwnershipPostgresTests.setUp(self)
        source = VirtualminServer.objects.create(
            name="Lost source", hostname="lost-source.example.net", ipv4_address="95.217.0.11"
        )
        self.token = uuid4()
        self.migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=source,
            target_server=self.account.server,
            status="repointing",
            contract="recovery",
            cutover_committed_at=timezone.now(),
            lease_token=self.token,
            worker_lease_expires_at=timezone.now() + timedelta(minutes=20),
        )
        with patch("apps.infrastructure.dns_agreement.routing_agreement", return_value=Agreement(True, 300)):
            self.proof = managed.observe_routing(self.hostname).unwrap()

    def test_completion_waiting_for_a_real_publisher_allows_its_deferred_target_fk_to_commit(self):
        engine = VirtualminMigrationService()
        inside, release = threading.Event(), threading.Event()
        original = managed._apply_row

        def pause_after_write(*args, **kwargs):
            result = original(*args, **kwargs)
            self.assertTrue(result.is_ok(), result)
            inside.set()
            if not release.wait(WAIT_SECONDS):
                raise RuntimeError("Managed publication proof was not released")
            return result

        def complete():
            migration = VirtualminMigration.objects.get(pk=self.migration.pk)
            engine._complete_cutover(migration, self.token, self.hostname, self.proof)

        with (
            patch.object(managed, "_apply_row", side_effect=pause_after_write),
            patch.object(engine, "_audit"),
            patch("apps.provisioning.virtualmin_migration_service._reconcile_after_migration"),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            pids, ready, done = [], threading.Event(), threading.Event()
            publisher = executor.submit(self._thread, self._publish, [], threading.Event(), threading.Event())
            try:
                self.assertTrue(inside.wait(WAIT_SECONDS), "The real managed record write was not reached")
                completion = executor.submit(self._thread, complete, pids, ready, done)
                self.assertTrue(ready.wait(WAIT_SECONDS))
                self.assertTrue(self._waits_on_lock(pids[0], done), "Completion did not wait for the publisher's Name")
            finally:
                release.set()
            self.assertTrue(publisher.result(timeout=WAIT_SECONDS).is_ok())
            completion.result(timeout=WAIT_SECONDS)
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.status, "completed")
        self.assertIsNotNone(self.migration.dns_converged_at)
