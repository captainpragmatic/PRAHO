"""Component contracts cannot fall through to whole-domain migration actions."""

from datetime import timedelta
from uuid import uuid4

from django.db import transaction

from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class ComponentDispatchTests(MigrationTestBase):
    def test_component_or_unknown_contract_never_runs_whole_domain_phases(self):
        for contract in (VirtualminMigration.Contract.IMPORTED_WEB, "unrecognised"):
            for phase in ("pending", "quiescing", "backing_up", "restoring", "activating", "compensating"):
                with self.subTest(contract=contract, phase=phase), transaction.atomic():
                    migration = self._start()
                    # fsm-bypass: establish an independently interrupted worker fixture.
                    VirtualminMigration.objects.filter(pk=migration.pk).update(contract=contract, status=phase)
                    migration.refresh_from_db()
                    self.events.clear()
                    token = uuid4()
                    self.assertTrue(migration.acquire_lease(token, timedelta(minutes=5)))
                    VirtualminMigrationService().execute(migration, token)
                    migration.refresh_from_db()
                    self.assertEqual(migration.status, "needs_review")
                    self.assertIn("whole-domain", migration.error_detail)
                    self.assertEqual(self.events, [])
                    self.ansible.return_value.run_playbook.assert_not_called()
                    self.account.refresh_from_db()
                    self.assertEqual(self.account.server_id, self.server.pk)
                    self.assertIsNone(migration.source_disabled_at)
                    self.assertFalse(migration.restore_issued)
                    # Retain the history while ending this isolated case's reservation.
                    migration.transition(token, "needs_review", "failed")
