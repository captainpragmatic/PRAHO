"""SSH schema changes must retain migration-owned encryption identity guards."""
import uuid

from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class SSHMigrationGuardTests(TransactionTestCase):
    def _assert_guard(self, executor: MigrationExecutor, migration: str) -> None:
        with connection.cursor() as cursor:
            if connection.vendor == "sqlite":
                cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name=%s AND tbl_name=%s", ["secret_ctx_provisioning_virtualminserver", "provisioning_virtualmin_servers"])
            elif connection.vendor == "postgresql":
                cursor.execute("SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE t.tgname=%s AND c.relname=%s AND NOT t.tgisinternal", ["secret_ctx_provisioning_virtualminserver", "provisioning_virtualmin_servers"])
            else:
                self.fail(f"Unsupported backend: {connection.vendor}")
            self.assertEqual(cursor.fetchone()[0], 1, "Virtualmin server encryption identity guard must survive schema changes")
        model = executor.loader.project_state([("provisioning", migration)]).apps.get_model("provisioning", "VirtualminServer")
        server = model.objects.create(name="SSH guard fixture", hostname="ssh-guard.example.test", api_username="root", encrypted_api_password=b"")
        try:
            with self.assertRaisesMessage(DatabaseError, "immutable"), transaction.atomic():
                model.objects.filter(pk=server.pk).update(id=uuid.uuid4())
            self.assertTrue(model.objects.filter(pk=server.pk).exists())
        finally:
            server.delete()

    def test_forward_and_reverse_keep_virtualmin_server_identity_guard(self) -> None:
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        try:
            executor.migrate([("provisioning", "0012_bind_server_hostname")])
            self._assert_guard(executor, "0012_bind_server_hostname")
            executor = MigrationExecutor(connection)
            executor.migrate([("provisioning", "0015_ssh_transport_state")])
            self._assert_guard(executor, "0015_ssh_transport_state")
            executor = MigrationExecutor(connection)
            executor.migrate([("provisioning", "0012_bind_server_hostname")])
            self._assert_guard(executor, "0012_bind_server_hostname")
        finally:
            MigrationExecutor(connection).migrate(latest)
