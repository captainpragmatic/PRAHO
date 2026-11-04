"""SQLite table rebuilds must preserve the existing secret-context guard in both directions."""

from uuid import uuid4

from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class SecurityMigrationIdentityGuardTests(TransactionTestCase):
    def test_existing_nodes_only_receive_the_explicit_rollout_exception(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        before = ("provisioning", "0023_alter_nodesecuritydecision_action")
        after = ("provisioning", "0024_virtualminserver_legacy_security_admission")
        try:
            executor.migrate([before])
            old_model = executor.loader.project_state([before]).apps.get_model("provisioning", "VirtualminServer")
            old = old_model.objects.create(name="existing", hostname="existing.example.test", status="active")
            executor = MigrationExecutor(connection)
            executor.migrate([after])
            model = executor.loader.project_state([after]).apps.get_model("provisioning", "VirtualminServer")
            existing = model.objects.get(pk=old.pk)
            self.assertTrue(existing.legacy_security_admission)
            self.assertEqual(existing.security_state, "unreviewed")
            self.assertEqual(existing.status, "active")
            fresh = model.objects.create(name="fresh", hostname="fresh.example.test")
            self.assertFalse(fresh.legacy_security_admission)
        finally:
            MigrationExecutor(connection).migrate(latest)

    def assert_identity_is_guarded(self, executor, target):
        model = executor.loader.project_state([target]).apps.get_model("provisioning", "VirtualminServer")
        hostname = f"guard-{uuid4().hex}.example.test"
        row = model.objects.create(
            name="guard-test", hostname=hostname, api_username="root", encrypted_api_password=b""
        )
        try:
            with (
                self.assertRaisesMessage(DatabaseError, "provisioning_virtualmin_servers.id is immutable"),
                transaction.atomic(),
                connection.cursor() as cursor,
            ):
                cursor.execute(
                    "UPDATE provisioning_virtualmin_servers SET id = %s WHERE id = %s", [uuid4().hex, row.pk.hex]
                )
            self.assertTrue(model.objects.filter(pk=row.pk).exists())
        finally:
            # A missing guard can let the UPDATE commit before the assertion fails.
            # Remove that changed row too, so it cannot hide the next boundary failure.
            model.objects.filter(hostname=hostname).delete()

    def test_security_migrations_keep_identity_immutable_forward_and_backward(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        try:
            for target in (("provisioning", "0019_usage_observations"), ("provisioning", "0020_node_security_review")):
                with self.subTest(target=target):
                    executor = MigrationExecutor(connection)
                    executor.migrate([target])
                    self.assert_identity_is_guarded(executor, target)
                    executor = MigrationExecutor(connection)
                    executor.migrate(latest)
                    provision = next(node for node in latest if node[0] == "provisioning")
                    self.assert_identity_is_guarded(executor, provision)
        finally:
            MigrationExecutor(connection).migrate(latest)

    def test_crowdsec_profile_preserves_identity_guard_forward_and_backward(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        before = ("provisioning", "0028_component_migration_authority")
        after = ("provisioning", "0029_crowdsec_qualification_profile")
        try:
            for target in (before, after, before, after):
                executor = MigrationExecutor(connection)
                executor.migrate([target])
                self.assert_identity_is_guarded(executor, target)
        finally:
            MigrationExecutor(connection).migrate(latest)
