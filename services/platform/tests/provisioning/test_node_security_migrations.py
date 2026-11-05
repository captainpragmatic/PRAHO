"""SQLite table rebuilds must preserve the existing secret-context guard in both directions."""

from uuid import uuid4

from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.loader import MigrationLoader
from django.test import SimpleTestCase, TransactionTestCase


class MergedSecurityMigrationGraphTests(SimpleTestCase):
    def test_crowdsec_and_hosting_limits_have_one_final_migration(self):
        loader = MigrationLoader(None)
        leaves = loader.graph.leaf_nodes("provisioning")
        self.assertEqual(len(leaves), 1, leaves)
        self.assertEqual(loader.detect_conflicts(), {})
        merged = leaves[0]
        ancestors = loader.graph.forwards_plan(merged)
        for required in (
            ("provisioning", "0029_crowdsec_qualification_profile"),
            ("provisioning", "0029_virtualminaccount_effective_disk_quota_mb_and_more"),
            ("provisioning", "0037_merge_crowdsec_hosting_limits"),
            ("provisioning", "0037_alter_virtualminprovisioningjob_operation"),
        ):
            with self.subTest(required=required):
                self.assertIn(required, ancestors)
        state = loader.project_state([merged])
        server = state.apps.get_model("provisioning", "VirtualminServer")
        self.assertEqual(server._meta.get_field("security_policy_version").default, "virtualmin-web-only-v2")
        self.assertEqual(server._meta.get_field("security_configuration_digest").default, "")
        account = state.apps.get_model("provisioning", "VirtualminAccount")
        for field in ("effective_disk_quota_mb", "quota_generation", "quota_managed"):
            with self.subTest(field=field):
                self.assertIsNotNone(account._meta.get_field(field))
        job = state.apps.get_model("provisioning", "VirtualminProvisioningJob")
        self.assertIn("observe_hosting_limits", dict(job._meta.get_field("operation").choices))

    def test_observation_and_crowdsec_join_preserves_both_histories_without_schema_operations(self):
        loader = MigrationLoader(None)
        joined = ("provisioning", "0038_merge_crowdsec_hosting_observation")
        self.assertIn(joined, loader.disk_migrations)
        migration = loader.disk_migrations[joined]
        self.assertEqual(
            set(migration.dependencies),
            {
                ("provisioning", "0037_merge_crowdsec_hosting_limits"),
                ("provisioning", "0037_alter_virtualminprovisioningjob_operation"),
            },
        )
        self.assertEqual(migration.operations, [])


# Django parallelizes classes; the shared assertions must not carry test methods.
class _SecurityMigrationAssertions(TransactionTestCase):
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

    def assert_security_roundtrip_is_guarded(self, target):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        try:
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


class SecurityMigrationIdentityGuardTests(_SecurityMigrationAssertions):
    def test_security_migrations_keep_identity_immutable_forward_and_backward(self):
        self.assert_security_roundtrip_is_guarded(("provisioning", "0019_usage_observations"))


class SecurityMigrationCrowdSecProfileTests(_SecurityMigrationAssertions):
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
            executor = MigrationExecutor(connection)
            executor.migrate(latest)
            provision = next(node for node in latest if node[0] == "provisioning")
            self.assert_identity_is_guarded(executor, provision)


class SecurityMigrationExistingNodeTests(TransactionTestCase):
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


class SecurityMigrationHostingFirstTests(_SecurityMigrationAssertions):
    def test_hosting_first_upgrade_preserves_server_identity(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        before = ("provisioning", "0028_component_migration_authority")
        hosting = ("provisioning", "0036_alter_nodehostingexecution_action")
        merged = ("provisioning", "0037_merge_crowdsec_hosting_limits")
        try:
            for target in (before, hosting, merged):
                with self.subTest(target=target):
                    executor = MigrationExecutor(connection)
                    executor.migrate([target])
                    self.assert_identity_is_guarded(executor, target)
        finally:
            MigrationExecutor(connection).migrate(latest)


class SecurityMigrationReviewIdentityGuardTests(_SecurityMigrationAssertions):
    def test_security_review_migration_keeps_identity_immutable_forward_and_backward(self):
        self.assert_security_roundtrip_is_guarded(("provisioning", "0020_node_security_review"))
