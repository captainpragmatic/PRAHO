"""SQLite table rebuilds must preserve the existing secret-context guard in both directions."""

from uuid import uuid4

from django.db import DatabaseError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.loader import MigrationLoader
from django.test import SimpleTestCase, TransactionTestCase


class MergedSecurityMigrationGraphTests(SimpleTestCase):
    def _final_project_state(self):
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
            ("provisioning", "0038_merge_crowdsec_hosting_observation"),
            ("provisioning", "0038_hostingwarningdelivery_hostingwarningdeliverypart_and_more"),
            ("provisioning", "0039_servicehostingraise_and_more"),
        ):
            with self.subTest(required=required):
                self.assertIn(required, ancestors)
        return loader.project_state([merged])

    def test_crowdsec_and_hosting_limits_have_one_final_migration(self):
        state = self._final_project_state()
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

    def test_warning_and_crowdsec_join_preserves_both_histories_without_schema_operations(self):
        loader = MigrationLoader(None)
        joined = ("provisioning", "0040_merge_crowdsec_hosting_warnings")
        self.assertIn(joined, loader.disk_migrations)
        migration = loader.disk_migrations[joined]
        self.assertCountEqual(
            migration.dependencies,
            [
                ("provisioning", "0038_merge_crowdsec_hosting_observation"),
                ("provisioning", "0039_servicehostingraise_and_more"),
            ],
        )
        self.assertEqual(migration.operations, [])

    def test_final_project_state_retains_warning_delivery_and_active_intent_deduplication(self):
        state = self._final_project_state()
        warning = state.apps.get_model("provisioning", "HostingWarningState")
        intent = state.apps.get_model("provisioning", "HostingWarningIntent")
        delivery = state.apps.get_model("provisioning", "HostingWarningDelivery")
        part = state.apps.get_model("provisioning", "HostingWarningDeliveryPart")
        self.assertEqual(set(dict(warning._meta.get_field("resource").choices)), {"disk", "bandwidth"})
        self.assertEqual(
            warning._meta.get_field("account").remote_field.model,
            state.apps.get_model("provisioning", "VirtualminAccount"),
        )
        self.assertEqual(intent._meta.get_field("state").remote_field.model, warning)
        self.assertEqual(part._meta.get_field("delivery").remote_field.model, delivery)
        self.assertEqual(part._meta.get_field("intent").remote_field.model, intent)
        email_log = delivery._meta.get_field("email_log")
        self.assertTrue(email_log.one_to_one)
        self.assertTrue(email_log.null)
        self.assertEqual(email_log.remote_field.model, state.apps.get_model("notifications", "EmailLog"))
        constraints = {constraint.name: constraint for constraint in part._meta.constraints}
        active_delivery = constraints["hosting_warning_active_delivery"]
        self.assertEqual(active_delivery.fields, ("intent",))
        self.assertEqual(active_delivery.condition.children, [("active", True)])

    def test_final_project_state_retains_persistent_raise_and_composed_application_identity(self):
        state = self._final_project_state()
        raise_model = state.apps.get_model("provisioning", "ServiceHostingRaise")
        self.assertEqual(raise_model._meta.pk.name, "service")
        self.assertTrue(raise_model._meta.pk.one_to_one)
        self.assertEqual(raise_model._meta.get_field("revision").default, 1)
        self.assertEqual(set(dict(raise_model._meta.get_field("status").choices)), {"active", "expired", "revoked"})
        application = state.apps.get_model("provisioning", "HostingLimitApplication")
        self.assertEqual(application._meta.get_field("overlay_revision").default, 0)
        self.assertEqual(application._meta.get_field("overlay_extra_mib").default, 0)
        self.assertTrue(application._meta.get_field("overlay_expires_at").null)
        limits = state.apps.get_model("provisioning", "ServiceHostingLimits")
        self.assertEqual(limits._meta.get_field("applied_overlay_revision").default, 0)
        constraints = {constraint.name: constraint for constraint in application._meta.constraints}
        self.assertNotIn("hosting_application_revision_unique", constraints)
        self.assertEqual(
            constraints["hosting_application_base_overlay_unique"].fields,
            ("service", "revision", "overlay_revision"),
        )


class SecurityMigrationIdentityGuardTests(TransactionTestCase):
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
            executor = MigrationExecutor(connection)
            executor.migrate(latest)
            provision = next(node for node in latest if node[0] == "provisioning")
            self.assert_identity_is_guarded(executor, provision)
