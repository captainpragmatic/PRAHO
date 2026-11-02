"""Actual migration reversal preserves operator templates and reconstructs feature state."""

from datetime import time, timedelta

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils import timezone

from apps.notifications.models import EmailTemplate


class NodeMaintenanceMigrationTests(TransactionTestCase):
    def test_reverse_and_forward_preserve_operator_template_edits(self) -> None:
        executor = MigrationExecutor(connection)
        previous = next(
            key for key in executor.loader.graph.nodes if key[0] == "infrastructure" and key[1].startswith("0006_")
        )
        current = ("infrastructure", "0010_maintenance_policy_default")
        # Reconstruct the actual seeded state even after another transaction test's flush.
        executor.migrate([previous])
        try:
            MigrationExecutor(connection).migrate([current])
            template = EmailTemplate.objects.get(key="maintenance_scheduled", locale="en")
            template.subject = "Operator-maintained maintenance subject"
            template.save(update_fields=["subject"])

            MigrationExecutor(connection).migrate([previous])
            surviving = EmailTemplate.objects.filter(key__startswith="maintenance_")
            self.assertEqual(
                list(surviving.values_list("key", "locale", "subject")),
                [("maintenance_scheduled", "en", "Operator-maintained maintenance subject")],
            )
            tables = connection.introspection.table_names()
            self.assertNotIn("infrastructure_nodemaintenancewindow", tables)

            MigrationExecutor(connection).migrate([current])
            self.assertEqual(EmailTemplate.objects.filter(key__startswith="maintenance_").count(), 6)
            self.assertEqual(
                EmailTemplate.objects.get(key="maintenance_scheduled", locale="en").subject,
                "Operator-maintained maintenance subject",
            )
            self.assertIn("infrastructure_nodemaintenancewindow", connection.introspection.table_names())
            state = MigrationExecutor(connection).loader.project_state()
            execution = state.apps.get_model("infrastructure", "NodeMaintenanceExecution")
            self.assertTrue(execution._meta.get_field("node_uuid").null)
            self.assertIn("maintenance_one_deployment_exec", {item.name for item in execution._meta.constraints})
        finally:
            MigrationExecutor(connection).migrate([current])

    def test_new_policy_default_preserves_saved_zero_and_existing_deadlines(self) -> None:
        previous = ("infrastructure", "0009_maintenance_deployment_ownership")
        current = ("infrastructure", "0010_maintenance_policy_default")
        executor = MigrationExecutor(connection)
        executor.migrate([previous])
        try:
            state = executor.loader.project_state([previous]).apps
            servers = state.get_model("provisioning", "VirtualminServer")
            policies = state.get_model("infrastructure", "NodeMaintenancePolicy")
            windows = state.get_model("infrastructure", "NodeMaintenanceWindow")
            node = servers.objects.create(
                name="Saved zero", hostname="saved-zero.example.test", encrypted_api_password=b""
            )
            policy = policies.objects.create(
                node=node, timezone="UTC", weekdays=list(range(7)), starts_time=time(0), ends_time=time(23, 59)
            )
            self.assertEqual(policy.max_defer_minutes, 0)
            starts = timezone.now() + timedelta(hours=2)
            window = windows.objects.create(
                node=node,
                node_uuid=node.pk,
                policy=policy,
                policy_timezone="UTC",
                starts_at=starts,
                start_by=starts,
                ends_at=starts + timedelta(minutes=30),
                kind="panel_update",
                execution_mode="manual",
            )
            MigrationExecutor(connection).migrate([current])
            state = MigrationExecutor(connection).loader.project_state([current]).apps
            policy_model = state.get_model("infrastructure", "NodeMaintenancePolicy")
            self.assertEqual(policy_model.objects.get(pk=policy.pk).max_defer_minutes, 0)
            self.assertEqual(
                state.get_model("infrastructure", "NodeMaintenanceWindow").objects.get(pk=window.pk).start_by, starts
            )
            self.assertEqual(policy_model._meta.get_field("max_defer_minutes").default, 15)
        finally:
            MigrationExecutor(connection).migrate([current])
