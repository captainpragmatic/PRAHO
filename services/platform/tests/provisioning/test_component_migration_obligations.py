"""Retained source services belong to the native source identity after the website moves."""

from unittest.mock import patch

from django.apps import apps
from django.core.exceptions import PermissionDenied, ValidationError

from apps.common.types import Err, Ok
from apps.infrastructure.node_teardown import close_node_admission
from apps.infrastructure.registration_service import NodeRegistrationService
from apps.provisioning.virtualmin_drain_service import NodeDrainService
from apps.provisioning.virtualmin_migration_models import NodeDrain, VirtualminMigration
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class SourceServiceObligationTests(MigrationTestBase):
    def setUp(self):
        super().setUp()
        self.staff.is_staff = True
        self.staff.is_superuser = True
        self.staff.save(update_fields=["is_staff", "is_superuser"])

    def test_imported_contract_fits_without_truncating(self):
        self.assertIn("imported_web", VirtualminMigration.Contract.values)
        self.assertGreaterEqual(VirtualminMigration._meta.get_field("contract").max_length, 20)

    def obligation(self):
        model = apps.get_model("provisioning", "SourceServiceObligation", require_ready=False)
        return model.objects.create(
            migration=VirtualminMigration.objects.create(
                account=self.account,
                source_server=self.server,
                target_server=self.target,
                contract="imported_web",
                status="completed",  # fsm-bypass: an obligation retained after a completed website move.
            ),
            source_server=self.server,
            source_domain_id="123456789",
            domain=self.account.domain,
            owner=self.account.virtualmin_username,
            retained_services=["mail", "dns"],
            backup_responsible=self.staff,
            backup_responsibility="Operator manages backups of retained source mail and DNS independently.",
        )

    def test_repointed_account_does_not_erase_source_obligation_even_with_force(self):
        obligation = self.obligation()
        self.account.server = self.target
        self.account.save(update_fields=["server", "updated_at"])
        for force in (False, True):
            result = close_node_admission(self.server.pk, force=force)
            self.assertTrue(result.is_err(), result)
            self.assertIn("retained source", result.unwrap_err())
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")
        self.assertEqual(obligation.source_server_id, self.server.pk)

    def test_operator_drain_confirmation_cannot_release_retained_mail_or_dns(self):
        self.obligation()
        self.account.server = self.target
        self.account.save(update_fields=["server", "updated_at"])
        self.server.is_draining = True
        self.server.save(update_fields=["is_draining", "updated_at"])
        drain = NodeDrain.objects.create(server=self.server, status="completed")  # fsm-bypass: completed fixture
        result = NodeDrainService.finalize_drain(drain, confirmed_by=self.staff)
        self.assertTrue(result.is_err(), result)
        self.assertIn("retained source", result.unwrap_err())
        drain.refresh_from_db()
        self.assertFalse(drain.routing_confirmed)

    def test_history_cannot_be_rewritten_to_allow_destroy(self):
        obligation = self.obligation()
        with self.assertRaises(ValidationError):
            type(obligation).objects.filter(pk=obligation.pk).update(retained_services=[])
        obligation.retained_services = []
        with self.assertRaises(ValidationError):
            obligation.save()
        with self.assertRaises(ValidationError):
            obligation.delete()

    def test_unregister_does_not_withdraw_retained_source_credentials(self):
        self.obligation()
        deployment = self.server.node_deployment
        with patch("apps.common.credential_vault.get_credential_vault") as vault:
            result = NodeRegistrationService().unregister_node(deployment, user=self.staff)
        self.assertTrue(result.is_err(), result)
        self.assertIn("retained source", result.unwrap_err())
        vault.assert_not_called()
        deployment.refresh_from_db()
        self.assertEqual(deployment.virtualmin_server_id, self.server.pk)

    def test_release_requires_live_native_absence_and_explicit_backup_handoff(self):
        from apps.provisioning.component_migration_service import release_source_obligation  # noqa: PLC0415

        obligation = self.obligation()
        self.account.server = self.target
        self.account.save(update_fields=["server", "updated_at"])
        with patch("apps.provisioning.component_migration_service.list_migration_domains", return_value=Ok([])):
            with self.assertRaises(ValidationError):
                release_source_obligation(obligation, self.staff, "")
            release = release_source_obligation(
                obligation, self.staff, "Retained services removed; source backups handed off to operations."
            )
        self.assertEqual(release.obligation_id, obligation.pk)
        self.assertEqual(release.actor, self.staff)
        self.assertTrue(close_node_admission(self.server.pk).is_ok())
        self.assertTrue(type(obligation).objects.filter(pk=obligation.pk).exists())
        with self.assertRaises(ValidationError):
            release.delete()

    def test_same_name_recreated_or_native_identity_renamed_cannot_release_obligations(self):
        from apps.provisioning.component_migration_service import release_source_obligation  # noqa: PLC0415

        obligation = self.obligation()
        for domain, native_id in ((self.account.domain, "999"), ("renamed.example.test", obligation.source_domain_id)):
            rows = [{"domain": domain, "username": "unrelated", "attributes": {"ID": native_id}}]
            with (
                self.subTest(domain=domain),
                patch("apps.provisioning.component_migration_service.list_migration_domains", return_value=Ok(rows)),
                self.assertRaisesRegex(ValidationError, "retained source"),
            ):
                release_source_obligation(obligation, self.staff, "Claimed cleanup cannot replace native absence.")
        self.assertIn("retained source", close_node_admission(self.server.pk, force=True).unwrap_err())

    def test_inactive_operator_cannot_release_before_any_native_request(self):
        from apps.provisioning.component_migration_service import release_source_obligation  # noqa: PLC0415

        obligation = self.obligation()
        self.staff.is_active = False
        with (
            patch("apps.provisioning.component_migration_service.list_migration_domains") as listing,
            self.assertRaises(PermissionDenied),
        ):
            release_source_obligation(obligation, self.staff, "Source services and backups handed off.")
        listing.assert_not_called()
        self.assertIn("retained source", close_node_admission(self.server.pk, force=True).unwrap_err())

    def test_offline_source_cannot_be_treated_as_proven_absent(self):
        from apps.provisioning.component_migration_service import release_source_obligation  # noqa: PLC0415

        obligation = self.obligation()
        with (
            patch("apps.provisioning.component_migration_service.list_migration_domains", return_value=Err("offline")),
            self.assertRaisesRegex(ValidationError, "live native"),
        ):
            release_source_obligation(obligation, self.staff, "Source services and backups handed off.")
        self.assertIn("retained source", close_node_admission(self.server.pk, force=True).unwrap_err())
