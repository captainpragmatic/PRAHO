"""Opt-in CrowdSec qualification cannot restore an earlier base attestation."""

from __future__ import annotations

import hashlib
import json
from importlib import import_module
from unittest.mock import patch

from django.apps import apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, connection, models, transaction
from django.db.migrations.state import ModelState, ProjectState
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.db_triggers import create_context_immutability_trigger, drop_context_immutability_trigger
from apps.provisioning import virtualmin_security as security
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_security_models import NodeSecurityReview
from apps.provisioning.virtualmin_security_views import _admission_context
from apps.users.models import User
from tests.provisioning.test_node_security_policy import node_policy_evidence

EXTENSION = "virtualmin-web-only-v2+crowdsec-v1"


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class CrowdSecProfileAdmissionTests(TestCase):
    def setUp(self) -> None:
        self.server = VirtualminServer.objects.create(
            hostname="crowdsec.example.test", api_username="praho-api", last_health_check=timezone.now()
        )
        self.admin = User.objects.create_superuser(email="security-admin@example.test", password=None)

    def attest_base(self) -> NodeSecurityReview:
        evidence = node_policy_evidence()
        evidence["identity"] = security.connection_identity(self.server)
        proof = NodeSecurityReview.objects.create(
            server=self.server,
            server_uuid=self.server.pk,
            policy_version=security.POLICY_VERSION,
            identity=evidence["identity"],
            digest=security._evidence_digest(evidence),
            evidence=evidence,
        )
        self.server.security_state = "verified_web"
        self.server.current_security_review = proof
        self.server.verified_security_review = proof
        self.server.save(update_fields=["security_state", "current_security_review", "verified_security_review"])
        return proof

    def test_base_profile_preserves_existing_identity_and_evidence_serialization(self) -> None:
        self.assertEqual(self.server.security_policy_version, security.POLICY_VERSION)
        with patch.object(security, "_digest", wraps=security._digest) as digest:
            security.connection_identity(self.server)
        self.assertNotIn("security_policy_version", digest.call_args.args[0])
        evidence = node_policy_evidence()
        encoded = json.dumps(
            {"policy": security.POLICY_VERSION, "evidence": evidence},
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        self.assertEqual(security._evidence_digest(evidence), hashlib.sha256(encoded).hexdigest())
        self.attest_base()
        self.assertIsNone(destination_refusal(self.server))

    def test_explicit_adoption_persists_and_withdraws_earlier_attestation(self) -> None:
        proof = self.attest_base()
        identity = security.connection_identity(self.server)
        security.select_security_profile(self.server, EXTENSION, self.admin, configuration_digest="c" * 64)
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_policy_version, EXTENSION)
        self.assertEqual(self.server.security_state, "unreviewed")
        self.assertIsNone(self.server.verified_security_review_id)
        self.assertNotEqual(security.connection_identity(self.server), identity)
        self.assertTrue(NodeSecurityReview.objects.filter(pk=proof.pk).exists())
        # A stale worker restoring the old pointers still cannot restore admission.
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            security_state="verified_web",
            verified_security_review=proof,
            current_security_review=proof,
        )
        self.assertIsNotNone(destination_refusal(self.server))
        event = AuditEvent.objects.get(object_id=str(self.server.pk), action="configuration_changed")
        self.assertEqual(event.user_id, self.admin.pk)
        self.assertEqual(event.new_values["security_policy_version"], EXTENSION)

    def test_extension_never_uses_legacy_admission_or_automatic_downgrade(self) -> None:
        self.server.legacy_security_admission = True
        self.server.save(update_fields=["legacy_security_admission"])
        security.select_security_profile(self.server, EXTENSION, self.admin, configuration_digest="c" * 64)
        self.server.refresh_from_db()
        self.assertFalse(self.server.legacy_security_admission)
        event = AuditEvent.objects.get(object_id=str(self.server.pk), action="configuration_changed")
        self.assertIs(event.old_values["legacy_security_admission"], True)
        self.assertIs(event.new_values["legacy_security_admission"], False)
        self.assertIsNotNone(destination_refusal(self.server))
        with self.assertRaises(ValidationError):
            security.select_security_profile(self.server, security.POLICY_VERSION, self.admin)
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_policy_version, EXTENSION)

    def test_only_active_admin_can_adopt_and_unresolved_operation_is_untouched(self) -> None:
        for role in ("support", "manager", "billing"):
            actor = User.objects.create_user(email=f"security-{role}@example.test", password=None, staff_role=role)
            with self.subTest(role=role), self.assertRaises(PermissionDenied):
                security.select_security_profile(self.server, EXTENSION, actor, configuration_digest="c" * 64)
        self.admin.is_active = False
        self.admin.save(update_fields=["is_active"])
        with self.assertRaises(PermissionDenied):
            security.select_security_profile(self.server, EXTENSION, self.admin, configuration_digest="c" * 64)
        self.admin.is_active = True
        self.admin.save(update_fields=["is_active"])
        self.server.security_operation = self.server.pk
        self.server.save(update_fields=["security_operation"])
        with self.assertRaises(ValidationError):
            security.select_security_profile(self.server, EXTENSION, self.admin, configuration_digest="c" * 64)
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_operation, self.server.pk)
        self.assertEqual(self.server.security_policy_version, security.POLICY_VERSION)

    def test_reselection_is_idempotent_and_a_new_configuration_withdraws_authority(self) -> None:
        proof = self.attest_base()
        security.select_security_profile(self.server, EXTENSION, self.admin, configuration_digest="c" * 64)
        first_identity = security.connection_identity(VirtualminServer.objects.get(pk=self.server.pk))
        security.select_security_profile(self.server, EXTENSION, self.admin, configuration_digest="c" * 64)
        self.assertEqual(
            AuditEvent.objects.filter(object_id=str(self.server.pk), action="configuration_changed").count(), 1
        )
        VirtualminServer.objects.filter(pk=self.server.pk).update(
            current_security_review=proof, verified_security_review=proof, security_state="verified_web"
        )
        security.select_security_profile(self.server, EXTENSION, self.admin, configuration_digest="d" * 64)
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_configuration_digest, "d" * 64)
        self.assertIsNone(self.server.current_security_review_id)
        self.assertIsNone(self.server.verified_security_review_id)
        self.assertNotEqual(security.connection_identity(self.server), first_identity)
        self.assertIsNotNone(destination_refusal(self.server))

    def test_profile_adoption_rejects_missing_noncanonical_or_incomplete_digests(self) -> None:
        for digest in ("", "a" * 63, "A" * 64, "g" * 64):
            with self.subTest(digest=digest), self.assertRaises(ValidationError):
                security.select_security_profile(self.server, EXTENSION, self.admin, configuration_digest=digest)
        self.server.refresh_from_db()
        self.assertEqual(self.server.security_policy_version, security.POLICY_VERSION)
        self.assertEqual(self.server.security_configuration_digest, "")

    def test_unrecognized_profile_remains_visible_as_stale_without_authorizing_work(self) -> None:
        self.attest_base()
        VirtualminServer.objects.filter(pk=self.server.pk).update(security_policy_version="unrecognized")
        self.server.refresh_from_db()
        self.assertIsNotNone(destination_refusal(self.server))
        context = _admission_context(self.server)
        self.assertIs(context["verification_stale"], True)
        self.assertTrue(context["network_preparation"])


class CrowdSecProfileMigrationTests(TransactionTestCase):
    def assert_probe_identity_is_guarded(self, pk: int) -> None:
        with (
            self.assertRaisesMessage(DatabaseError, "crowdsec_migration_probe.id is immutable"),
            transaction.atomic(),
            connection.cursor() as cursor,
        ):
            cursor.execute("UPDATE crowdsec_migration_probe SET id = %s WHERE id = %s", [pk + 1, pk])

    def test_additive_migration_defaults_existing_rows_to_base_and_reverses_without_data_loss(self) -> None:
        before = ProjectState()
        before.add_model(
            ModelState(
                "provisioning",
                "VirtualminServer",
                [
                    ("id", models.AutoField(primary_key=True)),
                    ("hostname", models.CharField(max_length=255)),
                ],
                options={"db_table": "crowdsec_migration_probe"},
            )
        )
        legacy = before.apps.get_model("provisioning", "VirtualminServer")
        migration_type = import_module("apps.provisioning.migrations.0029_crowdsec_qualification_profile").Migration
        migration = migration_type("0029_crowdsec_qualification_profile", "provisioning")
        restore_guard = import_module(
            "apps.provisioning.migrations.0015_ssh_transport_state"
        ).restore_server_identity_guard
        with connection.schema_editor() as editor:
            editor.create_model(legacy)
            create_context_immutability_trigger(
                editor, table="crowdsec_migration_probe", column="id", name="crowdsec_migration_probe_identity"
            )
        try:
            original = legacy.objects.create(hostname="preserved.example.test")
            self.assert_probe_identity_is_guarded(original.pk)
            with connection.schema_editor() as editor:
                after = migration.apply(before.clone(), editor)
            upgraded = after.apps.get_model("provisioning", "VirtualminServer")
            row = upgraded.objects.get()
            self.assertEqual(row.hostname, "preserved.example.test")
            self.assertEqual(row.security_policy_version, security.POLICY_VERSION)
            self.assertEqual(row.security_configuration_digest, "")
            self.assert_probe_identity_is_guarded(row.pk)
            with connection.schema_editor() as editor:
                migration.unapply(before.clone(), editor)
            self.assertEqual(legacy.objects.get().hostname, "preserved.example.test")
            self.assert_probe_identity_is_guarded(original.pk)
            with connection.cursor() as cursor:
                columns = connection.introspection.get_table_description(cursor, "crowdsec_migration_probe")
            self.assertEqual({column.name for column in columns}, {"id", "hostname"})
        finally:
            with connection.schema_editor() as editor:
                drop_context_immutability_trigger(
                    editor, table="crowdsec_migration_probe", name="crowdsec_migration_probe_identity"
                )
                editor.delete_model(legacy)
                # The frozen callback uses the production trigger's fixed name.
                # Restore its real-table binding after this isolated schema probe.
                restore_guard(apps, editor)
