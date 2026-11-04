"""An installation is enrolled explicitly and its historical identity never changes."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.security import services, transport
from apps.security.models import SecurityDecision, SecuritySource, SecuritySyncState
from apps.security.permissions import can_manage_security, can_revoke_security, can_view_security
from apps.users.models import User
from tests.provisioning.test_node_security_policy import OPERATOR_KEY


@override_settings(DISABLE_AUDIT_SIGNALS=True, PRAHO_CROWDSEC_SYNC_ENABLED=True)
class SourceEnrollmentTests(TestCase):
    def setUp(self) -> None:
        self.directory = TemporaryDirectory(prefix="praho-security-sources-")
        self.addCleanup(self.directory.cleanup)
        self.key = Path(self.directory.name) / "gateway-key"
        self.key.write_bytes(b"fixture private identity one")
        configured = override_settings(PRAHO_CROWDSEC_SSH_PRIVATE_KEY_PATH=str(self.key))
        configured.enable()
        self.addCleanup(configured.disable)
        self.admin = User.objects.create_superuser(email="security-enrollment@example.test", password=None)
        self.config = services.SourceConfiguration(
            kind="portal",
            transport="ssh",
            hostname="portal.example.test",
            port=9876,
            host_keys=OPERATOR_KEY,
            installation_id=uuid4(),
            configuration_digest="c" * 64,
            sync_enabled=True,
        )

    def test_enrollment_is_disabled_by_default_and_binds_physical_installation_and_key(self) -> None:
        source = services.enroll_source(replace(self.config, sync_enabled=False), self.admin)
        self.assertFalse(source.sync_enabled)
        self.assertEqual(source.installation_id, self.config.installation_id)
        self.assertEqual(source.generation, 1)
        self.assertEqual(len(source.key_identity), 64)
        self.assertEqual(SecuritySyncState.objects.get(source=source).alert_cursor, 0)
        event = AuditEvent.objects.get(action="configuration_changed", object_id=str(source.pk))
        self.assertEqual(event.metadata["security_operation"], "enroll")
        self.assertNotIn(self.key.read_text(), str(event.new_values))
        self.assertEqual(event.new_values["host_keys_sha256"], sha256(OPERATOR_KEY.encode()).hexdigest())

    def test_only_explicit_active_roles_have_security_authority(self) -> None:
        for role in ("admin", "support", "manager", "billing", ""):
            user = User.objects.create_user(email=f"security-{role or 'staff'}@example.test", staff_role=role)
            user.is_staff = True
            with self.subTest(role=role):
                self.assertEqual(can_view_security(user), role in {"admin", "support", "manager"})
                self.assertEqual(can_revoke_security(user), role in {"admin", "support", "manager"})
                self.assertEqual(can_manage_security(user), role == "admin")
                if role != "admin":
                    with self.assertRaises(PermissionDenied):
                        services.enroll_source(self.config, user)
        self.admin.is_active = False
        self.assertFalse(can_manage_security(self.admin))
        with self.assertRaises(PermissionDenied):
            services.enroll_source(self.config, self.admin)

    def test_reconfiguration_is_revisioned_but_never_retargets_an_installation(self) -> None:
        source = services.enroll_source(self.config, self.admin)
        changed = replace(self.config, hostname="enrolled-new.example.test", configuration_digest="d" * 64)
        updated = services.reconfigure_source(source.pk, changed, self.admin)
        self.assertEqual(updated.generation, 2)
        self.assertEqual(updated.hostname, changed.hostname)
        event = AuditEvent.objects.get(
            action="configuration_changed", object_id=str(source.pk), metadata__security_operation="reconfigure"
        )
        self.assertEqual(event.old_values["hostname"], self.config.hostname)
        self.assertEqual(event.new_values["hostname"], changed.hostname)
        with self.assertRaises(ValidationError):
            services.reconfigure_source(source.pk, replace(changed, installation_id=uuid4()), self.admin)
        source.refresh_from_db()
        self.assertEqual(source.installation_id, self.config.installation_id)
        services.retire_source(source.pk, self.admin)
        with self.assertRaises(ValidationError):
            services.reconfigure_source(source.pk, changed, self.admin)
        with self.assertRaises(ValidationError):
            services.enroll_source(self.config, self.admin)
        self.assertEqual(SecuritySource.objects.count(), 1)

    def test_key_file_changes_require_explicit_reconfiguration_and_local_is_staging_portal_only(self) -> None:
        source = services.enroll_source(self.config, self.admin)
        before = transport.capture_connection(source).identity
        self.key.write_bytes(b"fixture private identity two")
        with self.assertRaises(ValidationError):
            transport.capture_connection(source)
        source = services.reconfigure_source(source.pk, self.config, self.admin)
        self.assertNotEqual(transport.capture_connection(source).identity, before)
        local = replace(
            self.config, transport="local", hostname="localhost", port=0, host_keys="", installation_id=uuid4()
        )
        with self.assertRaises(ValidationError):
            services.enroll_source(local, self.admin)
        with (
            override_settings(PRAHO_CROWDSEC_LOCAL_SOURCE_ENABLED=True, ENVIRONMENT="production"),
            self.assertRaises(ValidationError),
        ):
            services.enroll_source(local, self.admin)
        with override_settings(PRAHO_CROWDSEC_LOCAL_SOURCE_ENABLED=True, ENVIRONMENT="staging"):
            enrolled = services.enroll_source(local, self.admin)
            with patch("apps.common.crowdsec_transport.local_rpc") as call:
                self.assertEqual(transport.capture_connection(enrolled).transport, "local")
                call.assert_not_called()

    def test_retirement_preserves_last_observed_ban_and_its_absolute_expiry(self) -> None:
        source = services.enroll_source(self.config, self.admin)
        now = timezone.now()
        expires = now + timedelta(hours=4)
        decision = SecurityDecision.objects.create(
            source=source,
            remote_id=1,
            source_created_at=now,
            expires_at=expires,
            scenario="crowdsecurity/ssh-bf",
            type="ban",
            scope="ip",
            value="198.51.100.8",
            origin="crowdsec",
            address_family=4,
            network_start=bytes.fromhex("000000000000000000000000c6336408"),
            network_end=bytes.fromhex("000000000000000000000000c6336408"),
        )
        source = services.retire_source(source.pk, self.admin)
        decision.refresh_from_db()
        self.assertIsNone(decision.ended_at)
        self.assertEqual(decision.expires_at, expires)
        self.assertFalse(source.sync_enabled)
        self.assertIsNotNone(source.retired_at)

    def test_sync_can_be_disabled_when_its_enrolled_key_is_unavailable(self) -> None:
        source = services.enroll_source(self.config, self.admin)
        identity = source.key_identity
        self.key.unlink()
        disabled = services.reconfigure_source(source.pk, replace(self.config, sync_enabled=False), self.admin)
        self.assertFalse(disabled.sync_enabled)
        self.assertEqual(disabled.key_identity, identity)
        self.assertEqual(disabled.generation, 2)
