"""A processed GDPR request leaves no trace of the person, in either erasure mode.

`process_deletion_request` ends with a sweep over every audit and compliance row the erasure
itself wrote, plus the deletion request and the person's earlier compliance records. Full
deletion tombstones what it deletes, so the audit chain records the removal as authorised.
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.actor_context import acting_as
from apps.audit.models import AuditChainHead, AuditChainLink, AuditEvent, ComplianceLog, audit_mutation_allowed
from apps.audit.services import AuditIntegrityService, AuditRetentionService, GDPRDeletionService, GDPRExportService
from apps.users.mfa import WebAuthnCredential
from apps.users.models import APIToken, CustomerMembership, User
from tests.factories.core_factories import create_individual_customer

EMAIL = "ioana.sweepwell@example.test"
IDENTIFIERS = (EMAIL, "Ioana", "Sweepwell", "+40722999111", "198.51.100.9")


def _texts() -> str:
    rows = [
        [event.description, event.metadata, event.old_values, event.new_values, event.ip_address, event.user_agent]
        for event in AuditEvent.objects.all()
    ] + [[log.description, log.evidence, log.metadata] for log in ComplianceLog.objects.all()]
    return json.dumps(rows, default=str).lower()


class ErasureSweepTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(
            email="staff.sweeper@example.test", password="x-pass-123", is_staff=True, staff_role="admin"
        )

    def person(self, mode: str = "anonymize") -> User:
        user = User.objects.create_user(
            email=EMAIL, password="x-pass-123", first_name="Ioana", last_name="Sweepwell", phone="+40722999111"
        )
        # What the erasure's own receivers write about: customer saves when anonymising, the
        # credential and token deleted with the user. An owned customer forces anonymisation.
        if mode == "anonymize":
            customer = create_individual_customer(email=EMAIL)
            CustomerMembership.objects.create(user=user, customer=customer, role="owner", is_primary=True)
        else:
            WebAuthnCredential.objects.create(user=user, credential_id="sweep-cred", public_key="k", name="Ioana key")
            APIToken.objects.create(user=user, key_hash=APIToken.hash_key("sweep-key"), key_prefix="sweepkey")
        AuditEvent.objects.create(
            action="search_performed", category="data_protection", severity="low", user=user, description="Searched"
        )
        AuditEvent.objects.create(
            action="login_success",
            category="authentication",
            severity="low",
            user=user,
            content_type=ContentType.objects.get_for_model(User),
            object_id=str(user.pk),
            description=f"Login by {EMAIL}",
            ip_address="198.51.100.9",
        )
        ComplianceLog.objects.create(
            compliance_type="gdpr_consent",
            reference_id=f"consent_{user.pk}",
            user=user,
            description=f"Marketing consent given by {EMAIL}",
            status="success",
            evidence={"email": EMAIL, "ip_address": "198.51.100.9"},
            metadata={"ip_address": "198.51.100.9", "user_agent": "Mozilla/5.0"},
        )
        return user

    def process(self, user: User, mode: str) -> ComplianceLog:
        request = GDPRDeletionService.create_deletion_request(
            user=user, deletion_type=mode, request_ip="198.51.100.9"
        ).unwrap()
        self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())
        request.refresh_from_db()
        return request

    def test_completed_deletion_request_holds_no_email(self) -> None:
        for mode in ("anonymize", "delete"):
            with self.subTest(mode=mode):
                request = self.process(self.person(mode), mode)

                self.assertEqual(request.status, "completed")
                self.assertEqual(request.compliance_type, "gdpr_deletion")
                text = json.dumps([request.description, request.evidence, request.metadata]).lower()
                self.assertNotIn(EMAIL, text)
                self.assertNotIn("198.51.100.9", text)
                self.assertEqual(request.evidence["deletion_type"], mode)

    def test_erasure_leaves_no_new_pii_in_its_own_transaction(self) -> None:
        for mode in ("anonymize", "delete"):
            with self.subTest(mode=mode):
                self.process(self.person(mode), mode)

                text = _texts()
                for identifier in IDENTIFIERS:
                    self.assertNotIn(identifier.lower(), text, f"{mode} left {identifier}")
                # The person's own action on no object is theirs: scrubbed, or deleted.
                search = AuditEvent.objects.filter(action="search_performed")
                if mode == "anonymize":
                    self.assertEqual(search.get().description, AuditRetentionService.ANONYMIZED_DESCRIPTION)
                    with audit_mutation_allowed("test fixture"):
                        search.delete()
                else:
                    self.assertFalse(search.exists())
                consent = ComplianceLog.objects.get(compliance_type="gdpr_consent")
                self.assertEqual(consent.status, "success")
                consent.delete()

    def test_erasure_run_by_a_staff_member_leaves_no_old_value_in_the_events_it_writes(self) -> None:
        """Receivers record the old value of what the erasure changes; the sweep must reach it."""
        for mode in ("anonymize", "delete"):
            with self.subTest(mode=mode):
                user = self.person(mode)
                with acting_as(self.staff):
                    self.process(user, mode)

                text = _texts()
                for identifier in IDENTIFIERS:
                    self.assertNotIn(identifier.lower(), text, f"{mode} left {identifier}")
                self.assertTrue(
                    AuditEvent.objects.filter(user=self.staff).exists(),
                    "the receivers' events are credited to the staff member who ran the erasure",
                )
                with audit_mutation_allowed("test fixture"):
                    AuditEvent.objects.all().delete()
                ComplianceLog.objects.all().delete()

    def test_sweep_finds_events_whose_uuid_sorts_below_existing_rows(self) -> None:
        user = self.person()
        highest = uuid.UUID(int=(1 << 128) - 1)
        AuditEvent.objects.create(id=highest, action="system_job_run", category="system_admin", severity="low")
        low_ids = (uuid.UUID(int=n) for n in range(1, 1000))
        revoke = GDPRDeletionService._revoke_user_exports

        def revoke_and_log(target: User) -> None:
            # Something the erasure runs records the person, as a receiver would.
            revoke(target)
            AuditEvent.objects.create(
                action="export_revoked",
                category="privacy",
                severity="low",
                description=f"Exports of {EMAIL} closed",
                metadata={"ip_address": "198.51.100.9"},
            )

        def low_id() -> uuid.UUID:
            return next(low_ids)

        id_field = AuditEvent._meta.get_field("id")
        with (
            patch.object(id_field, "default", low_id),
            patch.object(GDPRDeletionService, "_revoke_user_exports", side_effect=revoke_and_log),
        ):
            self.process(user, "anonymize")

        written = AuditEvent.objects.get(action="export_revoked")
        self.assertLess(written.pk, highest)
        self.assertNotIn(EMAIL, written.description)
        self.assertNotIn("ip_address", written.metadata)

    def test_the_proof_that_a_cnp_was_cleared_keeps_its_proof_and_nothing_of_the_person(self) -> None:
        user = self.person()
        clear_cnp = GDPRDeletionService._clear_cnp

        def clear_and_prove(*args: Any, **kwargs: Any) -> None:
            clear_cnp(*args, **kwargs)
            # The proof as written, and one a caller filled with the person's details.
            for description, extra in (
                ("CNP cleared from the customer tax profile (GDPR erasure)", {}),
                (f"CNP cleared for {EMAIL}", {"ip_address": "198.51.100.9"}),
            ):
                AuditEvent.objects.create(
                    action="data_anonymization_completed",
                    category="privacy",
                    severity="low",
                    description=description,
                    metadata={"field": "cnp", "customer_id": "7", **extra},
                )

        with patch.object(GDPRDeletionService, "_clear_cnp", side_effect=clear_and_prove):
            self.process(user, "anonymize")

        proofs = AuditEvent.objects.filter(action="data_anonymization_completed", metadata__customer_id="7")
        self.assertEqual(proofs.count(), 6)
        for proof in proofs:
            self.assertEqual((proof.metadata["field"], proof.metadata["customer_id"]), ("cnp", "7"))
            self.assertNotIn(EMAIL, proof.description)
            self.assertNotIn("ip_address", proof.metadata)
            if proof.description.startswith("CNP cleared from"):
                self.assertNotIn("identity_removed_at", proof.metadata)

    def test_an_earlier_proof_row_naming_the_person_keeps_only_its_proof(self) -> None:
        for mode in ("anonymize", "delete"):
            with self.subTest(mode=mode):
                user = self.person(mode)
                proof = AuditEvent.objects.create(
                    action="data_anonymization_completed",
                    category="privacy",
                    severity="low",
                    user=user,
                    description=f"CNP cleared for {EMAIL}",
                    metadata={"field": "cnp", "customer_id": "7", "ip_address": "198.51.100.9"},
                )

                self.process(user, mode)

                proof.refresh_from_db()
                self.assertIsNone(proof.user_id)
                self.assertNotIn(EMAIL, proof.description)
                self.assertEqual((proof.metadata["field"], proof.metadata["customer_id"]), ("cnp", "7"))
                self.assertNotIn("ip_address", proof.metadata)

    def test_a_failed_sweep_rolls_the_erasure_back(self) -> None:
        user = self.person()
        request = GDPRDeletionService.create_deletion_request(user=user, deletion_type="anonymize").unwrap()

        with patch.object(GDPRDeletionService, "_sweep_erasure", side_effect=RuntimeError("sweep failed")):
            self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_err())

        user.refresh_from_db()
        self.assertEqual(user.email, EMAIL)
        self.assertTrue(user.is_active)
        request.refresh_from_db()
        self.assertEqual(request.status, "failed")
        self.assertNotIn("completed_at", request.evidence)
        self.assertNotIn("action_taken", request.evidence)


@override_settings(AUDIT_CHAIN_ENABLED=True)
class FullErasureChainTests(TestCase):
    def setUp(self) -> None:
        self.staff = User.objects.create_user(
            email="staff.chain@example.test", password="x-pass-123", is_staff=True, staff_role="admin"
        )
        self.user = User.objects.create_user(email=EMAIL, password="x-pass-123", first_name="Ioana")
        # Rows written before the chain started are legitimately unlinked; this chain starts empty.
        with audit_mutation_allowed("test fixture"):
            AuditEvent.objects.all().delete()
        AuditChainHead.objects.get_or_create(pk=1)
        AuditChainHead.objects.filter(pk=1).update(backfill_complete=True)
        user_type = ContentType.objects.get_for_model(User)
        self.login = AuditEvent.objects.create(
            action="login_success",
            category="authentication",
            severity="low",
            user=self.user,
            content_type=user_type,
            object_id=str(self.user.pk),
            description=f"Login by {EMAIL}",
            ip_address="198.51.100.9",
        )
        self.search = AuditEvent.objects.create(
            action="search_performed", category="data_protection", severity="low", user=self.user, description="Searched"
        )
        self.staff_reset = AuditEvent.objects.create(
            action="2fa_admin_reset",
            category="security_event",
            severity="medium",
            user=self.staff,
            content_type=user_type,
            object_id=str(self.user.pk),
            description=f"2FA reset for {EMAIL} by support",
            ip_address="203.0.113.9",
        )

    def verify(self) -> list[dict[str, Any]]:
        now = timezone.now()
        return AuditIntegrityService._verify_chain_ledger(now - timedelta(days=1), now + timedelta(days=1))

    def test_full_erasure_tombstones_what_it_deletes(self) -> None:
        request = GDPRDeletionService.create_deletion_request(user=self.user, deletion_type="delete").unwrap()

        self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())

        for own in (self.login, self.search):
            self.assertFalse(AuditEvent.objects.filter(pk=own.pk).exists())
            self.assertTrue(AuditChainLink.objects.filter(event_id_str=str(own.pk), is_tombstone=True).exists())
        findings = {finding["type"] for finding in self.verify()}
        self.assertNotIn("chain_link_event_deleted_without_tombstone", findings)
        # A staff member's action on the person stays theirs, without the person in it.
        self.staff_reset.refresh_from_db()
        self.assertEqual(self.staff_reset.user_id, self.staff.pk)
        self.assertEqual(self.staff_reset.ip_address, "203.0.113.9")
        self.assertNotIn(EMAIL, self.staff_reset.description)

    def test_a_refused_user_delete_rolls_the_whole_erasure_back(self) -> None:
        request = GDPRDeletionService.create_deletion_request(user=self.user, deletion_type="delete").unwrap()
        tombstones = AuditChainLink.objects.filter(is_tombstone=True).count()

        with patch.object(User, "delete", side_effect=RuntimeError("protected row")):
            self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_err())

        self.login.refresh_from_db()
        self.assertEqual(self.login.description, f"Login by {EMAIL}")
        self.assertEqual(self.login.ip_address, "198.51.100.9")
        self.staff_reset.refresh_from_db()
        self.assertIn(EMAIL, self.staff_reset.description)
        self.assertEqual(AuditChainLink.objects.filter(is_tombstone=True).count(), tombstones)
        request.refresh_from_db()
        self.assertEqual(request.status, "failed")


class ExportListsTheWholeAuditTrailTests(TestCase):
    def test_export_includes_the_erasure_proof_rows_about_the_person(self) -> None:
        user = User.objects.create_user(email=EMAIL, password="x-pass-123")
        AuditEvent.objects.create(action="login_success", category="authentication", severity="low", user=user)
        AuditEvent.objects.create(
            action="data_anonymization_completed", category="privacy", severity="medium", user=user,
            description="Anonymisation completed for an earlier request",
        )

        summary = GDPRExportService._collect_user_data(user, {"include_audit_logs": True})["audit_summary"]

        actions = [entry["action"] for entry in summary["recent_activities"]]
        self.assertIn("data_anonymization_completed", actions)
        self.assertEqual(summary["total_events"], len(actions))

    def test_export_counts_every_event_about_the_person(self) -> None:
        user = User.objects.create_user(email=EMAIL, password="x-pass-123")
        staff = User.objects.create_user(email="staff.export@example.test", password="x-pass-123", is_staff=True)
        for _ in range(120):
            AuditEvent.objects.create(action="login_success", category="authentication", severity="low", user=user)
        AuditEvent.objects.create(
            action="2fa_admin_reset",
            category="security_event",
            severity="medium",
            user=staff,
            content_type=ContentType.objects.get_for_model(User),
            object_id=str(user.pk),
            description="2FA reset by support",
        )

        summary = GDPRExportService._collect_user_data(user, {"include_audit_logs": True})["audit_summary"]

        self.assertGreaterEqual(summary["total_events"], 121)
        self.assertEqual(len(summary["recent_activities"]), 100)
        self.assertEqual(summary["recent_activities"][0]["action"], "2fa_admin_reset")
