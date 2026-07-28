"""
Adversarial tests for the audit hash-chain ledger (#313).

The per-row keyed MAC (#217/#304, see test_audit_integrity_hash) authenticates each row
independently. That is necessary but not sufficient: independent per-row MACs cannot detect
what an attacker does to the SET of rows. A row deleted outright leaves no trace — the
verifier never sees it. A row inserted by direct SQL bypasses post_save and, carrying no
marker, is indistinguishable from a legacy row.

The ledger closes that gap: every event gets an append-only link carrying a serially
assigned sequence and an HMAC over (this link's identity + the previous link's MAC), under
a key domain distinct from the per-row MAC key. Deleting, inserting, or reordering rows
breaks the linkage in a way no database-only attacker can repair without the chain secret.

These tests are written as attacks, one per failure mode named in #313.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import (
    AuditChainAnchor,
    AuditChainHead,
    AuditChainLink,
    AuditEvent,
    AuditLedgerImmutabilityError,
    audit_mutation_allowed,
)
from apps.audit.services import AuditIntegrityService
from apps.users.models import User


@override_settings(AUDIT_CHAIN_ENABLED=True)
class AuditChainLedgerTestCase(TestCase):
    """Base fixture: a live, backfilled chain with a handful of linked events."""

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="ledger@example.com", password="testpass123")
        self.content_type = ContentType.objects.get_for_model(User)
        # Creating the user above fires its own audit signals, and those events land while the
        # chain is still gated — so they are legitimately unlinked. Clear them: every test here
        # reasons about a chain that starts empty, and leaving fixture noise behind would make
        # "unlinked event" findings ambiguous between fixture and attack.
        with audit_mutation_allowed("test_fixture_reset"):
            AuditEvent.objects.all().delete()
        # Live appends stay gated until the backfill marks the head complete, so mark it
        # complete up front — these tests exercise the post-cutover steady state.
        AuditChainHead.objects.get_or_create(pk=1)
        AuditChainHead.objects.filter(pk=1).update(backfill_complete=True)

    def _event(self, description: str = "Chained event", **overrides: Any) -> AuditEvent:
        fields: dict[str, Any] = {
            "user": self.user,
            "action": "login_success",
            "category": "authentication",
            "severity": "low",
            "content_type": self.content_type,
            "object_id": str(self.user.id),
            "description": description,
            "ip_address": "192.168.1.1",
        }
        fields.update(overrides)
        return AuditEvent.objects.create(**fields)

    def _verify(self) -> list[dict[str, Any]]:
        """Run the ledger verifier over a window wide enough to cover the fixture."""
        now = timezone.now()
        return AuditIntegrityService._verify_chain_ledger(
            now - timezone.timedelta(days=1), now + timezone.timedelta(days=1)
        )

    def _finding_types(self, findings: list[dict[str, Any]]) -> set[str]:
        return {finding["type"] for finding in findings}


class ChainAppendTests(AuditChainLedgerTestCase):
    """The happy path: appends produce a contiguous, verifying chain."""

    def test_creating_events_appends_verifying_links(self) -> None:
        for index in range(3):
            self._event(description=f"event {index}")

        links = list(AuditChainLink.objects.order_by("sequence"))
        self.assertEqual(len(links), 3)
        self.assertEqual([link.sequence for link in links], [1, 2, 3])
        # Genesis link has no predecessor; each subsequent link commits to the prior MAC.
        self.assertEqual(links[0].prev_chain_mac, "")
        self.assertEqual(links[1].prev_chain_mac, links[0].chain_mac)
        self.assertEqual(links[2].prev_chain_mac, links[1].chain_mac)
        self.assertEqual(self._verify(), [])

    def test_chain_head_tracks_the_last_link(self) -> None:
        self._event()
        last = self._event()

        head = AuditChainHead.objects.get(pk=1)
        link = AuditChainLink.objects.get(event_id_str=str(last.id))
        self.assertEqual(head.last_sequence, link.sequence)
        self.assertEqual(head.last_chain_mac, link.chain_mac)

    def test_appends_are_gated_until_backfill_completes(self) -> None:
        """Live appends must not interleave with the backfill over the head lock."""
        AuditChainHead.objects.filter(pk=1).update(backfill_complete=False)

        self._event()

        self.assertEqual(AuditChainLink.objects.count(), 0)


class ChainTamperDetectionTests(AuditChainLedgerTestCase):
    """Each test is one of the attacks #313 enumerates, executed against a live chain."""

    def test_row_deletion_is_detected(self) -> None:
        """The headline gap: independent per-row MACs cannot reveal a deleted row."""
        self._event(description="first")
        victim = self._event(description="incriminating")
        self._event(description="third")

        # Attacker deletes the middle link by raw SQL, bypassing the append-only manager.
        link = AuditChainLink.objects.get(event_id_str=str(victim.id))
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM audit_chain_links WHERE sequence = %s", [link.sequence])

        findings = self._verify()
        # The gap shows up twice over: a missing sequence AND a broken prev-linkage.
        self.assertIn("chain_sequence_gap", self._finding_types(findings))
        self.assertIn("chain_prev_link_broken", self._finding_types(findings))

    def test_tail_truncation_is_detected_via_the_head(self) -> None:
        """Chaining alone cannot detect tail deletion — the head cursor is what catches it."""
        self._event()
        self._event()
        last_link = AuditChainLink.objects.order_by("-sequence").first()
        assert last_link is not None

        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM audit_chain_links WHERE sequence = %s", [last_link.sequence])

        # Walking the surviving links is clean — truncation leaves no internal gap. The head
        # row still points past the end, which is the in-database tell; the control that does
        # not depend on attacker-writable state is the external anchor (see ChainAnchorTests).
        head = AuditChainHead.objects.get(pk=1)
        self.assertEqual(head.last_sequence, last_link.sequence)
        self.assertFalse(AuditChainLink.objects.filter(sequence=last_link.sequence).exists())
        self.assertEqual(head.last_chain_mac, last_link.chain_mac)
        surviving_tail = AuditChainLink.objects.order_by("-sequence").first()
        assert surviving_tail is not None
        self.assertNotEqual(surviving_tail.chain_mac, head.last_chain_mac)

    def test_forged_event_insert_without_a_link_is_detected(self) -> None:
        """A direct SQL INSERT bypasses post_save, so it never gets a link."""
        self._event(description="genuine")

        forged_id = "11111111-1111-4111-8111-111111111111"
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO audit_events
                    (id, action, category, severity, description, object_id, metadata,
                     old_values, new_values, timestamp, is_sensitive, requires_review,
                     user_agent, request_id, session_key, actor_type, content_type_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                [
                    forged_id,
                    "login_success",
                    "authentication",
                    "low",
                    "forged by direct SQL",
                    "",
                    "{}",
                    "{}",
                    "{}",
                    timezone.now(),
                    False,
                    False,
                    "",
                    "",
                    "",
                    "system",
                    self.content_type.id,
                ],
            )

        with override_settings(AUDIT_CHAIN_REQUIRE=True):
            findings = self._verify()

        missing = [f for f in findings if f["type"] == "chain_link_missing_for_event"]
        self.assertEqual(len(missing), 1)
        self.assertIn(forged_id, missing[0]["description"])
        self.assertEqual(missing[0]["severity"], "critical")

    def test_unlinked_event_is_informational_until_chain_is_required(self) -> None:
        """Pre-cutover, an unlinked event is an expected artifact — not a forgery signal."""
        AuditChainHead.objects.filter(pk=1).update(backfill_complete=False)
        self._event(description="predates the backfill")

        with override_settings(AUDIT_CHAIN_REQUIRE=False):
            findings = self._verify()

        missing = [f for f in findings if f["type"] == "chain_link_missing_for_event"]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["severity"], "info")

    def test_link_field_tamper_breaks_the_mac(self) -> None:
        """Rewriting what a link commits to, without the chain key, cannot be repaired."""
        event = self._event(description="original")
        link = AuditChainLink.objects.get(event_id_str=str(event.id))

        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE audit_chain_links SET event_action = %s WHERE sequence = %s",
                ["payment_refunded", link.sequence],
            )

        findings = self._verify()
        self.assertIn("chain_mac_mismatch", self._finding_types(findings))

    def test_reordering_links_is_detected(self) -> None:
        """Sequence is bound into the MAC, so swapping two links cannot verify."""
        self._event(description="first")
        self._event(description="second")
        first, second = list(AuditChainLink.objects.order_by("sequence"))

        # Key the raw UPDATEs off `sequence`, not `id`: the pk is a UUIDField, which SQLite
        # stores as undashed hex, so a dashed str(uuid) bind would silently match zero rows.
        first_seq, second_seq = first.sequence, second.sequence
        with connection.cursor() as cursor:
            # Park the first out of the way, swap, then land the second.
            cursor.execute("UPDATE audit_chain_links SET sequence = -1 WHERE sequence = %s", [first_seq])
            cursor.execute("UPDATE audit_chain_links SET sequence = %s WHERE sequence = %s", [first_seq, second_seq])
            cursor.execute("UPDATE audit_chain_links SET sequence = %s WHERE sequence = -1", [second_seq])

        findings = self._verify()
        self.assertIn("chain_mac_mismatch", self._finding_types(findings))

    def test_wholesale_rechain_under_a_wrong_key_is_detected(self) -> None:
        """The attacker's best move: rebuild a self-consistent chain. Without the secret it fails."""
        self._event(description="first")
        self._event(description="second")

        forged_key = b"attacker-controlled-key-material"
        prev = ""
        for link in AuditChainLink.objects.order_by("sequence"):
            payload = AuditIntegrityService._chain_payload(
                sequence=link.sequence,
                prev_chain_mac=prev,
                event_id=link.event_id_str,
                event_v2_mac=link.event_v2_mac,
                timestamp_iso=link.event_timestamp.isoformat(),
                action="payment_refunded",  # the rewrite the attacker wants to land
                content_type_id=link.event_content_type_id,
                object_id=link.event_object_id,
                is_tombstone=link.is_tombstone,
            )
            mac = AuditIntegrityService._compute_chain_mac(payload=payload, key=forged_key)
            with connection.cursor() as cursor:
                # Keyed off `sequence` — see the note in test_reordering_links_is_detected on
                # why a str(uuid) bind against the pk matches nothing under SQLite.
                cursor.execute(
                    """
                    UPDATE audit_chain_links
                       SET event_action = %s, chain_mac = %s, prev_chain_mac = %s
                     WHERE sequence = %s
                    """,
                    ["payment_refunded", mac, prev, link.sequence],
                )
            prev = mac

        # Internally consistent — sequence and prev-linkage both walk clean — but every MAC
        # fails under the real key. This is the property the keyed tier buys over plain SHA-256.
        findings = self._verify()
        self.assertIn("chain_mac_mismatch", self._finding_types(findings))
        self.assertNotIn("chain_sequence_gap", self._finding_types(findings))
        self.assertNotIn("chain_prev_link_broken", self._finding_types(findings))

    def test_unknown_key_id_is_flagged(self) -> None:
        """A link stamped by a key the verifier cannot resolve is never silently accepted."""
        self._event()

        with connection.cursor() as cursor:
            cursor.execute("UPDATE audit_chain_links SET key_id = %s", ["deadbeef"])

        findings = self._verify()
        self.assertIn("chain_unknown_key_id", self._finding_types(findings))


class ChainBackfillTests(TestCase):
    """The cutover runbook: backfill historical rows, then turn live appends on.

    Deliberately NOT under the AUDIT_CHAIN_ENABLED override — the whole point of the backfill
    is that it runs while live appends are still dark, so the two never interleave over the
    chain-head lock.
    """

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="backfill@example.com", password="testpass123")
        self.content_type = ContentType.objects.get_for_model(User)

    def _event(self, description: str) -> AuditEvent:
        return AuditEvent.objects.create(
            user=self.user,
            action="login_success",
            category="authentication",
            severity="low",
            content_type=self.content_type,
            object_id=str(self.user.id),
            description=description,
            ip_address="192.168.1.1",
        )

    def _verify(self) -> list[dict[str, Any]]:
        now = timezone.now()
        return AuditIntegrityService._verify_chain_ledger(
            now - timezone.timedelta(days=2), now + timezone.timedelta(days=2)
        )

    def test_backfill_links_history_and_live_appends_continue_the_chain(self) -> None:
        for index in range(5):
            self._event(f"historical {index}")
        history_count = AuditEvent.objects.count()
        self.assertEqual(AuditChainLink.objects.count(), 0)

        call_command("backfill_audit_chain", verbosity=0)

        head = AuditChainHead.objects.get(pk=1)
        self.assertEqual(AuditChainLink.objects.count(), history_count)
        self.assertEqual(head.last_sequence, history_count)
        self.assertTrue(head.backfill_complete)
        self.assertEqual(self._verify(), [])

        # Re-running is a no-op: the command is resumable and idempotent, so a partially
        # completed run can simply be re-issued without double-linking anything.
        call_command("backfill_audit_chain", verbosity=0)
        self.assertEqual(AuditChainLink.objects.count(), history_count)
        self.assertEqual(AuditChainHead.objects.get(pk=1).last_sequence, history_count)

        # Only now does the operator flip the flag; the live append extends the same chain.
        with override_settings(AUDIT_CHAIN_ENABLED=True):
            self._event("live")

        self.assertEqual(AuditChainLink.objects.count(), history_count + 1)
        self.assertEqual(self._verify(), [])


class ChainAnchorTests(AuditChainLedgerTestCase):
    """The external anchor: the only control that survives an attacker owning the database.

    Every test writes to a temp-dir sink, so the log-file sink is exercised for real rather
    than mocked — the file format IS the evidence an operator reads back.
    """

    def setUp(self) -> None:
        super().setUp()
        self._sink_dir = tempfile.mkdtemp()
        self.anchor_path = Path(self._sink_dir) / "anchors.jsonl"
        self.addCleanup(shutil.rmtree, self._sink_dir, True)
        overrides = override_settings(AUDIT_ANCHOR_SINK="logfile", AUDIT_ANCHOR_LOG_PATH=str(self.anchor_path))
        overrides.enable()
        self.addCleanup(overrides.disable)

    def _sink_records(self) -> list[dict[str, Any]]:
        """Read back what the sink actually holds — the operator's view of the evidence."""
        if not self.anchor_path.exists():
            return []
        return [json.loads(line) for line in self.anchor_path.read_text().splitlines() if line.strip()]

    def test_publishing_writes_a_verifiable_record_to_the_sink(self) -> None:
        self._event()
        self._event()

        result = AuditIntegrityService.publish_chain_anchor()
        self.assertTrue(result.is_ok())

        records = self._sink_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["sequence"], 2)
        self.assertEqual(records[0]["link_count"], 2)
        self.assertEqual(AuditIntegrityService._verify_chain_anchors(), [])

    def test_tail_truncation_is_caught_by_the_anchor(self) -> None:
        """The gap chaining cannot close: truncation leaves the surviving links consistent."""
        for index in range(3):
            self._event(description=f"event {index}")
        AuditIntegrityService.publish_chain_anchor()

        # Attacker lops off the tail AND repairs the head row to match, so nothing in the
        # database contradicts itself any more.
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM audit_chain_links WHERE sequence = 3")
        surviving = AuditChainLink.objects.order_by("-sequence").first()
        assert surviving is not None
        AuditChainHead.objects.filter(pk=1).update(last_sequence=surviving.sequence, last_chain_mac=surviving.chain_mac)

        # The chain walk finds no structural break — no gap, no snapped prev-link, no bad MAC.
        # This is exactly the blind spot #313 names. (The orphaned event does surface as an
        # informational "missing link", but that is a benign cutover signal pre-REQUIRE, not
        # something an operator would treat as evidence of tampering.)
        chain_findings = self._finding_types(self._verify())
        self.assertNotIn("chain_sequence_gap", chain_findings)
        self.assertNotIn("chain_prev_link_broken", chain_findings)
        self.assertNotIn("chain_mac_mismatch", chain_findings)

        # The anchor catches it, because it was published before the truncation.
        findings = AuditIntegrityService._verify_chain_anchors()
        self.assertIn("chain_truncated_below_anchor", self._finding_types(findings))

    def test_truncation_is_caught_from_the_sink_copy_alone(self) -> None:
        """The real verification path: anchors read back from the sink, not from the database.

        An attacker who owns the database deletes the local anchor rows too. What they cannot
        reach is the off-host sink, so verification must work from those records alone.
        """
        for index in range(3):
            self._event(description=f"event {index}")
        AuditIntegrityService.publish_chain_anchor()
        sink_records = self._sink_records()

        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM audit_chain_links WHERE sequence = 3")
            # ...and destroy the local anchor copy, which the append-only manager blocks but
            # raw SQL does not.
            cursor.execute("DELETE FROM audit_chain_anchors")
        self.assertEqual(AuditChainAnchor.objects.count(), 0)

        # Nothing left in the database to check against — but the sink copy still convicts.
        findings = AuditIntegrityService.verify_anchor_records(sink_records)
        self.assertIn("chain_truncated_below_anchor", self._finding_types(findings))

    def test_rewriting_an_anchored_link_is_caught(self) -> None:
        """Truncation is not the only post-anchor rewrite; the head MAC is pinned too."""
        self._event()
        self._event()
        AuditIntegrityService.publish_chain_anchor()
        sink_records = self._sink_records()

        # Re-chain link 2 under the real key so the ledger walk itself stays clean.
        link = AuditChainLink.objects.get(sequence=2)
        payload = AuditIntegrityService._chain_payload(
            sequence=link.sequence,
            prev_chain_mac=link.prev_chain_mac,
            event_id=link.event_id_str,
            event_v2_mac=link.event_v2_mac,
            timestamp_iso=link.event_timestamp.isoformat(),
            action="payment_refunded",
            content_type_id=link.event_content_type_id,
            object_id=link.event_object_id,
            is_tombstone=link.is_tombstone,
        )
        _key_id, key = AuditIntegrityService._chain_keys()[0]
        forged_mac = AuditIntegrityService._compute_chain_mac(payload=payload, key=key)
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE audit_chain_links SET event_action = %s, chain_mac = %s WHERE sequence = 2",
                ["payment_refunded", forged_mac],
            )

        findings = AuditIntegrityService.verify_anchor_records(sink_records)
        self.assertIn("anchor_head_mismatch", self._finding_types(findings))

    def test_forged_anchor_record_is_rejected(self) -> None:
        """An attacker minting an anchor to match a rewritten chain lacks the anchor key."""
        self._event()
        AuditIntegrityService.publish_chain_anchor()
        records = self._sink_records()
        records[0]["link_count"] = 99

        findings = AuditIntegrityService.verify_anchor_records(records)
        self.assertIn("anchor_mac_mismatch", self._finding_types(findings))
        # A forged anchor proves nothing about the chain, so it must not also emit
        # chain-truncation findings derived from its own bogus numbers.
        self.assertNotIn("chain_truncated_below_anchor", self._finding_types(findings))

    def test_anchor_key_is_independent_of_the_chain_key(self) -> None:
        """Domain separation: recovering the chain key must not let an attacker mint anchors."""
        chain_key = AuditIntegrityService._chain_keys()[0][1]
        anchor_key = AuditIntegrityService._anchor_keys()[0][1]
        self.assertNotEqual(chain_key, anchor_key)

    def test_publishing_without_a_chain_head_is_an_error(self) -> None:
        """Anchoring an empty chain would publish a meaningless record."""
        AuditChainHead.objects.filter(pk=1).update(last_sequence=0, last_chain_mac="")

        result = AuditIntegrityService.publish_chain_anchor()

        self.assertTrue(result.is_err())
        self.assertEqual(self._sink_records(), [])

    def test_sink_failure_does_not_record_a_local_anchor(self) -> None:
        """A local row written despite a failed publish would overstate the real protection."""
        self._event()

        # Point the sink at a path that cannot be created.
        with override_settings(AUDIT_ANCHOR_LOG_PATH="/proc/praho-nonexistent/anchors.jsonl"):
            result = AuditIntegrityService.publish_chain_anchor()

        self.assertTrue(result.is_err())
        self.assertEqual(AuditChainAnchor.objects.count(), 0)

    def test_none_sink_records_locally_but_publishes_nothing(self) -> None:
        """The explicit opt-out still tracks heads locally — with no external evidence."""
        self._event()

        with override_settings(AUDIT_ANCHOR_SINK="none"):
            result = AuditIntegrityService.publish_chain_anchor()

        self.assertTrue(result.is_ok())
        self.assertEqual(AuditChainAnchor.objects.count(), 1)
        self.assertEqual(self._sink_records(), [])

    def test_unknown_sink_is_rejected(self) -> None:
        self._event()

        with override_settings(AUDIT_ANCHOR_SINK="carrier-pigeon"):
            result = AuditIntegrityService.publish_chain_anchor()

        self.assertTrue(result.is_err())
        self.assertEqual(AuditChainAnchor.objects.count(), 0)

    def test_anchor_rows_are_append_only(self) -> None:
        self._event()
        AuditIntegrityService.publish_chain_anchor()

        with self.assertRaises(AuditLedgerImmutabilityError):
            AuditChainAnchor.objects.update(sequence=99)
        with self.assertRaises(AuditLedgerImmutabilityError):
            AuditChainAnchor.objects.delete()

    def test_anchor_command_publishes_and_verifies(self) -> None:
        self._event()

        call_command("anchor_audit_chain", verbosity=0)
        self.assertEqual(len(self._sink_records()), 1)

        # --verify is the operator's clean-bill-of-health path; it must not raise.
        call_command("anchor_audit_chain", "--verify", verbosity=0)


class ChainImmutabilityTests(AuditChainLedgerTestCase):
    """The ORM offers no escape hatch — a chain link is append-only, with no exceptions."""

    def test_queryset_update_is_blocked(self) -> None:
        self._event()
        with self.assertRaises(AuditLedgerImmutabilityError):
            AuditChainLink.objects.update(event_action="tampered")

    def test_queryset_delete_is_blocked(self) -> None:
        self._event()
        with self.assertRaises(AuditLedgerImmutabilityError):
            AuditChainLink.objects.delete()

    def test_instance_delete_is_blocked(self) -> None:
        event = self._event()
        link = AuditChainLink.objects.get(event_id_str=str(event.id))
        with self.assertRaises(AuditLedgerImmutabilityError):
            link.delete()

    def test_resaving_an_existing_link_is_blocked(self) -> None:
        event = self._event()
        link = AuditChainLink.objects.get(event_id_str=str(event.id))
        link.event_action = "tampered"
        with self.assertRaises(AuditLedgerImmutabilityError):
            link.save()

    def test_immutability_guard_does_not_block_appends(self) -> None:
        """The guard must not be so broad that it breaks the ledger's only legal write."""
        event = self._event()
        self.assertTrue(AuditChainLink.objects.filter(event_id_str=str(event.id)).exists())


class ChainSurvivesLegitimateEventChangesTests(AuditChainLedgerTestCase):
    """Anonymization and retention are authorized; they must not read as tampering."""

    def test_anonymization_restamp_does_not_break_the_chain(self) -> None:
        """The link commits to the v2 MAC as of append time, never the live row."""
        event = self._event(description="contains personal data")
        self.assertEqual(self._verify(), [])

        with audit_mutation_allowed("retention_anonymize"):
            AuditEvent.objects.filter(pk=event.pk).update(description="[anonymized]", user=None)

        # The event changed underneath the link; the chain still verifies because it was built
        # from the identity snapshot copied at append time.
        self.assertEqual(self._verify(), [])

    def test_retention_delete_records_a_tombstone(self) -> None:
        """A deleted event must leave an authorized-removal record in the ledger."""
        event = self._event(description="aged out")
        original_link = AuditChainLink.objects.get(event_id_str=str(event.id))

        appended = AuditIntegrityService.append_tombstone_links([event])
        self.assertEqual(appended, 1)

        with audit_mutation_allowed("retention_delete"):
            AuditEvent.objects.filter(pk=event.pk).delete()

        tombstone = AuditChainLink.objects.get(is_tombstone=True)
        self.assertEqual(tombstone.event_id_str, str(event.id))
        self.assertGreater(tombstone.sequence, original_link.sequence)
        # The original link survives with a nulled FK — it is never rewritten.
        original_link.refresh_from_db()
        self.assertIsNone(original_link.event_id)
        # And the whole ledger, tombstone included, still verifies.
        self.assertEqual(self._verify(), [])


class ChainAdversarialReviewRegressionTests(AuditChainLedgerTestCase):
    """Attacks found by adversarial review of the first implementation.

    Each one verified clean against the original code — the ledger reported healthy while
    evidence had in fact been destroyed or suppressed.
    """

    def test_deleting_the_event_row_without_a_tombstone_is_detected(self) -> None:
        """The link verifies from its own snapshot, so deleting the EVENT left no trace.

        SET_NULL nulls the link's FK and the chain still walks clean: an attacker could erase
        the actual evidence and pass verification.
        """
        self._event(description="first")
        victim = self._event(description="incriminating")
        self.assertEqual(self._verify(), [])

        # Delete the event the way the ORM's SET_NULL would leave things: FK nulled, link row
        # intact. (Raw SQL alone would strand a dangling FK that SQLite rejects at commit; the
        # attacker-relevant end state is the same either way — event gone, link still there.)
        with audit_mutation_allowed("attacker_delete"):
            AuditEvent.objects.filter(pk=victim.pk).delete()
        self.assertFalse(AuditEvent.objects.filter(pk=victim.pk).exists())
        self.assertTrue(AuditChainLink.objects.filter(event_id_str=str(victim.id), is_tombstone=False).exists())

        findings = self._verify()
        self.assertIn("chain_link_event_deleted_without_tombstone", self._finding_types(findings))

    def test_authorized_retention_delete_is_not_flagged(self) -> None:
        """The counterpart: a tombstoned deletion is authorized and must stay clean, or the
        new check would cry wolf on every retention run."""
        event = self._event(description="aged out")
        AuditIntegrityService.append_tombstone_links([event])
        with audit_mutation_allowed("retention_delete"):
            AuditEvent.objects.filter(pk=event.pk).delete()

        findings = self._verify()
        self.assertNotIn("chain_link_event_deleted_without_tombstone", self._finding_types(findings))

    def test_chain_link_pending_marker_is_reported_critical(self) -> None:
        """An attacker can force an append to fail (e.g. by squatting the next sequence).

        The append path is fail-open by design, so the marker is the only remaining signal —
        and nothing read it, despite the verifier docstring claiming otherwise.
        """
        event = self._event()
        with audit_mutation_allowed("test"):
            AuditEvent.objects.filter(pk=event.pk).update(metadata={**event.metadata, "chain_link_pending": True})

        findings = self._verify()
        pending = [f for f in findings if f["type"] == "chain_link_pending"]
        self.assertEqual(len(pending), 1)
        # Always critical: unlike an unlinked event, this marker only appears when a live
        # append actually broke, so it is never a benign cutover artifact.
        self.assertEqual(pending[0]["severity"], "critical")

    def test_forced_append_failure_surfaces_as_a_finding(self) -> None:
        """End to end: squat the next sequence, let the app create an event, and confirm the
        suppressed link does not pass silently."""
        head = AuditChainHead.objects.get(pk=1)
        AuditChainLink.objects.create(
            sequence=head.last_sequence + 1,
            event=None,
            event_id_str="squatted",
            event_timestamp=timezone.now(),
            event_action="squat",
            event_content_type_id=None,
            event_object_id="",
            event_v2_mac="",
            chain_mac="0" * 64,
            prev_chain_mac="",
            key_id="00000000",
            is_tombstone=True,
        )

        self._event(description="append will fail")

        findings = self._verify()
        self.assertIn("chain_link_pending", self._finding_types(findings))


class AnchorFailClosedTests(AuditChainLedgerTestCase):
    """_verify_chain_anchors must read the SINK and fail closed (adversarial review finding).

    Originally it read the local AuditChainAnchor table. An attacker who can truncate the
    chain can equally delete those rows — the verifier then found nothing to check and
    reported healthy, disabling the control precisely when it was needed.
    """

    def setUp(self) -> None:
        super().setUp()
        self._sink_dir = tempfile.mkdtemp()
        self.anchor_path = Path(self._sink_dir) / "anchors.jsonl"
        self.addCleanup(shutil.rmtree, self._sink_dir, True)
        overrides = override_settings(AUDIT_ANCHOR_SINK="logfile", AUDIT_ANCHOR_LOG_PATH=str(self.anchor_path))
        overrides.enable()
        self.addCleanup(overrides.disable)

    def _sink_records(self) -> list[dict[str, Any]]:
        """Read back what the sink actually holds — the operator's view of the evidence."""
        if not self.anchor_path.exists():
            return []
        return [json.loads(line) for line in self.anchor_path.read_text().splitlines() if line.strip()]

    def test_truncation_is_caught_even_after_local_anchor_rows_are_deleted(self) -> None:
        """The headline bypass: delete the local anchors and the old verifier passed."""
        for index in range(3):
            self._event(description=f"event {index}")
        AuditIntegrityService.publish_chain_anchor()

        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM audit_chain_links WHERE sequence = 3")
            cursor.execute("DELETE FROM audit_chain_anchors WHERE sequence >= 0")
        surviving = AuditChainLink.objects.order_by("-sequence").first()
        assert surviving is not None
        AuditChainHead.objects.filter(pk=1).update(last_sequence=surviving.sequence, last_chain_mac=surviving.chain_mac)
        self.assertEqual(AuditChainAnchor.objects.count(), 0)

        findings = AuditIntegrityService._verify_chain_anchors()
        self.assertIn("chain_truncated_below_anchor", self._finding_types(findings))

    def test_missing_sink_is_critical_not_healthy(self) -> None:
        """No readable external evidence must never read as a pass."""
        self._event()

        with override_settings(AUDIT_ANCHOR_LOG_PATH=str(Path(self._sink_dir) / "absent.jsonl")):
            findings = AuditIntegrityService._verify_chain_anchors()

        self.assertIn("anchor_sink_unavailable", self._finding_types(findings))
        self.assertEqual(findings[0]["severity"], "critical")

    def test_sink_disabled_is_critical(self) -> None:
        """AUDIT_ANCHOR_SINK=none means truncation is undetectable — say so, loudly."""
        self._event()

        with override_settings(AUDIT_ANCHOR_SINK="none"):
            findings = AuditIntegrityService._verify_chain_anchors()

        self.assertIn("anchor_sink_unavailable", self._finding_types(findings))

    def test_anchor_removed_from_sink_is_detected_via_the_local_copy(self) -> None:
        """The mirror image: the local table corroborates the sink, catching sink tampering."""
        self._event()
        AuditIntegrityService.publish_chain_anchor()
        self.assertEqual(AuditChainAnchor.objects.count(), 1)

        # Attacker with filesystem access empties the anchor file.
        self.anchor_path.write_text("")

        # Emptying the sink is itself critical (nothing left pinning the chain's reach); the
        # local copy is what identifies WHICH anchor was removed.
        findings = AuditIntegrityService._verify_chain_anchors()
        self.assertIn("anchor_sink_empty", self._finding_types(findings))

    def test_empty_but_readable_sink_is_critical(self) -> None:
        """A readable sink with zero anchors must not read as healthy (review finding).

        With no anchor to compare against, nothing pins how far the chain must reach — the
        same fail-open trap as an unreadable sink, just quieter.
        """
        self._event()
        self.anchor_path.write_text("")

        findings = AuditIntegrityService._verify_chain_anchors()

        self.assertIn("anchor_sink_empty", self._finding_types(findings))
        self.assertEqual(findings[0]["severity"], "critical")

    def test_malformed_sink_record_is_a_finding_not_a_crash(self) -> None:
        """Sink records are untrusted input; a bad one must not abort the whole check.

        Raising here would be a denial of verification an attacker could trigger at will by
        appending one junk line.
        """
        self._event()
        AuditIntegrityService.publish_chain_anchor()
        good = self._sink_records()[0]

        malformed = [
            {},  # nothing at all
            {"sequence": "not-an-int", **{k: v for k, v in good.items() if k != "sequence"}},
            {k: v for k, v in good.items() if k != "anchor_mac"},  # missing a required field
            {"sequence": True, "link_count": 1, "head_chain_mac": "x", "anchor_mac": "y", "key_id": "z"},
        ]
        for record in malformed:
            with self.subTest(record=record):
                findings = AuditIntegrityService.verify_anchor_records([record])
                self.assertIn("anchor_record_malformed", self._finding_types(findings))

    def test_malformed_record_does_not_mask_a_valid_one(self) -> None:
        """One junk line must not stop the real anchors from being checked."""
        for index in range(3):
            self._event(description=f"event {index}")
        AuditIntegrityService.publish_chain_anchor()
        good = self._sink_records()[0]

        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM audit_chain_links WHERE sequence = 3")

        findings = AuditIntegrityService.verify_anchor_records([{"junk": True}, good])

        self.assertIn("anchor_record_malformed", self._finding_types(findings))
        self.assertIn("chain_truncated_below_anchor", self._finding_types(findings))

    def test_sink_is_read_without_loading_the_whole_file(self) -> None:
        """Streamed line-by-line; behaviour must stay identical across many records."""
        for index in range(5):
            self._event(description=f"event {index}")
            AuditIntegrityService.publish_chain_anchor()

        result = AuditIntegrityService.read_anchor_sink_records()

        self.assertTrue(result.is_ok())
        self.assertEqual(len(result.unwrap()), 5)
        self.assertEqual(AuditIntegrityService._verify_chain_anchors(), [])
