"""
Backfill the audit hash-chain ledger over existing events (#313, ADR-0043).

Runbook order: deploy (AUDIT_CHAIN_ENABLED off) -> provision AUDIT_CHAIN_SECRET ->
run this command to completion -> flip AUDIT_CHAIN_ENABLED=true (live appends begin)
-> run verify-integrity --check-type chain_verification.

Deliberately a command, not a data migration: it is batched, resumable, and idempotent,
and it must run to completion before live appends turn on so the two never interleave
over the chain-head lock.

Ordering: events are sequenced by (timestamp ASC, id ASC). `timestamp` is non-unique
(auto_now_add), so `id` (the unique uuid4) is the deterministic tiebreaker — a resumed
run continues the exact same chain. Idempotent: an event that already has a link is
skipped (the partial-unique constraint is the backstop).
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Exists, OuterRef

from apps.audit.models import AuditChainHead, AuditChainLink, AuditEvent
from apps.audit.services import AuditIntegrityService


def _unlinked_events() -> Any:
    """Events with no chain link yet, in deterministic chain order."""
    has_link = AuditChainLink.objects.filter(event_id=OuterRef("pk"))
    return AuditEvent.objects.annotate(_linked=Exists(has_link)).filter(_linked=False).order_by("timestamp", "id")


class Command(BaseCommand):
    help = "Backfill the audit hash-chain ledger over existing events (resumable, idempotent)"

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--batch-size", type=int, default=1000, help="Rows per transaction batch")
        parser.add_argument("--dry-run", action="store_true", help="Report preflight counts only")

    def handle(self, *args: Any, **options: Any) -> None:
        batch_size = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be >= 1")

        total = AuditEvent.objects.count()
        pending = _unlinked_events().count()
        self.stdout.write(f"Preflight: {total} audit events, {pending} to link")

        if options["dry_run"]:
            self.stdout.write(self.style.NOTICE("Dry run - no rows modified"))
            return

        done = 0
        while True:
            # Re-take the head lock per batch so a concurrent live append (if the flag were on)
            # cannot interleave. Everything in the batch chains under this single lock.
            with transaction.atomic():
                head, _created = AuditChainHead.objects.select_for_update().get_or_create(pk=1)
                batch = list(_unlinked_events()[:batch_size])
                if not batch:
                    if not head.backfill_complete:
                        head.backfill_complete = True
                        head.save(update_fields=["backfill_complete", "updated_at"])
                    break

                sequence = head.last_sequence
                prev = head.last_chain_mac
                key_id, key = AuditIntegrityService._chain_keys()[0]
                links = []
                for event in batch:
                    sequence += 1
                    event_v2_mac = ""
                    if isinstance(event.metadata, dict):
                        event_v2_mac = str(event.metadata.get("integrity_hash", ""))
                    payload = AuditIntegrityService._chain_payload(
                        sequence=sequence,
                        prev_chain_mac=prev,
                        event_id=str(event.id),
                        event_v2_mac=event_v2_mac,
                        timestamp_iso=event.timestamp.isoformat(),
                        action=event.action,
                        content_type_id=event.content_type_id,
                        object_id=event.object_id,
                        is_tombstone=False,
                    )
                    mac = AuditIntegrityService._compute_chain_mac(payload=payload, key=key)
                    links.append(
                        AuditChainLink(
                            sequence=sequence,
                            event=event,
                            event_id_str=str(event.id),
                            event_timestamp=event.timestamp,
                            event_action=event.action,
                            event_content_type_id=event.content_type_id,
                            event_object_id=event.object_id,
                            event_v2_mac=event_v2_mac,
                            chain_mac=mac,
                            prev_chain_mac=prev,
                            key_id=key_id,
                            is_tombstone=False,
                        )
                    )
                    prev = mac

                AuditChainLink.objects.bulk_create(links)
                AuditChainHead.objects.filter(pk=1).update(last_sequence=sequence, last_chain_mac=prev)

            done += len(batch)
            self.stdout.write(f"  linked {done}/{pending}")

        remaining = _unlinked_events().count()
        if remaining:
            raise CommandError(f"Backfill incomplete: {remaining} events still unlinked - re-run to resume")
        self.stdout.write(self.style.SUCCESS(f"Linked {done} events; chain backfill complete"))
