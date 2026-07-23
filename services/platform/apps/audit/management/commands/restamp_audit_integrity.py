"""
Restamp audit events with v2 keyed integrity MACs (the #313 cutover, ADR-0043).

Runbook order: provision AUDIT_INTEGRITY_SECRET -> deploy (all v1 writers gone) ->
run this command -> run verify-integrity. After a clean run every row carries a v2
marker, and the verifier's post-cutover rule (non-v2 == compromised) becomes safe
to leave enabled.

Deliberately a command, not a data migration: the restamp is pk-batched, resumable,
and idempotent - a deploy-time migration would hold one transaction over the whole
table and could not be re-run after a partial failure.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q

from apps.audit.models import AuditEvent, audit_mutation_allowed
from apps.audit.services import AuditIntegrityService


def _non_v2_filter() -> Q:
    """Rows lacking a current-version marker.

    The isnull arm is load-bearing: SQL three-valued logic makes ~Q(key=2) silently
    drop rows where the key is missing, which are exactly the rows most in need of
    a restamp.
    """
    return Q(metadata__integrity_hash_version__isnull=True) | ~Q(
        metadata__integrity_hash_version=AuditIntegrityService.HASH_VERSION
    )


class Command(BaseCommand):
    help = "Restamp audit events with v2 keyed integrity MACs (resumable, idempotent)"

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--batch-size", type=int, default=1000, help="Rows per transaction batch")
        parser.add_argument("--dry-run", action="store_true", help="Report preflight counts only")
        parser.add_argument(
            "--all",
            action="store_true",
            dest="restamp_all",
            help="Restamp v2 rows too (after key rotation, to retire the previous key)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        batch_size = options["batch_size"]
        if batch_size < 1:
            raise CommandError("--batch-size must be >= 1")

        total = AuditEvent.objects.count()
        pending_qs = AuditEvent.objects.all() if options["restamp_all"] else AuditEvent.objects.filter(_non_v2_filter())
        pending = pending_qs.count()
        self.stdout.write(f"Preflight: {total} audit events, {pending} to restamp")

        if options["dry_run"]:
            self.stdout.write(self.style.NOTICE("Dry run - no rows modified"))
            return
        if pending == 0:
            self.stdout.write(self.style.SUCCESS("Nothing to restamp - all rows carry a v2 marker"))
            return

        done = 0
        last_pk = None
        while True:
            batch_qs = pending_qs.order_by("pk")
            if last_pk is not None:
                batch_qs = batch_qs.filter(pk__gt=last_pk)
            batch = list(batch_qs[:batch_size])
            if not batch:
                break

            with transaction.atomic(), audit_mutation_allowed("integrity_restamp"):
                for event in batch:
                    metadata = dict(event.metadata) if isinstance(event.metadata, dict) else {}
                    metadata.update(AuditIntegrityService.integrity_stamp_marker(event))
                    AuditEvent.objects.filter(pk=event.pk).update(metadata=metadata)

            last_pk = batch[-1].pk
            done += len(batch)
            self.stdout.write(f"  restamped {done}/{pending}")

        remaining = AuditEvent.objects.filter(_non_v2_filter()).count()
        if remaining:
            raise CommandError(f"Restamp incomplete: {remaining} rows still lack a v2 marker - re-run to resume")
        self.stdout.write(self.style.SUCCESS(f"Restamped {done} events; all rows now carry v2 markers"))
