"""
Publish the audit chain head to an external anchor sink (#313, ADR-0043).

Run on a schedule (hourly is a reasonable default). Each run pins "the chain reached at
least this far" in a record held OUTSIDE this database, which is what makes tail truncation
detectable — chaining alone cannot see it, because lopping off the last N links leaves the
surviving links internally consistent and the head row can be rewritten to match.

The anchor's value is entirely in the external copy. If AUDIT_ANCHOR_SINK=none, or the sink
writes somewhere an attacker who owns the database can also reach, this command provides no
protection against truncation.

Verify with: python manage.py run_integrity_check --type anchor_verification
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.audit.services import AuditIntegrityService


class Command(BaseCommand):
    help = "Publish the audit chain head to the configured external anchor sink"

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--verify",
            action="store_true",
            help="Verify the live chain against locally recorded anchors instead of publishing",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if not getattr(settings, "AUDIT_CHAIN_ENABLED", False):
            raise CommandError("AUDIT_CHAIN_ENABLED is off - there is no live chain to anchor")

        if options["verify"]:
            self._verify()
            return

        result = AuditIntegrityService.publish_chain_anchor()
        if result.is_err():
            raise CommandError(f"Anchor publication failed: {result.unwrap_err()}")

        record = result.unwrap()
        sink = getattr(settings, "AUDIT_ANCHOR_SINK", "logfile")
        self.stdout.write(
            self.style.SUCCESS(
                f"Anchored chain head: sequence={record['sequence']} links={record['link_count']} sink={sink}"
            )
        )
        if sink == "none":
            self.stdout.write(
                self.style.WARNING(
                    "AUDIT_ANCHOR_SINK=none - nothing was published externally, so tail truncation remains undetectable"
                )
            )

    def _verify(self) -> None:
        findings = AuditIntegrityService._verify_chain_anchors()
        if not findings:
            self.stdout.write(self.style.SUCCESS("All anchors verify against the live chain"))
            return

        for finding in findings:
            self.stdout.write(self.style.ERROR(f"[{finding['severity']}] {finding['type']}: {finding['description']}"))
        raise CommandError(f"{len(findings)} anchor finding(s) - the chain does not match its anchors")
