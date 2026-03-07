"""Re-encrypt plaintext EmailLog body fields to AES format.

Idempotent: already-encrypted rows are skipped. Safe to run multiple times.
Uses .update() instead of .save() to avoid double-encryption via model signals
and to bypass SoftDeleteManager restrictions (ADR-0016).
"""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Q

from apps.common.encryption import encrypt_value, is_encrypted
from apps.notifications.models import EmailLog

logger = logging.getLogger(__name__)

PROGRESS_INTERVAL = 100


def _build_row_updates(email_log: EmailLog) -> dict[str, Any]:
    """Build update dict for a single EmailLog row. Returns empty dict if no update needed."""
    updates: dict[str, Any] = {}

    if email_log.body_text and not is_encrypted(email_log.body_text):
        encrypted_text = encrypt_value(email_log.body_text)
        if not encrypted_text:
            raise ValueError(f"Encryption returned empty body_text value for log {email_log.id}")
        updates["body_text"] = encrypted_text

    if email_log.body_html and not is_encrypted(email_log.body_html):
        encrypted_html = encrypt_value(email_log.body_html)
        if not encrypted_html:
            raise ValueError(f"Encryption returned empty body_html value for log {email_log.id}")
        updates["body_html"] = encrypted_html

    if not updates and not email_log.body_encrypted:
        # Row has body_encrypted=False but bodies are already encrypted
        updates["body_encrypted"] = True
    elif updates:
        updates["body_encrypted"] = True

    return updates


def _apply_optimistic_update(email_log: EmailLog, updates: dict[str, Any]) -> bool:
    """Apply update with optimistic lock. Returns True if row was updated."""
    conditions: dict[str, Any] = {"pk": email_log.pk}
    if "body_text" in updates:
        conditions["body_text"] = email_log.body_text
    if "body_html" in updates:
        conditions["body_html"] = email_log.body_html
    return EmailLog.objects.filter(**conditions).update(**updates) > 0


class Command(BaseCommand):
    help = (
        "Scan EmailLog rows and re-encrypt plaintext body fields. "
        "Idempotent — safe to run repeatedly after encryption infra recovery."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Only report what would be updated, without writing data.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=500,
            help="Rows to fetch per iterator batch (default: 500).",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run = bool(options["dry_run"])
        batch_size = int(options["batch_size"])

        if batch_size < 1:
            raise CommandError("--batch-size must be >= 1")

        targets = EmailLog.objects.filter(
            Q(body_encrypted=False)
            | (Q(body_text__isnull=False) & ~Q(body_text="") & ~Q(body_text__startswith="aes:"))
            | (Q(body_html__isnull=False) & ~Q(body_html="") & ~Q(body_html__startswith="aes:"))
        ).only("id", "body_text", "body_html", "body_encrypted")

        scanned = 0
        updated = 0
        skipped = 0
        failed = 0
        total = targets.count()

        self.stdout.write(f"Scanning {total} EmailLog row(s) for plaintext body fields...")

        for email_log in targets.iterator(chunk_size=batch_size):
            scanned += 1
            try:
                updates = _build_row_updates(email_log)
                if not updates:
                    continue
                if dry_run or _apply_optimistic_update(email_log, updates):
                    updated += 1
                else:
                    skipped += 1
            except Exception as exc:
                failed += 1
                logger.exception("Failed re-encrypting EmailLog id=%s: %s", email_log.id, exc)

            if scanned % PROGRESS_INTERVAL == 0:
                self.stdout.write(f"  Progress: {scanned}/{total} scanned, {updated} updated, {failed} failed")

        mode = "Dry run complete" if dry_run else "Re-encryption complete"
        self.stdout.write(
            f"{mode}. scanned={scanned}, updated={updated}, skipped={skipped}, "
            f"failed={failed}, unchanged={max(scanned - updated - skipped - failed, 0)}"
        )
