"""Re-encrypt plaintext EmailLog body fields to AES format."""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand
from django.db.models import Q

from apps.common.encryption import encrypt_value, is_encrypted
from apps.notifications.models import EmailLog

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Scan EmailLog rows and re-encrypt plaintext body fields."

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

        targets = EmailLog.objects.filter(
            (Q(body_text__isnull=False) & ~Q(body_text="") & ~Q(body_text__startswith="aes:"))
            | (Q(body_html__isnull=False) & ~Q(body_html="") & ~Q(body_html__startswith="aes:"))
        ).only("id", "body_text", "body_html")

        scanned = 0
        updated = 0
        failed = 0
        total = targets.count()

        self.stdout.write(f"Scanning {total} EmailLog row(s) for plaintext body fields...")

        for email_log in targets.iterator(chunk_size=batch_size):
            scanned += 1
            updates: dict[str, str] = {}
            try:
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

                if not updates:
                    continue

                if not dry_run:
                    EmailLog.objects.filter(pk=email_log.pk).update(**updates)
                updated += 1
            except Exception as exc:  # pragma: no cover - defensive command guard
                failed += 1
                logger.exception("Failed re-encrypting EmailLog id=%s: %s", email_log.id, exc)

        mode = "Dry run complete" if dry_run else "Re-encryption complete"
        self.stdout.write(
            f"{mode}. scanned={scanned}, updated={updated}, failed={failed}, unchanged={max(scanned - updated - failed, 0)}"
        )
