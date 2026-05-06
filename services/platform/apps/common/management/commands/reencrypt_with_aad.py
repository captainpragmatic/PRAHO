"""Re-encrypt EncryptedJSONField values with AAD context binding.

Migrates existing v1/legacy ciphertext to v2 format with AAD bound to
table:field:pk. Idempotent — skips rows already in v2 format.

Usage:
    python manage.py reencrypt_with_aad              # re-encrypt all
    python manage.py reencrypt_with_aad --dry-run    # preview only
    python manage.py reencrypt_with_aad --batch=500  # custom batch size
"""

from __future__ import annotations

import json
import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandParser
from django.db import models, transaction

from apps.common.encryption import VERSIONED_V2_PREFIX, decrypt_sensitive_data, encrypt_sensitive_data
from apps.common.fields import EncryptedJSONField

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 100


class Command(BaseCommand):
    help = "Re-encrypt EncryptedJSONField values with AAD context binding (v1→v2)"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--dry-run", action="store_true", help="Preview without changes")
        parser.add_argument("--batch", type=int, default=DEFAULT_BATCH_SIZE, help="Batch size")

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run = options["dry_run"]
        batch_size = options["batch"]

        from django.apps import apps  # noqa: PLC0415

        total_migrated = 0
        total_skipped = 0

        for model in apps.get_models():
            encrypted_fields = [f for f in model._meta.get_fields() if isinstance(f, EncryptedJSONField)]
            if not encrypted_fields:
                continue

            for field in encrypted_fields:
                migrated, skipped = self._migrate_field(model, field, batch_size, dry_run)
                total_migrated += migrated
                total_skipped += skipped

        self.stdout.write("")
        prefix = "[DRY RUN] " if dry_run else ""
        self.stdout.write(f"{prefix}Total: {total_migrated} migrated, {total_skipped} already v2 or NULL")

    def _migrate_field(
        self, model: type[models.Model], field: EncryptedJSONField, batch_size: int, dry_run: bool
    ) -> tuple[int, int]:
        table = model._meta.db_table
        field_name = field.attname
        self.stdout.write(f"  Processing {table}.{field_name}...")

        qs = model._default_manager.exclude(**{field_name: None}).exclude(**{field_name: ""})
        migrated = 0
        skipped = 0

        for obj in qs.iterator(chunk_size=batch_size):
            raw_value = getattr(obj, field_name)

            # Check if already v2 — value might be a dict (ORM decrypted) or string (raw)
            if isinstance(raw_value, str) and raw_value.startswith(VERSIONED_V2_PREFIX):
                skipped += 1
                continue

            # Decrypt current value (handles v1, legacy, and plaintext)
            if isinstance(raw_value, dict):
                plaintext_dict = raw_value
            elif isinstance(raw_value, str):
                try:
                    decrypted = decrypt_sensitive_data(raw_value)
                    plaintext_dict = json.loads(decrypted)
                except Exception:
                    self.stdout.write(self.style.WARNING(f"    Skip {obj.pk}: cannot decrypt"))
                    skipped += 1
                    continue
            else:
                skipped += 1
                continue

            # Build AAD and re-encrypt
            aad = f"{table}:{field_name}:{obj.pk}".encode()
            json_str = json.dumps(plaintext_dict)
            encrypted_v2 = encrypt_sensitive_data(json_str, aad=aad)

            if dry_run:
                self.stdout.write(f"    Would migrate: {obj.pk}")
            else:
                with transaction.atomic():
                    # Use queryset update to avoid triggering pre_save
                    model._default_manager.filter(pk=obj.pk).update(**{field_name: encrypted_v2})

            migrated += 1

        self.stdout.write(f"    {migrated} migrated, {skipped} skipped")
        return migrated, skipped
