"""Re-encrypt EncryptedJSONField values with AAD context binding.

Migrates existing v1/legacy ciphertext (and any stored plaintext JSON) to the v2
wire format with AAD bound to ``table:field:pk``.

Design notes (why this reads raw SQL rather than the ORM):
  * ``EncryptedJSONField.from_db_value`` decrypts on read, so a value fetched via the
    ORM is already a Python object — an "is it v2?" check on it can never fire, and a
    ``require_v2`` field would hide the very v1 rows this command must migrate. Reading
    the physical column with a converter-free cursor avoids both.
  * The scan runs over the physical table, so soft-deleted rows are included (the model's
    default manager would filter them out and leave them un-migrated).
  * Each write is a compare-and-swap constrained by the value we read, so a concurrent
    application save is never silently overwritten with stale data.

Usage:
    python manage.py reencrypt_with_aad                 # migrate all
    python manage.py reencrypt_with_aad --dry-run       # preview only
    python manage.py reencrypt_with_aad --batch=500     # rows read per round
    python manage.py reencrypt_with_aad --allow-corrupt # exit 0 even if corrupt rows found
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, models, transaction

from apps.common.encryption import ENCRYPTED_PREFIX, VERSIONED_V2_PREFIX, decrypt_sensitive_data, encrypt_sensitive_data
from apps.common.fields import EncryptedJSONField

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 100


class Command(BaseCommand):
    help = "Re-encrypt EncryptedJSONField values with AAD context binding (v1/legacy/plaintext → v2)"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
        parser.add_argument("--batch", type=int, default=DEFAULT_BATCH_SIZE, help="Rows read per round")
        parser.add_argument(
            "--allow-corrupt",
            action="store_true",
            help="Exit 0 even when undecryptable rows are found (they are still reported, never migrated)",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        dry_run: bool = options["dry_run"]
        batch_size: int = options["batch"]
        allow_corrupt: bool = options["allow_corrupt"]

        if batch_size <= 0:
            raise CommandError("--batch must be a positive integer")

        from django.apps import apps  # noqa: PLC0415  # avoid app-registry import at module load

        totals: Counter[str] = Counter()

        for model in apps.get_models():
            encrypted_fields = [f for f in model._meta.get_fields() if isinstance(f, EncryptedJSONField)]
            for field in encrypted_fields:
                self._migrate_field(model, field, batch_size, dry_run, totals)

        prefix = "[DRY RUN] " if dry_run else ""
        self.stdout.write("")
        self.stdout.write(
            f"{prefix}Total: {totals['migrated']} migrated, {totals['skipped_v2']} already v2, "
            f"{totals['corrupt']} corrupt, {totals['concurrent']} changed-concurrently"
        )

        if totals["corrupt"] and not allow_corrupt:
            raise CommandError(
                f"{totals['corrupt']} undecryptable row(s) found and left untouched; "
                "investigate them, then re-run with --allow-corrupt to proceed."
            )

    def _migrate_field(
        self,
        model: type[models.Model],
        field: EncryptedJSONField,
        batch_size: int,
        dry_run: bool,
        totals: Counter[str],
    ) -> None:
        table_name = model._meta.db_table
        field_name = field.column
        pk_name = model._meta.pk.column
        quote = connection.ops.quote_name
        q_table, q_col, q_pk = quote(table_name), quote(field_name), quote(pk_name)

        self.stdout.write(f"  Processing {table_name}.{field_name}...")

        # Keyset-paginate over the physical table (converter-free, includes soft-deleted rows).
        # Reads are drained fully before any write so we never write on an open read cursor.
        last_pk: Any = None
        while True:
            rows = self._read_batch(q_table, q_col, q_pk, last_pk, batch_size)
            if not rows:
                break
            for pk, raw in rows:
                last_pk = pk
                self._migrate_row(table_name, field_name, q_table, q_col, q_pk, pk, raw, dry_run, totals)

        self.stdout.write(
            f"    {totals['migrated']} migrated, {totals['skipped_v2']} already v2, "
            f"{totals['corrupt']} corrupt, {totals['concurrent']} changed-concurrently (cumulative)"
        )

    def _read_batch(self, q_table: str, q_col: str, q_pk: str, last_pk: Any, batch_size: int) -> list[tuple[Any, Any]]:
        with connection.cursor() as cursor:
            if last_pk is None:
                cursor.execute(
                    f"SELECT {q_pk}, {q_col} FROM {q_table} "  # noqa: S608 — identifiers are quoted model metadata
                    f"WHERE {q_col} IS NOT NULL ORDER BY {q_pk} LIMIT %s",
                    [batch_size],
                )
            else:
                cursor.execute(
                    f"SELECT {q_pk}, {q_col} FROM {q_table} "  # noqa: S608 — identifiers are quoted model metadata
                    f"WHERE {q_col} IS NOT NULL AND {q_pk} > %s ORDER BY {q_pk} LIMIT %s",
                    [last_pk, batch_size],
                )
            rows: list[tuple[Any, Any]] = cursor.fetchall()
            return rows

    def _migrate_row(  # noqa: PLR0913 — cohesive per-row context, not worth a dataclass here
        self,
        table_name: str,
        field_name: str,
        q_table: str,
        q_col: str,
        q_pk: str,
        pk: Any,
        raw: Any,
        dry_run: bool,
        totals: Counter[str],
    ) -> None:
        # The column holds a JSON string, e.g. '"aes:v2:..."' (jsonb / quoted text).
        try:
            inner = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            totals["corrupt"] += 1
            self.stdout.write(self.style.WARNING(f"    Corrupt (non-JSON column) {table_name}.{field_name} pk={pk}"))
            return

        # Already v2 — skip (this is what makes the command idempotent).
        if isinstance(inner, str) and inner.startswith(VERSIONED_V2_PREFIX):
            totals["skipped_v2"] += 1
            return

        # Recover the plaintext value: decrypt v1/legacy ciphertext, or take stored plaintext as-is.
        if isinstance(inner, str) and inner.startswith(ENCRYPTED_PREFIX):
            try:
                plaintext_value = json.loads(decrypt_sensitive_data(inner))
            except Exception:
                totals["corrupt"] += 1
                self.stdout.write(
                    self.style.WARNING(f"    Corrupt (undecryptable) {table_name}.{field_name} pk={pk}")
                )
                return
        else:
            plaintext_value = inner

        aad = f"{table_name}:{field_name}:{pk}".encode()
        new_wire = encrypt_sensitive_data(json.dumps(plaintext_value), aad=aad)
        new_stored = json.dumps(new_wire)  # store as a JSON string, matching the ORM's write

        if dry_run:
            totals["migrated"] += 1
            self.stdout.write(f"    Would migrate {table_name}.{field_name} pk={pk}")
            return

        # Compare-and-swap: only overwrite if the row still holds the value we read, so a
        # concurrent application write is never clobbered. On PostgreSQL the jsonb column is
        # compared as text to match the value the cursor returned.
        cas = f"{q_col}::text = %s" if connection.vendor == "postgresql" else f"{q_col} = %s"
        with transaction.atomic(), connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE {q_table} SET {q_col} = %s WHERE {q_pk} = %s AND {cas}",  # noqa: S608 — quoted identifiers
                [new_stored, pk, raw],
            )
            affected = cursor.rowcount

        if affected == 1:
            totals["migrated"] += 1
        else:
            totals["concurrent"] += 1
            self.stdout.write(
                self.style.WARNING(f"    Skipped (changed concurrently) {table_name}.{field_name} pk={pk}")
            )
