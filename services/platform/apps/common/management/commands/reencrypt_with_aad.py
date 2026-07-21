"""Re-encrypt EncryptedJSONField values with AAD context binding.

Migrates existing v1/legacy ciphertext (and any stored plaintext JSON) to the v2
wire format with AAD bound to the field's configured stable row context (falling
back to the primary key for compatibility fields).

Design notes (why this reads raw SQL rather than the ORM):
  * ``EncryptedJSONField.from_db_value`` decrypts on read, so a value fetched via the
    ORM is already a Python object — an "is it v2?" check on it can never fire, and a
    ``require_v2`` field would hide the very v1 rows this command must migrate. Reading
    the physical column with a converter-free cursor avoids both.
  * The scan runs over the physical table, so soft-deleted rows are included (the model's
    default manager would filter them out and leave them un-migrated).
  * Each write is a compare-and-swap constrained by the value we read, so a concurrent
    application save is never silently overwritten with stale data; a row that keeps
    changing is retried and, if still unresolved, causes a non-zero exit.
  * Already-v2 rows are decrypted to confirm they are readable before being skipped, so a
    corrupt/tampered v2 blob is reported (never counted as healthy).

OPERATIONAL NOTE — PostgreSQL: the raw read/CAS relies on Django's jsonb text loader and
str→jsonb coercion. The automated suite exercises SQLite only. Before a production run,
do a ``--dry-run`` and then a real run against a PostgreSQL copy of the data and confirm
the reported counts, then run against production.

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
from dataclasses import dataclass
from typing import Any, cast

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection, models

from apps.common.encryption import ENCRYPTED_PREFIX, VERSIONED_V2_PREFIX, decrypt_sensitive_data, encrypt_sensitive_data
from apps.common.fields import EncryptedJSONField

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 100
MAX_CAS_ATTEMPTS = 3  # re-read + retry a row that changed under us before giving up


@dataclass(frozen=True)
class FieldSQL:
    table_name: str
    attname: str
    q_table: str
    q_col: str
    q_pk: str
    q_context: str


@dataclass(frozen=True)
class MigrationRow:
    field: FieldSQL
    expected_aad: bytes
    pk: Any
    raw: Any


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
            f"{totals['corrupt']} corrupt, {totals['unresolved']} unresolved"
        )

        # Unresolved rows may still be un-migrated — always fail so require_v2 is not enabled
        # on the false assumption that every row is v2.
        if totals["unresolved"]:
            raise CommandError(
                f"{totals['unresolved']} row(s) could not be migrated because they kept changing "
                "concurrently; re-run the command."
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
        column_name = field.column  # physical column, used only as the (quoted) SQL identifier
        attname = field.attname  # AAD field component — MUST match EncryptedJSONField._build_aad
        pk_name = model._meta.pk.column
        quote = connection.ops.quote_name
        q_table, q_col, q_pk = quote(table_name), quote(column_name), quote(pk_name)
        context_field = cast(
            "models.Field[Any, Any]",
            (model._meta.get_field(field.aad_context_field) if field.aad_context_field else model._meta.pk),
        )
        if context_field.column is None:
            raise CommandError(f"AAD context field for {table_name}.{attname} has no database column")
        field_sql = FieldSQL(
            table_name=table_name,
            attname=attname,
            q_table=q_table,
            q_col=q_col,
            q_pk=q_pk,
            q_context=quote(context_field.column),
        )

        self.stdout.write(f"  Processing {table_name}.{column_name}...")

        # Keyset-paginate over the physical table (converter-free, includes soft-deleted rows).
        # Reads are drained fully before any write so we never write on an open read cursor.
        last_pk: Any = None
        while True:
            rows = self._read_batch(field_sql, last_pk, batch_size)
            if not rows:
                break
            for pk, raw_context, raw in rows:
                last_pk = pk
                context = context_field.to_python(raw_context)
                if context is None:
                    totals["corrupt"] += 1
                    self.stdout.write(self.style.WARNING(f"    Missing AAD context {table_name}.{attname} pk={pk}"))
                    continue
                expected_aad = f"{table_name}:{attname}:{context}".encode()
                self._migrate_row(
                    MigrationRow(
                        field=field_sql,
                        expected_aad=expected_aad,
                        pk=pk,
                        raw=raw,
                    ),
                    dry_run,
                    totals,
                )

    def _read_batch(
        self,
        field: FieldSQL,
        last_pk: Any,
        batch_size: int,
    ) -> list[tuple[Any, Any, Any]]:
        raw_column = f"{field.q_col}::text" if connection.vendor == "postgresql" else field.q_col
        with connection.cursor() as cursor:
            if last_pk is None:
                cursor.execute(
                    f"SELECT {field.q_pk}, {field.q_context}, {raw_column} "  # noqa: S608
                    f"FROM {field.q_table} WHERE {field.q_col} IS NOT NULL "
                    f"ORDER BY {field.q_pk} LIMIT %s",
                    [batch_size],
                )
            else:
                cursor.execute(
                    f"SELECT {field.q_pk}, {field.q_context}, {raw_column} "  # noqa: S608
                    f"FROM {field.q_table} WHERE {field.q_col} IS NOT NULL "
                    f"AND {field.q_pk} > %s ORDER BY {field.q_pk} LIMIT %s",
                    [last_pk, batch_size],
                )
            rows: list[tuple[Any, Any, Any]] = cursor.fetchall()
            return rows

    def _migrate_row(
        self,
        row: MigrationRow,
        dry_run: bool,
        totals: Counter[str],
    ) -> None:
        raw = row.raw
        for _attempt in range(MAX_CAS_ATTEMPTS):
            kind, new_stored = self._classify(row.expected_aad, raw)

            if kind == "corrupt":
                totals["corrupt"] += 1
                self.stdout.write(
                    self.style.WARNING(
                        f"    Corrupt (unreadable) {row.field.table_name}.{row.field.attname} pk={row.pk}"
                    )
                )
                return
            if kind == "skip_v2":
                totals["skipped_v2"] += 1
                return

            if dry_run:
                totals["migrated"] += 1
                self.stdout.write(f"    Would migrate {row.field.table_name}.{row.field.attname} pk={row.pk}")
                return

            assert new_stored is not None  # kind == "migrate" guarantees this
            if self._cas_update(row.field, row.pk, new_stored, raw) == 1:
                totals["migrated"] += 1
                return

            # CAS miss: the row changed since we read it. Re-read the current value and retry
            # so we never advance past a row that is still un-migrated.
            raw = self._read_one(row.field, row.pk)
            if raw is None:
                totals["skipped_deleted"] += 1
                return

        totals["unresolved"] += 1
        self.stdout.write(
            self.style.WARNING(
                f"    Unresolved after {MAX_CAS_ATTEMPTS} attempts (row kept changing) "
                f"{row.field.table_name}.{row.field.attname} pk={row.pk}"
            )
        )

    def _classify(self, expected_aad: bytes, raw: Any) -> tuple[str, str | None]:
        """Return (kind, new_stored) for a raw column value.

        kind is 'corrupt', 'skip_v2', or 'migrate' (new_stored set only for 'migrate').
        The column holds a JSON string, e.g. '"aes:v2:..."' (jsonb / quoted text).
        """
        try:
            inner = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            if isinstance(raw, str) and raw.startswith(ENCRYPTED_PREFIX):
                inner = raw
            else:
                return "corrupt", None

        # Already v2 — confirm it is readable under this row's exact AAD before
        # skipping, so a corrupt, tampered, or transplanted blob is never reported healthy.
        if isinstance(inner, str) and inner.startswith(VERSIONED_V2_PREFIX):
            try:
                decrypt_sensitive_data(inner, aad=expected_aad)
            except Exception:
                return "corrupt", None
            return "skip_v2", None

        # Recover the plaintext: decrypt v1/legacy ciphertext, or take stored plaintext as-is.
        if isinstance(inner, str) and inner.startswith(ENCRYPTED_PREFIX):
            try:
                plaintext_value = json.loads(decrypt_sensitive_data(inner))
            except Exception:
                return "corrupt", None
        else:
            plaintext_value = inner

        new_wire = encrypt_sensitive_data(json.dumps(plaintext_value), aad=expected_aad)
        return "migrate", json.dumps(new_wire)  # store as a JSON string, matching the ORM's write

    def _cas_update(
        self,
        field: FieldSQL,
        pk: Any,
        new_stored: str,
        old_raw: Any,
    ) -> int:
        # Only overwrite if the row still holds the value we read. On PostgreSQL the jsonb
        # column is compared as text to match the value the cursor returned. A single
        # UPDATE statement is atomic on its own — no surrounding transaction needed.
        cas = f"{field.q_col}::text = %s" if connection.vendor == "postgresql" else f"{field.q_col} = %s"
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE {field.q_table} SET {field.q_col} = %s "  # noqa: S608
                f"WHERE {field.q_pk} = %s AND {cas}",
                [new_stored, pk, old_raw],
            )
            return int(cursor.rowcount)

    def _read_one(self, field: FieldSQL, pk: Any) -> Any:
        raw_column = f"{field.q_col}::text" if connection.vendor == "postgresql" else field.q_col
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {raw_column} FROM {field.q_table} "  # noqa: S608
                f"WHERE {field.q_pk} = %s",
                [pk],
            )
            row = cursor.fetchone()
        return row[0] if row else None
