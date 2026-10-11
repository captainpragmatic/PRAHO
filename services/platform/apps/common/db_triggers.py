"""Database triggers that keep an encryption context column immutable (ADR-0040).

An EncryptedJSONField bound to a context column (`aad_context_field`) can only be decrypted
with that row's context. Changing the context would make the value unreadable, or let a
ciphertext from another row read as this one. The trigger refuses any UPDATE that changes it.

PostgreSQL gets a plpgsql function and trigger, SQLite a RAISE(ABORT) trigger, and any other
backend fails closed. SQLite drops a table's triggers whenever Django rebuilds the table, so a
migration that alters such a table on SQLite must create the trigger again, after the change.

Migrations call these from their own top-level functions, so the migration stays serializable.
"""

from __future__ import annotations

from typing import Any


def create_context_immutability_trigger(schema_editor: Any, *, table: str, column: str, name: str) -> None:
    """Create trigger `name` refusing a change of `table.column`."""
    vendor = schema_editor.connection.vendor
    quote = schema_editor.quote_name
    message = f"{table}.{column} is immutable"
    if vendor == "postgresql":
        schema_editor.execute(
            f"""
            CREATE FUNCTION {quote(name)}()
            RETURNS trigger AS $$
            BEGIN
                IF NEW.{quote(column)} IS DISTINCT FROM OLD.{quote(column)} THEN
                    RAISE EXCEPTION '{message}';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
        schema_editor.execute(
            f"""
            CREATE TRIGGER {quote(name)}
            BEFORE UPDATE OF {quote(column)} ON {quote(table)}
            FOR EACH ROW
            EXECUTE FUNCTION {quote(name)}()
            """
        )
    elif vendor == "sqlite":
        schema_editor.execute(
            f"""
            CREATE TRIGGER {quote(name)}
            BEFORE UPDATE OF {quote(column)} ON {quote(table)}
            FOR EACH ROW
            WHEN OLD.{quote(column)} IS NOT NEW.{quote(column)}
            BEGIN
                SELECT RAISE(ABORT, '{message}');
            END
            """
        )
    else:
        raise RuntimeError(f"{table}.{column} immutability supports PostgreSQL and SQLite only")


def drop_context_immutability_trigger(schema_editor: Any, *, table: str, name: str) -> None:
    """Drop trigger `name` (and its PostgreSQL function) if it exists."""
    quote = schema_editor.quote_name
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(f"DROP TRIGGER IF EXISTS {quote(name)} ON {quote(table)}")
        schema_editor.execute(f"DROP FUNCTION IF EXISTS {quote(name)}()")
    else:
        schema_editor.execute(f"DROP TRIGGER IF EXISTS {quote(name)}")
