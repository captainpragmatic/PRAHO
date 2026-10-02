"""Make a payment method's encryption context immutable at the database level.

Carried forward verbatim from customers 0019 of the old history (ADR-0052).
PostgreSQL gets a plpgsql function and trigger, SQLite a RAISE(ABORT)
trigger, and any other backend fails closed.

SQLite drops a table's triggers whenever Django rebuilds the table, so any
future migration that alters customer_payment_methods must re-create this
trigger.
"""

from typing import Any

from django.db import migrations


def create_context_immutability_trigger(apps: Any, schema_editor: Any) -> None:
    vendor = schema_editor.connection.vendor
    if vendor == "postgresql":
        schema_editor.execute(
            """
            CREATE FUNCTION customer_payment_method_encryption_context_immutable()
            RETURNS trigger AS $$
            BEGIN
                IF NEW.encryption_context_id IS DISTINCT FROM OLD.encryption_context_id THEN
                    RAISE EXCEPTION 'customer payment method encryption context is immutable';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
        schema_editor.execute(
            """
            CREATE TRIGGER customer_payment_method_encryption_context_immutable
            BEFORE UPDATE OF encryption_context_id ON customer_payment_methods
            FOR EACH ROW
            EXECUTE FUNCTION customer_payment_method_encryption_context_immutable()
            """
        )
    elif vendor == "sqlite":
        schema_editor.execute(
            """
            CREATE TRIGGER customer_payment_method_encryption_context_immutable
            BEFORE UPDATE OF encryption_context_id ON customer_payment_methods
            FOR EACH ROW
            WHEN OLD.encryption_context_id IS NOT NEW.encryption_context_id
            BEGIN
                SELECT RAISE(ABORT, 'customer payment method encryption context is immutable');
            END
            """
        )
    else:
        raise RuntimeError(
            "payment-method encryption context supports PostgreSQL and SQLite only"
        )


def drop_context_immutability_trigger(apps: Any, schema_editor: Any) -> None:
    vendor = schema_editor.connection.vendor
    schema_editor.execute(
        "DROP TRIGGER IF EXISTS customer_payment_method_encryption_context_immutable "
        "ON customer_payment_methods"
        if vendor == "postgresql"
        else "DROP TRIGGER IF EXISTS customer_payment_method_encryption_context_immutable"
    )
    if vendor == "postgresql":
        schema_editor.execute(
            "DROP FUNCTION IF EXISTS customer_payment_method_encryption_context_immutable()"
        )


class Migration(migrations.Migration):
    dependencies = [
        ("customers", "0002_initial"),
    ]

    operations = [
        migrations.RunPython(
            create_context_immutability_trigger,
            drop_context_immutability_trigger,
        ),
    ]
