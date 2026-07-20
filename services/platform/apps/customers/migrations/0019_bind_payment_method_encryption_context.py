import json
import uuid
from collections.abc import Iterator
from typing import Any

from django.db import migrations, models

import apps.common.fields
from apps.common.encryption import (
    ENCRYPTED_PREFIX,
    VERSIONED_V2_PREFIX,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)
from apps.common.fields import _extract_embedded_aad

TABLE = "customer_payment_methods"
COLUMN = "bank_details"
CONTEXT_COLUMN = "encryption_context_id"
BATCH_SIZE = 500


def _decoded_column(raw: Any) -> Any:
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        # Django's PostgreSQL adapter can return a JSON string as its already-decoded
        # Python string, while SQLite returns the quoted JSON representation.
        if raw.startswith(ENCRYPTED_PREFIX):
            return raw
        raise RuntimeError("customer payment bank details contain invalid JSON") from exc


def _plaintext_for_forward(inner: Any, pk: Any) -> dict[str, Any]:
    if isinstance(inner, str) and inner.startswith(ENCRYPTED_PREFIX):
        if inner.startswith(VERSIONED_V2_PREFIX):
            embedded = _extract_embedded_aad(inner)
            allowed = {
                f"{TABLE}:{COLUMN}:{pk}".encode(),
                f"{TABLE}:{COLUMN}:".encode(),
            }
            if embedded not in allowed:
                raise RuntimeError(
                    f"customer payment method {pk} has ciphertext bound to an unexpected context"
                )
            plaintext = decrypt_sensitive_data(inner, aad=embedded)
        else:
            plaintext = decrypt_sensitive_data(inner)
        try:
            value = json.loads(plaintext)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"customer payment method {pk} decrypts to invalid JSON"
            ) from exc
    else:
        value = inner

    if not isinstance(value, dict):
        raise RuntimeError(
            f"customer payment method {pk} bank details must be a JSON object"
        )
    return value


def _stored_wire(value: dict[str, Any], aad: bytes) -> str:
    wire = encrypt_sensitive_data(json.dumps(value), aad=aad)
    return json.dumps(wire)


def _rows(schema_editor: Any) -> Iterator[tuple[Any, Any, Any]]:
    connection = schema_editor.connection
    quote = connection.ops.quote_name
    q_table = quote(TABLE)
    q_pk = quote("id")
    q_context = quote(CONTEXT_COLUMN)
    q_column = quote(COLUMN)
    raw_column = (
        f"{q_column}::text"
        if connection.vendor == "postgresql"
        else q_column
    )
    last_pk: Any = None
    while True:
        with connection.cursor() as cursor:
            if last_pk is None:
                cursor.execute(
                    f"SELECT {q_pk}, {q_context}, {raw_column} FROM {q_table} "  # noqa: S608
                    f"ORDER BY {q_pk} LIMIT %s",
                    [BATCH_SIZE],
                )
            else:
                cursor.execute(
                    f"SELECT {q_pk}, {q_context}, {raw_column} FROM {q_table} "  # noqa: S608
                    f"WHERE {q_pk} > %s ORDER BY {q_pk} LIMIT %s",
                    [last_pk, BATCH_SIZE],
                )
            batch = cursor.fetchall()
        if not batch:
            return
        yield from batch
        last_pk = batch[-1][0]


def bind_encryption_context(apps: Any, schema_editor: Any) -> None:
    connection = schema_editor.connection
    quote = connection.ops.quote_name
    q_table = quote(TABLE)
    q_pk = quote("id")
    q_context = quote(CONTEXT_COLUMN)
    q_column = quote(COLUMN)
    context_field = apps.get_model("customers", "CustomerPaymentMethod")._meta.get_field(
        CONTEXT_COLUMN
    )

    for pk, existing_context, raw in _rows(schema_editor):
        if existing_context is not None:
            raise RuntimeError(
                f"customer payment method {pk} already has an encryption context"
            )
        context = uuid.uuid4()
        stored_context = context_field.get_db_prep_value(context, connection)
        stored_value = None
        if raw is not None:
            plaintext = _plaintext_for_forward(_decoded_column(raw), pk)
            aad = f"{TABLE}:{COLUMN}:{context}".encode()
            stored_value = _stored_wire(plaintext, aad)

        with connection.cursor() as cursor:
            raw_cas = (
                f"{q_column}::text = %s"
                if connection.vendor == "postgresql"
                else f"{q_column} = %s"
            )
            value_predicate = (
                f"{q_column} IS NULL"
                if raw is None
                else raw_cas
            )
            params = [stored_context, stored_value, pk]
            if raw is not None:
                params.append(raw)
            cursor.execute(
                f"UPDATE {q_table} SET {q_context} = %s, {q_column} = %s "  # noqa: S608
                f"WHERE {q_pk} = %s AND {q_context} IS NULL "
                f"AND {value_predicate}",
                params,
            )
            if cursor.rowcount != 1:
                raise RuntimeError(
                    f"customer payment method {pk} changed during encryption migration"
                )


def restore_primary_key_context(apps: Any, schema_editor: Any) -> None:
    connection = schema_editor.connection
    quote = connection.ops.quote_name
    q_table = quote(TABLE)
    q_pk = quote("id")
    q_context = quote(CONTEXT_COLUMN)
    q_column = quote(COLUMN)

    for pk, context, raw in _rows(schema_editor):
        if context is None:
            raise RuntimeError(
                f"customer payment method {pk} has no encryption context"
            )
        if raw is None:
            continue
        inner = _decoded_column(raw)
        if not isinstance(inner, str) or not inner.startswith(VERSIONED_V2_PREFIX):
            raise RuntimeError(
                f"customer payment method {pk} is not context-bound v2 ciphertext"
            )
        canonical_context = str(uuid.UUID(str(context)))
        current_aad = f"{TABLE}:{COLUMN}:{canonical_context}".encode()
        try:
            value = json.loads(decrypt_sensitive_data(inner, aad=current_aad))
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                f"customer payment method {pk} cannot be restored"
            ) from exc
        old_aad = f"{TABLE}:{COLUMN}:{pk}".encode()
        restored = _stored_wire(value, old_aad)
        with connection.cursor() as cursor:
            raw_cas = (
                f"{q_column}::text = %s"
                if connection.vendor == "postgresql"
                else f"{q_column} = %s"
            )
            cursor.execute(
                f"UPDATE {q_table} SET {q_column} = %s "  # noqa: S608
                f"WHERE {q_pk} = %s AND {q_context} = %s AND {raw_cas}",
                [restored, pk, context, raw],
            )
            if cursor.rowcount != 1:
                raise RuntimeError(
                    f"customer payment method {pk} changed during encryption rollback"
                )


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
        ("customers", "0018_remove_dormant_auto_payment_flag"),
    ]

    operations = [
        migrations.AddField(
            model_name="customerpaymentmethod",
            name="encryption_context_id",
            field=models.UUIDField(editable=False, null=True),
        ),
        migrations.RunPython(
            bind_encryption_context,
            restore_primary_key_context,
        ),
        migrations.AlterField(
            model_name="customerpaymentmethod",
            name="encryption_context_id",
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AlterField(
            model_name="customerpaymentmethod",
            name="bank_details",
            field=apps.common.fields.EncryptedJSONField(
                aad_context_field="encryption_context_id",
                blank=True,
                null=True,
                require_v2=True,
                verbose_name="Detalii bancare",
            ),
        ),
        migrations.RunPython(
            create_context_immutability_trigger,
            drop_context_immutability_trigger,
        ),
    ]
