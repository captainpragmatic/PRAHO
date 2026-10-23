"""Strict context binding for persistent secret accessors.

Integer-keyed models carry a separate, immutable UUID available before INSERT.
UUID-keyed models use their preallocated primary key. No legacy/plaintext read
fallback is permitted; operators must replace affected secrets at cutover.
"""

import json
import uuid
from typing import Any

from django.db.models import Model

from apps.common.encryption import (
    ENCRYPTED_PREFIX,
    VERSIONED_V2_PREFIX,
    DecryptionError,
    EncryptionError,
    KeyringDecryptionError,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)


def secret_aad(instance: Model, field: str) -> bytes:
    instance._meta.get_field(field)
    identity = getattr(instance, "encryption_context_id", instance.pk)
    if not isinstance(identity, uuid.UUID):
        raise DecryptionError("Persistent secrets require a preallocated immutable UUID context")
    return json.dumps([instance._meta.db_table, field, str(identity)], separators=(",", ":")).encode()


def encrypt_model_secret(instance: Model, field: str, value: str) -> str:
    return encrypt_sensitive_data(value, aad=secret_aad(instance, field))


def decrypt_model_secret(instance: Model, field: str, value: str) -> str:
    if not value:
        return ""
    if not value.startswith(VERSIONED_V2_PREFIX):
        raise DecryptionError("Persistent secret requires context-bound v2 ciphertext; replace the stored secret")
    return decrypt_sensitive_data(value, aad=secret_aad(instance, field))


def seal_model_secret(instance: Model, field: str, value: str) -> str:
    """The value to store in a secret field: ciphertext that decrypts for this row and this field.

    Empty stays empty. A current (v2) value is kept only if it decrypts here: another row's or field's
    ciphertext, or plaintext that merely starts "aes:v2:", is refused. A keyring that lacks the key raises
    KeyringDecryptionError instead (a rotation rolling out is not a bad value). Any other "aes:" value (a
    superseded format, or plaintext that looks like ciphertext) is refused; it is never stored as is, nor
    wrapped. Anything else is plaintext and is encrypted for this row and field.
    """
    if not value:
        return value
    if value.startswith(VERSIONED_V2_PREFIX):
        try:
            decrypt_model_secret(instance, field, value)
        except KeyringDecryptionError:
            raise
        except DecryptionError as error:
            raise EncryptionError(f"Refused for {field}: not this field's ciphertext; replace the value") from error
        return value
    if value.startswith(ENCRYPTED_PREFIX):
        raise EncryptionError(f"Refused for {field}: a superseded or invalid ciphertext; replace the value")
    return encrypt_model_secret(instance, field, value)


def written_fields(kwargs: dict[str, Any], fields: tuple[str, ...]) -> tuple[list[str] | None, list[str]]:
    """(update_fields, the given fields being written). update_fields is materialised once, in place.

    A save with no update_fields writes every field; otherwise only the listed ones are written, and only
    those are sealed, so a status write on a row holding an unreadable value still succeeds.
    """
    update_fields = kwargs.get("update_fields")
    if update_fields is None:
        return None, list(fields)
    listed = list(update_fields)  # Django accepts any iterable: read it once
    kwargs["update_fields"] = listed
    return listed, [field for field in fields if field in listed]
