"""Strict context binding for persistent secret accessors.

Integer-keyed models carry a separate, immutable UUID available before INSERT.
UUID-keyed models use their preallocated primary key. No legacy/plaintext read
fallback is permitted; operators must replace affected secrets at cutover.
"""

import json
import uuid

from django.db.models import Model

from apps.common.encryption import (
    VERSIONED_V2_PREFIX,
    DecryptionError,
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
