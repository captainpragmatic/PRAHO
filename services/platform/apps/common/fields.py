"""
Custom Django model fields for PRAHO Platform.

EncryptedJSONField: JSONField with transparent AES-256-GCM encryption at rest.
Uses the existing encryption infrastructure in apps.common.encryption.
"""

from __future__ import annotations

import json
from typing import Any

from django.db import models

from apps.common.encryption import ENCRYPTED_PREFIX, decrypt_sensitive_data, encrypt_sensitive_data


class EncryptedJSONField(models.JSONField):
    """JSONField with transparent AES-256-GCM encryption at rest.

    Data is encrypted before writing to the database and decrypted on read.
    Legacy unencrypted data (plain JSON objects) is handled transparently —
    returned as-is on read and encrypted on next save.

    Wire format in DB: jsonb string containing ``"aes:<base64>"``
    Python interface: plain dict (identical to standard JSONField)

    Usage::

        bank_details = EncryptedJSONField(blank=True, null=True)
        obj.bank_details = {"iban": "RO49AAAA1B31007593840000"}
        obj.save()  # Stored encrypted in DB
        obj.refresh_from_db()
        obj.bank_details  # {"iban": "RO49AAAA1B31007593840000"}
    """

    def get_prep_value(self, value: Any) -> Any:
        """Encrypt dict → JSON string → AES-256-GCM → store as JSON string in DB."""
        if value is None:
            return None
        # Serialize to JSON, then encrypt the JSON string
        json_str = json.dumps(value, cls=self.encoder)
        encrypted = encrypt_sensitive_data(json_str)
        # Let parent JSONField serialize the encrypted string for the DB adapter
        # (produces a JSON string value in jsonb / quoted text in SQLite)
        return super().get_prep_value(encrypted)

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> Any:
        """Decrypt on read; handle legacy unencrypted data transparently."""
        # Let parent deserialize from DB format first
        result = super().from_db_value(value, expression, connection)
        if result is None:
            return None
        # Encrypted data: parent returns a Python string "aes:..."
        if isinstance(result, str) and result.startswith(ENCRYPTED_PREFIX):
            decrypted_json = decrypt_sensitive_data(result)
            return json.loads(decrypted_json)
        # Legacy unencrypted data: parent already returned a dict
        return result

    def deconstruct(self) -> tuple[str, str, list[Any], dict[str, Any]]:
        """Return deconstruction for migrations."""
        name, path, args, kwargs = super().deconstruct()
        # Use our module path so Django tracks the field type change
        path = "apps.common.fields.EncryptedJSONField"
        return name, path, list(args), kwargs
