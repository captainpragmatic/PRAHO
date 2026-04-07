"""
Custom Django model fields for PRAHO Platform.

EncryptedJSONField: JSONField with transparent AES-256-GCM encryption at rest.
Uses the existing encryption infrastructure in apps.common.encryption.
Supports AAD (Associated Authenticated Data) binding to prevent ciphertext
transplant attacks between rows/tables.
"""

from __future__ import annotations

import base64
import json
import logging
import struct
import threading
from typing import Any

from django.db import models

from apps.common.encryption import (
    AAD_LEN_SIZE,
    ENCRYPTED_PREFIX,
    VERSIONED_V2_PREFIX,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)

logger = logging.getLogger(__name__)


def _extract_embedded_aad(encrypted_str: str) -> bytes | None:
    """Extract the embedded AAD from a v2 ciphertext string, or None if parsing fails."""
    try:
        encoded = encrypted_str[len(VERSIONED_V2_PREFIX) :]
        raw = base64.urlsafe_b64decode(encoded)
        if len(raw) < AAD_LEN_SIZE:
            return None
        aad_len = struct.unpack("!H", raw[:AAD_LEN_SIZE])[0]
        if len(raw) < AAD_LEN_SIZE + aad_len:
            return None
        return raw[AAD_LEN_SIZE : AAD_LEN_SIZE + aad_len]
    except Exception:
        return None


# Thread-local storage for passing AAD from pre_save to get_prep_value
_aad_context = threading.local()


class EncryptedJSONField(models.JSONField):
    """JSONField with transparent AES-256-GCM encryption at rest.

    Data is encrypted before writing to the database and decrypted on read.
    Legacy unencrypted data (plain JSON objects) is handled transparently —
    returned as-is on read and encrypted on next save.

    AAD binding: encrypts with ``aad=b"{db_table}:{field_name}:{pk}"`` so that
    ciphertext is context-bound. Swapping encrypted values between tables
    will fail GCM authentication on read.

    Wire format in DB: jsonb string containing ``"aes:v2:<base64>"`` (AAD-bound)
    Python interface: plain dict (identical to standard JSONField)
    """

    def _build_aad(self, model_instance: models.Model) -> bytes:
        """Build AAD context string for this field on this instance."""
        table = model_instance._meta.db_table
        field = self.attname
        pk = model_instance.pk or ""
        return f"{table}:{field}:{pk}".encode()

    def pre_save(self, model_instance: models.Model, add: bool) -> Any:
        """Stash AAD context for get_prep_value to use during this save."""
        value = getattr(model_instance, self.attname)
        if value is not None and not (isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)):
            _aad_context.aad = self._build_aad(model_instance)
        else:
            _aad_context.aad = None
        return super().pre_save(model_instance, add)

    def get_prep_value(self, value: Any) -> Any:
        """Encrypt dict → JSON string → AES-256-GCM → store as JSON string in DB."""
        if value is None:
            return None
        if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
            return super().get_prep_value(value)
        json_str = json.dumps(value, cls=self.encoder)
        aad = getattr(_aad_context, "aad", None)
        encrypted = encrypt_sensitive_data(json_str, aad=aad)
        # Clear after use
        _aad_context.aad = None
        return super().get_prep_value(encrypted)

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> Any:
        """Decrypt on read; handle legacy unencrypted data transparently.

        v2 format: AAD is embedded in the payload and verified by GCM.
        Also cross-checks embedded AAD prefix against expected table:field:
        to detect ciphertext transplant between different tables/fields.
        v1/legacy: decrypted without AAD (backward compatible).
        """
        result = super().from_db_value(value, expression, connection)
        if result is None:
            return None
        if isinstance(result, str) and result.startswith(ENCRYPTED_PREFIX):
            try:
                decrypted = decrypt_sensitive_data(result)

                # Cross-check embedded AAD for v2 ciphertext
                if result.startswith(VERSIONED_V2_PREFIX):
                    embedded_aad = _extract_embedded_aad(result)
                    if embedded_aad is not None:
                        expected_prefix = self._expected_aad_prefix()
                        if not embedded_aad.startswith(expected_prefix):
                            logger.error(
                                "EncryptedJSONField AAD context mismatch — possible ciphertext transplant. "
                                "Expected prefix %r, got %r",
                                expected_prefix,
                                embedded_aad[:50],
                            )
                            return None

                return json.loads(decrypted)
            except Exception:
                logger.error(
                    "Failed to decrypt EncryptedJSONField value (possible key rotation or data corruption). "
                    "Returning None.",
                    exc_info=True,
                )
                return None
        return result

    def _expected_aad_prefix(self) -> bytes:
        """Return the expected AAD prefix (table:field:) for this field."""
        table = self.model._meta.db_table
        return f"{table}:{self.attname}:".encode()

    def deconstruct(self) -> tuple[str, str, list[Any], dict[str, Any]]:
        """Return deconstruction for migrations."""
        name, path, args, kwargs = super().deconstruct()
        path = "apps.common.fields.EncryptedJSONField"
        return name, path, list(args), kwargs
