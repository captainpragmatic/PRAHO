"""
Custom Django model fields for PRAHO Platform.

EncryptedJSONField: JSONField with transparent AES-256-GCM encryption at rest.
Uses the existing encryption infrastructure in apps.common.encryption.
Supports AAD (Associated Authenticated Data) binding to prevent ciphertext
transplant attacks between rows/tables.
"""

from __future__ import annotations

import json
import logging
import struct
from typing import Any, cast

from django.db import models
from django.db.models.expressions import Col
from django.db.utils import NotSupportedError

from apps.common.encryption import (
    AAD_LEN_SIZE,
    ENCRYPTED_PREFIX,
    VERSIONED_V2_PREFIX,
    DecryptionError,
    EncryptionError,
    _strict_urlsafe_b64decode,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)

logger = logging.getLogger(__name__)

_AAD_CONTEXT_KEY = "__praho_encrypted_aad_context__"
_ENCRYPTED_VALUE_KEY = "__praho_encrypted_value__"
SQLParams = list[str | int] | tuple[str | int, ...] | tuple[()]


class _PreparedEncryptedValue(str):
    """Ciphertext produced or verified with a concrete model instance."""


def _extract_embedded_aad(encrypted_str: str) -> bytes | None:
    """Extract the embedded AAD from a v2 ciphertext string, or None if parsing fails."""
    try:
        encoded = encrypted_str[len(VERSIONED_V2_PREFIX) :]
        raw = _strict_urlsafe_b64decode(encoded)
        if len(raw) < AAD_LEN_SIZE:
            return None
        aad_len = struct.unpack("!H", raw[:AAD_LEN_SIZE])[0]
        if len(raw) < AAD_LEN_SIZE + aad_len:
            return None
        return raw[AAD_LEN_SIZE : AAD_LEN_SIZE + aad_len]
    except Exception:
        return None


# SQL identifiers come only from Django's compiler/model metadata and the JSON
# property names are fixed module constants; no request or stored value is interpolated.
# nosemgrep: python.django.security.audit.extends-custom-expression.extends-custom-expression  # noqa: ERA001
class EncryptedJSONCol(Col):
    """Select an encrypted value together with its immutable row context."""

    def select_format(
        self,
        compiler: Any,
        sql: str,
        params: SQLParams,
    ) -> tuple[str, list[str | int]]:
        field = cast("EncryptedJSONField", self.target)
        context_name = field.aad_context_field
        if context_name is None:
            raise DecryptionError("EncryptedJSONCol requires an AAD context field")
        context_field = cast(
            "models.Field[Any, Any]",
            field.model._meta.get_field(context_name),
        )
        context_sql, context_params = compiler.compile(Col(self.alias, context_field))

        if compiler.connection.vendor == "postgresql":
            wrapped = (
                f"jsonb_build_object('{_AAD_CONTEXT_KEY}', ({context_sql})::text, '{_ENCRYPTED_VALUE_KEY}', {sql})"
            )
        elif compiler.connection.vendor == "sqlite":
            # SQLite stores UUIDField values as 32 hex characters. Normalize them
            # to UUID's canonical representation so write- and read-time AAD match.
            canonical_context = (
                f"lower(substr({context_sql}, 1, 8) || '-' || substr({context_sql}, 9, 4) || '-' || "
                f"substr({context_sql}, 13, 4) || '-' || substr({context_sql}, 17, 4) || '-' || "
                f"substr({context_sql}, 21, 12))"
            )
            wrapped = f"json_object('{_AAD_CONTEXT_KEY}', {canonical_context}, '{_ENCRYPTED_VALUE_KEY}', json({sql}))"
        else:
            raise NotSupportedError("Context-bound EncryptedJSONField supports PostgreSQL and SQLite only")
        return wrapped, [*context_params, *params]


class EncryptedJSONField(models.JSONField):
    """JSONField with transparent AES-256-GCM encryption at rest.

    Data is encrypted before writing to the database and decrypted on read.
    Decryption, downgrade, and AAD mismatches raise ``DecryptionError``.

    When ``aad_context_field`` is configured, AAD binds to a stable row
    identity available before INSERT. The select expression carries that identity
    in an internal envelope so model and projection reads verify exact AAD.

    Wire format in DB: jsonb string containing ``"aes:v2:<base64>"`` (AAD-bound)
    Python interface: plain dict (identical to standard JSONField)

    ``require_v2``: when True, the field rejects
    any stored value that is not v2 AAD-bound ciphertext — v1/legacy ciphertext or
    plaintext. This closes the downgrade bypass where an attacker with DB write
    access supplies a v1 blob (which carries no AAD binding) to sidestep transplant
    protection. Set it True only after ``reencrypt_with_aad`` has upgraded existing
    rows to v2; otherwise unmigrated rows raise ``DecryptionError``.
    """

    def __init__(
        self,
        *args: Any,
        require_v2: bool = False,
        aad_context_field: str | None = None,
        **kwargs: Any,
    ) -> None:
        # require_v2 is read-time behavior only (no DB column). deconstruct() preserves it
        # when non-default so Field.clone() and historical migration models keep the flag;
        # the default (False) is omitted, so no schema migration is generated by default.
        self.require_v2 = require_v2
        self.aad_context_field = aad_context_field
        super().__init__(*args, **kwargs)

    def get_col(self, alias: str, output_field: models.Field[Any, Any] | None = None) -> Col:
        if self.aad_context_field and (output_field is None or output_field == self):
            return EncryptedJSONCol(alias, self, output_field)
        return super().get_col(alias, output_field)

    def _build_aad(self, model_instance: models.Model) -> bytes:
        """Build AAD context string for this field on this instance."""
        table = model_instance._meta.db_table
        field = self.attname
        if self.aad_context_field:
            context = getattr(model_instance, self.aad_context_field, None)
            if context is None or str(context) == "":
                raise EncryptionError(
                    f"EncryptedJSONField {table}.{field} requires {self.aad_context_field} before save"
                )
            return f"{table}:{field}:{context}".encode()

        # Compatibility mode for fields not yet assigned a stable row identity.
        pk = model_instance.pk if model_instance.pk is not None else ""
        return f"{table}:{field}:{pk}".encode()

    def pre_save(self, model_instance: models.Model, add: bool) -> Any:
        """Encrypt the value with this field's AAD context and return the wire string.

        Encrypting here (rather than stashing AAD in shared state for get_prep_value)
        keeps each field's AAD bound to its own value — Django calls every field's
        pre_save before preparing any value, so a shared slot would let one encrypted
        field clobber another's context. The in-memory instance keeps the plaintext
        dict; only the DB write receives the ciphertext.
        """
        value = getattr(model_instance, self.attname)
        if value is None:
            return None
        aad = self._build_aad(model_instance)
        if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
            if self.require_v2 and not value.startswith(VERSIONED_V2_PREFIX):
                raise EncryptionError(
                    f"EncryptedJSONField {self.model._meta.db_table}.{self.attname} requires v2 ciphertext"
                )
            if value.startswith(VERSIONED_V2_PREFIX):
                decrypt_sensitive_data(value, aad=aad)
            return _PreparedEncryptedValue(value)
        json_str = json.dumps(value, cls=self.encoder)
        return _PreparedEncryptedValue(encrypt_sensitive_data(json_str, aad=aad))

    def get_prep_value(self, value: Any) -> Any:
        """Prepare a value for the DB adapter.

        Normal saves flow through pre_save, which returns the already-encrypted wire
        string; that string passes straight through here. A raw (unencrypted) value
        reaching this point came from a write path that bypassed pre_save —
        ``QuerySet.update()``/``bulk_update()`` or a raw/fixture save (``loaddata``) —
        where no model instance is available, so AAD context cannot be bound.
        Context-bound or v2-only fields reject that write; compatibility fields
        retain the legacy v1 fallback.
        """
        if value is None:
            return None
        if isinstance(value, _PreparedEncryptedValue):
            return super().get_prep_value(value)
        if self.aad_context_field or self.require_v2:
            raise EncryptionError(
                f"EncryptedJSONField {self.model._meta.db_table}.{self.attname} "
                "cannot be written without model AAD context"
            )
        if isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX):
            return super().get_prep_value(value)
        logger.warning(
            "EncryptedJSONField '%s' written without AAD context (pre_save was bypassed — e.g. "
            "QuerySet.update()/bulk_update()/loaddata); stored as unbound v1 ciphertext. Use "
            "Model.save() to bind AAD context.",
            self.attname,
        )
        json_str = json.dumps(value, cls=self.encoder)
        return super().get_prep_value(encrypt_sensitive_data(json_str))

    def from_db_value(self, value: Any, expression: Any, connection: Any) -> Any:
        """Decrypt on read and fail loudly on integrity or downgrade failures."""
        result = super().from_db_value(value, expression, connection)
        if result is None:
            return None

        expected_aad: bytes | None = None
        if self.aad_context_field:
            if not isinstance(result, dict) or not {
                _AAD_CONTEXT_KEY,
                _ENCRYPTED_VALUE_KEY,
            }.issubset(result):
                raise DecryptionError(
                    f"EncryptedJSONField {self.model._meta.db_table}.{self.attname} "
                    "was selected without its row AAD context"
                )
            context = result[_AAD_CONTEXT_KEY]
            result = result[_ENCRYPTED_VALUE_KEY]
            if result is None:
                return None
            if not isinstance(context, str) or not context:
                raise DecryptionError(
                    f"EncryptedJSONField {self.model._meta.db_table}.{self.attname} has no row AAD context"
                )
            expected_aad = f"{self.model._meta.db_table}:{self.attname}:{context}".encode()

        is_v2 = isinstance(result, str) and result.startswith(VERSIONED_V2_PREFIX)
        if self.require_v2 and not is_v2:
            encrypted = isinstance(result, str) and result.startswith(ENCRYPTED_PREFIX)
            logger.error(
                "EncryptedJSONField requires v2 AAD-bound ciphertext but found %s on %s.%s — "
                "rejecting (run reencrypt_with_aad; possible downgrade attack).",
                "v1/legacy ciphertext" if encrypted else "a non-encrypted value",
                self.model._meta.db_table,
                self.attname,
            )
            raise DecryptionError(
                f"EncryptedJSONField {self.model._meta.db_table}.{self.attname} requires v2 ciphertext"
            )

        if isinstance(result, str) and result.startswith(ENCRYPTED_PREFIX):
            try:
                decrypted = decrypt_sensitive_data(result, aad=expected_aad)
                if is_v2 and expected_aad is None:
                    embedded_aad = _extract_embedded_aad(result)
                    if embedded_aad is None or not embedded_aad.startswith(self._expected_aad_prefix()):
                        raise DecryptionError("Ciphertext AAD does not match the encrypted field")
                return json.loads(decrypted)
            except DecryptionError:
                logger.error(
                    "Failed to decrypt EncryptedJSONField %s.%s; refusing to return a replacement value.",
                    self.model._meta.db_table,
                    self.attname,
                    exc_info=True,
                )
                raise
            except (TypeError, ValueError) as exc:
                logger.error(
                    "EncryptedJSONField %s.%s plaintext is not valid JSON.",
                    self.model._meta.db_table,
                    self.attname,
                )
                raise DecryptionError("Decrypted field value is not valid JSON") from exc
        return result

    def _expected_aad_prefix(self) -> bytes:
        """Return the expected AAD prefix (table:field:) for this field."""
        table = self.model._meta.db_table
        return f"{table}:{self.attname}:".encode()

    def deconstruct(self) -> tuple[str, str, list[Any], dict[str, Any]]:
        """Return deconstruction for migrations."""
        name, path, args, kwargs = super().deconstruct()
        path = "apps.common.fields.EncryptedJSONField"
        # Preserve the security-relevant require_v2 flag so Field.clone() and historical
        # migration models don't silently revert to the default (unenforced) behavior.
        # It's read-time-only (no DB column), so a non-default value yields a state-only
        # migration; the default False stays omitted, so no migration is generated today.
        if self.require_v2:
            kwargs["require_v2"] = True
        if self.aad_context_field:
            kwargs["aad_context_field"] = self.aad_context_field
        return name, path, list(args), kwargs
