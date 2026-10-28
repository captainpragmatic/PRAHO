"""Re-binding stored secrets to their natural key, with the AAD formulas frozen (#751 follow-up, M19).

The vault's credentials and the servers' API passwords were bound to their row and field only; they are now
also bound to the natural key that finds them. Migrations common 0005 and provisioning 0012, and the
`rebind_secrets` command, move existing ciphertext between the two formulas. The formulas are written out
here, never taken from the live `secret_aad`, so a later change to it cannot change what these migrations do.

A value that authenticates under the target formula is already bound and stays; one under the source formula
is re-encrypted under the target; a well-formed value that opens under neither aborts, naming the row: with
AES-GCM a wrong key and a wrong AAD fail the same way, so skipping it could record a migration that bound
nothing. A value in a superseded format is skipped and counted: it is unreadable since the strict cutover
and must be entered again either way.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.db import transaction

from apps.common.encryption import (
    VERSIONED_V2_PREFIX,
    DecryptionError,
    KeyringDecryptionError,
    decrypt_sensitive_data,
    encrypt_sensitive_data,
)

VAULT_PREFIX = b"vault:v2:"
VAULT_FIELDS = ("encrypted_username", "encrypted_password", "encrypted_metadata")


class RebindAbortedError(Exception):
    """A well-formed secret opened under neither formula: nothing is changed and the operator looks at it."""


@dataclass
class RebindCounts:
    rebound: int = 0
    current: int = 0
    superseded: int = 0

    def __str__(self) -> str:
        return f"{self.rebound} re-bound, {self.current} already bound, {self.superseded} superseded (re-enter)"


def context_aad(table: str, field: str, identity: str) -> bytes:
    """The AAD before #751's follow-up: the row and the field."""
    return json.dumps([table, field, identity], separators=(",", ":")).encode()


def natural_key_aad(table: str, field: str, identity: str, key: Iterable[object]) -> bytes:
    """The AAD after it: the row, the field and the natural key's values as strings."""
    return json.dumps([table, field, identity, *(str(value) for value in key)], separators=(",", ":")).encode()


def vault_cipher(raw_key: str | bytes | None) -> AESGCM:
    """The vault's cipher from CREDENTIAL_VAULT_MASTER_KEY, decoded exactly as CredentialVault does."""
    if not raw_key:
        raise RebindAbortedError("CREDENTIAL_VAULT_MASTER_KEY is not set and the vault holds credentials")
    text = raw_key if isinstance(raw_key, str) else raw_key.decode("ascii")
    key = base64.urlsafe_b64decode(text)
    if len(key) != 32:  # noqa: PLR2004  # AES-256
        raise RebindAbortedError("CREDENTIAL_VAULT_MASTER_KEY must decode to 32 bytes")
    return AESGCM(key)


def _aads(table: str, field: str, identity: str, key: Iterable[object], forward: bool) -> tuple[bytes, bytes]:
    old, new = context_aad(table, field, identity), natural_key_aad(table, field, identity, key)
    return (old, new) if forward else (new, old)


def rebind_vault_value(
    cipher: AESGCM, value: bytes, aads: tuple[bytes, bytes], where: str, counts: RebindCounts
) -> bytes | None:
    """The value to store, or None when it stays as it is."""
    source, target = aads
    if not value:
        return None
    if not value.startswith(VAULT_PREFIX):
        counts.superseded += 1
        return None
    body = value[len(VAULT_PREFIX) :]
    nonce, sealed = body[:12], body[12:]
    try:
        cipher.decrypt(nonce, sealed, target)
    except InvalidTag:
        pass
    else:
        counts.current += 1
        return None
    try:
        plaintext = cipher.decrypt(nonce, sealed, source)
    except InvalidTag as error:
        raise RebindAbortedError(f"{where} opens under neither formula (wrong vault key, or altered)") from error
    fresh = os.urandom(12)
    counts.rebound += 1
    return VAULT_PREFIX + fresh + cipher.encrypt(fresh, plaintext, target)


def rebind_text_value(value: str, aads: tuple[bytes, bytes], where: str, counts: RebindCounts) -> str | None:
    """An application-keyring value (aes:v2 text): the value to store, or None when it stays as it is.

    KeyringDecryptionError propagates: a keyring that lacks the key is fixed by configuration, not skipped.
    """
    source, target = aads
    if not value:
        return None
    if not value.startswith(VERSIONED_V2_PREFIX):
        counts.superseded += 1
        return None
    for aad, is_target in ((target, True), (source, False)):
        try:
            plaintext = decrypt_sensitive_data(value, aad=aad)
        except KeyringDecryptionError:
            raise
        except DecryptionError:
            continue
        if is_target:
            counts.current += 1
            return None
        counts.rebound += 1
        return encrypt_sensitive_data(plaintext, aad=target)
    raise RebindAbortedError(f"{where} opens under neither formula (altered, or another row's)")


def _rows(model: Any, alias: str, lock: bool) -> Iterable[Any]:
    for pk in model._base_manager.using(alias).order_by("pk").values_list("pk", flat=True):
        queryset = model._base_manager.using(alias).filter(pk=pk)
        row = (queryset.select_for_update() if lock else queryset).first()
        if row is not None:
            yield row


def rebind_vault(
    model: Any, alias: str, raw_key: str | bytes | None, *, forward: bool = True, lock: bool = False
) -> RebindCounts:
    """EncryptedCredential: username, password and metadata, under the vault key."""
    counts = RebindCounts()
    cipher: AESGCM | None = None
    table = model._meta.db_table
    with transaction.atomic(using=alias):
        for row in _rows(model, alias, lock):
            changes: dict[str, bytes] = {}
            for field in VAULT_FIELDS:
                value = bytes(getattr(row, field) or b"")
                if not value:
                    continue
                if cipher is None:
                    cipher = vault_cipher(raw_key)
                aads = _aads(table, field, str(row.pk), (row.service_type, row.service_identifier), forward)
                new = rebind_vault_value(cipher, value, aads, f"{table} {row.pk} {field}", counts)
                if new is not None:
                    changes[field] = new
            if changes:
                model._base_manager.using(alias).filter(pk=row.pk).update(**changes)
    return counts


@dataclass(frozen=True)
class HostnamePassword:
    """A server model's API password field: where it is and which identity its AAD carries."""

    model: Any
    field: str
    identity: Callable[[Any], object]
    binary: bool  # Bytes holding the aes:v2 text, or the text itself


def rebind_hostname_passwords(
    target: HostnamePassword, alias: str, *, forward: bool = True, lock: bool = False
) -> RebindCounts:
    """A server model's API password, under the application keyring, bound to its hostname."""
    counts = RebindCounts()
    model, field = target.model, target.field
    table = model._meta.db_table
    with transaction.atomic(using=alias):
        for row in _rows(model, alias, lock):
            stored: Any = getattr(row, field)
            value = bytes(stored or b"").decode() if target.binary else str(stored or "")
            aads = _aads(table, field, str(target.identity(row)), (row.hostname,), forward)
            new = rebind_text_value(value, aads, f"{table} {row.pk} {field}", counts)
            if new is not None:
                stored_new = new.encode() if target.binary else new
                model._base_manager.using(alias).filter(pk=row.pk).update(**{field: stored_new})
    return counts
