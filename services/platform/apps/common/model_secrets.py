"""Strict context binding for persistent secret accessors.

Integer-keyed models carry a separate, immutable UUID available before INSERT.
UUID-keyed models use their preallocated primary key. No legacy/plaintext read
fallback is permitted; operators must replace affected secrets at cutover.

A model whose secrets are found by a natural key (a vault credential by its service and identifier, a
server's password by its hostname) names those fields in SECRET_NATURAL_KEY; their values are bound too, so
a row renamed in the database no longer serves its secret under the new name.
"""

import json
import uuid
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, ClassVar

from django.db import models, transaction
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


class NaturalKeyChangeError(ValueError):
    """A bulk write would change a natural key its row's secrets are bound to."""


def natural_key(instance: Model) -> tuple[str, ...]:
    """The instance's SECRET_NATURAL_KEY values as bound: each as a string."""
    return tuple(str(getattr(instance, name)) for name in getattr(type(instance), "SECRET_NATURAL_KEY", ()))


def secret_aad(instance: Model, field: str, key: tuple[str, ...] | None = None) -> bytes:
    """The AAD binding a secret to its row, its field and, when the model declares one, its natural key.

    `key` replaces the instance's natural-key values: the AAD the secret had, or will have, under another one.
    """
    instance._meta.get_field(field)
    identity = getattr(instance, "encryption_context_id", instance.pk)
    if not isinstance(identity, uuid.UUID):
        raise DecryptionError("Persistent secrets require a preallocated immutable UUID context")
    parts = [instance._meta.db_table, field, str(identity), *(natural_key(instance) if key is None else key)]
    return json.dumps(parts, separators=(",", ":")).encode()


def encrypt_model_secret(instance: Model, field: str, value: str) -> str:
    return encrypt_sensitive_data(value, aad=secret_aad(instance, field))


def decrypt_model_secret(instance: Model, field: str, value: str, key: tuple[str, ...] | None = None) -> str:
    if not value:
        return ""
    if not value.startswith(VERSIONED_V2_PREFIX):
        raise DecryptionError("Persistent secret requires context-bound v2 ciphertext; replace the stored secret")
    return decrypt_sensitive_data(value, aad=secret_aad(instance, field, key))


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


class NaturalKeyQuerySet(models.QuerySet[Any]):
    """Refuses a bulk write of a SECRET_NATURAL_KEY field: it skips save(), so nothing would re-bind the secret."""

    def _refuse(self, fields: Iterable[str]) -> None:
        names = getattr(self.model, "SECRET_NATURAL_KEY", ())
        changed = sorted(set(fields) & set(names))
        if changed:
            raise NaturalKeyChangeError(
                f"{self.model.__name__}: {', '.join(changed)} is a natural key its secrets are bound to; "
                "change it through save(), which re-binds them"
            )

    def update(self, **kwargs: Any) -> int:
        self._refuse(kwargs)
        return super().update(**kwargs)

    def bulk_update(self, objs: Iterable[Model], fields: Iterable[str], *args: Any, **kwargs: Any) -> int:
        fields = list(fields)  # Django accepts any iterable: read it once
        self._refuse(fields)
        return super().bulk_update(objs, fields, *args, **kwargs)


LOADED_SECRETS_ATTRIBUTE = "_secrets_as_loaded"


def remember_secrets(instance: Model, fields: Iterable[str]) -> None:
    """Record the stored ciphertext of `fields` as this instance last read or wrote it (deferred ones are skipped)."""
    loaded = instance.__dict__.setdefault(LOADED_SECRETS_ATTRIBUTE, {})
    for field in fields:
        attname = getattr(instance._meta.get_field(field), "attname", field)
        if attname in instance.__dict__:
            loaded[field] = _as_text(instance.__dict__[attname])


def _as_text(value: object) -> str:
    if isinstance(value, memoryview):
        value = bytes(value)
    if isinstance(value, bytes):
        return value.decode()
    return str(value or "")


def _stored_form(instance: Model, field: str, text: str) -> object:
    return text.encode() if isinstance(instance._meta.get_field(field), models.BinaryField) else text


def bind_secret_on_save(instance: Model, field: str, kwargs: dict[str, Any]) -> None:
    """Before saving an existing row, leave `field` holding ciphertext bound to the natural key that will be stored.

    Call inside the transaction that saves, so the row stays locked until the write. It runs when the save
    writes the natural key or the secret. The source is the instance's value only when this save writes the
    secret and the instance changed it since it last read or wrote it; otherwise the locked row's value, so
    a stale instance never writes back an older secret. The final key is the instance's where the save writes
    it, the stored row's otherwise. The chosen value is authenticated under the final key (kept), or under the
    other known one (re-wrapped); a value that opens under neither is refused, never stored unreadable. A
    keyring that lacks the key raises KeyringDecryptionError (a rotation rolling out is not a bad value).
    """
    if instance._state.adding:
        return  # The accessors encrypt under the instance's own key; nothing is stored yet
    update_fields = kwargs.get("update_fields")
    if update_fields is not None:
        update_fields = list(update_fields)  # Django accepts any iterable: read it once
        kwargs["update_fields"] = update_fields
    names = tuple(getattr(type(instance), "SECRET_NATURAL_KEY", ()))
    writes_key = update_fields is None or any(name in update_fields for name in names)
    writes_secret = update_fields is None or field in update_fields
    if not (writes_key or writes_secret):
        return
    locked = type(instance)._base_manager.select_for_update().filter(pk=instance.pk).values(field, *names).first()
    if locked is None:
        return  # Deleted meanwhile: the save inserts or fails as it would have
    stored = _as_text(locked[field])
    in_memory = _as_text(getattr(instance, field))
    loaded = instance.__dict__.get(LOADED_SECRETS_ATTRIBUTE, {}).get(field)
    explicit = writes_secret and (loaded is None or in_memory != loaded)
    chosen = in_memory if explicit else stored
    stored_key = tuple(str(locked[name]) for name in names)
    final_key = tuple(
        str(getattr(instance, name)) if update_fields is None or name in update_fields else str(locked[name])
        for name in names
    )
    value = (
        chosen
        if not chosen or (chosen == stored and final_key == stored_key)
        else _rebound(instance, field, chosen, final_key, (stored_key, natural_key(instance)))
    )
    setattr(instance, field, _stored_form(instance, field, value))
    if update_fields is not None and field not in update_fields and value != stored:
        update_fields.append(field)


def _rebound(
    instance: Model, field: str, value: str, final_key: tuple[str, ...], others: Iterable[tuple[str, ...]]
) -> str:
    for key in dict.fromkeys((final_key, *others)):
        try:
            plaintext = decrypt_model_secret(instance, field, value, key)
        except KeyringDecryptionError:
            raise
        except DecryptionError:
            continue
        return (
            value if key == final_key else encrypt_sensitive_data(plaintext, aad=secret_aad(instance, field, final_key))
        )
    raise EncryptionError(f"Refused for {field}: the value is not this row's ciphertext under any known key")


# The mixin goes before models.Model in a model's bases; to the type checker it is that Model.
if TYPE_CHECKING:
    _MixinBase = Model
else:
    _MixinBase = object


class NaturalKeySecretsMixin(_MixinBase):
    """For a model whose BOUND_SECRET_FIELDS are bound to its SECRET_NATURAL_KEY: saves keep them readable.

    Each save of an existing row runs bind_secret_on_save for every bound field inside one transaction, so a
    rename re-wraps the secrets under the new key and a stale instance never writes back an older secret.
    """

    BOUND_SECRET_FIELDS: ClassVar[tuple[str, ...]] = ()

    @classmethod
    def from_db(cls, db: str | None, field_names: Any, values: Any) -> Any:
        instance = super().from_db(db, field_names, values)
        remember_secrets(instance, cls.BOUND_SECRET_FIELDS)
        return instance

    def refresh_from_db(self, *args: Any, **kwargs: Any) -> None:
        super().refresh_from_db(*args, **kwargs)
        fields = kwargs.get("fields", args[1] if len(args) > 1 else None)  # (using, fields, from_queryset)
        # Only what was re-read: an unsaved value in another secret field stays this instance's own change
        remember_secrets(self, [f for f in self.BOUND_SECRET_FIELDS if fields is None or f in fields])

    def save(self, *args: Any, **kwargs: Any) -> None:
        with transaction.atomic(using=kwargs.get("using") or self._state.db or "default"):
            for field in self.BOUND_SECRET_FIELDS:
                bind_secret_on_save(self, field, kwargs)
            super().save(*args, **kwargs)
        update_fields = kwargs.get("update_fields")  # The list bind_secret_on_save may have extended
        # Only what was written: an unsaved value in a field this save left out stays this instance's change
        remember_secrets(self, [f for f in self.BOUND_SECRET_FIELDS if update_fields is None or f in update_fields])
