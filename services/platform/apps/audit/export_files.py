"""GDPR export files: encrypted at rest, bound to their export (ADR-0040).

An export holds a person's data, and from media it reaches every backup and the staff network's
direct /media route. So the file holds only AES-256-GCM ciphertext whose AAD names the export it
belongs to, and every read passes that AAD: a file copied from another export, plaintext, an
empty or truncated file, or ciphertext without that binding is refused, never served.

`reencrypt_with_aad` does not find these files. A retired key must stay in the keyring until every
export file encrypted under it has been deleted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.core.files.base import ContentFile
from django.core.files.storage import default_storage

from apps.common.encryption import VERSIONED_V2_PREFIX, DecryptionError, decrypt_sensitive_data, encrypt_sensitive_data

if TYPE_CHECKING:
    from .models import DataExport

EXPORT_DIRECTORY = "gdpr_exports"


def _aad(export: DataExport) -> bytes:
    return f"audit_data_exports:file:{export.id}".encode()


def write_export_file(export: DataExport, content: str) -> str:
    """Encrypt `content` for `export` and store it; returns the stored path."""
    ciphertext = encrypt_sensitive_data(content, aad=_aad(export))
    return default_storage.save(f"{EXPORT_DIRECTORY}/{export.id}.enc", ContentFile(ciphertext.encode("ascii")))


def read_export_file(export: DataExport) -> str:
    """Return the decrypted export, or raise DecryptionError for anything but this export's ciphertext."""
    with default_storage.open(export.file_path, "rb") as stored:
        raw = stored.read()
    try:
        data = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DecryptionError("Export file is not ciphertext") from exc
    # decrypt_sensitive_data returns "" for empty input, and decrypts a v1 blob under any AAD it
    # is given; only a v2 envelope carries the binding checked below.
    if not data.startswith(VERSIONED_V2_PREFIX):
        raise DecryptionError("Export file is not v2 ciphertext")
    return decrypt_sensitive_data(data, aad=_aad(export))


def delete_export_file(path: str) -> None:
    """Delete a stored export file; a file that is already gone is not an error."""
    default_storage.delete(path)
