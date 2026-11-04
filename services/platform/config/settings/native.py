"""Opt-in native VM acceptance, isolated PostgreSQL and manifest-derived vault keys."""

import base64
import hashlib
import json
import os
import re
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from apps.infrastructure.native_lab import native_authority, write_private

try:
    if (
        os.environ.get("PRAHO_NATIVE_LAB") != "1"
        or re.fullmatch(r"praho_native_[a-z0-9_]+", os.environ.get("DB_NAME", "")) is None
    ):
        raise ValueError("Explicit native lab mode and isolated praho_native_ PostgreSQL database are required")
    _native = native_authority(
        Path(os.environ["NATIVE_VM_MANIFEST"]), cleanup=os.environ.get("PRAHO_NATIVE_CLEANUP_ONLY") == "1"
    )
except (KeyError, OSError, ValueError, TypeError) as error:
    raise ImproperlyConfigured(
        "A current private owned native VM manifest and isolated native database are required"
    ) from error

os.environ["DJANGO_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(
    hashlib.sha256(_native.key + b":native-field-v1").digest()
).decode()
os.environ["DJANGO_SECRET_KEY"] = hashlib.sha512(_native.key + b":native-session-v1").hexdigest()
os.environ["PRAHO_SKIP_DOTENV"] = "1"

from .ci import *  # noqa: F403 -- Authority must be established before base encryption settings load.

# CI imports test constants; the real native consumers must use this original VM identity.
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ENCRYPTION_KEY = os.environ["DJANGO_ENCRYPTION_KEY"]
ENCRYPTION_KEYS = [ENCRYPTION_KEY]
CREDENTIAL_VAULT_MASTER_KEY = base64.urlsafe_b64encode(
    hashlib.sha256(_native.key + b":native-vault-v1").digest()
).decode()
_crypto_path = _native.path.parent / (_native.manifest["run"] + ".native-crypto.json")
_crypto_value = json.dumps(
    {
        "schema": 1,
        "profile": "native-crypto-v1",
        "run": _native.manifest["run"],
        "database": os.environ["DB_NAME"],
        "key_sha256": hashlib.sha256(_native.key).hexdigest(),
    },
    sort_keys=True,
)
try:
    if not _crypto_path.exists() and not _crypto_path.is_symlink():
        if any(_native.manifest.get(name) is not None for name in ("platform_fixture", "fresh_deployment")):
            raise ValueError(
                "Existing native fixture predates the original-key profile; use a fresh isolated fixture database"
            )
        if os.environ.get("PRAHO_NATIVE_CLEANUP_ONLY") != "1":
            try:
                write_private(_crypto_path, _crypto_value)
            except FileExistsError:
                write_private(_crypto_path, _crypto_value)
    else:
        write_private(_crypto_path, _crypto_value)
except (OSError, ValueError, TypeError) as error:
    raise ImproperlyConfigured(
        "Native crypto identity mismatch; retain the original authority and use a fresh isolated fixture database"
    ) from error

NATIVE_VM_MANIFEST = _native.path
NATIVE_VM_RUN = _native.manifest["run"]
PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE = str(_native.path.parent / (NATIVE_VM_RUN + ".operator.pub"))
EMAIL_BACKEND = "django.core.mail.backends.filebased.EmailBackend"
EMAIL_FILE_PATH = str(_native.path.parent / (NATIVE_VM_RUN + ".platform-mail"))
if os.environ.get("PRAHO_NATIVE_SMTP_MANIFEST") and os.environ.get("PRAHO_NATIVE_CLEANUP_ONLY") != "1":
    from apps.infrastructure.native_smtp import smtp_settings

    try:
        globals().update(smtp_settings(_native, Path(os.environ["PRAHO_NATIVE_SMTP_MANIFEST"])))
    except (OSError, ValueError, TypeError) as error:
        raise ImproperlyConfigured("A current private owned native SMTP capture is required for this opt-in") from error
Q_CLUSTER = {**Q_CLUSTER, "name": "native-acceptance", "orm": "default", "sync": False}
ALLOWED_HOSTS = ["127.0.0.1"]
