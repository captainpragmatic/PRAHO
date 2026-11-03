"""Opt-in native VM acceptance, isolated PostgreSQL and manifest-derived vault keys."""

import base64
import hashlib
import os
import re
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

from apps.infrastructure.native_lab import native_authority

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
    hashlib.sha256(_native.key + b":native-vault-v1").digest()
).decode()
os.environ["DJANGO_SECRET_KEY"] = hashlib.sha512(_native.key + b":native-session-v1").hexdigest()
os.environ["PRAHO_SKIP_DOTENV"] = "1"

from .ci import *  # noqa: F403 -- Authority must be established before base encryption settings load.

NATIVE_VM_MANIFEST = _native.path
NATIVE_VM_RUN = _native.manifest["run"]
PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE = str(_native.path.parent / (NATIVE_VM_RUN + ".operator.pub"))
EMAIL_BACKEND = "django.core.mail.backends.filebased.EmailBackend"
EMAIL_FILE_PATH = str(_native.path.parent / (NATIVE_VM_RUN + ".platform-mail"))
Q_CLUSTER = {**Q_CLUSTER, "name": "native-acceptance", "orm": "default", "sync": False}
ALLOWED_HOSTS = ["127.0.0.1"]
