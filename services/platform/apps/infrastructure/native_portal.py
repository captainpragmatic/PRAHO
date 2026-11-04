"""Private native UI authority and reserved listeners; no business fixtures or provider doubles."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
import socket
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import Any
from uuid import UUID, uuid4

from .native_lab import NativeAuthority, native_authority

OWNER = "praho-native-ui"
FILE_MODE = 0o600
MAX_AUTHORITY_BYTES = 8192
MAX_LIFETIME = 21600
MIN_SECRET_LENGTH = 64
MIN_PORT = 1024
MAX_PORT = 65535
FIELDS = {
    "schema",
    "owner",
    "run",
    "authority",
    "instance",
    "secret",
    "platform_port",
    "portal_port",
    "expires_at",
    "phase",
    "seal",
}
HOST_ENVIRONMENT = frozenset({"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT"})
PLATFORM_ENVIRONMENT = frozenset(
    {"DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "PRAHO_NATIVE_SMTP_MANIFEST"}
)


def read_ui(path: Path) -> dict[str, Any]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != FILE_MODE
            or info.st_uid != os.getuid()
            or info.st_size > MAX_AUTHORITY_BYTES
        ):
            raise ValueError("Native UI authority must be private, owned and bounded")
        value = json.loads(source.read(MAX_AUTHORITY_BYTES + 1))
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or value["owner"] != OWNER
        or value["phase"] != "serving"
        or not isinstance(value["secret"], str)
        or len(value["secret"]) < MIN_SECRET_LENGTH
        or any(not isinstance(value[key], str) or str(UUID(value[key])) != value[key] for key in ("run", "instance"))
        or any(
            type(value[key]) is not int or not MIN_PORT <= value[key] <= MAX_PORT
            for key in ("platform_port", "portal_port")
        )
        or value["platform_port"] == value["portal_port"]
    ):
        raise ValueError("Native UI authority has invalid scope or listener ports")
    expiry = datetime.fromisoformat(value["expires_at"])
    if expiry.tzinfo is None or expiry <= datetime.now(UTC):
        raise ValueError("Native UI authority expired")
    return value


def _seal(authority: NativeAuthority, value: dict[str, Any]) -> str:
    unsigned = {key: item for key, item in value.items() if key != "seal"}
    return hmac.new(
        authority.key, json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256
    ).hexdigest()


def validate_ui(authority: NativeAuthority, path: Path) -> dict[str, Any]:
    current = native_authority(authority.path)
    value = read_ui(path)
    if (
        current.public_key != authority.public_key
        or current.manifest["run"] != authority.manifest["run"]
        or value["run"] != current.manifest["run"]
        or value["authority"] != hashlib.sha256(current.public_key.encode()).hexdigest()
        or not isinstance(value["seal"], str)
        or not hmac.compare_digest(value["seal"], _seal(current, value))
        or datetime.fromisoformat(value["expires_at"]) > datetime.fromisoformat(current.manifest["expires_at"])
    ):
        raise ValueError("Native UI authority does not match its original owned VM")
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE), "w") as target:
        json.dump(value, target, sort_keys=True)
        target.flush()
        os.fsync(target.fileno())


class NativeUIPair:
    """Reserve both OS listeners before publishing the shared UI-only authority."""

    def __init__(self, authority: NativeAuthority, path: Path, *, lifetime_seconds: int = 10800) -> None:
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= MAX_LIFETIME:
            raise ValueError("Native UI lifetime must be bounded between one second and six hours")
        self.authority = native_authority(authority.path)
        if self.authority.public_key != authority.public_key:
            raise ValueError("Original native VM authority changed")
        self.path = path.absolute()
        self.lifetime_seconds = lifetime_seconds
        self.listeners: dict[str, socket.socket] = {}
        self.value: dict[str, Any] = {}

    def __enter__(self) -> NativeUIPair:
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("Preserve the existing native UI authority and its logs")
        with contextlib.ExitStack() as acquisition:
            acquisition.callback(self.close)
            for role in ("platform", "portal"):
                listener = socket.socket()
                self.listeners[role] = listener
                listener.bind(("127.0.0.1", 0))
                listener.listen(16)
            instance = str(uuid4())
            self.value = {
                "schema": 1,
                "owner": OWNER,
                "run": self.authority.manifest["run"],
                "authority": hashlib.sha256(self.authority.public_key.encode()).hexdigest(),
                "instance": instance,
                "secret": base64.urlsafe_b64encode(
                    hmac.new(self.authority.key, (":native-ui-hmac-v1:" + instance).encode(), hashlib.sha512).digest()
                ).decode(),
                "phase": "serving",
                "expires_at": min(
                    datetime.now(UTC) + timedelta(seconds=self.lifetime_seconds),
                    datetime.fromisoformat(self.authority.manifest["expires_at"]),
                ).isoformat(),
                **{role + "_port": int(listener.getsockname()[1]) for role, listener in self.listeners.items()},
            }
            self.value["seal"] = _seal(self.authority, self.value)
            _write(self.path, self.value)
            acquisition.pop_all()
            return self

    def close(self) -> None:
        for listener in self.listeners.values():
            listener.close()
        self.listeners.clear()
        with contextlib.suppress(OSError, ValueError):
            if json.loads(self.path.read_text()) == self.value:
                temporary = self.path.with_name(self.path.name + "." + self.value["instance"] + ".closed")
                _write(temporary, {**self.value, "phase": "closed"})
                os.replace(temporary, self.path)

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()


def child_environment(pair: NativeUIPair, role: str, root: Path, environment: dict[str, str]) -> dict[str, str]:
    """Portal never inherits database, SSH, vault, SMTP or payment-provider authority."""
    if role not in ("platform", "portal"):
        raise ValueError("Unknown native UI role")
    result = {key: value for key, value in environment.items() if key in HOST_ENVIRONMENT}
    result.update(
        {
            "PRAHO_SKIP_DOTENV": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PRAHO_NATIVE_UI": "1",
            "PRAHO_NATIVE_UI_AUTHORITY": str(pair.path),
            "PRAHO_NATIVE_UI_AUTHORITY_SHA256": hashlib.sha256(pair.path.read_bytes()).hexdigest(),
            "DJANGO_SETTINGS_MODULE": "config.settings.native_portal"
            if role == "platform"
            else "config.settings.native",
            "PYTHONPATH": str(root / "services" / role),
        }
    )
    if role == "platform":
        result.update({key: value for key, value in environment.items() if key in PLATFORM_ENVIRONMENT})
        if result.get("DB_HOST") not in ("127.0.0.1", "localhost") or not result.get("DB_NAME", "").startswith(
            "praho_native_"
        ):
            raise ValueError("Native UI requires its explicit isolated loopback PostgreSQL database")
        result.update({"PRAHO_NATIVE_LAB": "1", "NATIVE_VM_MANIFEST": str(pair.authority.path)})
    return result
