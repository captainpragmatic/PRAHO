"""Private, exact-VM native acceptance authority. Never imported by production workflows."""

from __future__ import annotations

import fcntl
import importlib.util
import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from types import ModuleType
from typing import Any

from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[4]
MAX_PRIVATE_KEY = 65536
PRIVATE_MODE = 0o600


@lru_cache(maxsize=1)
def native_driver() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "praho_owned_native_driver",
        ROOT / "tests/virtualmin_lab/native/provider_vm.py",
    )
    if spec is None or spec.loader is None:
        raise ValueError("The repository-owned native VM driver is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class NativeAuthority:
    path: Path
    manifest: dict[str, Any]
    key: bytes = field(repr=False)
    public_key: str = field(repr=False)


def native_authority(path: Path) -> NativeAuthority:
    driver = native_driver()
    manifest = driver.read_manifest(path)
    if datetime.now(UTC) >= datetime.fromisoformat(manifest["expires_at"]) or manifest.get("phase") == "destroyed":
        raise ValueError("The native VM authority has expired or was destroyed")
    key_path, _trust = driver.paths(path, manifest)
    info = key_path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != PRIVATE_MODE
        or info.st_uid != os.getuid()
        or info.st_size > MAX_PRIVATE_KEY
    ):
        raise ValueError("A private locally owned native VM identity is required")
    key = key_path.read_bytes()
    parsed = serialization.load_ssh_private_key(key, password=None)
    public = (
        parsed.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    )
    return NativeAuthority(path.absolute(), manifest, key, public)


def write_private(path: Path, value: str) -> None:
    """Create one exact owned private file, refusing symlinks and changed content."""
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != PRIVATE_MODE
            or info.st_uid != os.getuid()
            or path.read_text() != value
        ):
            raise ValueError("Native fixture authority file changed; inspect it before continuing")
        return
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as target:
        target.write(value)


@contextmanager
def native_run_lock(authority: NativeAuthority) -> Iterator[None]:
    """One controller owns a manifest; no expired lease permits a second writer."""
    path = authority.path.parent / (authority.manifest["run"] + ".platform.lock")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, PRIVATE_MODE)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != PRIVATE_MODE or info.st_uid != os.getuid():
            raise ValueError("Native controller lock is not private and locally owned")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Another controller owns this exact native VM workflow") from error
        yield
    finally:
        os.close(descriptor)
