#!/usr/bin/env python3
"""Install only an exact reviewed root helper bundle, with permanent token fencing.

Runs as fixed Python code over enrolled SSH stdin, so a source-only node needs no
existing PRAHO binary. No kernel, Virtualmin configuration or MTA mutation occurs.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path
from uuid import UUID

LIMIT = 1024 * 1024
FILES = frozenset(
    {
        "praho_quota.py",
        "praho_quota_native.py",
        "praho-quota-metadata.pl",
        "praho_usage.py",
        "praho_hosting_node.py",
        "praho-notification-policy.pl",
    }
)


def private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Native helper directory must be private and owned")


def write(path: Path, contents: bytes, *, mode: int = 0o600) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".prepare-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


class BundleInstaller:
    def __init__(self, state: Path, library: Path) -> None:
        self.state, self.library = state, library

    def perform(self, action: str, request: dict[str, object]) -> dict[str, str]:
        if set(request) != {"identity", "token", "helper_bundle_digest", "files"} or action not in {"install", "fence"}:
            raise ValueError("An exact reviewed native helper bundle is required")
        token, identity, files = request["token"], request["identity"], request["files"]
        if (
            not isinstance(token, str)
            or str(UUID(token)) != token
            or not isinstance(identity, str)
            or re.fullmatch(r"[0-9a-f]{64}", identity) is None
            or not isinstance(files, dict)
            or set(files) != FILES
        ):
            raise ValueError("Native helper installation scope is invalid")
        serialized = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(serialized).hexdigest()
        if len(serialized) > LIMIT or digest != request["helper_bundle_digest"]:
            raise ValueError("Native helper bundle differs from its accepted review")
        decoded = {}
        for name, value in files.items():
            if not isinstance(value, str):
                raise ValueError("Native helper content is invalid")
            decoded[name] = base64.b64decode(value, validate=True)
        private_directory(self.state)
        private_directory(self.library)
        fd = os.open(self.state / "operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            cancelled = self.state / ("cancelled-" + token)
            if action == "install" and cancelled.exists():
                raise ValueError("The native installer token was permanently cancelled")
            # Reconciliation fences first, then repairs only the exact originally reviewed bundle.
            if action == "fence":
                write(cancelled, token.encode())
            for name, value in decoded.items():
                write(self.library / name, value, mode=0o700)
            write(cancelled, token.encode())
            return {"identity": identity, "fenced_token": token, "helper_bundle_digest": digest}
        finally:
            os.close(fd)


def main() -> None:
    if os.geteuid() != 0:
        raise ValueError("Root helper preparation is required")
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("Native helper bundle is oversized")
    request = json.loads(raw)
    if not isinstance(request, dict) or set(request) != {"action", "request"}:
        raise ValueError("A fixed preparation action is required")
    result = BundleInstaller(Path("/var/lib/praho/hosting"), Path("/usr/local/lib/praho")).perform(
        request["action"], request["request"]
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
