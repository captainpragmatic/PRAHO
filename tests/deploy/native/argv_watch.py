"""Observe fixture processes without ever recording credentials or command lines."""

from __future__ import annotations

import json
import shlex
import sys
import time
from pathlib import Path

SECRET_KEYS = {"DB_PASSWORD", "DJANGO_SECRET_KEY", "PORTAL_DJANGO_SECRET_KEY", "PORTAL_HMAC_SECRET",
               "HMAC_SECRET", "PLATFORM_API_SECRET", "PLATFORM_TO_PORTAL_WEBHOOK_SECRET",
               "DJANGO_ENCRYPTION_KEY", "CREDENTIAL_VAULT_MASTER_KEY"}


def observe(paths: list[str]) -> None:
    running = Path("/fixture/argv-watch.running")
    report = Path("/fixture/argv-watch.json")
    markers: set[bytes] = set()
    exposures = scans = 0
    deadline = time.monotonic() + 2100
    while running.exists() and time.monotonic() < deadline:
        for name in paths:
            try:
                lines = Path(name).read_text().splitlines()
            except FileNotFoundError:
                continue
            for line in lines:
                key, separator, raw = line.partition("=")
                if separator and key in SECRET_KEYS:
                    values = shlex.split(raw)
                    if len(values) == 1 and len(values[0]) >= 24:
                        markers.add(values[0].encode())
        for path in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                command = path.read_bytes()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            scans += 1
            exposures += int(any(marker in command for marker in markers))
        time.sleep(0.02)
    report.write_text(json.dumps({"exposures": exposures, "scans": scans, "credentials_observed": len(markers)}))
    report.chmod(0o600)


if __name__ == "__main__":
    observe(sys.argv[1:])
