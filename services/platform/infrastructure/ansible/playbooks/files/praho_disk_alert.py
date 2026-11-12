#!/usr/bin/env python3
"""Warn operators as a node's root filesystem fills.

Database files have no kernel cap (ADR-0075), and a completely full disk aborts the shared MariaDB, so this is the only
guard against that outage. Sends to operators only, never to tenants.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

STATE = Path("/var/lib/praho/usage/disk-alert.json")
OPERATORS = Path("/var/lib/praho/hosting/operators.json")
WEBMIN_CONFIG = Path("/etc/webmin/config")
THRESHOLDS = (5, 10)  # Most urgent first.
REPEAT = timedelta(hours=24)
ADDRESS = re.compile(r"[^\s<>,;@]{1,64}@[A-Za-z0-9.-]{1,253}")


def free_percent(space: os.statvfs_result) -> float:
    """f_bavail is what unprivileged writers such as mysqld can still use; blocks reserved for root are excluded."""
    usable = space.f_blocks - space.f_bfree + space.f_bavail
    return 100.0 * space.f_bavail / usable if usable > 0 else 0.0


def _level(percent: float) -> int | None:
    return next((threshold for threshold in THRESHOLDS if percent <= threshold), None)


def _recipients() -> list[str]:
    if OPERATORS.exists():
        listed = json.loads(OPERATORS.read_text())
    else:
        lines = [line for line in WEBMIN_CONFIG.read_text().splitlines() if line.startswith("webmin_email_to=")]
        listed = re.split(r"[\s,]+", lines[0].partition("=")[2]) if lines else []
    recipients = [item for item in listed if isinstance(item, str) and ADDRESS.fullmatch(item)]
    if not recipients:
        raise ValueError("No operator recipient is configured for node free-space alerts")
    return recipients


def _send(recipients: list[str], message: str) -> None:
    subprocess.run(  # noqa: S603 -- Fixed executable; validated addresses are argv, never shell.
        ["/usr/sbin/sendmail", "-oi", "--", *recipients],
        input=message,
        text=True,
        capture_output=True,
        timeout=60,
        check=True,
    )


def _read_state() -> dict[str, object]:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def _write_state(level: int | None, sent_at: datetime | None) -> None:
    temporary = STATE.with_suffix(".tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump({"level": level, "sent_at": sent_at.isoformat() if sent_at else None}, stream)
    temporary.replace(STATE)


def check(*, now: datetime | None = None) -> None:
    moment = now or datetime.now(UTC)
    percent = free_percent(os.statvfs("/"))
    level = _level(percent)
    prior = _read_state()
    previous = prior.get("level")
    last_sent = datetime.fromisoformat(str(prior["sent_at"])) if prior.get("sent_at") else None
    worsened = level is not None and (previous is None or level < previous)
    # Any low disk is repeated daily, including one that improved between thresholds without recovering.
    due = level is not None and last_sent is not None and moment - last_sent >= REPEAT
    recovered = level is None and previous is not None
    if not (worsened or due or recovered):
        if level != previous:
            # Record an improvement between thresholds, so falling back below the lower one alerts again.
            _write_state(level, last_sent)
        return
    host = socket.gethostname()
    if recovered:
        subject = f"Subject: [PRAHO] {host}: free disk space recovered to {percent:.1f}%"
    else:
        subject = f"Subject: [PRAHO] {host}: free disk space at {percent:.1f}%, below {level}%"
    body = "A full disk aborts the node's shared MariaDB. Tenant databases are not limited by the kernel quota.\n"
    _send(_recipients(), f"{subject}\nFrom: root@{host}\n\n{body}")
    _write_state(level, moment)


if __name__ == "__main__":
    check()
