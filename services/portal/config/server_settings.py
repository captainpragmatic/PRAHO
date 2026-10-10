"""The portal's gunicorn server settings, read from PORTAL_GUNICORN_* environment variables.

gunicorn.conf.py applies these; the launchers pass only the bind address and log targets, because
a command-line flag would override them. A value that is not allowed raises ValueError, which stops
gunicorn from starting instead of running with something unintended.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

WORKER_CLASSES = ("sync", "gthread")
MAX_WORKERS = 16
MAX_THREADS = 32


def _text(env: Mapping[str, str], name: str, default: str) -> str:
    return env.get(name, "").strip() or default


def _number(env: Mapping[str, str], name: str, default: int, maximum: int) -> int:
    raw = _text(env, name, str(default))
    if not raw.isascii() or not raw.isdigit() or not 1 <= int(raw) <= maximum:
        raise ValueError(f"{name} must be a whole number from 1 to {maximum}, got {raw!r}")
    return int(raw)


def server_settings(env: Mapping[str, str] = os.environ) -> dict[str, Any]:
    """The gunicorn settings this environment asks for."""
    if env.get("GUNICORN_CMD_ARGS", "").strip():
        # gunicorn applies these over this config, so they would replace the settings below. On a
        # native install the .env is shared with Platform, whose tuning would become the portal's.
        raise ValueError("GUNICORN_CMD_ARGS is not used by the portal; set PORTAL_GUNICORN_* instead")
    worker_class = _text(env, "PORTAL_GUNICORN_WORKER_CLASS", "sync")
    if worker_class not in WORKER_CLASSES:
        raise ValueError(f"PORTAL_GUNICORN_WORKER_CLASS must be one of {WORKER_CLASSES}, got {worker_class!r}")
    # gunicorn quietly turns "sync" into "gthread" whenever threads > 1, so a sync worker is
    # always given one thread: choosing sync (for example to roll back) must mean sync.
    threads = 1 if worker_class == "sync" else _number(env, "PORTAL_GUNICORN_THREADS", 4, MAX_THREADS)
    return {
        "worker_class": worker_class,
        "workers": _number(env, "PORTAL_GUNICORN_WORKERS", 2, MAX_WORKERS),
        "threads": threads,
        # A worker accepts no more connections than it has threads, so a busy worker leaves new
        # connections to an idle sibling instead of queueing them behind its own requests.
        "worker_connections": threads,
        # Close each connection after its response, as sync workers always did: no idle
        # connection for the reverse proxy to reuse after the worker has dropped it.
        "keepalive": 0,
        "timeout": 60,
        "graceful_timeout": 50,
    }
