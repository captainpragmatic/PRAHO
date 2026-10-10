"""Where the deployed Platform writes its log files, and how they survive several writing processes.

Platform runs several processes that log to the same files: the gunicorn workers and the django-q
cluster's workers. Each used to rotate them itself (RotatingFileHandler), so one process renamed a
file under the others: a rename of a file another process had already moved failed and its record
was dropped, early rollovers left short backups, and lines kept landing in moved files.

The files are now written with WatchedFileHandler, which reopens a file once logrotate has moved it,
and nothing rotates in process. The native role installs the rotation policy. PLATFORM_LOG_DIR names
the directory; unset means /var/log/praho, and empty means console only, which the Docker image
sets: a container's files were never on a volume, and ``docker logs`` carries every line.
"""

from __future__ import annotations

import copy
import os
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

DEFAULT_LOG_DIR = "/var/log/praho"
FILE_HANDLERS = ("file", "security_file", "audit_file", "error_file")


def platform_log_dir(env: Mapping[str, str] = os.environ) -> str:
    """The directory for Platform's log files, or "" for console only. Unset means the default."""
    value = env.get("PLATFORM_LOG_DIR")
    return DEFAULT_LOG_DIR if value is None else value.strip()


def place_log_files(logging_config: dict[str, Any], log_dir: str) -> dict[str, Any]:
    """The LOGGING dict with its file handlers in ``log_dir``, or without them when it is empty."""
    config = copy.deepcopy(logging_config)
    handlers: dict[str, dict[str, Any]] = config["handlers"]
    if log_dir:
        for name in FILE_HANDLERS:
            handler = handlers[name]
            handler["filename"] = str(PurePosixPath(log_dir) / PurePosixPath(handler["filename"]).name)
        return config
    for name in FILE_HANDLERS:
        handlers.pop(name, None)
    for logger in (config["root"], *config["loggers"].values()):
        logger["handlers"] = [handler for handler in logger["handlers"] if handler not in FILE_HANDLERS]
    return config
