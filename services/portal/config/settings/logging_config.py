"""Structured JSON logging for the deployed portal (prod and staging), with request ID tracing.

Log lines always go to the console (stderr), which journald and ``docker logs`` collect. When
PORTAL_LOG_DIR names a directory, they are also written to ``app.log`` and ``error.log`` there.

Several gunicorn processes write those files at once, so the portal never rotates them itself: one
process renaming a file under the others loses or misplaces their lines. ``WatchedFileHandler``
instead reopens the file when logrotate has moved it (the native role installs that policy). The
Docker image sets PORTAL_LOG_DIR empty: a container's files were never on a volume, and nothing
rotated them; ``docker logs`` already carries every line.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from apps.common.secret_urls import secure_logging_config

DEFAULT_LOG_DIR = "/var/log/praho/portal"


def portal_log_dir(env: Mapping[str, str] = os.environ) -> str:
    """The directory for the portal's log files, or "" for console only. Unset means the default."""
    value = env.get("PORTAL_LOG_DIR")
    return DEFAULT_LOG_DIR if value is None else value.strip()


def add_crowdsec_auth_logging(config: dict[str, Any], auth_log_path: str) -> dict[str, Any]:
    """Attach the dedicated event sink before privacy filters are applied."""
    config["formatters"]["crowdsec_auth"] = {"format": "%(message)s"}
    config["handlers"]["crowdsec_auth"] = {
        "class": "apps.common.auth_events.SecurityEventFileHandler"
        if auth_log_path
        else "apps.common.auth_events.SecurityEventStreamHandler",
        "formatter": "crowdsec_auth",
        **(
            {
                "filename": auth_log_path,
                "maxBytes": 10 * 1024 * 1024,
                "backupCount": 4,
                "delay": True,
                "encoding": "utf-8",
            }
            if auth_log_path
            else {"stream": "ext://sys.stdout"}
        ),
    }
    config["loggers"]["praho.crowdsec.auth"] = {"handlers": ["crowdsec_auth"], "level": "INFO", "propagate": False}
    return config


def portal_logging(log_dir: str, *, apps_level: str = "INFO", auth_log_path: str | None = None) -> dict[str, Any]:
    """The LOGGING dict: console always, plus watched files when ``log_dir`` is set."""
    files = ["file"] if log_dir else []
    error_files = ["error_file"] if log_dir else []
    handlers: dict[str, dict[str, Any]] = {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["add_request_id"],
        },
    }
    if log_dir:
        directory = Path(log_dir)
        handlers["file"] = {
            "class": "logging.handlers.WatchedFileHandler",
            "filename": str(directory / "app.log"),
            "formatter": "json",
            "filters": ["add_request_id"],
        }
        handlers["error_file"] = {
            "class": "logging.handlers.WatchedFileHandler",
            "filename": str(directory / "error.log"),
            "formatter": "json",
            "filters": ["add_request_id"],
            "level": "ERROR",
        }
    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "json": {
                "()": "apps.common.logging.PortalJSONFormatter",
            },
            "verbose": {
                "format": "[{asctime}] {levelname} [{name}:{funcName}:{lineno}] {message}",
                "style": "{",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "filters": {
            "add_request_id": {
                "()": "apps.common.middleware.RequestIDFilter",
            },
        },
        "handlers": handlers,
        "root": {
            "handlers": ["console", *files],
            "level": "INFO",
        },
        "loggers": {
            "django": {
                "handlers": ["console", *files],
                "level": "INFO",
                "propagate": False,
            },
            "django.security": {
                "handlers": ["console", *files, *error_files],
                "level": "WARNING",
                "propagate": False,
            },
            "django.request": {
                "handlers": ["console", *files, *error_files],
                "level": "ERROR",
                "propagate": False,
            },
            "apps": {
                "handlers": ["console", *files],
                "level": apps_level,
                "propagate": False,
            },
        },
    }

    if auth_log_path is not None:
        add_crowdsec_auth_logging(config, auth_log_path)
    return secure_logging_config(config)
