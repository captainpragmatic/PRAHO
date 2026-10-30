"""Who ran a management command, for the audit trail: a command has no request user."""

from __future__ import annotations

import getpass


def operator_name() -> str:
    """The server account running the command."""
    try:
        return getpass.getuser()
    except (KeyError, OSError):  # no passwd entry for the uid, as in some containers
        return "unknown"
