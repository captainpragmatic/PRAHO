"""The server acceptance tests start real gunicorn processes: they run only when asked for.

``make test-portal-server`` sets PORTAL_SERVER_TESTS=1. Without it they are deselected (not skipped)
however the run selects markers: a plain ``-m "not slow"`` would otherwise replace pytest.ini's
``-m "not server"`` and start them.
"""

from __future__ import annotations

import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("PORTAL_SERVER_TESTS") == "1":
        return
    deselected = [item for item in items if item.get_closest_marker("server") is not None]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = [item for item in items if item.get_closest_marker("server") is None]
