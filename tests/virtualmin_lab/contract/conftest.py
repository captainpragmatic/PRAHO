"""Session set-up for the Virtualmin contract suite: lab settings, the node, and the recording.

Run it with `make test-virtualmin-contract` (it needs `make virtualmin-lab-up`). It is never collected by
the ordinary test runs: it lives outside the Django test tree and outside `tests/integration`.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path

import django
import pytest
from django.core.cache import cache

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.lab")
django.setup()

from apps.provisioning.management.commands._virtualmin_lab import (  # noqa: E402
    DEPLOY_NODE,
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
    with_deploy_node,
)
from apps.provisioning.virtualmin_gateway import VirtualminConfig  # noqa: E402
from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: E402
from tests.virtualmin_lab.contract.harness import (  # noqa: E402
    SANDBOX_DOMAIN,
    SANDBOX_USER,
    Lab,
    Recorder,
    RecordingGateway,
)

RECORD_DIR_ENV = "VIRTUALMIN_CONTRACT_RECORD_DIR"
# The node under test: vm-b, or the freshly deployed node-c (make test-virtualmin-node-deploy).
LAB_NODE = os.environ.get("VIRTUALMIN_CONTRACT_NODE", "vm-b")
_VERSION = re.compile(r"virtualmin version:\s*(\S+)")
_recorders: list[Recorder] = []


@pytest.fixture(scope="session")
def lab() -> Iterator[Lab]:
    refuse_unless_lab_settings()
    state = load_state()
    if DEPLOY_NODE.key == LAB_NODE:
        state = with_deploy_node(state)
    node = state.node(LAB_NODE)
    server = VirtualminServer.objects.get(hostname=node.server_hostname)
    # The gateway meters calls per server and program for an hour; a contract run makes many.
    cache.clear()
    with ExitStack() as stack:
        stack.enter_context(lab_transport(state))
        gateway = RecordingGateway(VirtualminConfig(server=server))
        gateway.call("info")
        info = gateway.exchanges[-1]
        assert info.result.is_ok(), f"cannot reach {node.server_hostname}: {info.result.unwrap_err()}"
        match = _VERSION.search(str(info.response.data.get("output", "")))
        assert match, "the node's info does not report a Virtualmin version"
        record_dir = os.environ.get(RECORD_DIR_ENV)
        recorder = Recorder(version=match.group(1), directory=Path(record_dir) if record_dir else None)
        _recorders.append(recorder)
        # A random password per run; recordings never keep it (the sanitiser redacts `pass`).
        the_lab = Lab(gateway, node, server, recorder, password="Qz9" + secrets.token_hex(10))
        the_lab.remove_leftovers()
        the_lab.create_domain(SANDBOX_DOMAIN, SANDBOX_USER)
        try:
            yield the_lab
        finally:
            the_lab.remove_leftovers()


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write the recording only after a fully green run: a partial one would read as drift."""
    if exitstatus == 0:
        for recorder in _recorders:
            recorder.write()
