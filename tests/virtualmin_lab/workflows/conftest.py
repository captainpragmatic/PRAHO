"""Session set-up for the Virtualmin workflow suite: lab settings, both nodes, and a clean way back.

Run it with `make test-virtualmin-workflows` (it needs `make virtualmin-lab-up`). It is never collected by
the ordinary test runs: it lives outside the Django test tree and outside `tests/integration`.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import ExitStack

import django
import pytest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.lab")
django.setup()

from apps.provisioning.management.commands._virtualmin_lab import (  # noqa: E402
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
)
from tests.virtualmin_lab.workflows.harness import Bench, build_bench  # noqa: E402

# Settings every workflow needs on; the bench puts them back.
WORKFLOW_SETTINGS = {
    "provisioning.migration_enabled": True,
    "infrastructure.drain_enabled": True,
    "provisioning.incremental_backups_enabled": True,
}


@pytest.fixture(scope="session")
def bench() -> Iterator[Bench]:
    refuse_unless_lab_settings()
    state = load_state()
    with ExitStack() as stack:
        stack.enter_context(lab_transport(state))
        the_bench = build_bench(state)
        the_bench.reset_meters()
        the_bench.refresh_health()
        the_bench.remove_leftovers()
        for key, value in WORKFLOW_SETTINGS.items():
            the_bench.set_setting(key, value)
        try:
            yield the_bench
        finally:
            the_bench.remove_leftovers()
            the_bench.put_back()
