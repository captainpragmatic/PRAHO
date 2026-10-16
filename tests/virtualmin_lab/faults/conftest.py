"""Session set-up for the Virtualmin fault suite: the workflow bench, plus the means to break and mend the lab.

Run it with `make test-virtualmin-faults` (it needs `make virtualmin-lab-up`). The runner's trap restores the
lab even when pytest is killed; the fixtures here restore it after every test, so one fault cannot leak into the
next.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import django
import pytest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.lab")
django.setup()

from tests.virtualmin_lab.faults.harness import Chaos  # noqa: E402
from tests.virtualmin_lab.workflows.conftest import bench  # noqa: E402, F401  # The fixture, shared with the workflows
from tests.virtualmin_lab.workflows.harness import Bench  # noqa: E402


@pytest.fixture
def chaos(bench: Bench) -> Iterator[Chaos]:  # noqa: F811  # Takes the shared fixture by name
    the_chaos = Chaos(bench)
    the_chaos.restore_all()
    try:
        yield the_chaos
    finally:
        the_chaos.restore_all()
        bench.reset_meters()
