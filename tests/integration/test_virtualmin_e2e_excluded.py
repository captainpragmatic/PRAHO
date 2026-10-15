"""The Virtualmin browser smoke tests never run in the default `make test-e2e`. No lab needed.

They need the Docker lab, its settings module and a server that only `make test-virtualmin-e2e`
(tests/virtualmin_lab/run_e2e.sh) starts. Three things keep them out of every other run, and each is proven here:

(a) the platform conftest tells pytest not to import `test_virtualmin_lab_*.py` unless the runner set
    `VIRTUALMIN_E2E=1` (a deselect by marker would still import the module, and the module imports the lab);
(b) the default E2E stack hands pytest an allow-listed environment, so a `VIRTUALMIN_E2E` in the caller's shell
    cannot reach it;
(c) every such test carries the `virtualmin_lab` marker, registered in both pytest ini files.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest import mock

import pytest

from scripts.e2e_stack import environment

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
E2E_PLATFORM = REPO / "tests/e2e/platform"
LAB_TEST_GLOB = "test_virtualmin_lab_*.py"


def _load_platform_conftest() -> object:
    spec = importlib.util.spec_from_file_location("virtualmin_e2e_platform_conftest", E2E_PLATFORM / "conftest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_platform_conftest_ignores_the_lab_tests_without_the_runner_flag() -> None:
    with mock.patch.dict(os.environ):
        os.environ.pop("VIRTUALMIN_E2E", None)
        conftest = _load_platform_conftest()

    assert getattr(conftest, "collect_ignore_glob", None) == [LAB_TEST_GLOB]


def test_the_ignore_pattern_matches_every_lab_test_file() -> None:
    files = sorted(E2E_PLATFORM.glob(LAB_TEST_GLOB))

    assert files, "the smoke tests moved: update LAB_TEST_GLOB and the conftest together"
    assert {file.name for file in files} >= {"test_virtualmin_lab_account.py"}


def test_the_default_e2e_stack_does_not_forward_the_runner_flag() -> None:
    with mock.patch.dict(os.environ, {"VIRTUALMIN_E2E": "1", "VIRTUALMIN_LAB_DATABASE": "/tmp/x.sqlite3"}):  # noqa: S108
        forwarded = environment()

    assert "VIRTUALMIN_E2E" not in forwarded
    assert "VIRTUALMIN_LAB_DATABASE" not in forwarded
    assert forwarded["DJANGO_SETTINGS_MODULE"] == "config.settings.e2e"


@pytest.mark.parametrize("ini", ["pytest.ini", "tests/virtualmin_lab/pytest.ini"])
def test_the_marker_is_registered(ini: str) -> None:
    assert "virtualmin_lab:" in (REPO / ini).read_text()


@pytest.mark.parametrize("path", sorted(E2E_PLATFORM.glob(LAB_TEST_GLOB)), ids=lambda path: path.name)
def test_every_lab_test_module_carries_the_marker(path: Path) -> None:
    assert "pytestmark = pytest.mark.virtualmin_lab" in path.read_text(), path.name
