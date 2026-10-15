"""The Virtualmin lab stays opt-in and wired where the task says. No lab needed.

The lab needs Docker with privileged systemd containers, so none of it may leak into the default test targets;
the CI workflow must run on the paths that can break it; the image must still build both pinned and unpinned.
Each fact is read from source, never by running the lab.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = (REPO / "Makefile").read_text()
WORKFLOW = yaml.safe_load((REPO / ".github/workflows/virtualmin-lab.yml").read_text())
DOCKERFILE = (REPO / "deploy/virtualmin-lab/virtualmin/Dockerfile").read_text()

# The targets a developer or CI runs without opting in to the lab.
DEFAULT_TARGETS = ("test", "test-fast", "test-platform", "test-portal", "test-integration", "test-e2e", "test-ci")


def recipe(target: str) -> str:
    """The prerequisites and recipe lines of one Makefile target (empty when it has none)."""
    match = re.search(rf"^{re.escape(target)}:(?P<body>.*?)(?=^\S)", MAKEFILE, re.MULTILINE | re.DOTALL)
    return match.group("body") if match else ""


@pytest.mark.parametrize("target", DEFAULT_TARGETS)
def test_default_targets_never_touch_the_lab(target: str) -> None:
    body = recipe(target)

    assert body.strip(), f"make {target} was not found: the finder is broken"
    assert "virtualmin" not in body.lower(), f"make {target} must not run or depend on the Virtualmin lab"


def test_plain_make_dev_is_unchanged_and_the_lab_variant_is_opt_in() -> None:
    assert "ifeq ($(VIRTUALMIN_LAB),1)\ndev: virtualmin-lab-ensure\n\t@$(MAKE) dev-platform-lab\nelse\ndev:\n\t@$(MAKE) dev-all\nendif" in MAKEFILE


def test_the_full_target_runs_every_leg_the_task_names() -> None:
    body = recipe("test-virtualmin-lab-full")

    for leg in ("test-virtualmin-lab", "test-virtualmin-node-deploy", "test-virtualmin-faults", "test-virtualmin-e2e"):
        assert re.search(rf"\b{leg}\b", body), leg


def test_the_drift_target_builds_unpinned_and_records_nothing() -> None:
    body = recipe("test-virtualmin-drift")

    assert "VIRTUALMIN_LAB_UNPINNED=1" in body and "VIRTUALMIN_LAB_TAG=latest" in body
    assert "RECORD=none" in body


def on_block() -> dict[str, Any]:
    return WORKFLOW[True] if True in WORKFLOW else WORKFLOW["on"]  # YAML 1.1 reads the key `on` as True


def test_pull_requests_run_on_the_paths_that_can_break_the_lab() -> None:
    paths = on_block()["pull_request"]["paths"]

    for needed in (
        "services/platform/apps/provisioning/**",
        "services/platform/infrastructure/ansible/**",
        "deploy/virtualmin-lab/**",
        "tests/virtualmin_lab/**",
    ):
        assert needed in paths, needed


def test_the_workflow_follows_the_nightly_conventions() -> None:
    jobs = WORKFLOW["jobs"]

    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert on_block()["schedule"], "a nightly schedule"
    assert "check-activity" in jobs and "notify-scheduled-failure" in jobs
    assert jobs["notify-scheduled-failure"]["permissions"] == {"issues": "write"}
    assert "make test-virtualmin-lab-full" in str(jobs["nightly-full"]["steps"])
    assert "make test-virtualmin-lab" in str(jobs["pull-request"]["steps"])
    assert "make test-virtualmin-drift" in str(jobs["nightly-drift"]["steps"])
    assert set(jobs["nightly-drift"]["strategy"]["matrix"]["runner"]) == {"ubuntu-latest", "ubuntu-24.04-arm"}


def test_the_image_workflow_can_still_read_the_pinned_version() -> None:
    assert re.search(r"^ARG VIRTUAL_SERVER_VERSION=[0-9][0-9.]*", DOCKERFILE, re.MULTILINE)


@pytest.mark.parametrize(
    "package",
    ["webmin", "webmin-virtual-server", "virtualmin-core", "virtualmin-config", "virtualmin-lamp-stack-minimal"],
)
def test_every_pinned_package_installs_unpinned_when_its_version_argument_is_empty(package: str) -> None:
    assert re.search(rf'"{re.escape(package)}\$\{{[A-Z_]+:\+=\$\{{[A-Z_]+\}}\}}"', DOCKERFILE), package
