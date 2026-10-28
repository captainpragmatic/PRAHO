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

from scripts.ci_lab_needed import lab_needed

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
MAKEFILE = (REPO / "Makefile").read_text()
WORKFLOW = yaml.safe_load((REPO / ".github/workflows/virtualmin-lab.yml").read_text())
PR_WORKFLOW = yaml.safe_load((REPO / ".github/workflows/virtualmin-lab-pr.yml").read_text())
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


def test_pull_requests_run_the_lab_when_a_change_can_break_it() -> None:
    # `pull-request` is a required check: a workflow skipped by a paths filter never reports, so the
    # selection lives in a job, and the job it gates reports success when skipped.
    pr_on = PR_WORKFLOW[True] if True in PR_WORKFLOW else PR_WORKFLOW["on"]
    assert list(pr_on) == ["pull_request"] and "paths" not in pr_on["pull_request"]
    assert "pull_request" not in on_block(), "the nightly workflow must not also hold a job named pull-request"
    jobs = PR_WORKFLOW["jobs"]
    # The base branch's rules decide, renames count as both paths, and an unreadable diff runs the lab.
    decide = str(jobs["changes"]["steps"])
    assert 'git show "${BASE_SHA}:scripts/ci_lab_needed.py"' in decide and "--no-renames" in decide
    assert jobs["pull-request"]["needs"] == "changes"
    assert jobs["pull-request"]["if"] == "!cancelled() && needs.changes.outputs.lab != 'false'"

    for changed in (
        "services/platform/apps/provisioning/virtualmin_service.py",
        "services/platform/apps/infrastructure/ansible_service.py",
        "services/platform/infrastructure/ansible/playbooks/node.yml",
        "deploy/virtualmin-lab/virtualmin/Dockerfile",
        "tests/virtualmin_lab/contract/test_bridge.py",
        "Makefile",  # the targets the job runs live there
        "uv.lock",
    ):
        assert lab_needed([changed]), changed


def test_the_workflow_follows_the_nightly_conventions() -> None:
    jobs = WORKFLOW["jobs"]

    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert on_block()["schedule"], "a nightly schedule"
    assert "check-activity" in jobs and "notify-scheduled-failure" in jobs
    assert jobs["notify-scheduled-failure"]["permissions"] == {"issues": "write"}
    assert "make test-virtualmin-lab-full" in str(jobs["nightly-full"]["steps"])
    assert "make test-virtualmin-lab" in str(PR_WORKFLOW["jobs"]["pull-request"]["steps"])
    # A release candidate's lab must test the candidate, not the master tip it was dispatched on.
    checkout = next(step for step in jobs["nightly-full"]["steps"] if "actions/checkout" in str(step.get("uses")))
    assert checkout["with"]["ref"] == "${{ inputs.ref }}"
    assert "make test-virtualmin-drift" in str(jobs["nightly-drift"]["steps"])
    assert set(jobs["nightly-drift"]["strategy"]["matrix"]["runner"]) == {"ubuntu-latest", "ubuntu-24.04-arm"}


def test_the_image_workflow_can_still_read_the_pinned_version() -> None:
    assert re.search(r"^ARG VIRTUAL_SERVER_VERSION=[0-9][0-9.]*", DOCKERFILE, re.MULTILINE)


# webmin-virtual-server is not here: it is resolved to the highest -gpl version before apt runs
# (tests/integration/test_virtualmin_lab_drift_build.py), because the repository also carries a -pro build.
@pytest.mark.parametrize(
    "package",
    ["webmin", "virtualmin-core", "virtualmin-config", "virtualmin-lamp-stack-minimal"],
)
def test_every_pinned_package_installs_unpinned_when_its_version_argument_is_empty(package: str) -> None:
    assert re.search(rf'"{re.escape(package)}\$\{{[A-Z_]+:\+=\$\{{[A-Z_]+\}}\}}"', DOCKERFILE), package


def test_the_runner_installs_the_ansible_collections_the_playbooks_load() -> None:
    """The node playbooks load community.general and ansible.posix, which ansible-core does not ship.

    A runner without them failed the node-deploy check with "No module named ansible_collections"; the
    Platform image installs them from the same requirements file (deploy/platform/Dockerfile).
    """
    assert "ansible-galaxy collection install -r services/platform/infrastructure/ansible/requirements.yml" in (
        recipe("ansible-collections")
    )
    setup = (REPO / ".github/actions/virtualmin-lab-setup/action.yml").read_text()
    assert "make ansible-collections" in setup
