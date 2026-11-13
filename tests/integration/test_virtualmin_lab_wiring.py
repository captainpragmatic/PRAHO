"""The Virtualmin lab stays opt-in and wired where the task says. No lab needed.

The lab needs Docker with privileged systemd containers, so none of it may leak into the default test targets;
the CI workflow must run on the paths that can break it; the image must still build both pinned and unpinned.
Each fact is read from source, never by running the lab.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

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
    assert (
        "ifeq ($(VIRTUALMIN_LAB),1)\ndev: virtualmin-lab-ensure\n\t@$(MAKE) dev-platform-lab\nelse\ndev:\n\t@$(MAKE) dev-all\nendif"
        in MAKEFILE
    )


def test_the_full_target_runs_every_leg_the_task_names() -> None:
    body = recipe("test-virtualmin-lab-full")

    for leg in ("test-virtualmin-lab", "test-virtualmin-node-deploy", "test-virtualmin-faults", "test-virtualmin-e2e"):
        assert re.search(rf"\b{leg}\b", body), leg


def test_full_native_failure_remains_fatal_and_other_legs_still_run(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    stub = tmp_path / "record-step"
    stub.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$LAB_RECIPE_TRACE"\nfor argument do\n  if [ "$argument" = test-virtualmin-node-deploy ]; then exit 23; fi\ndone\n'
    )
    stub.chmod(0o700)
    result = subprocess.run(  # noqa: S603 -- Actual unchanged full Make recipe, all external legs are task-owned recorders.
        [
            shutil.which("make") or "make",
            "--no-print-directory",
            "test-virtualmin-lab-full",
            "MAKE=" + shlex.quote(str(stub)),
        ],
        cwd=REPO,
        env={**os.environ, "LAB_RECIPE_TRACE": str(calls)},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0
    assert calls.read_text().splitlines() == [
        "--no-print-directory " + leg
        for leg in (
            "test-virtualmin-lab",
            "test-virtualmin-node-deploy",
            "test-virtualmin-faults",
            "test-virtualmin-e2e",
        )
    ]
    assert "Failed legs: test-virtualmin-node-deploy" in result.stdout


@pytest.mark.parametrize("failed_leg", ["", "test-virtualmin-faults"])
def test_container_aggregation_runs_every_non_native_leg_and_reports_failure(tmp_path: Path, failed_leg: str) -> None:
    calls = tmp_path / "calls"
    stub = tmp_path / "record-step"
    stub.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$LAB_RECIPE_TRACE"\nfor argument do\n  if [ "$argument" = "$FAILED_LEG" ]; then exit 23; fi\ndone\n'
    )
    stub.chmod(0o700)
    result = subprocess.run(  # noqa: S603 -- Actual Make aggregation, external leg calls replaced by an exact recorder.
        [
            shutil.which("make") or "make",
            "--no-print-directory",
            "test-virtualmin-lab-containers",
            "MAKE=" + shlex.quote(str(stub)),
        ],
        cwd=REPO,
        env={**os.environ, "LAB_RECIPE_TRACE": str(calls), "FAILED_LEG": failed_leg},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert calls.read_text().splitlines() == [
        "--no-print-directory " + name
        for name in (
            "test-virtualmin-lab",
            "test-virtualmin-faults",
            "test-virtualmin-e2e",
            "test-virtualmin-maintenance-portal",
        )
    ]
    assert (result.returncode != 0) is bool(failed_leg)
    assert "native" not in recipe("test-virtualmin-lab-containers").split("for leg", 1)[1].split("; do", 1)[0]
    if failed_leg:
        assert failed_leg in result.stdout


@pytest.mark.parametrize("refuse_admission", [False, True])
def test_native_node_script_runs_only_the_supported_fresh_pipeline_serially(
    tmp_path: Path, refuse_admission: bool
) -> None:
    calls = tmp_path / "calls"
    stub = tmp_path / "make"
    stub.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$NATIVE_RECIPE_TRACE"\nif [ "$REFUSE_NATIVE_ADMISSION" = 1 ]; then\n  for argument do\n    if [ "$argument" = test-virtualmin-native-fresh-deployment ]; then exit 23; fi\n  done\nfi\n'
    )
    stub.chmod(0o700)
    environment = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "NATIVE_RECIPE_TRACE": str(calls),
        "NATIVE_VM_MANIFEST": str(tmp_path / "owned VM.json"),
        "NATIVE_DNS_ZONE": "native.example.invalid",
        "REFUSE_NATIVE_ADMISSION": "1" if refuse_admission else "0",
        "NATIVE_S3_MANIFEST": str(tmp_path / "owned S3.json"),
        "PRAHO_NATIVE_S3_ENDPOINT_URL": "http://127.0.0.1:1",
        "PRAHO_NATIVE_S3_BUCKET": "synthetic-fixture-bucket",
        "PRAHO_NATIVE_S3_ACCESS_KEY_ID": "fixture-only",
        "PRAHO_NATIVE_S3_SECRET_ACCESS_KEY": "fixture-only",
    }
    result = subprocess.run(  # noqa: S603 -- Exact repository shell script; Make replaced by a task-owned recorder.
        [shutil.which("bash") or "/bin/bash", str(REPO / "tests/virtualmin_lab/run_node_deploy.sh")],
        cwd=REPO,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert (result.returncode != 0) is refuse_admission, result.stderr
    expected = (
        ("test-virtualmin-native-fresh-deployment",)
        if refuse_admission
        else (
            "test-virtualmin-native-fresh-deployment",
            "native-vm-migrate",
            "native-vm-fresh-deploy",
            "native-vm-register",
            "test-virtualmin-quotas",
            "test-virtualmin-native-fresh-deployment",
            "native-s3-verify",
            "test-virtualmin-native-workflow",
        )
    )
    assert calls.read_text().splitlines() == [f"-C {REPO} --no-print-directory {name}" for name in expected]


def test_native_full_is_manual_isolated_and_checks_actual_capability() -> None:
    assert on_block()["workflow_dispatch"]["inputs"]["suite"]["default"] == "containers"
    job = WORKFLOW["jobs"]["native-full"]
    assert job["if"] == "github.event_name == 'workflow_dispatch' && inputs.suite == 'full'"
    assert job["runs-on"] == ["self-hosted", "linux", "native-acceptance"]
    assert job["environment"] == "native-acceptance"
    assert job["needs"] == "native-admission"
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["ref"] == "${{ github.sha }}"
    capability = [step for step in job["steps"] if step.get("name") == "Verify fresh Ubuntu native hosting capability"]
    assert len(capability) == 1 and capability[0]["run"] == "make test-virtualmin-native-fresh-deployment"
    full = next(step for step in job["steps"] if step.get("run") == "make test-virtualmin-lab-full")
    assert job["steps"].index(capability[0]) < job["steps"].index(full)
    assert "continue-on-error" not in capability[0] and "continue-on-error" not in job
    assert "make test-virtualmin-lab-full" in str(job["steps"])
    assert "native-full" not in WORKFLOW["jobs"]["notify-scheduled-failure"]["needs"]


@pytest.mark.parametrize("ready,successful", [("", False), ("false", False), ("TRUE", False), ("true", True)])
def test_native_admission_fails_fast_until_explicitly_configured(ready: str, successful: bool) -> None:
    admission = WORKFLOW["jobs"]["native-admission"]
    assert admission["if"] == "github.event_name == 'workflow_dispatch' && inputs.suite == 'full'"
    assert admission["runs-on"] == "ubuntu-latest"
    command = admission["steps"][0]
    assert command["env"]["NATIVE_ACCEPTANCE_RUNNER_READY"] == "${{ vars.NATIVE_ACCEPTANCE_RUNNER_READY }}"
    result = subprocess.run(  # noqa: S603 -- Exact workflow configuration precheck, no resources or credentials.
        [shutil.which("bash") or "/bin/bash", "-c", command["run"]],
        env={**os.environ, "NATIVE_ACCEPTANCE_RUNNER_READY": ready},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert (result.returncode == 0) is successful
    if not successful:
        assert "private authority" in result.stdout


def test_queue_lab_target_runs_components_serially_after_existing_suites(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    stub = tmp_path / "record-step"
    stub.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$LAB_RECIPE_TRACE"\n')
    stub.chmod(0o700)
    result = subprocess.run(  # noqa: S603 -- actual make recipe with every external action replaced by a recorder.
        [
            shutil.which("make") or "make",
            "--no-print-directory",
            "test-virtualmin-lab",
            "MAKE=" + shlex.quote(str(stub)) + " recursive",
            "PYTHON_PLATFORM_LAB_MANAGE=" + shlex.quote(str(stub)) + " manage",
        ],
        cwd=REPO,
        env={**os.environ, "LAB_RECIPE_TRACE": str(calls)},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert calls.read_text().splitlines() == [
        "manage virtualmin_lab_roundtrip",
        "recursive --no-print-directory test-virtualmin-contract",
        "recursive --no-print-directory test-virtualmin-workflows",
        "manage virtualmin_lab_checks",
        "recursive --no-print-directory test-virtualmin-components",
    ]
    assert recipe("test-virtualmin-components").splitlines()[0].strip() == "virtualmin-lab-component-source-up"


def test_native_sql_contract_transfers_all_database_export_import_dependencies(tmp_path: Path) -> None:
    contract = REPO / "tests/virtualmin_lab/contract/test_component_database_fence.py"
    tree = ast.parse(contract.read_text())
    copied = next(
        ast.literal_eval(row.value)
        for row in tree.body
        if isinstance(row, ast.Assign)
        and any(isinstance(name, ast.Name) and name.id == "HELPERS" for name in row.targets)
    )
    helpers = REPO / "services/platform/infrastructure/ansible/playbooks/files"
    for filename in copied:
        shutil.copyfile(helpers / filename, tmp_path / filename)
    spec = importlib.util.spec_from_file_location(
        "isolated_contract_export", tmp_path / "praho-component-database-export.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(module.capacity.OutputBudget)


def test_full_lab_failure_diagnostics_include_imported_component_source() -> None:
    for workflow, job in ((WORKFLOW, "nightly-containers"), (WORKFLOW, "native-full")):
        diagnostics = next(
            step["run"] for step in workflow["jobs"][job]["steps"] if step.get("name") == "Lab diagnostics"
        )
        assert "vmlab-component-source" in diagnostics


def test_the_drift_target_builds_unpinned_and_records_nothing() -> None:
    body = recipe("test-virtualmin-drift")

    assert "VIRTUALMIN_LAB_UNPINNED=1" in body and "VIRTUALMIN_LAB_TAG=latest" in body
    assert "RECORD=none" in body


def on_block() -> dict[str, Any]:
    return WORKFLOW[True] if True in WORKFLOW else WORKFLOW["on"]  # YAML 1.1 reads the key `on` as True


def test_component_diagnostics_require_an_explicit_manual_dispatch_and_have_a_distinct_job() -> None:
    suite = on_block()["workflow_dispatch"]["inputs"]["suite"]
    assert suite["options"] == ["containers", "full", "drift", "components"]
    assert suite["default"] == "containers"
    job = WORKFLOW["jobs"]["components-diagnostic"]
    assert job["if"] == "github.event_name == 'workflow_dispatch' && inputs.suite == 'components'"
    assert "needs" not in job, "Diagnostics must not depend on a scheduled/full proof job"
    assert job["runs-on"] == "ubuntu-24.04"
    assert 1 <= job["timeout-minutes"] <= 90
    assert "components-diagnostic" not in WORKFLOW["jobs"]["notify-scheduled-failure"]["needs"]
    assert "inputs.suite == 'full'" in WORKFLOW["jobs"]["native-full"]["if"]
    assert "components" not in WORKFLOW["jobs"]["native-full"]["if"]


def test_component_diagnostics_use_only_the_component_boundary_with_unconditional_evidence_and_cleanup() -> None:
    steps = WORKFLOW["jobs"]["components-diagnostic"]["steps"]
    checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0
    setup = [step for step in steps if step.get("uses") == "./.github/actions/virtualmin-lab-setup"]
    assert len(setup) == 1
    assert setup[0].get("with", {}).get("browser", "false") == "false"
    commands = [step for step in steps if "run" in step and step["run"].startswith("make ")]
    assert [shlex.split(step["run"]) for step in commands] == [
        ["make", "virtualmin-lab-up"],
        ["make", "test-virtualmin-components"],
        ["make", "virtualmin-lab-down"],
    ], "A diagnostic run must not substitute full/queue/release evidence or run unrelated lab legs"
    assert commands[-1]["if"] == "always()"
    upload = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
    assert len(upload) == 1
    assert upload[0]["if"] == "always()"
    assert upload[0]["with"]["path"] == "output/virtualmin-lab/components/"
    assert upload[0]["with"]["name"] == "virtualmin-components-diagnostics"
    assert steps.index(upload[0]) < steps.index(commands[-1])
    diagnostics = next(step for step in steps if step.get("name") == "Lab diagnostics")
    assert diagnostics["if"] == "failure()"
    assert "vmlab-component-source" in diagnostics["run"]


def test_the_lab_runs_nightly_and_never_per_pull_request() -> None:
    # The lab no longer runs per pull request or in the merge queue (ADR-0036, amended). `pull-request` stays a
    # required check until the ruleset drops it, so it must report on every pull request and merge group,
    # unconditionally, and run nothing.
    pr_on = PR_WORKFLOW[True] if True in PR_WORKFLOW else PR_WORKFLOW["on"]
    assert list(pr_on) == ["pull_request", "merge_group"]
    assert all("paths" not in (pr_on[event] or {}) for event in pr_on)
    assert "pull_request" not in on_block(), "the nightly workflow must not also hold a job named pull-request"
    assert list(PR_WORKFLOW["jobs"]) == ["pull-request"]
    job = PR_WORKFLOW["jobs"]["pull-request"]
    assert "if" not in job and "needs" not in job and "continue-on-error" not in job
    assert "make" not in str(job["steps"]) and "virtualmin-lab-setup" not in str(job["steps"])

    # What replaces it: the full container lab every night master changed, and the release gate on it.
    from scripts.verify_release_candidate import RELEASE_SCOPES  # noqa: PLC0415

    lab_workflow, lab_jobs, _step = RELEASE_SCOPES["lab"]
    assert lab_workflow == "virtualmin-lab.yml"
    assert "nightly-containers" in lab_jobs
    nightly = WORKFLOW["jobs"]["nightly-containers"]
    assert "make test-virtualmin-lab-containers" in str(nightly["steps"])
    assert "30 3 * * *" in [entry["cron"] for entry in on_block()["schedule"]]
    assert "containers" in on_block()["workflow_dispatch"]["inputs"]["suite"]["options"], "run it on a branch"


def test_the_workflow_follows_the_nightly_conventions() -> None:
    jobs = WORKFLOW["jobs"]

    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert on_block()["schedule"], "a nightly schedule"
    assert "check-activity" in jobs and "notify-scheduled-failure" in jobs
    assert jobs["notify-scheduled-failure"]["permissions"] == {"issues": "write"}
    assert "make test-virtualmin-lab-containers" in str(jobs["nightly-containers"]["steps"])
    assert "make test-virtualmin-lab-full" not in str(jobs["nightly-containers"]["steps"])
    assert "make test-virtualmin-lab-full" in str(jobs["native-full"]["steps"])
    # A release candidate's lab must test the candidate, not the master tip it was dispatched on.
    checkout = next(step for step in jobs["native-full"]["steps"] if "actions/checkout" in str(step.get("uses")))
    assert checkout["with"]["ref"] == "${{ github.sha }}"
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
