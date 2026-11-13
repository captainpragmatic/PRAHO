"""Exercise real Make entrypoints with only build/pytest boundaries doubled."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BINARIES = ("crowdsec-firewall-bouncer-amd64", "crowdsec-firewall-bouncer-arm64")
BOUNDARY = r"""
import json, os, sys
from pathlib import Path
root = Path(os.environ["FIXTURE_ROOT"])
output = root / "build/crowdsec-patched"
def event(**values):
    with (root / "events.jsonl").open("a") as stream:
        stream.write(json.dumps(values) + "\n")
if Path(sys.argv[0]).name == "docker":
    event(kind="forbidden-docker")
    raise SystemExit(99)
if Path(sys.argv[0]).name == "build.sh":
    assert sys.argv[1:] == ["build"]
    event(kind="build")
    if os.environ.get("FIXTURE_BUILD_FAIL") == "1":
        raise SystemExit(17)
    output.mkdir(parents=True, exist_ok=True)
    for name in ("crowdsec-firewall-bouncer-amd64", "crowdsec-firewall-bouncer-arm64"):
        (output / name).write_bytes(b"synthetic build boundary output")
    raise SystemExit(0)
assert sys.argv[1:3] == ["-m", "pytest"], sys.argv
args = sys.argv[3:]
if "tests/common/test_counters.py" in args:
    scope = "counter"
elif "tests/integration/" in args and "tests/deploy/" in args:
    scope = "aggregate"
elif any("test_crowdsec" in value for value in args):
    scope = "native"
else:
    raise AssertionError(args)
ready = all((output / name).is_file() for name in ("crowdsec-firewall-bouncer-amd64", "crowdsec-firewall-bouncer-arm64"))
if scope == "aggregate":
    # The queue's aggregate (CROWDSEC_DOCKER=0) collects no CrowdSec Docker suite, so it needs no artifacts.
    ignored = "--ignore-glob=tests/deploy/test_crowdsec*_docker.py" in args
    event(kind="pytest", scope=scope, artifacts_ready=ready, crowdsec_ignored=ignored)
    if ignored:
        raise SystemExit(0)
else:
    event(kind="pytest", scope=scope, artifacts_ready=ready)
# Observe the existing Make override policy only. Real provenance/role tests
# continue to require their locked outputs even in these override modes.
override = bool(os.environ.get("CROWDSEC_BOUNCER_BINARY")) or os.environ.get("CROWDSEC_BOUNCER_REJECTED_PACKAGE") == "1"
if scope != "counter" and not ready and not override:
    print("Synthetic pytest boundary reached without required CrowdSec build outputs", file=sys.stderr)
    raise SystemExit(86)
if scope != "counter" and os.environ.get("FIXTURE_PYTEST_FAIL") == "1":
    print("Synthetic existing artifact hash/provenance refusal", file=sys.stderr)
    raise SystemExit(88)
"""


@pytest.fixture
def make_fixture(tmp_path: Path):
    (tmp_path / "Makefile").write_bytes((REPO / "Makefile").read_bytes())
    (tmp_path / "services/platform").mkdir(parents=True)
    executables = (
        tmp_path / ".venv-fixture/bin/python",
        tmp_path / "deploy/crowdsec/build-patched/build.sh",
        tmp_path / "bin/docker",
    )
    for executable in executables:
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text(f"#!{sys.executable}\n" + BOUNDARY)
        executable.chmod(0o700)

    def run(*targets: str, overrides: dict[str, str] | None = None):
        executable = shutil.which("make")
        assert executable is not None
        environment = {
            "PATH": str(tmp_path / "bin") + os.pathsep + os.defpath,
            "PWD": str(tmp_path),
            "FIXTURE_ROOT": str(tmp_path),
            **(overrides or {}),
        }
        result = subprocess.run(  # noqa: S603 -- Fixed Make targets, private Makefile and inert external boundaries.
            [executable, "-f", "Makefile", "VENV_DIR=.venv-fixture", *targets],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        events = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
        assert not any(event["kind"] == "forbidden-docker" for event in events)
        return result, events

    return tmp_path, run


def test_fresh_aggregate_prepares_artifacts_before_pytest(make_fixture):
    root, run = make_fixture
    assert not (root / "build/crowdsec-patched").exists()
    result, events = run("test-integration")
    assert result.returncode == 0, (result.stderr, events)
    assert [event["kind"] for event in events] == ["build", "pytest", "pytest"]
    assert [event["scope"] for event in events if event["kind"] == "pytest"] == ["counter", "aggregate"]
    assert all(event["artifacts_ready"] for event in events if event["kind"] == "pytest")


def test_the_default_aggregate_collects_the_crowdsec_docker_suites(make_fixture):
    # Local `make test-integration` and the nightly: unchanged, CrowdSec's Docker suites included.
    _, run = make_fixture
    result, events = run("test-integration")
    assert result.returncode == 0, (result.stderr, events)
    (aggregate,) = [event for event in events if event.get("scope") == "aggregate"]
    assert aggregate["crowdsec_ignored"] is False


def test_without_crowdsec_docker_the_aggregate_neither_builds_nor_collects_them(make_fixture):
    # The merge queue (integration.yml): no bouncer build, and the CrowdSec Docker suites are not collected.
    root, run = make_fixture
    result, events = run("test-integration", "CROWDSEC_DOCKER=0")
    assert result.returncode == 0, (result.stderr, events)
    assert not any(event["kind"] == "build" for event in events)
    assert not (root / "build/crowdsec-patched").exists()
    assert [event["scope"] for event in events if event["kind"] == "pytest"] == ["counter", "aggregate"]
    (aggregate,) = [event for event in events if event.get("scope") == "aggregate"]
    assert aggregate["crowdsec_ignored"] is True


@pytest.mark.parametrize("value", ["1", "", "no", "false"])
def test_only_an_explicit_zero_drops_the_crowdsec_docker_suites(make_fixture, value):
    _, run = make_fixture
    result, events = run("test-integration", f"CROWDSEC_DOCKER={value}")
    assert result.returncode == 0, (result.stderr, events)
    assert events[0] == {"kind": "build"}
    (aggregate,) = [event for event in events if event.get("scope") == "aggregate"]
    assert aggregate["crowdsec_ignored"] is False


def test_fresh_native_target_keeps_existing_preparation(make_fixture):
    _, run = make_fixture
    result, events = run("test-crowdsec-docker")
    assert result.returncode == 0, (result.stderr, events)
    assert [event["kind"] for event in events] == ["build", "pytest"]
    assert events[1] == {"kind": "pytest", "scope": "native", "artifacts_ready": True}


def test_combined_entrypoints_prepare_once_even_when_aggregate_is_first(make_fixture):
    _, run = make_fixture
    result, events = run("test-integration", "test-crowdsec-docker")
    assert result.returncode == 0, (result.stderr, events)
    assert sum(event["kind"] == "build" for event in events) == 1
    assert [event["scope"] for event in events if event["kind"] == "pytest"] == ["counter", "aggregate", "native"]


def test_existing_both_binaries_skip_rebuild(make_fixture):
    root, run = make_fixture
    output = root / "build/crowdsec-patched"
    output.mkdir(parents=True)
    for name in BINARIES:
        (output / name).write_bytes(b"preexisting fixture output")
    result, events = run("test-integration", "test-crowdsec-docker")
    assert result.returncode == 0, (result.stderr, events)
    assert not any(event["kind"] == "build" for event in events)


def test_cached_outputs_do_not_hide_a_downstream_provenance_refusal(make_fixture):
    root, run = make_fixture
    output = root / "build/crowdsec-patched"
    output.mkdir(parents=True)
    for name in BINARIES:
        (output / name).write_bytes(b"preexisting fixture output")
    result, events = run("test-integration", overrides={"FIXTURE_PYTEST_FAIL": "1"})
    assert result.returncode != 0
    assert not any(event["kind"] == "build" for event in events)
    assert [event["scope"] for event in events] == ["counter", "aggregate"]
    assert "artifact hash/provenance refusal" in result.stderr
    assert all((output / name).read_bytes() == b"preexisting fixture output" for name in BINARIES)


@pytest.mark.parametrize("missing", BINARIES)
def test_either_missing_binary_prepares_before_aggregate(make_fixture, missing):
    root, run = make_fixture
    output = root / "build/crowdsec-patched"
    output.mkdir(parents=True)
    for name in BINARIES:
        if name != missing:
            (output / name).write_bytes(b"preexisting fixture output")
    assert not (output / missing).exists()
    result, events = run("test-integration")
    assert result.returncode == 0, (result.stderr, events)
    assert events[0] == {"kind": "build"}
    assert all((output / name).is_file() for name in BINARIES)


@pytest.mark.parametrize(
    "override",
    [
        {"CROWDSEC_BOUNCER_REJECTED_PACKAGE": ""},
        {"CROWDSEC_BOUNCER_REJECTED_PACKAGE": "0"},
        {"CROWDSEC_BOUNCER_REJECTED_PACKAGE": "01"},
        {"CROWDSEC_BOUNCER_REJECTED_PACKAGE": "true"},
        {"CROWDSEC_BOUNCER_BINARY": ""},
    ],
)
def test_only_exact_trial_overrides_bypass_autobuild(make_fixture, override):
    _, run = make_fixture
    result, events = run("test-integration", overrides=override)
    assert result.returncode == 0, (result.stderr, events)
    assert events[0] == {"kind": "build"}


@pytest.mark.parametrize(
    "override", [{"CROWDSEC_BOUNCER_BINARY": "/synthetic/candidate"}, {"CROWDSEC_BOUNCER_REJECTED_PACKAGE": "1"}]
)
def test_explicit_override_preserves_autobuild_bypass_only(make_fixture, override):
    _, run = make_fixture
    result, events = run("test-integration", "test-crowdsec-docker", overrides=override)
    assert result.returncode == 0, (result.stderr, events)
    assert not any(event["kind"] == "build" for event in events)
    assert [event["scope"] for event in events if event["kind"] == "pytest"] == ["counter", "aggregate", "native"]


def test_build_failure_stops_aggregate_before_any_pytest(make_fixture):
    _, run = make_fixture
    result, events = run("test-integration", overrides={"FIXTURE_BUILD_FAIL": "1"})
    assert result.returncode != 0
    assert events == [{"kind": "build"}]
