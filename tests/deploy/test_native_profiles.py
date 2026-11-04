"""Parallel native qualification must partition the real cases and reject partial reports."""

from __future__ import annotations

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from scripts import run_native_acceptance

ROOT = Path(__file__).resolve().parents[2]
PROFILE_ENV = "PRAHO_NATIVE_ACCEPTANCE_PROFILE"
COUNTS = {"all": 29, "split-prod": 17, "combined-staging": 6, "combined-prod": 6}


def collect(profile: str) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, PROFILE_ENV: profile}
    return subprocess.run(  # noqa: S603 -- actual pytest collection, without executing deployment fixtures.
        [
            sys.executable,
            "-m",
            "pytest",
            "-o",
            "addopts=",
            "--collect-only",
            "-q",
            "-m",
            "docker",
            "tests/deploy/test_native_acceptance.py",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=40,
    )


@pytest.fixture(scope="module")
def selections() -> dict[str, set[str]]:
    selected = {}
    for profile in COUNTS:
        result = collect(profile)
        assert result.returncode == 0, result.stdout + result.stderr
        selected[profile] = {
            line for line in result.stdout.splitlines() if line.startswith("tests/deploy/test_native_acceptance.py::")
        }
    return selected


@pytest.mark.parametrize("profile", list(COUNTS))
def test_profiles_collect_the_actual_expected_cases(selections: dict[str, set[str]], profile: str) -> None:
    assert len(selections[profile]) == COUNTS[profile], selections[profile]


def test_ci_profiles_partition_every_real_case_exactly_once(selections: dict[str, set[str]]) -> None:
    split, staging, combined = (selections[name] for name in ("split-prod", "combined-staging", "combined-prod"))
    assert not (split & staging or split & combined or staging & combined)
    assert split | staging | combined == selections["all"]


@pytest.mark.parametrize("profile", ["", "unknown"])
def test_invalid_profile_cannot_silently_qualify_another_topology(profile: str) -> None:
    result = collect(profile)
    assert result.returncode != 0
    assert "native acceptance profile" in result.stderr.lower(), result.stdout + result.stderr


@pytest.mark.parametrize(
    ("profile", "count", "skipped", "accepted"),
    [
        ("all", 29, False, True),
        ("all", 1, False, False),
        ("split-prod", 17, False, True),
        ("split-prod", 16, False, False),
        ("combined-staging", 6, False, True),
        ("combined-staging", 29, False, False),
        ("combined-prod", 6, False, True),
        ("combined-prod", 6, True, False),
    ],
)
def test_runner_requires_the_complete_requested_profile(
    monkeypatch: pytest.MonkeyPatch,
    profile: str,
    count: int,
    skipped: bool,
    accepted: bool,
) -> None:
    monkeypatch.setenv(PROFILE_ENV, profile)

    def report(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        # Unit-test the gate's report validation; the real deployment cases above are collected
        # unchanged and executed by every mandatory CI matrix job.
        destination = next(
            Path(value.removeprefix("--junitxml=")) for value in arguments if value.startswith("--junitxml=")
        )
        root = ET.Element("testsuites")
        suite = ET.SubElement(root, "testsuite")
        for index in range(count):
            case = ET.SubElement(suite, "testcase", name=f"case-{index}")
            if skipped and index == 0:
                ET.SubElement(case, "skipped")
        ET.ElementTree(root).write(destination)
        return subprocess.CompletedProcess(arguments, 0)

    monkeypatch.setattr(run_native_acceptance.subprocess, "run", report)
    assert (run_native_acceptance.main() == 0) is accepted
