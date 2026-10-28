"""The release candidate vouches only for the tree its pull request's required checks passed on.

scripts/verify_release_candidate.py decides from GitHub's run and job data; these tests drive its
decisions with fixtures shaped like that data, and its tree comparison with a real repository.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.verify_release_candidate import (
    VerificationError,
    check_conclusions,
    failed_checks,
    required_contexts,
    same_tree,
)

pytestmark = pytest.mark.integration

PLATFORM = ".github/workflows/platform.yml"
LAB = ".github/workflows/virtualmin-lab-pr.yml"
CONTEXTS = ["coverage-gate", "pull-request"]


def run(run_id: int, path: str, **jobs: str) -> dict[str, Any]:
    return {"id": run_id, "path": path, "jobs": [{"name": name.replace("_", "-"), "conclusion": c} for name, c in jobs.items()]}


def green_runs() -> list[dict[str, Any]]:
    return [run(1, PLATFORM, coverage_gate="success"), run(2, LAB, changes="success", pull_request="success")]


def test_every_required_check_green_passes() -> None:
    assert failed_checks(CONTEXTS, check_conclusions(green_runs())) == []


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "action_required", "None"])
def test_a_check_that_did_not_succeed_fails(conclusion: str) -> None:
    runs = [run(1, PLATFORM, coverage_gate=conclusion), run(2, LAB, changes="success", pull_request="success")]

    assert failed_checks(CONTEXTS, check_conclusions(runs)) == [f"coverage-gate: {conclusion} ({PLATFORM})"]


def test_a_check_that_never_reported_fails() -> None:
    runs = [run(2, LAB, changes="success", pull_request="success")]

    assert failed_checks(CONTEXTS, check_conclusions(runs)) == ["coverage-gate: never reported"]


def test_the_newest_run_of_a_workflow_decides() -> None:
    newer_failure = run(3, PLATFORM, coverage_gate="failure")
    # GitHub lists runs newest first, but the decision must not depend on the order.
    for runs in ([newer_failure, *green_runs()], [*green_runs(), newer_failure]):
        assert failed_checks(CONTEXTS, check_conclusions(runs)) == [f"coverage-gate: failure ({PLATFORM})"]


def test_the_same_check_name_from_two_workflows_is_ambiguous() -> None:
    runs = [*green_runs(), run(4, ".github/workflows/other.yml", coverage_gate="success")]

    assert failed_checks(CONTEXTS, check_conclusions(runs)) == ["coverage-gate: reported by several workflows"]


def test_the_lab_may_skip_only_when_its_own_selection_succeeded() -> None:
    skipped = [run(1, PLATFORM, coverage_gate="success"), run(2, LAB, changes="success", pull_request="skipped")]
    assert failed_checks(CONTEXTS, check_conclusions(skipped)) == []

    failed_selection = [run(1, PLATFORM, coverage_gate="success"), run(2, LAB, changes="failure", pull_request="skipped")]
    assert failed_checks(CONTEXTS, check_conclusions(failed_selection)) == [f"pull-request: skipped ({LAB})"]


def test_only_the_lab_may_skip() -> None:
    runs = [run(1, PLATFORM, coverage_gate="skipped"), run(2, LAB, changes="success", pull_request="success")]

    assert failed_checks(CONTEXTS, check_conclusions(runs)) == [f"coverage-gate: skipped ({PLATFORM})"]


def test_a_ruleset_without_required_checks_refuses() -> None:
    with pytest.raises(VerificationError):
        required_contexts({"rules": [{"type": "deletion"}]})


def test_the_committed_ruleset_is_read() -> None:
    ruleset = json.loads((Path(__file__).resolve().parents[2] / ".github/rulesets/master.json").read_text())
    assert "coverage-gate" in required_contexts(ruleset)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()  # noqa: S603, S607


def test_the_tree_comparison_tells_equal_from_different(tmp_path: Path) -> None:
    _git(tmp_path, "init", "--quiet")
    _git(tmp_path, "config", "user.email", "ci@example.com")
    _git(tmp_path, "config", "user.name", "CI")
    (tmp_path / "a.txt").write_text("one\n")
    _git(tmp_path, "add", "a.txt")
    _git(tmp_path, "commit", "--quiet", "-m", "one")
    first = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "commit", "--quiet", "--allow-empty", "-m", "same tree, new commit")
    same = _git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "a.txt").write_text("two\n")
    _git(tmp_path, "commit", "--quiet", "-am", "two")
    different = _git(tmp_path, "rev-parse", "HEAD")

    assert same_tree(tmp_path, first, same)
    assert not same_tree(tmp_path, first, different)
