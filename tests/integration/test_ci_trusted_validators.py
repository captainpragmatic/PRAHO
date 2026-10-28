"""CI checks a PR's migrations with the base branch's validators, not the PR's own (#751 follow-up, M7).

The migration checksum and new-model schema validators ran from the PR's checkout, so a PR could weaken the
validator that judged it. The integration workflow now runs the base revision's copies against the PR's tree.
This raises the bar only: a PR can edit the workflow too, and code-owner review stays the gate.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = PROJECT_ROOT / ".github/workflows/integration.yml"
STEP = "Check migrations with the base branch's validators"
GIT = shutil.which("git") or "/usr/bin/git"


def _step_script() -> str:
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    steps = [step for job in jobs.values() for step in job.get("steps", []) if step.get("name") == STEP]
    assert len(steps) == 1, f"one '{STEP}' step"
    return str(steps[0]["run"])


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603  # Fixed git arguments in a temporary clone.
        [GIT, *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def clone(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    subprocess.run(  # noqa: S603  # A local clone sharing this repository's objects.
        [GIT, "clone", "--quiet", "--shared", str(PROJECT_ROOT), str(target)], check=True, capture_output=True
    )
    _git(target, "config", "user.email", "ci@example.com")
    _git(target, "config", "user.name", "CI")
    # As in CI, origin/master is the remote's master (the clone would otherwise mirror a local branch)
    _git(target, "update-ref", "refs/remotes/origin/master", _git(PROJECT_ROOT, "rev-parse", "origin/master"))
    return target


def _run_step(repo: Path, base: str, output: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/tmp"),  # noqa: S108  # Only git's config lookup
        "BASE_REF": base,
        "PYTHON": sys.executable,
    }
    if output is not None:
        env["GITHUB_OUTPUT"] = str(output)
    return subprocess.run(  # noqa: S603  # The workflow's own script, in a temporary clone.
        ["/bin/bash", "-c", _step_script()], cwd=repo, env=env, capture_output=True, text=True, timeout=120, check=False
    )


def test_the_workflow_runs_the_base_revisions_copies() -> None:
    script = _step_script()
    assert 'git show "$base:scripts/migration_checksums.py"' in script
    assert 'git show "$base:scripts/check_new_model_schema.py"' in script


def test_a_pr_that_weakens_the_validator_is_still_judged_by_the_base_copy(clone: Path) -> None:
    base = _git(clone, "rev-parse", "HEAD")
    validator = clone / "scripts/migration_checksums.py"
    validator.write_text(validator.read_text().replace("def main() -> int:", "def main() -> int:\n    return 0\n\n\ndef _unused() -> int:", 1))
    frozen = clone / "services/platform/apps/audit/migrations/0001_initial.py"
    frozen.write_text(frozen.read_text() + "\n# changed by the PR\n")
    _git(clone, "commit", "--quiet", "-am", "weaken the validator and edit a frozen migration")
    result = _run_step(clone, base)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "Frozen migration changed" in result.stdout + result.stderr
    assert not list((clone / "scripts").glob("_trusted_*")), "the trusted copies are removed"


def test_an_unchanged_tree_passes(clone: Path) -> None:
    result = _run_step(clone, _git(clone, "rev-parse", "HEAD"))
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_first_push_compares_with_master(clone: Path) -> None:
    result = _run_step(clone, "0" * 40)
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_dispatch_on_the_compared_commit_still_compares_with_its_parent(clone: Path, tmp_path: Path) -> None:
    # A dispatch on master resolves the base to HEAD itself; HEAD against HEAD would check nothing. The
    # resolved base is also what the migration-state and Semgrep steps compare against.
    output = tmp_path / "github_output"
    result = _run_step(clone, _git(clone, "rev-parse", "HEAD"), output)
    assert result.returncode == 0, result.stdout + result.stderr
    assert output.read_text().strip() == f"ref={_git(clone, 'rev-parse', 'HEAD^')}"


def test_a_base_without_the_validators_fails_instead_of_checking_less(clone: Path) -> None:
    # A stale base (a branch far behind master) predates the trusted scripts: refuse, never fall back.
    added = _git(clone, "log", "--diff-filter=A", "--format=%H", "--", "scripts/migration_checksums.py").splitlines()[-1]
    result = _run_step(clone, _git(clone, "rev-parse", f"{added}^"))
    assert result.returncode != 0, result.stdout + result.stderr
    assert "refusing a weaker check" in result.stderr
