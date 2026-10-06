"""A workflow may only install Node dependencies from a lockfile the repository tracks.

`.gitignore` excluded `package-lock.json` from the day the services were split, so the lockfile
existed on every developer machine and in no checkout. Nothing depended on that until the nightly
browser job became the first thing in CI to install Node dependencies: `actions/setup-node` with
`cache: npm` aborts when it finds no lockfile, and `npm ci` refuses to run without one. The job
failed at "Set up Node" on each of its first seven nights, before a browser was ever installed,
while the documentation said the suite ran nightly. A scheduled workflow does not run on a pull
request, so its first execution was its first night on master and nothing at review could see it.

"Tracked" is asked of git and not of the filesystem. The file being present locally is exactly
what hid this - `git add` declines an ignored path quietly, and the build works on the machine
that wrote the workflow.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml
from django.test import SimpleTestCase

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_WORKFLOWS = _REPOSITORY_ROOT / ".github" / "workflows"
_LOCKFILE = "package-lock.json"

# Canary: the job that exposed the defect. A scan that stops seeing it is broken.
_KNOWN_WORKFLOW = "nightly.yml"
_KNOWN_JOB = "nightly-e2e"


def _is_tracked(path: str) -> bool:
    """Whether git tracks ``path`` - the index, not the working tree."""
    completed = subprocess.run(  # noqa: S603 -- a fixed git query over paths read from this repository's own workflows
        ["git", "ls-files", "--error-unmatch", "--", path],  # noqa: S607 -- git from PATH, as scripts/e2e_stack.py resolves it
        cwd=_REPOSITORY_ROOT,
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0


def _lockfiles_a_step_needs(step: dict[str, Any]) -> list[str]:
    """Repository-relative lockfiles this step cannot run without."""
    needed: list[str] = []
    settings = step.get("with") or {}
    if str(step.get("uses", "")).startswith("actions/setup-node") and settings.get("cache") == "npm":
        explicit = str(settings.get("cache-dependency-path", "")).split()
        needed.extend(explicit or [_LOCKFILE])
    if "npm ci" in str(step.get("run", "")):
        directory = str(step.get("working-directory", "")).strip("./")
        needed.append(f"{directory}/{_LOCKFILE}" if directory else _LOCKFILE)
    return needed


def _lockfile_needs() -> dict[str, list[str]]:
    """Every workflow step that needs a Node lockfile, keyed ``workflow:job:step``."""
    found: dict[str, list[str]] = {}
    for workflow in sorted(_WORKFLOWS.glob("*.yml")):
        jobs = yaml.safe_load(workflow.read_text(encoding="utf-8")).get("jobs") or {}
        for job_name, job in jobs.items():
            for index, step in enumerate(job.get("steps") or []):
                if needed := _lockfiles_a_step_needs(step):
                    label = step.get("name") or step.get("uses") or f"step {index}"
                    found[f"{workflow.name}:{job_name}:{label}"] = needed
    return found


class WorkflowNodeLockfileTests(SimpleTestCase):
    """CI can only install from what a checkout contains."""

    def test_every_lockfile_a_workflow_installs_from_is_tracked(self) -> None:
        offending = {
            step: missing
            for step, needed in _lockfile_needs().items()
            if (missing := [path for path in needed if not _is_tracked(path)])
        }

        self.assertEqual(
            offending,
            {},
            msg=(
                "A workflow step installs Node dependencies from a lockfile git does not track, so "
                "it fails in every checkout however well it works locally. If the file exists but "
                "`git add` will not take it, an ignore rule in .gitignore is swallowing it."
            ),
        )

    def test_the_scan_still_sees_the_job_that_exposed_this(self) -> None:
        """Structural-Helper Integrity: a scan matching nothing must fail, not pass."""
        prefix = f"{_KNOWN_WORKFLOW}:{_KNOWN_JOB}:"
        seen = {step: needed for step, needed in _lockfile_needs().items() if step.startswith(prefix)}

        # Both the cache lookup and the install: fixing only the first leaves the second failing.
        self.assertEqual(len(seen), 2, msg=f"expected the setup-node and `npm ci` steps, saw {sorted(seen)}")
        self.assertTrue(all(needed == [_LOCKFILE] for needed in seen.values()))
