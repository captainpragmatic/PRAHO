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

import json
import posixpath
import subprocess
import tempfile
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, ClassVar

import yaml
from django.test import SimpleTestCase

_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_WORKFLOWS = _REPOSITORY_ROOT / ".github" / "workflows"
_LOCKFILE = "package-lock.json"

# Canary: the job that exposed the defect. A scan that stops seeing it is broken.
_KNOWN_WORKFLOW = "nightly.yml"
_KNOWN_JOB = "nightly-e2e"

# The workflow that runs this test on a pull request, and the files this test reads. A pull request
# that changes only these - deleting the lockfile, say - has to run it, or it can merge the very
# defect this guard exists for and surface it only in the next nightly.
_GUARD_WORKFLOW = _WORKFLOWS / "platform.yml"
_GUARD_INPUTS = (_LOCKFILE, "package.json", ".gitignore", ".github/workflows/nightly.yml")


def _is_tracked(path: str) -> bool:
    """Whether git tracks ``path`` - the index, not the working tree."""
    completed = subprocess.run(  # noqa: S603 -- a fixed git query over paths read from this repository's own workflows
        ["git", "ls-files", "--error-unmatch", "--", path],  # noqa: S607 -- git from PATH, as scripts/e2e_stack.py resolves it
        cwd=_REPOSITORY_ROOT,
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0


def _run_directory(step: dict[str, Any], job: dict[str, Any], workflow: dict[str, Any]) -> str:
    """The repository-relative directory a ``run`` step executes in; ``""`` is the root.

    GitHub applies ``defaults.run.working-directory`` at workflow and at job scope, and a step's own
    ``working-directory`` overrides both - so the nearest scope that sets one wins.
    """
    for raw in (
        step.get("working-directory"),
        ((job.get("defaults") or {}).get("run") or {}).get("working-directory"),
        ((workflow.get("defaults") or {}).get("run") or {}).get("working-directory"),
    ):
        if raw:
            directory = posixpath.normpath(str(raw))
            return "" if directory == "." else directory
    return ""


def _lockfiles_a_step_needs(step: dict[str, Any], job: dict[str, Any], workflow: dict[str, Any]) -> list[str]:
    """Repository-relative lockfiles this step cannot run without."""
    needed: list[str] = []
    settings = step.get("with") or {}
    if str(step.get("uses", "")).startswith("actions/setup-node") and settings.get("cache") == "npm":
        # An action's inputs are workspace-relative; `defaults.run` never applies to `uses` steps.
        explicit = str(settings.get("cache-dependency-path", "")).split()
        needed.extend(explicit or [_LOCKFILE])
    if "npm ci" in str(step.get("run", "")):
        directory = _run_directory(step, job, workflow)
        needed.append(posixpath.join(directory, _LOCKFILE) if directory else _LOCKFILE)
    return needed


def _lockfile_needs_in(workflow: dict[str, Any], workflow_name: str) -> dict[str, list[str]]:
    """Every step of one parsed workflow that needs a Node lockfile, keyed ``workflow:job:step``."""
    found: dict[str, list[str]] = {}
    for job_name, job in (workflow.get("jobs") or {}).items():
        for index, step in enumerate(job.get("steps") or []):
            if needed := _lockfiles_a_step_needs(step, job, workflow):
                label = step.get("name") or step.get("uses") or f"step {index}"
                # Step names need not be unique; a later step must not overwrite an earlier need.
                found.setdefault(f"{workflow_name}:{job_name}:{label}", []).extend(needed)
    return found


def _lockfile_needs(directory: Path = _WORKFLOWS) -> dict[str, list[str]]:
    """Every step in a directory of workflows that needs a Node lockfile."""
    found: dict[str, list[str]] = {}
    # GitHub accepts both extensions for a workflow file.
    for path in sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")]):
        found.update(_lockfile_needs_in(yaml.safe_load(path.read_text(encoding="utf-8")), path.name))
    return found


# The sections `npm ci` compares between package.json and the lockfile's root entry before it
# installs anything. A mismatch fails it outright, which a pull request that edits package.json
# without reinstalling would otherwise first meet in the nightly.
_DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _unsynchronised(package: dict[str, Any], lock: dict[str, Any]) -> dict[str, tuple[Any, Any]]:
    """Dependency sections that differ between a package.json and its lockfile's root entry."""
    root = (lock.get("packages") or {}).get("") or {}
    return {
        section: (package.get(section) or {}, root.get(section) or {})
        for section in _DEPENDENCY_SECTIONS
        if (package.get(section) or {}) != (root.get(section) or {})
    }


def _pull_request_paths(workflow: dict[str, Any]) -> list[str]:
    """A workflow's ``pull_request`` path filter.

    PyYAML follows YAML 1.1, where a bare ``on`` is the boolean ``True``, so the trigger block is
    stored under ``True`` rather than ``"on"``.
    """
    triggers = workflow.get("on", workflow.get(True)) or {}
    return [str(pattern) for pattern in (triggers.get("pull_request") or {}).get("paths") or []]


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

    def test_each_lockfile_records_what_its_package_json_declares(self) -> None:
        checked: list[str] = []
        offending: dict[str, dict[str, tuple[Any, Any]]] = {}
        for lockfile in sorted({path for needed in _lockfile_needs().values() for path in needed}):
            manifest = _REPOSITORY_ROOT / posixpath.dirname(lockfile) / "package.json"
            if not (manifest.is_file() and (_REPOSITORY_ROOT / lockfile).is_file()):
                continue  # an absent lockfile is the tracking test's finding, not this one's
            checked.append(lockfile)
            package = json.loads(manifest.read_text(encoding="utf-8"))
            lock = json.loads((_REPOSITORY_ROOT / lockfile).read_text(encoding="utf-8"))
            if difference := _unsynchronised(package, lock):
                offending[lockfile] = difference

        self.assertIn(_LOCKFILE, checked, msg="canary: the root lockfile was not compared at all")
        self.assertEqual(
            offending,
            {},
            msg="package.json changed without the lockfile: run `npm install` and commit both, or `npm ci` fails",
        )

    def test_a_pull_request_that_changes_only_the_guards_inputs_still_runs_it(self) -> None:
        paths = _pull_request_paths(yaml.safe_load(_GUARD_WORKFLOW.read_text(encoding="utf-8")))
        # Canary: an unreadable filter would leave every input "unmatched" for the wrong reason.
        self.assertIn("services/platform/**", paths)

        # `fnmatch` lets `*` cross `/`, which is how GitHub's `**` behaves for these patterns.
        unmatched = [path for path in _GUARD_INPUTS if not any(fnmatch(path, pattern) for pattern in paths)]
        self.assertEqual(
            unmatched,
            [],
            msg=f"{_GUARD_WORKFLOW.name} does not run on a pull request that changes only these files",
        )


class LockfileNeedResolutionTests(SimpleTestCase):
    """Which lockfile a step needs, on workflows built here rather than read from disk."""

    @staticmethod
    def _needs(*, step: dict[str, Any], job: dict[str, Any] | None = None, **workflow: Any) -> dict[str, list[str]]:
        return _lockfile_needs_in({**workflow, "jobs": {"j": {**(job or {}), "steps": [step]}}}, "w.yml")

    @staticmethod
    def _defaults(directory: str) -> dict[str, Any]:
        return {"defaults": {"run": {"working-directory": directory}}}

    def test_npm_ci_at_the_root_needs_the_root_lockfile(self) -> None:
        self.assertEqual(self._needs(step={"name": "i", "run": "npm ci"}), {"w.yml:j:i": [_LOCKFILE]})

    def test_a_step_working_directory_is_normalised(self) -> None:
        needs = self._needs(step={"name": "i", "run": "npm ci", "working-directory": "./frontend/"})
        self.assertEqual(needs, {"w.yml:j:i": ["frontend/package-lock.json"]})

    def test_a_job_default_working_directory_is_inherited(self) -> None:
        needs = self._needs(step={"name": "i", "run": "npm ci"}, job=self._defaults("frontend"))
        self.assertEqual(needs, {"w.yml:j:i": ["frontend/package-lock.json"]})

    def test_a_workflow_default_working_directory_is_inherited(self) -> None:
        needs = self._needs(step={"name": "i", "run": "npm ci"}, **self._defaults("frontend"))
        self.assertEqual(needs, {"w.yml:j:i": ["frontend/package-lock.json"]})

    def test_the_nearest_scope_wins(self) -> None:
        workflow = self._defaults("outer")
        job = self._defaults("middle")
        self.assertEqual(
            self._needs(step={"name": "i", "run": "npm ci", "working-directory": "inner"}, job=job, **workflow),
            {"w.yml:j:i": ["inner/package-lock.json"]},
        )
        self.assertEqual(
            self._needs(step={"name": "i", "run": "npm ci"}, job=job, **workflow),
            {"w.yml:j:i": ["middle/package-lock.json"]},
        )

    def test_run_defaults_do_not_move_a_setup_node_cache_lookup(self) -> None:
        step = {"name": "n", "uses": "actions/setup-node@v4", "with": {"cache": "npm"}}
        self.assertEqual(self._needs(step=step, job=self._defaults("frontend")), {"w.yml:j:n": [_LOCKFILE]})

        explicit = {**step, "with": {"cache": "npm", "cache-dependency-path": "a/package-lock.json\nb/package-lock.json"}}
        self.assertEqual(self._needs(step=explicit), {"w.yml:j:n": ["a/package-lock.json", "b/package-lock.json"]})

    def test_same_named_steps_keep_both_requirements(self) -> None:
        workflow = {
            "jobs": {
                "j": {
                    "steps": [
                        {"name": "install", "run": "npm ci", "working-directory": "a"},
                        {"name": "install", "run": "npm ci", "working-directory": "b"},
                    ]
                }
            }
        }
        self.assertEqual(
            _lockfile_needs_in(workflow, "w.yml"),
            {"w.yml:j:install": ["a/package-lock.json", "b/package-lock.json"]},
        )

    def test_yaml_and_yml_workflows_are_both_scanned(self) -> None:
        step = {"name": "i", "run": "npm ci"}
        with tempfile.TemporaryDirectory() as directory:
            for name in ("short.yml", "long.yaml"):
                (Path(directory) / name).write_text(yaml.safe_dump({"jobs": {"j": {"steps": [step]}}}))
            self.assertEqual(sorted(_lockfile_needs(Path(directory))), ["long.yaml:j:i", "short.yml:j:i"])

    def test_steps_that_install_from_no_lockfile_need_none(self) -> None:
        for step in (
            {"name": "x", "run": "npm install"},
            {"name": "x", "uses": "actions/setup-node@v4", "with": {"node-version": "20"}},
            {"name": "x", "uses": "actions/setup-node@v4", "with": {"cache": "yarn"}},
        ):
            with self.subTest(step=step):
                self.assertEqual(self._needs(step=step, job=self._defaults("frontend")), {})


class LockfileSynchronisationTests(SimpleTestCase):
    """The comparison `npm ci` makes first, on manifests built here."""

    _PACKAGE: ClassVar[dict[str, Any]] = {"devDependencies": {"tailwindcss": "^4.1.13"}}
    _LOCK: ClassVar[dict[str, Any]] = {"packages": {"": {"devDependencies": {"tailwindcss": "^4.1.13"}}}}

    def test_matching_sections_are_synchronised(self) -> None:
        self.assertEqual(_unsynchronised(self._PACKAGE, self._LOCK), {})

    def test_a_dependency_added_without_reinstalling_is_caught(self) -> None:
        package = {"devDependencies": {"tailwindcss": "^4.1.13", "postcss": "^8.0.0"}}
        self.assertEqual(list(_unsynchronised(package, self._LOCK)), ["devDependencies"])

    def test_a_changed_range_is_caught(self) -> None:
        package = {"devDependencies": {"tailwindcss": "^4.3.3"}}
        self.assertEqual(list(_unsynchronised(package, self._LOCK)), ["devDependencies"])

    def test_a_section_present_on_one_side_only_is_caught(self) -> None:
        package = {**self._PACKAGE, "optionalDependencies": {"fsevents": "^2.3.0"}}
        self.assertEqual(list(_unsynchronised(package, self._LOCK)), ["optionalDependencies"])

    def test_empty_and_absent_sections_are_equivalent(self) -> None:
        self.assertEqual(_unsynchronised({**self._PACKAGE, "dependencies": {}}, self._LOCK), {})
