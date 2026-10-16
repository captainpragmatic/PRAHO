"""Every platform test that only means something on PostgreSQL must run on PostgreSQL in CI.

Those tests skip themselves on SQLite, which is what the default run uses, so a module that is
not named in a PostgreSQL workflow step passes everywhere while proving nothing. The workflows
named the modules by hand, and the list fell behind: dozens of gated modules ran nowhere.

CI now derives the list with ``scripts/pg_gated_test_modules.py``. This test checks the two
halves of that arrangement: the scan finds every gate idiom in use, and a workflow job with a
PostgreSQL service runs what the scan finds under ``config.settings.ci``.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = PROJECT_ROOT / ".github" / "workflows"
TESTS = PROJECT_ROOT / "services" / "platform" / "tests"
SCRIPT = "scripts/pg_gated_test_modules.py"
GATED_TARGET = "test-platform-postgres-gated"
# The scan is the source of truth; this floor only catches a scan that silently finds nothing.
MINIMUM_GATED_MODULES = 30


def _scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pg_gated_test_modules", PROJECT_ROOT / SCRIPT)
    assert spec and spec.loader, SCRIPT
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _workflow_jobs() -> list[tuple[str, str, dict[str, Any]]]:
    jobs = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for name, job in (yaml.safe_load(path.read_text()).get("jobs") or {}).items():
            jobs.append((path.name, name, job))
    return jobs


def _postgres_service(job: dict[str, object]) -> bool:
    services = job.get("services")
    return isinstance(services, dict) and any(
        isinstance(service, dict) and "postgres" in str(service.get("image", "")) for service in services.values()
    )


def _bootstrap_index(job: dict[str, object]) -> int | None:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return None
    nightly = [
        "git show '${{ github.workflow_sha }}:scripts/start_ci_postgres.sh' > \"$RUNNER_TEMP/praho-ci-postgres.sh\"",
        'bash "$RUNNER_TEMP/praho-ci-postgres.sh" 16-alpine',
    ]
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or step.get("continue-on-error"):
            continue
        run = step.get("run")
        if not isinstance(run, str):
            continue
        lines = [line.strip() for line in run.splitlines() if line.strip()]
        if lines in (["make ci-postgres-start CI_POSTGRES_IMAGE_TAG=16"], nightly):
            return index
    return None


def _postgres_ci_runs(job: dict[str, object]) -> list[str]:
    """Count only settings.ci steps after a required, real PostgreSQL bootstrap has succeeded."""
    if _postgres_service(job):
        return _ci_runs(job)
    index = _bootstrap_index(job)
    if index is None:
        return []
    steps = job["steps"]
    assert isinstance(steps, list)
    return _ci_runs({**job, "steps": steps[index + 1 :]})


def _ci_runs(job: dict[str, Any]) -> list[str]:
    """The `run:` text of every step that uses the PostgreSQL CI settings, set on the step or the job."""
    job_settings = str((job.get("env") or {}).get("DJANGO_SETTINGS_MODULE", ""))
    return [
        step["run"]
        for step in job.get("steps", [])
        if "run" in step
        and "config.settings.ci"
        in (step["run"] + str((step.get("env") or {}).get("DJANGO_SETTINGS_MODULE", job_settings)))
    ]


def _explicit_labels() -> set[str]:
    """Dotted labels named on a `manage.py test` line in a PostgreSQL job's CI step."""
    labels: set[str] = set()
    for _file, _name, job in _workflow_jobs():
        for run in _postgres_ci_runs(job):
            for invocation in re.findall(r"manage\.py test(.*?)--settings", run, flags=re.DOTALL):
                labels.update(re.findall(r"\btests(?:\.\w+)+", invocation))
    return labels


def _derived_step_runs_in_postgres_job() -> bool:
    return any(any(SCRIPT in run for run in _postgres_ci_runs(job)) for _file, _name, job in _workflow_jobs())


def _triggers(workflow_file: str) -> set[str]:
    document = yaml.safe_load((WORKFLOWS / workflow_file).read_text())
    # YAML 1.1 reads a bare `on:` key as the boolean True.
    triggers = document.get("on", document.get(True)) or {}
    return {triggers} if isinstance(triggers, str) else set(triggers)


def _make_recipe(target: str) -> str:
    """The recipe lines of one Makefile target, joined as make sees them."""
    lines = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    start = lines.index(f"{target}:")
    recipe = []
    for line in lines[start + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line.strip())
    return "\n".join(recipe)


def _covered(module: str, labels: set[str]) -> bool:
    return any(module == label or module.startswith(label + ".") for label in labels)


@pytest.mark.integration
class TestPostgresGatedTestsRunInCi:
    def test_the_scan_finds_the_gated_modules(self) -> None:
        modules = _scanner().gated_modules()

        assert len(modules) >= MINIMUM_GATED_MODULES, modules
        # Canaries for each gate idiom the platform tests use.
        assert "tests.promotions.test_concurrency" in modules  # @skipUnless(connection.vendor == ...)
        assert "tests.users.test_lockout_counter_concurrency" in modules  # self.skipTest("... PostgreSQL ...")
        assert "tests.users.test_apitoken_expiry_indexes" in modules  # if connection.vendor == "sqlite": ... else

    def test_a_sqlite_branch_is_a_gate_but_a_mention_of_sqlite_is_not(self) -> None:
        """The other side of a SQLite branch is what PostgreSQL runs, so it needs a PostgreSQL step."""
        is_gated = _scanner().is_gated

        assert is_gated('if connection.vendor == "sqlite":\n    pass\nelse:\n    run_concurrently()')
        assert is_gated("@skipUnless(connection.vendor != 'sqlite', 'needs row locks')")
        assert not is_gated('ENGINE = "django.db.backends.sqlite3"  # the default test database')
        assert not is_gated('"""SQLite runs these sequentially."""')

    def test_the_scan_misses_no_test_that_skips_near_a_mention_of_postgresql(self) -> None:
        """A looser, independent net: a skip call with PostgreSQL named within three lines."""
        scan = set(_scanner().gated_modules())
        loose = set()
        for path in TESTS.rglob("test*.py"):
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if "sqlite" in line.lower():
                    continue  # a SQLite-only test is the opposite of a PostgreSQL gate
                if re.search(r"skipUnless|skipIf|skipTest|pytest\.skip", line) and re.search(
                    r"postgres", "\n".join(lines[max(index - 3, 0) : index + 4]), re.IGNORECASE
                ):
                    loose.add(".".join(path.relative_to(TESTS.parent).with_suffix("").parts))

        assert sorted(loose - scan) == []

    def test_every_gated_module_runs_on_postgres_in_ci(self) -> None:
        modules = _scanner().gated_modules()
        if _derived_step_runs_in_postgres_job():
            return
        labels = _explicit_labels()

        uncovered = [module for module in modules if not _covered(module, labels)]

        assert uncovered == [], f"{len(uncovered)} PostgreSQL-gated modules run in no CI job:\n" + "\n".join(uncovered)

    def test_the_derived_step_runs_under_the_ci_settings_in_a_postgres_job(self) -> None:
        assert _derived_step_runs_in_postgres_job(), (
            f"no workflow job with a PostgreSQL service runs {SCRIPT} under config.settings.ci"
        )

    def test_the_derived_step_runs_nothing_but_the_scan_output(self) -> None:
        """A hand-kept subset beside the scan would reopen the gap."""
        seen = 0
        for _file, _name, job in _workflow_jobs():
            for run in _ci_runs(job):
                if SCRIPT not in run:
                    continue
                seen += 1
                assert "set -euo pipefail" in run, "a failing scan must stop the step, not run everything"
                invocation = re.search(r"manage\.py test(.*?)--settings", run, flags=re.DOTALL)
                assert invocation, "the step must run the platform tests"
                assert not re.findall(r"\btests(?:\.\w+)+", invocation.group(1)), "no hand-named labels"
        assert seen == 1

    def test_the_make_target_runs_the_scan_output_and_stops_on_a_failed_or_empty_scan(self) -> None:
        recipe = _make_recipe(GATED_TARGET)

        assert f"{SCRIPT}) || exit 1" in recipe, "a failing scan must stop the target, not run everything"
        assert '[ -z "$$modules" ]' in recipe and "exit 1" in recipe, "an empty scan must fail, not pass"
        invocation = re.search(r"manage\.py test(.*?)--settings=config\.settings\.ci", recipe, flags=re.DOTALL)
        assert invocation, "the target must run the platform tests under config.settings.ci"
        assert invocation.group(1).split() == ["$$modules", "\\"], "no hand-named labels"

    def test_pull_requests_run_the_gated_tests_on_postgres(self) -> None:
        """Before this job they first ran in the nightly, after merge, and a PR broke three of them."""
        jobs = [
            name
            for file, name, job in _workflow_jobs()
            if "pull_request" in _triggers(file)
            and any(f"make {GATED_TARGET}" in run for run in _postgres_ci_runs(job))
        ]

        assert jobs, f"no pull-request job runs `make {GATED_TARGET}` after a PostgreSQL bootstrap"


def test_bootstrap_must_precede_gated_steps_and_must_be_required() -> None:
    bootstrap = {"run": "make ci-postgres-start CI_POSTGRES_IMAGE_TAG=16"}
    test = {"run": f"python {SCRIPT}", "env": {"DJANGO_SETTINGS_MODULE": "config.settings.ci"}}
    assert _postgres_ci_runs({"steps": [bootstrap, test]}) == [test["run"]]
    assert _postgres_ci_runs({"steps": [test, bootstrap]}) == []
    assert _postgres_ci_runs({"steps": [{**bootstrap, "continue-on-error": True}, test]}) == []
