"""Every plain ``Test*`` class and top-level ``test_*`` function in the platform tests must run in CI.

``manage.py test`` only collects ``unittest.TestCase`` subclasses. A ``class TestX:`` with
``test_*`` methods and pytest fixtures is silently ignored by it, so 40 such classes in nine
files passed nothing for as long as they existed, and several had gone stale. Module-level
``def test_x()`` functions are ignored the same way: three DNS modules ran in no CI job.

CI now derives the modules holding them with ``scripts/plain_test_class_modules.py`` and runs
exactly those under pytest (``make test-platform-pytest-only``). This test checks the three
parts of that arrangement: the scan finds every plain class and function, the target runs what
the scan finds, and a pull-request job runs the target.
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
SCRIPT = "scripts/plain_test_class_modules.py"
TARGET = "test-platform-pytest-only"


def _scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("plain_test_class_modules", PROJECT_ROOT / SCRIPT)
    assert spec and spec.loader, SCRIPT
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def _triggers(document: dict[Any, Any]) -> set[str]:
    # YAML 1.1 reads a bare `on:` key as the boolean True.
    triggers = document.get("on", document.get(True)) or {}
    return {triggers} if isinstance(triggers, str) else set(triggers)


@pytest.mark.integration
class TestPlainTestClassesRunInCi:
    def test_the_scan_finds_the_plain_classes(self) -> None:
        found = _scanner().plain_class_modules()

        assert "TestQueryTracer" in found["tests/tracing/test_trace_analysis.py"]  # no base class at all
        assert "TestOrdersAuditService" in found["tests/audit/test_audit_services.py"]  # pytest fixtures
        # A TestCase subclass in the same module is not plain: the Django runner already runs it.
        assert "TestRequestIDFilter" not in found["tests/tracing/test_trace_analysis.py"]
        assert sum(len(names) for names in found.values()) >= 40

    def test_a_class_is_plain_unless_it_reaches_a_testcase(self) -> None:
        plain = _scanner().plain_test_classes

        assert plain("class TestA:\n    def test_x(self): ...") == ["TestA"]
        assert plain("class TestA(object):\n    def test_x(self): ...") == ["TestA"]
        assert plain("class TestA(TestCase):\n    def test_x(self): ...") == []
        assert plain("class TestA(django.test.TransactionTestCase):\n    def test_x(self): ...") == []
        assert plain("class TestA(Mixin):\n    def test_x(self): ...") == ["TestA"]
        assert plain("class TestA:\n    def helper(self): ...") == []
        # A fixture base defined in this module or elsewhere in the tree decides, not its spelling.
        assert plain("class Base(TestCase): ...\nclass TestA(Base):\n    def test_x(self): ...") == []
        assert plain("class TestA(Fixture):\n    def test_x(self): ...", {"Fixture": ["APITestCase"]}) == []
        assert plain("class TestA(Fixture):\n    def test_x(self): ...", {"Fixture": []}) == ["TestA"]
        # A same-named TestCase elsewhere does not hide a plain class here.
        assert plain("class TestA:\n    def test_x(self): ...", {"TestA": ["TestCase"]}) == ["TestA"]

    def test_a_module_of_top_level_test_functions_is_listed(self, tmp_path: Path) -> None:
        tests = tmp_path / "tests"
        (tests / "dns").mkdir(parents=True)
        testcase = "from django.test import TestCase\nclass ZoneTests(TestCase):\n    def test_a(self): ...\n"
        modules = {
            "test_functions.py": "def test_x():\n    assert True\n",
            "test_async.py": "async def test_y():\n    assert True\n",
            "test_mixed.py": testcase + "def test_z():\n    assert True\n",
            # Controls: only the Django runner's TestCase, and only helpers pytest does not collect.
            "test_cases.py": testcase,
            "test_helpers.py": "def build_zone():\n    def test_inner(): ...\n    return 1\ndef testing_wire(): ...\n",
        }
        for name, source in modules.items():
            (tests / "dns" / name).write_text(source, encoding="utf-8")

        assert _scanner().plain_class_modules(tests) == {
            "tests/dns/test_async.py": ["test_y"],
            "tests/dns/test_functions.py": ["test_x"],
            "tests/dns/test_mixed.py": ["test_z"],
        }

    def test_the_scan_misses_no_class_a_regex_can_see(self) -> None:
        """An independent net: any `class TestX:` or `class TestX():` line in a test module."""
        scanned = _scanner().plain_class_modules()
        seen: dict[str, set[str]] = {}
        for path in TESTS.rglob("test*.py"):
            names = set(re.findall(r"^class (Test\w*)(?:\(\))?:", path.read_text(encoding="utf-8"), flags=re.MULTILINE))
            if names:
                seen[path.relative_to(TESTS.parent).as_posix()] = names

        missed = {
            module: sorted(names - set(scanned.get(module, [])))
            for module, names in seen.items()
            if names - set(scanned.get(module, []))
        }

        assert missed == {}

    def test_the_scan_misses_no_top_level_test_function_a_regex_can_see(self) -> None:
        """An independent net: any `def test_x(` or `async def test_x(` line at column 0 in a test module."""
        scanned = _scanner().plain_class_modules()
        missed: dict[str, list[str]] = {}
        for path in TESTS.rglob("test*.py"):
            text = path.read_text(encoding="utf-8")
            names = set(re.findall(r"^(?:async )?def (test_\w*)\(", text, flags=re.MULTILINE))
            module = path.relative_to(TESTS.parent).as_posix()
            if names - set(scanned.get(module, [])):
                missed[module] = sorted(names - set(scanned.get(module, [])))

        assert missed == {}
        assert "test_caa_policy_and_unknown_parameters" in scanned["tests/infrastructure/test_dns_probes.py"]

    def test_the_make_target_runs_the_scan_output_and_stops_on_a_failed_or_empty_scan(self) -> None:
        recipe = _make_recipe(TARGET)

        assert f"{SCRIPT}) || exit 1" in recipe, "a failing scan must stop the target, not run everything"
        assert '[ -z "$$modules" ]' in recipe and "exit 1" in recipe, "an empty scan must fail, not pass"
        invocation = re.search(r"-m pytest(.*)", recipe)
        assert invocation, "the target must run pytest"
        assert not re.findall(r"\btests/\w+", invocation.group(1)), "no hand-named modules"
        assert invocation.group(1).split()[-1] == "$$modules"

    def test_every_plain_test_class_is_run_by_ci(self) -> None:
        """A pull-request job runs the target, so a new plain class cannot sit unrun."""
        jobs = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            document = yaml.safe_load(path.read_text())
            if "pull_request" not in _triggers(document):
                continue
            for name, job in (document.get("jobs") or {}).items():
                if any(f"make {TARGET}" in str(step.get("run", "")) for step in job.get("steps", [])):
                    jobs.append(f"{path.name}:{name}")

        assert jobs, f"no pull-request job runs `make {TARGET}`"
        assert _scanner().plain_class_modules(), "the scan must find the plain classes it is meant to run"

    def test_the_platform_workflow_reruns_when_the_scan_changes(self) -> None:
        document = yaml.safe_load((WORKFLOWS / "platform.yml").read_text())
        triggers = document.get("on", document.get(True))

        assert SCRIPT in triggers["push"]["paths"]
