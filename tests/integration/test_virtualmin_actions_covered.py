"""Every Virtualmin action PRAHO can take is covered by a contract test and a lab test. No lab needed.

The contract suite (`tests/virtualmin_lab/contract/`, `make test-virtualmin-contract`) holds one test per
program on `VIRTUALMIN_ALLOWED_PROGRAMS`. This guard keeps that true by reading source, never by running it:

(a) a program the code can call must have a contract test (an AST scan of the real call styles);
(b) the allowlist and the set of contract tests must be the same set, one test each, and each test must say
    whether its program is read-only or mutating the way the replay classification does;
(c) every `virtualmin_*.yml` playbook must be named by a lab test.

Each check is proven by running its finder on a planted violation (the `Planted` tests at the end).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
APPS = REPO / "services/platform/apps"
VALIDATORS = APPS / "provisioning/virtualmin_validators.py"
CONTRACT_DIR = REPO / "tests/virtualmin_lab/contract"
PLAYBOOKS = REPO / "services/platform/infrastructure/ansible/playbooks"
LAB_COMMANDS = APPS / "provisioning/management/commands"

# A Virtualmin command is lower-case words joined by hyphens, or `info`; a loyalty "program" is neither.
COMMAND_SHAPE = re.compile(r"^(?:[a-z]+(?:-[a-z]+)+|info)$")

# Call sites whose program is not a literal. Each is resolved by hand to the programs it can reach; a new
# dynamic site fails the guard until it is added here with its programs.
DYNAMIC_SITES: dict[tuple[str, str], frozenset[str]] = {
    # The authentication manager only ever probes with list-domains (health_check_all_methods).
    ("provisioning/virtualmin_auth_manager.py", "_execute_acl_auth"): frozenset({"list-domains"}),
    ("provisioning/virtualmin_auth_manager.py", "_execute_master_proxy"): frozenset({"list-domains"}),
    # The two helpers below pass their caller's literal through; the callers are scanned as call sites.
    ("provisioning/virtualmin_backup_service.py", "_call_checked"): frozenset(),
    ("provisioning/virtualmin_migration_service.py", "_command"): frozenset(),
    # operations = {"suspend_domain": ("disable-domain", ...), "unsuspend_domain": ("enable-domain", ...), ...}
    ("provisioning/virtualmin_service.py", "_execute_lifecycle_operation"): frozenset(
        {"disable-domain", "enable-domain", "delete-domain"}
    ),
    ("provisioning/management/commands/virtualmin_lab_checks.py", "_check_node_deploy_playbook"): frozenset(
        {"disable-domain", "enable-domain"}
    ),
}


@dataclass(frozen=True)
class CallSite:
    path: str
    function: str
    line: int
    program: str | None  # None: not a literal


@dataclass(frozen=True)
class ContractTest:
    path: str
    function: str
    program: str
    helpers: frozenset[str]  # names called in the test body


# ------------------------------------------------------------------ scanners


def _callee_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def _program_argument(node: ast.Call, name: str) -> ast.expr | None:
    """The expression that names the program in a call, for the styles PRAHO uses."""
    positions = {"call": 0, "_call_checked": 1, "_command": 2}
    index = positions.get(name)
    if index is not None and len(node.args) > index:
        return node.args[index]
    for keyword in node.keywords:
        if keyword.arg == "program":
            return keyword.value
    return None


def scan_call_sites(source: str, path: str) -> list[CallSite]:
    """Every place the source names a Virtualmin program.

    Real styles accepted: `gateway.call("p", ...)` / `self.call("p")`, `self._call_checked(gw, "p", ...)`,
    `self._command(migration, server, "p", ...)`, and a `program="p"` keyword. A `program=` keyword counts
    only when its value is a literal shaped like a Virtualmin command (the promotions app has a loyalty
    `program=` of its own, always a variable).
    """
    sites: list[CallSite] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.functions: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # ast visitor protocol
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815  # ast visitor protocol

        def visit_Call(self, node: ast.Call) -> None:  # ast visitor protocol
            name = _callee_name(node)
            argument = _program_argument(node, name) if name else None
            styled = name in {"call", "_call_checked", "_command"}
            if argument is not None:
                function = self.functions[-1] if self.functions else "<module>"
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    if styled or COMMAND_SHAPE.match(argument.value):
                        sites.append(CallSite(path, function, node.lineno, argument.value))
                elif styled:
                    sites.append(CallSite(path, function, node.lineno, None))
            self.generic_visit(node)

    Visitor().visit(ast.parse(source))
    return sites


def scan_application() -> list[CallSite]:
    sites: list[CallSite] = []
    for path in sorted(APPS.rglob("*.py")):
        relative = path.relative_to(APPS)
        if "tests" in relative.parts or "migrations" in relative.parts:
            continue
        text = path.read_text()
        if "call" not in text and "program" not in text and "_command" not in text:
            continue
        sites.extend(scan_call_sites(text, str(relative)))
    return sites


def scan_contract_tests(source: str, path: str) -> list[ContractTest]:
    """The tests marked `@covers("<program>")`, with the helper names each one calls."""
    tests: list[ContractTest] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and _callee_name(decorator) == "covers"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                called = {name for call in ast.walk(node) if isinstance(call, ast.Call) and (name := _callee_name(call))}
                tests.append(ContractTest(path, node.name, decorator.args[0].value, frozenset(called)))
    return tests


def scan_contract_directory(directory: Path) -> list[ContractTest]:
    tests: list[ContractTest] = []
    for path in sorted(directory.glob("test_*.py")):
        tests.extend(scan_contract_tests(path.read_text(), path.name))
    return tests


def allowlisted_programs(source: str) -> tuple[set[str], set[str]]:
    """(VIRTUALMIN_ALLOWED_PROGRAMS, VIRTUALMIN_READ_ONLY_PROGRAMS) from their frozenset literals."""
    found: dict[str, set[str]] = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"VIRTUALMIN_ALLOWED_PROGRAMS", "VIRTUALMIN_READ_ONLY_PROGRAMS"} and isinstance(node.value, ast.Call):
                found[name] = {str(item) for item in ast.literal_eval(node.value.args[0])}
    return found["VIRTUALMIN_ALLOWED_PROGRAMS"], found["VIRTUALMIN_READ_ONLY_PROGRAMS"]


# ------------------------------------------------------------------- finders


def programs_the_code_can_call(sites: Iterable[CallSite], dynamic: Mapping[tuple[str, str], frozenset[str]]) -> set[str]:
    reachable: set[str] = set()
    for site in sites:
        if site.program is not None:
            reachable.add(site.program)
        else:
            reachable |= dynamic.get((site.path, site.function), frozenset())
    return reachable


def undeclared_dynamic_sites(sites: Iterable[CallSite], dynamic: Mapping[tuple[str, str], frozenset[str]]) -> set[tuple[str, str]]:
    return {(site.path, site.function) for site in sites if site.program is None} - set(dynamic)


def uncovered_programs(reachable: set[str], covered: set[str]) -> set[str]:
    """(a) programs the code can call that have no contract test."""
    return reachable - covered


def allowlist_mismatch(allowed: set[str], tests: list[ContractTest]) -> list[str]:
    """(b) differences between the allowlist and the contract tests."""
    covered = [test.program for test in tests]
    problems = [f"allowlisted, no contract test: {program}" for program in sorted(allowed - set(covered))]
    problems += [f"contract test, not allowlisted: {program}" for program in sorted(set(covered) - allowed)]
    problems += [f"more than one contract test: {program}" for program in sorted({p for p in covered if covered.count(p) > 1})]
    return problems


def wrong_replay_declaration(tests: list[ContractTest], read_only: set[str]) -> list[str]:
    """(b) a test must prove a read-only program read-only, and say a mutating one is not."""
    problems: list[str] = []
    for test in tests:
        wanted, forbidden = ("prove_read_only", "assert_mutating") if test.program in read_only else ("assert_mutating", "prove_read_only")
        if wanted not in test.helpers or forbidden in test.helpers:
            problems.append(f"{test.path}::{test.function} ({test.program}) must call {wanted} and not {forbidden}")
    return problems


def unreferenced_playbooks(playbooks: Iterable[str], lab_sources: Iterable[str]) -> list[str]:
    """(c) playbooks that no lab test names."""
    combined = "\n".join(lab_sources)
    return [name for name in sorted(playbooks) if name not in combined]


def lab_test_sources() -> list[str]:
    paths = [*sorted(LAB_COMMANDS.glob("virtualmin_lab_*.py")), *sorted((REPO / "tests/virtualmin_lab").rglob("*.py"))]
    return [path.read_text() for path in paths]


# ------------------------------------------------------- the guard, on the repo


@pytest.fixture(scope="module")
def sites() -> list[CallSite]:
    return scan_application()


@pytest.fixture(scope="module")
def contract_tests() -> list[ContractTest]:
    return scan_contract_directory(CONTRACT_DIR)


@pytest.fixture(scope="module")
def allowlist() -> tuple[set[str], set[str]]:
    return allowlisted_programs(VALIDATORS.read_text())


class TestScannerSeesTheRealCode:
    """Check 4 of the test-integrity gate: pin what the scan finds, and that it finds the newest sites."""

    def test_the_allowlist_is_read_in_full(self, allowlist: tuple[set[str], set[str]]) -> None:
        allowed, read_only = allowlist
        assert len(allowed) == 26
        assert "info" in allowed
        assert len(read_only) == 10
        assert read_only <= allowed

    def test_the_scan_finds_every_real_call_style(self, sites: list[CallSite]) -> None:
        found = {(site.path, site.program) for site in sites if site.program}
        assert ("provisioning/virtualmin_service.py", "create-domain") in found  # gateway.call("p", params)
        assert ("provisioning/virtualmin_gateway.py", "list-templates") in found  # self.call("p", ...)
        assert ("provisioning/virtualmin_backup_service.py", "restore-domain") in found  # self._call_checked(gw, "p")
        assert ("provisioning/virtualmin_backup_service.py", "backup-domain") in found
        assert ("provisioning/virtualmin_migration_service.py", "enable-domain") in found  # self._command(m, s, "p")
        assert ("provisioning/virtualmin_disaster_recovery.py", "modify-domain") in found
        assert ("provisioning/virtualmin_gateway.py", "list-bandwidth") in found
        assert len([site for site in sites if site.program]) == 44, "a new call site: add it, then update this count"

    def test_the_loyalty_program_keyword_is_not_a_virtualmin_program(self, sites: list[CallSite]) -> None:
        assert not [site for site in sites if site.path.startswith("promotions/")]

    def test_every_dynamic_site_is_declared_and_every_declaration_is_real(self, sites: list[CallSite]) -> None:
        assert undeclared_dynamic_sites(sites, DYNAMIC_SITES) == set()
        found = {(site.path, site.function) for site in sites if site.program is None}
        assert found == set(DYNAMIC_SITES), "a declared dynamic site no longer exists"

    def test_the_contract_tests_are_found(self, contract_tests: list[ContractTest]) -> None:
        assert len(contract_tests) == 26
        assert "test_node_transfer.py" not in {test.path for test in contract_tests}
        assert ("test_backups.py", "restore-domain") in {(test.path, test.program) for test in contract_tests}


class TestEveryActionIsCovered:
    def test_a_program_the_code_can_call_has_a_contract_test(
        self, sites: list[CallSite], contract_tests: list[ContractTest]
    ) -> None:
        reachable = programs_the_code_can_call(sites, DYNAMIC_SITES)
        assert reachable, "the scan found nothing"
        assert uncovered_programs(reachable, {test.program for test in contract_tests}) == set()

    def test_the_code_calls_only_allowlisted_programs(
        self, sites: list[CallSite], allowlist: tuple[set[str], set[str]]
    ) -> None:
        assert programs_the_code_can_call(sites, DYNAMIC_SITES) <= allowlist[0]

    def test_the_allowlist_and_the_contract_tests_are_the_same_set(
        self, allowlist: tuple[set[str], set[str]], contract_tests: list[ContractTest]
    ) -> None:
        assert allowlist_mismatch(allowlist[0], contract_tests) == []

    def test_each_test_declares_read_only_or_mutating_as_the_replay_classification_does(
        self, allowlist: tuple[set[str], set[str]], contract_tests: list[ContractTest]
    ) -> None:
        assert wrong_replay_declaration(contract_tests, allowlist[1]) == []

    def test_every_node_playbook_is_named_by_a_lab_test(self) -> None:
        playbooks = [path.name for path in PLAYBOOKS.glob("virtualmin_*.yml")] + ["virtualmin.yml"]
        assert len(playbooks) == 10, "a new playbook: it needs a lab test, then update this count"
        assert unreferenced_playbooks(playbooks, lab_test_sources()) == []


# ------------------------------------------------- each check on a planted violation


class TestPlantedViolations:
    """Run the finders on source that breaks each rule. A guard that cannot fail proves nothing."""

    STYLES = '''
class Service:
    def run(self, gateway, migration, server):
        gateway.call("create-domain", {})
        self.call("info")
        self._call_checked(gateway, "restore-domain", {}, 10)
        self._command(migration, server, "enable-domain")
        thing(program="list-certs")
        loyalty(program="gold")
        loyalty(program=chosen)
        gateway.call(self.program, {})
'''

    def test_the_scanner_accepts_each_real_call_style(self) -> None:
        sites = scan_call_sites(self.STYLES, "provisioning/planted.py")
        assert [site.program for site in sites] == [
            "create-domain",
            "info",
            "restore-domain",
            "enable-domain",
            "list-certs",
            None,
        ]
        assert {site.function for site in sites} == {"run"}

    def test_a_called_program_without_a_contract_test_is_reported(self) -> None:
        planted = 'def go(gateway):\n    gateway.call("frobnicate-domain", {})\n    gateway.call("info")\n'
        reachable = programs_the_code_can_call(scan_call_sites(planted, "provisioning/planted.py"), {})
        assert uncovered_programs(reachable, {"info"}) == {"frobnicate-domain"}

    def test_a_program_reached_through_a_variable_must_be_declared(self) -> None:
        planted = "def go(gateway, program):\n    gateway.call(program, {})\n"
        sites = scan_call_sites(planted, "provisioning/planted.py")
        assert undeclared_dynamic_sites(sites, DYNAMIC_SITES) == {("provisioning/planted.py", "go")}
        declared = {("provisioning/planted.py", "go"): frozenset({"info"})}
        assert undeclared_dynamic_sites(sites, declared) == set()
        assert programs_the_code_can_call(sites, declared) == {"info"}

    def test_an_allowlist_and_a_set_of_contract_tests_that_differ_are_reported(self) -> None:
        tests = [
            ContractTest("a.py", "test_info", "info", frozenset()),
            ContractTest("a.py", "test_extra", "extra-thing", frozenset()),
            ContractTest("b.py", "test_info_again", "info", frozenset()),
        ]
        assert allowlist_mismatch({"info", "list-domains"}, tests) == [
            "allowlisted, no contract test: list-domains",
            "contract test, not allowlisted: extra-thing",
            "more than one contract test: info",
        ]

    def test_a_test_that_is_silent_about_replay_safety_is_reported(self) -> None:
        source = (
            "@covers('list-domains')\ndef test_a(lab):\n    lab.prove_read_only('list-domains', run)\n"
            "@covers('create-domain')\ndef test_b(lab):\n    lab.prove_read_only('create-domain', run)\n"
            "@covers('delete-domain')\ndef test_c(lab):\n    pass\n"
        )
        tests = scan_contract_tests(source, "planted.py")
        assert [test.program for test in tests] == ["list-domains", "create-domain", "delete-domain"]
        assert wrong_replay_declaration(tests, {"list-domains"}) == [
            "planted.py::test_b (create-domain) must call assert_mutating and not prove_read_only",
            "planted.py::test_c (delete-domain) must call assert_mutating and not prove_read_only",
        ]

    def test_a_playbook_no_lab_test_names_is_reported(self, tmp_path: Path) -> None:
        (tmp_path / "virtualmin_new_thing.yml").write_text("- hosts: all\n")
        names = [path.name for path in tmp_path.glob("virtualmin_*.yml")]
        assert unreferenced_playbooks(names, ["runs virtualmin_backup.yml only"]) == ["virtualmin_new_thing.yml"]
        assert unreferenced_playbooks(names, ["runs virtualmin_new_thing.yml"]) == []
