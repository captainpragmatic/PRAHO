"""Guardrails against creating bare Django is_staff accounts.

#271 established that native ``is_staff`` gates nothing in this platform (Django
admin is disabled); authorization derives from ``staff_role``. A future creation
path that mints ``is_staff=True`` with no ``staff_role`` and not superuser would
be a misconfigured account that silently loses credential-vault access. These
AST guards fail if any non-test creation path introduces such an account.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from django.test import SimpleTestCase

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOTS = (PLATFORM_ROOT / "apps", PLATFORM_ROOT / "scripts")

CREATION_METHODS = frozenset(
    {
        "create",
        "create_user",
        "get_or_create",
        "update_or_create",
    }
)

EXPECTED_CREATION_SITES = frozenset(
    {
        "apps/common/management/commands/generate_sample_data.py:ensure_e2e_users:e2e_admin",
        "apps/common/management/commands/generate_sample_data.py:_create_customer_permutations:inactive_staff",
        "apps/common/management/commands/generate_sample_data.py:_create_customer_permutations:manager_user",
        "apps/common/management/commands/setup_test_users.py:_create_test_admin:_create_test_admin",
        "scripts/setup_test_data.py:create_test_data:superuser",
        "scripts/setup_test_data.py:create_test_data:e2e_admin",
    }
)

# Assignment after get_or_create; it is safe because the same creation site also
# supplies is_superuser=True and staff_role="admin".
EXPECTED_IS_STAFF_MUTATIONS = frozenset(
    {
        "apps/common/management/commands/generate_sample_data.py:ensure_e2e_users:e2e_admin",
    }
)

NEWEST_KNOWN_CREATION_SITE = (
    "apps/common/management/commands/generate_sample_data.py:_create_customer_permutations:manager_user"
)


@dataclass(frozen=True)
class StaffCreationSite:
    identifier: str
    line_number: int
    has_staff_role: bool
    is_superuser: bool


def _iter_production_python_files() -> list[Path]:
    files: list[Path] = []

    for root in SCAN_ROOTS:
        for path in root.rglob("*.py"):
            relative_path = path.relative_to(PLATFORM_ROOT)
            if "tests" in relative_path.parts or path.name.startswith("test_"):
                continue
            files.append(path)

    return sorted(files)


def _parents_for(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _enclosing_scope(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            return current.name
    return "<module>"


def _target_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [] if target.id == "_" else [target.id]
    if isinstance(target, ast.Tuple | ast.List):
        return [name for element in target.elts for name in _target_names(element)]
    return []


def _assigned_subject(node: ast.AST, parents: dict[ast.AST, ast.AST], scope: str) -> str:
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.Assign):
            names = [name for target in current.targets for name in _target_names(target)]
            if names:
                return names[0]
        if isinstance(current, ast.AnnAssign):
            names = _target_names(current.target)
            if names:
                return names[0]
        if isinstance(current, ast.stmt):
            break
    return scope


def _literal_mapping(node: ast.AST) -> dict[str, ast.AST]:
    if not isinstance(node, ast.Dict):
        return {}

    mapping: dict[str, ast.AST] = {}
    for key, value in zip(node.keys, node.values, strict=True):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            mapping[key.value] = value
    return mapping


def _creation_values(call: ast.Call) -> dict[str, ast.AST]:
    values: dict[str, ast.AST] = {}

    for keyword in call.keywords:
        if keyword.arg == "defaults":
            values.update(_literal_mapping(keyword.value))
        elif keyword.arg is not None:
            values[keyword.arg] = keyword.value

    return values


def _is_creation_call(call: ast.Call) -> bool:
    if isinstance(call.func, ast.Attribute):
        return call.func.attr in CREATION_METHODS

    # Also cover direct User(is_staff=True, ...) construction followed by save().
    return isinstance(call.func, ast.Name) and call.func.id == "User"


def _is_literal_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_nonempty_literal_string(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and bool(node.value)


def _find_staff_creation_sites() -> list[StaffCreationSite]:
    sites: list[StaffCreationSite] = []

    for path in _iter_production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = _parents_for(tree)
        relative_path = path.relative_to(PLATFORM_ROOT).as_posix()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_creation_call(node):
                continue

            values = _creation_values(node)
            if not _is_literal_true(values.get("is_staff")):
                continue

            scope = _enclosing_scope(node, parents)
            subject = _assigned_subject(node, parents, scope)
            sites.append(
                StaffCreationSite(
                    identifier=f"{relative_path}:{scope}:{subject}",
                    line_number=node.lineno,
                    has_staff_role=_is_nonempty_literal_string(values.get("staff_role")),
                    is_superuser=_is_literal_true(values.get("is_superuser")),
                )
            )

    return sites


def _find_is_staff_mutations() -> set[str]:
    mutations: set[str] = set()

    for path in _iter_production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = _parents_for(tree)
        relative_path = path.relative_to(PLATFORM_ROOT).as_posix()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not _is_literal_true(node.value):
                continue

            scope = _enclosing_scope(node, parents)
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "is_staff" and isinstance(target.value, ast.Name):
                    mutations.add(f"{relative_path}:{scope}:{target.value.id}")

    return mutations


class BareIsStaffCreationGuardrailTests(SimpleTestCase):
    def test_literal_is_staff_creation_sites_are_complete_and_safe(self) -> None:
        sites = _find_staff_creation_sites()
        identifiers = {site.identifier for site in sites}

        # Structural-Helper Integrity: exact count plus newest-site canary.
        self.assertEqual(len(sites), 6)
        self.assertEqual(identifiers, EXPECTED_CREATION_SITES)
        self.assertIn(NEWEST_KNOWN_CREATION_SITE, identifiers)

        unsafe_sites = [
            f"{site.identifier}:{site.line_number}"
            for site in sites
            if not (site.has_staff_role or site.is_superuser)
        ]
        self.assertEqual(
            unsafe_sites,
            [],
            msg=(
                "Bare is_staff accounts are forbidden. Every is_staff=True creation must also set a "
                f"non-empty staff_role or is_superuser=True; unsafe sites: {unsafe_sites}"
            ),
        )

    def test_direct_is_staff_mutations_are_complete(self) -> None:
        mutations = _find_is_staff_mutations()

        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations, EXPECTED_IS_STAFF_MUTATIONS)
        self.assertIn(
            "apps/common/management/commands/generate_sample_data.py:ensure_e2e_users:e2e_admin",
            mutations,
        )
