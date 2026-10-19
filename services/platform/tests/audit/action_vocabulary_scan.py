"""Find every audit action the platform code writes, by reading its syntax tree.

An action is a string handed to an audit writer: ``AuditEventData(event_type=...)``,
``log_simple_event("...")``, ``log_security_event("...")`` and so on. The scan follows a name
back to the literals assigned to it in the same function or module, expands f-strings and
dict lookups over such names, and learns local wrappers: a function that passes one of its own
parameters to a writer is a writer too, so its callers' literals are collected.

What it cannot resolve is returned as ``unresolved`` for the guard test to account for. The
same scan feeds BUSINESS_AUDIT_EVENTS.md, so the document lists exactly the actions that have
a writer.
"""

from __future__ import annotations

import ast
import itertools
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
APPS_ROOT = PLATFORM_ROOT / "apps"

# parameter name -> (positional index or None, templates). A template turns the argument into the
# action actually written ("{}_success"); a plain writer's single template is "{}".
Spec = dict[str, tuple[int | None, tuple[str, ...]]]
_PLAIN = ("{}",)
SEED_WRITERS: dict[str, Spec] = {
    "AuditEventData": {"event_type": (0, _PLAIN)},
    "BusinessEventData": {"event_type": (None, _PLAIN)},
    "TwoFactorAuditRequest": {"event_type": (None, _PLAIN)},
    "log_simple_event": {"event_type": (0, _PLAIN)},
    "log_security_event": {"event_type": (0, _PLAIN)},
    "_create_audit_event": {"action": (None, _PLAIN)},
    "AuditEventCreationData": {"action": (0, _PLAIN)},
    "create_audit_event": {"action": (0, _PLAIN)},
    "_create_event": {"action": (None, _PLAIN)},
    "AuditEvent": {"action": (None, _PLAIN)},
    "AuditEvent.objects.create": {"action": (None, _PLAIN)},
}

# Calls that carry an ``event_type`` or ``action`` that is not an audit action.
NOT_WRITERS = frozenset({"create", "get_or_create", "update_or_create", "filter", "get", "exclude"})

SKIPPED_PARTS = ("/tests/", "/migrations/")

_MAX_DEPTH = 6  # how far a name is followed back through assignments
_MAX_PASSES = 8  # enough for any realistic chain of wrappers
_MAX_TEMPLATE_LENGTH = 80  # a template longer than this is a runaway composition


@dataclass
class Scan:
    literals: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    unresolved: list[tuple[str, str, str]] = field(default_factory=list)  # (file, callee, expression)


def _callee(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Attribute):
        if func.attr == "create" and ast.unparse(func.value) == "AuditEvent.objects":
            return "AuditEvent.objects.create"
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}


def _enclosing_function(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    current: ast.AST | None = parents.get(node)
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            return current
        current = parents.get(current)
    return None


def _assignments(scope: ast.AST, name: str) -> list[ast.expr] | None:
    """Every value bound to ``name`` in ``scope``; None when one of them is not a plain assignment."""
    values: list[ast.expr] = []
    for node in ast.walk(scope):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    values.append(node.value)
                elif isinstance(target, ast.Tuple) and any(
                    isinstance(e, ast.Name) and e.id == name for e in target.elts
                ):
                    return None
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name and node.value is not None:
                values.append(node.value)
        elif isinstance(node, ast.For):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                if isinstance(node.iter, ast.Tuple | ast.List | ast.Set):
                    values.extend(node.iter.elts)
                else:
                    return None
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            return None
    return values


class _Resolver:
    def __init__(self, module: ast.Module, parents: dict[ast.AST, ast.AST]) -> None:
        self.module = module
        self.parents = parents

    def values(self, node: ast.AST, scope: ast.AST, depth: int = 0) -> set[str] | None:  # noqa: PLR0911  # one branch per node kind
        if depth > _MAX_DEPTH:
            return None
        if isinstance(node, ast.Constant):
            return {node.value} if isinstance(node.value, str) else None
        if isinstance(node, ast.IfExp):
            body, orelse = self.values(node.body, scope, depth + 1), self.values(node.orelse, scope, depth + 1)
            return None if body is None or orelse is None else body | orelse
        if isinstance(node, ast.JoinedStr):
            return self._fstring(node, scope, depth)
        if isinstance(node, ast.Name):
            return self._name(node.id, scope, depth)
        if isinstance(node, ast.Subscript):
            return self._subscript(node, scope, depth)
        if isinstance(node, ast.Call) and _callee(node) in {"get"} and isinstance(node.func, ast.Attribute):
            return self._dict_values(node.func.value, scope, depth)
        return None

    def _name(self, name: str, scope: ast.AST, depth: int) -> set[str] | None:
        for search in (scope, self.module):
            assigned = _assignments(search, name)
            if assigned:
                found: set[str] = set()
                for value in assigned:
                    resolved = self.values(value, scope, depth + 1)
                    if resolved is None:
                        return None
                    found |= resolved
                return found
        return None

    def _fstring(self, node: ast.JoinedStr, scope: ast.AST, depth: int) -> set[str] | None:
        parts: list[set[str]] = []
        for piece in node.values:
            if isinstance(piece, ast.Constant):
                parts.append({str(piece.value)})
            elif isinstance(piece, ast.FormattedValue):
                resolved = self.values(piece.value, scope, depth + 1)
                if resolved is None:
                    return None
                parts.append(resolved)
        return {"".join(combo) for combo in itertools.product(*parts)}

    def _dict_values(self, node: ast.AST, scope: ast.AST, depth: int) -> set[str] | None:
        if isinstance(node, ast.Name):
            for search in (scope, self.module):
                assigned = _assignments(search, node.id)
                if assigned and all(isinstance(v, ast.Dict) for v in assigned):
                    found: set[str] = set()
                    for value in assigned:
                        assert isinstance(value, ast.Dict)
                        for item in value.values:
                            resolved = self.values(item, scope, depth + 1)
                            if resolved is None:
                                return None
                            found |= resolved
                    return found
        if isinstance(node, ast.Dict):
            found = set()
            for item in node.values:
                resolved = self.values(item, scope, depth + 1)
                if resolved is None:
                    return None
                found |= resolved
            return found
        return None

    def _subscript(self, node: ast.Subscript, scope: ast.AST, depth: int) -> set[str] | None:
        return self._dict_values(node.value, scope, depth)


def _positional_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    names = [a.arg for a in func.args.posonlyargs + func.args.args]
    return names[1:] if names and names[0] in {"self", "cls"} else names


def _python_files() -> list[Path]:
    return sorted(p for p in APPS_ROOT.rglob("*.py") if not any(part in str(p) for part in SKIPPED_PARTS))


def _action_args(call: ast.Call, spec: Spec) -> list[tuple[ast.expr, tuple[str, ...]]]:
    by_keyword = [(keyword.value, spec[keyword.arg][1]) for keyword in call.keywords if keyword.arg in spec]
    named = {keyword.arg for keyword in call.keywords}
    by_position = [
        (call.args[index], templates)
        for name, (index, templates) in spec.items()
        if index is not None and len(call.args) > index and name not in named
    ]
    return by_keyword + by_position


def _placeholder_template(node: ast.JoinedStr, params: set[str]) -> tuple[str, str] | None:
    """("{}" template, parameter) for an f-string built from constants and exactly one parameter."""
    pieces: list[str] = []
    parameter: str | None = None
    for piece in node.values:
        if isinstance(piece, ast.Constant):
            pieces.append(str(piece.value).replace("{", "{{").replace("}", "}}"))
        elif isinstance(piece, ast.FormattedValue) and isinstance(piece.value, ast.Name) and piece.value.id in params:
            if parameter is not None:
                return None
            parameter = piece.value.id
            pieces.append("{}")
        else:
            return None
    return ("".join(pieces), parameter) if parameter else None


def _compose(outer: tuple[str, ...], inner: str) -> tuple[str, ...]:
    return tuple(template.replace("{}", inner, 1) for template in outer)


class Writers:
    """Public writer names are global; a private (underscore) wrapper is local to its module."""

    def __init__(self) -> None:
        self.public: dict[str, Spec] = {name: dict(spec) for name, spec in SEED_WRITERS.items()}
        self.private: dict[Path, dict[str, Spec]] = defaultdict(dict)

    def spec(self, path: Path, name: str) -> Spec | None:
        if name.startswith("_") and name not in SEED_WRITERS:
            return self.private[path].get(name)
        return self.public.get(name)

    def add(self, path: Path, name: str, param: str, index: int | None, templates: tuple[str, ...]) -> bool:
        """Learn that ``name`` writes ``param`` under ``templates``; True when that is new.

        Templates accumulate: a wrapper that hands one parameter to a writer more than once (an
        ``audit_service_call`` writes ``{}_success`` and ``{}_failed``) writes every one of them.
        Replacing them would keep only the last call site and silently drop the others.
        """
        table = self.private[path] if name.startswith("_") and name not in SEED_WRITERS else self.public
        spec = table.setdefault(name, {})
        known_index, known = spec.get(param, (index, ()))
        merged = tuple(sorted(set(known) | set(templates)))
        entry = (known_index if known_index is not None else index, merged)
        if spec.get(param) == entry:
            return False
        spec[param] = entry
        return True


def _learn_from_function(path: Path, func: ast.FunctionDef | ast.AsyncFunctionDef, writers: Writers) -> bool:
    """Teach ``writers`` what ``func`` passes on to a writer; True when something new was learned."""
    params = _positional_params(func)
    all_params = set(params) | {a.arg for a in func.args.kwonlyargs}
    learned_something = False
    for call in ast.walk(func):
        if not isinstance(call, ast.Call):
            continue
        callee = _callee(call)
        spec = writers.spec(path, callee) if callee else None
        if spec is None or callee in NOT_WRITERS or callee == func.name:
            continue
        for arg, templates in _action_args(call, spec):
            parameter: str | None = None
            learned = templates
            if isinstance(arg, ast.Name) and arg.id in all_params:
                parameter = arg.id
            elif isinstance(arg, ast.JoinedStr):
                built = _placeholder_template(arg, all_params)
                if built is not None:
                    learned, parameter = _compose(templates, built[0]), built[1]
            if parameter is not None and all(len(t) < _MAX_TEMPLATE_LENGTH for t in learned):
                index = params.index(parameter) if parameter in params else None
                learned_something = writers.add(path, func.name, parameter, index, learned) or learned_something
    return learned_something


def _learn_wrappers(trees: dict[Path, ast.Module]) -> Writers:
    """Writers plus every function that hands one of its own parameters to a writer."""
    writers = Writers()
    changed = True
    passes = 0
    while changed and passes < _MAX_PASSES:
        changed = False
        passes += 1
        for path, tree in trees.items():
            for func in ast.walk(tree):
                if isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                    changed = _learn_from_function(path, func, writers) or changed
    return writers


def _is_wrapper_argument(
    arg: ast.expr,
    call: ast.Call,
    parents: dict[ast.AST, ast.AST],
    spec_of: Callable[[str], Spec | None],
) -> bool:
    """Is ``arg`` a parameter of an enclosing function that is itself a learned writer?"""
    current: ast.AST | None = parents.get(call)
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef):
            own = spec_of(current.name)
            params = {a.arg for a in current.args.args + current.args.kwonlyargs + current.args.posonlyargs}
            if own is not None:
                if isinstance(arg, ast.Name) and arg.id in params and arg.id in own:
                    return True
                if isinstance(arg, ast.JoinedStr):
                    built = _placeholder_template(arg, params)
                    if built is not None and built[1] in own:
                        return True
        current = parents.get(current)
    return False


def scan() -> Scan:
    trees = {path: ast.parse(path.read_text()) for path in _python_files()}
    writers = _learn_wrappers(trees)
    result = Scan()
    for path, tree in trees.items():
        parents = _parents(tree)
        resolver = _Resolver(tree, parents)
        relative = str(path.relative_to(APPS_ROOT))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            callee = _callee(call)
            spec = writers.spec(path, callee) if callee else None
            if callee is None or spec is None or callee in NOT_WRITERS:
                continue
            function = _enclosing_function(call, parents)
            scope: ast.AST = function if function is not None else tree
            for arg, templates in _action_args(call, spec):
                resolved = resolver.values(arg, scope)
                if resolved is not None:
                    for action in resolved:
                        for template in templates:
                            result.literals[template.replace("{}", action, 1)].add(f"{relative}:{call.lineno}")
                    continue
                if isinstance(arg, ast.Attribute):
                    continue  # read off a data object built elsewhere, where its literal is scanned
                if _is_wrapper_argument(arg, call, parents, lambda name, p=path: writers.spec(p, name)):
                    continue  # a wrapper: its callers' arguments are scanned instead
                result.unresolved.append((relative, callee, ast.unparse(arg)))
    return result


def registered_actions() -> set[str]:
    """The action choices declared on AuditEvent, read from its source (no Django needed)."""
    tree = ast.parse((APPS_ROOT / "audit" / "models.py").read_text())
    for node in ast.walk(tree):
        target = node.target if isinstance(node, ast.AnnAssign) else None
        if isinstance(node, ast.Assign):
            target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == "ACTION_CHOICES" and isinstance(node.value, ast.Tuple):
            return {
                element.elts[0].value
                for element in node.value.elts
                if isinstance(element, ast.Tuple) and isinstance(element.elts[0], ast.Constant)
            }
    raise AssertionError("ACTION_CHOICES not found in apps/audit/models.py")
