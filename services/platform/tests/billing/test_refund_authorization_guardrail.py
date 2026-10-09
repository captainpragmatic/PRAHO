"""#104 [M11]: every refund entry point is classified with its authorization mechanism.

The defect this pins down was a *count-of-one outlier*: ``invoice_refund`` was the only
view in ``apps/billing/views.py`` on ``@staff_required`` while 19 siblings used
``@billing_staff_required``, and its twin ``orders.views.order_refund`` carried the same
effective predicate under a third decorator name. Nothing failed; the wrong role simply got
through.

The invariant is deliberately narrow. "Every money-moving view carries a staff decorator"
would be false — customer payment endpoints and verified gateway webhooks move money
legitimately without one. Instead this enumerates every function that starts a refund (a
``RefundService.refund_*`` call, a tender-refund retry or a gift-card purchase refund) and
asserts each is gated by the mechanism it is supposed to be gated by. A private helper is
classified through its caller. A new refund entry point fails this test until it is
classified here, which is the point.

Structure follows ``tests/users/test_staff_account_creation_guardrail.py``: AST over
production sources, a frozen record per site, and an exact expected set.

What it is not: a defence against code written to evade it. It catches the accidental shapes
(a new view, a dropped decorator, a forgotten actor). It does not follow a refund called through a
lambda, an alias, an exported wrapper of a private helper, or an actor laundered through a
variable; it does not prove a called check's result is enforced. Those are code-review concerns.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from django.test import SimpleTestCase

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOT = PLATFORM_ROOT / "apps"

# Every primitive that sends money back to a customer. ``RefundService`` methods are called as
# attributes; the others are imported and called by bare name. ``refresh_refund`` belongs here: a
# gift-card refund reserved but not yet sent is submitted to the gateway by it.
REFUND_SERVICE_METHODS = frozenset({"refund_invoice", "refund_order"})
REFUND_PRIMITIVES = frozenset({"resume_refund", "refund_purchase", "refresh_refund"})
# Resumes a refund whose reservation already recorded its actor (``created_by``) and checked
# ``can_manage_financial_data`` (``reserve_funding_refund``), so it takes no ``actor=`` of its own.
RESUMING_PRIMITIVES = frozenset({"refresh_refund"})

# Modules that define and orchestrate those primitives. Their internal calls (for example
# ``refund_service.py`` -> ``tender_refunds.refund_from_existing_flow``) are plumbing reached
# only through an entry point below, not entry points of their own. ``record_bank_refund`` is
# out of scope by design: it records a bank transfer staff already made, it sends nothing.
PRIMITIVE_MODULES = frozenset(
    {"apps/billing/refund_service.py", "apps/promotions/tender_refunds.py", "apps/promotions/gift_refunds.py"}
)

# A scheduled task has no request: its authority is the staff action that reserved the refund it
# resumes. Declared with this marker, which holds only for a request-less function in a tasks.py.
SYSTEM_TASK = "<system task>"

# The complete inventory of paths that start a refund, each mapped to the gate tokens that must
# all be present on it. Refunds are staff-only: the portal's customer endpoint
# (`api_process_refund`) was removed, and a new entry point of any kind fails this test until it
# is declared here. A private helper (`_name`) is classified through its callers, named after
# "via"; the gate must sit on that caller.
EXPECTED_REFUND_ENTRY_POINTS: dict[str, tuple[str, ...]] = {
    "apps/billing/views.py:invoice_refund": ("billing_staff_api_required",),
    "apps/orders/views.py:order_refund": ("billing_staff_api_required",),
    "apps/billing/views.py:invoice_refund_retry": ("billing_staff_api_required",),
    "apps/promotions/gift_staff_views.py:_request_refund via gift_card_action": ("can_manage_financial_data",),
    "apps/promotions/gift_staff_views.py:_existing_refund_action via gift_card_action": ("can_manage_financial_data",),
    "apps/promotions/tasks.py:reconcile_gift_refunds": (SYSTEM_TASK,),
}

# Canary: the newest entry point. A scan that drifts off it (wrong root, helper resolution
# broken, guards no longer read) fails here instead of passing vacuously.
NEWEST_KNOWN_ENTRY_POINT = "apps/promotions/gift_staff_views.py:_existing_refund_action via gift_card_action"

# A financial gate. Bare staff decorators admit `support` and plain `is_staff`, so on their own
# they are not authority to move money (#104 [M11]); with one of these present they are fine.
FINANCIAL_GATES = frozenset({"billing_staff_api_required", "billing_staff_required", "can_manage_financial_data"})

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True)
class RefundCallSite:
    identifier: str
    line_number: int
    decorators: tuple[str, ...]
    gate_tokens: frozenset[str]
    passes_actor: bool


def _iter_production_python_files() -> list[Path]:
    files = []
    for path in SCAN_ROOT.rglob("*.py"):
        relative = path.relative_to(PLATFORM_ROOT)
        if "tests" in relative.parts or path.name.startswith("test_") or "migrations" in relative.parts:
            continue
        if relative.as_posix() in PRIMITIVE_MODULES:
            continue
        files.append(path)
    return files


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return "<unknown>"


def _own_nodes(func: FunctionNode) -> list[ast.AST]:
    """Nodes in a function's own body, not in functions or classes nested inside it."""
    found: list[ast.AST] = []
    pending: list[ast.AST] = list(func.body)
    while pending:
        node = pending.pop()
        found.append(node)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda):
            continue
        pending.extend(ast.iter_child_nodes(node))
    return found


def _is_refund_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in REFUND_SERVICE_METHODS:
        return isinstance(func.value, ast.Name) and func.value.id == "RefundService"
    return isinstance(func, ast.Name) and func.id in REFUND_PRIMITIVES


def _refund_calls(func: FunctionNode) -> list[ast.Call]:
    return [node for node in _own_nodes(func) if isinstance(node, ast.Call) and _is_refund_call(node)]


def _raises(statements: list[ast.stmt]) -> bool:
    return any(isinstance(node, ast.Raise) for statement in statements for node in ast.walk(statement))


def _gate_tokens(func: FunctionNode) -> frozenset[str]:
    """The guards a function actually applies, never words that merely appear in it.

    A guard is a decorator, a function it calls, or an attribute or ``getattr`` string tested by
    an ``if`` whose branch raises - `gift_card_action` writes
    ``if not getattr(request.user, "can_manage_financial_data", False): raise PermissionDenied``.
    Strings in log calls, docstrings and attribute reads that decide nothing do not count.
    """
    tokens: set[str] = {_decorator_name(d) for d in func.decorator_list}
    for node in _own_nodes(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name | ast.Attribute):
            name = _decorator_name(node.func)
            if name != "getattr":
                tokens.add(name)
        if isinstance(node, ast.If) and _raises(node.body):
            for part in ast.walk(node.test):
                if isinstance(part, ast.Attribute):
                    tokens.add(part.attr)
                elif (
                    isinstance(part, ast.Call)
                    and isinstance(part.func, ast.Name)
                    and part.func.id == "getattr"
                    and len(part.args) >= 2
                    and isinstance(part.args[1], ast.Constant)
                    and isinstance(part.args[1].value, str)
                ):
                    tokens.add(part.args[1].value)
    return frozenset(tokens)


def _system_task_tokens(relative: str, func: FunctionNode) -> frozenset[str]:
    parameters = {arg.arg for arg in func.args.args + func.args.kwonlyargs}
    return frozenset({SYSTEM_TASK}) if relative.endswith("/tasks.py") and "request" not in parameters else frozenset()


def _passes_actor(calls: list[ast.Call]) -> bool:
    """Every refund call names an actor, and not the constant ``None``."""

    def named(call: ast.Call) -> bool:
        return any(
            keyword.arg == "actor" and not (isinstance(keyword.value, ast.Constant) and keyword.value.value is None)
            for keyword in call.keywords
        )

    return all(
        named(call)
        for call in calls
        if not (isinstance(call.func, ast.Name) and call.func.id in RESUMING_PRIMITIVES)
    )


def _functions(tree: ast.Module) -> list[FunctionNode]:
    return [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)]


def _calls_name(func: FunctionNode, name: str) -> bool:
    return any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name | ast.Attribute) and _decorator_name(node.func) == name
        for node in _own_nodes(func)
    )


def _references_elsewhere(name: str, home: Path) -> bool:
    """Whether any other production module names this private helper (an import or a call)."""
    for path in SCAN_ROOT.rglob("*.py"):
        relative = path.relative_to(PLATFORM_ROOT)
        if path == home or "tests" in relative.parts or "migrations" in relative.parts:
            continue
        source = path.read_text(encoding="utf-8")
        if name in source and re.search(rf"\b{re.escape(name)}\b", source):
            return True
    return False


def _entry_callers(tree: ast.Module, helper: FunctionNode, depth: int = 0) -> list[FunctionNode | None]:
    """The public functions that reach a private helper, following private helpers transitively.

    ``None`` stands for "no caller found": an unreachable or externally called helper fails closed.
    """
    callers = [fn for fn in _functions(tree) if fn is not helper and _calls_name(fn, helper.name)]
    if not callers or depth > 5:
        return [None]
    resolved: list[FunctionNode | None] = []
    for caller in callers:
        if caller.name.startswith("_"):
            resolved.extend(_entry_callers(tree, caller, depth + 1))
        else:
            resolved.append(caller)
    return resolved


def _find_refund_call_sites() -> list[RefundCallSite]:
    sites: list[RefundCallSite] = []
    for path in _iter_production_python_files():
        source = path.read_text(encoding="utf-8")
        if not any(word in source for word in ("RefundService", *REFUND_PRIMITIVES)):
            continue
        tree = ast.parse(source, filename=str(path))
        relative = path.relative_to(PLATFORM_ROOT).as_posix()
        for node in _functions(tree):
            calls = _refund_calls(node)
            if not calls:
                continue
            passes_actor = _passes_actor(calls)
            if not node.name.startswith("_"):
                sites.append(
                    RefundCallSite(
                        identifier=f"{relative}:{node.name}",
                        line_number=calls[0].lineno,
                        decorators=tuple(_decorator_name(d) for d in node.decorator_list),
                        gate_tokens=_gate_tokens(node) | _system_task_tokens(relative, node),
                        passes_actor=passes_actor,
                    )
                )
                continue
            if _references_elsewhere(node.name, path):
                sites.append(RefundCallSite(f"{relative}:{node.name} via <another module>", calls[0].lineno, (),
                                            frozenset(), passes_actor))
                continue
            for caller in _entry_callers(tree, node):
                if caller is None:
                    sites.append(RefundCallSite(f"{relative}:{node.name} via <no caller>", calls[0].lineno, (),
                                                frozenset(), passes_actor))
                    continue
                sites.append(
                    RefundCallSite(
                        identifier=f"{relative}:{node.name} via {caller.name}",
                        line_number=calls[0].lineno,
                        decorators=tuple(_decorator_name(d) for d in caller.decorator_list),
                        gate_tokens=_gate_tokens(caller),
                        passes_actor=passes_actor,
                    )
                )
    return sites


class RefundAuthorizationGuardrailTests(SimpleTestCase):
    """Every refund entry point is known, and gated by its declared mechanism."""

    def test_refund_entry_points_are_complete_and_classified(self) -> None:
        sites = _find_refund_call_sites()
        identifiers = {site.identifier for site in sites}

        # Structural-Helper Integrity: exact count plus newest-site canary, so a scan that
        # silently matches nothing (or drifts off the newest site) fails loudly.
        self.assertEqual(len(sites), len(EXPECTED_REFUND_ENTRY_POINTS))
        self.assertEqual(identifiers, set(EXPECTED_REFUND_ENTRY_POINTS))
        self.assertIn(NEWEST_KNOWN_ENTRY_POINT, identifiers)

        unguarded = [
            site.identifier
            for site in sites
            if not set(EXPECTED_REFUND_ENTRY_POINTS[site.identifier]) <= site.gate_tokens
        ]
        self.assertEqual(
            unguarded,
            [],
            msg=(
                "A refund entry point lost its authorization mechanism. Refunds are a financial "
                "operation (ADR-0024): they require admin/billing/manager staff. There is no "
                "customer or portal refund path. See #104 [M11]."
            ),
        )

    def test_no_refund_entry_point_relies_on_a_bare_staff_predicate(self) -> None:
        """``staff_required``/``staff_required_strict`` both reduce to ``is_staff_user``.

        That predicate admits ``support`` and bare ``is_staff`` accounts, which is exactly
        how the original defect shipped. It may sit on a refund path only together with a
        financial gate (the gift-card action adds an explicit ``can_manage_financial_data``).
        """
        bare_staff_decorators = {"staff_required", "staff_required_strict", "staff_member_required"}
        offenders = [
            f"{site.identifier} -> @{decorator}"
            for site in _find_refund_call_sites()
            for decorator in site.decorators
            if decorator in bare_staff_decorators and not (FINANCIAL_GATES & site.gate_tokens)
        ]
        self.assertEqual(offenders, [], msg="A refund is gated by a bare is_staff_user predicate (#104 [M11]).")


class RefundProvenanceGuardrailTests(SimpleTestCase):
    """Every refund a human initiates must name that human on the row.

    ``Refund.created_by`` was NULL on every path for the repository's entire history because
    the service read an undeclared key. The actor now travels as an explicit ``actor=``
    argument rather than inside ``refund_data`` — on the API path that dict is built from the
    request body, and an audit field must not be readable from caller-shaped data.

    This is enforced structurally rather than by a runtime check. A service-side "reject a
    refund with no actor" guard would put an audit field in a position to fail a money
    operation; asserting it at the call sites costs nothing at runtime and cannot.
    """

    def test_every_view_entry_point_passes_an_actor(self) -> None:
        offenders = [site.identifier for site in _find_refund_call_sites() if not site.passes_actor]
        self.assertEqual(
            offenders,
            [],
            msg=(
                "A refund entry point starts a refund without naming who issued it. That is "
                "how created_by stayed NULL since the first architecture commit."
            ),
        )
