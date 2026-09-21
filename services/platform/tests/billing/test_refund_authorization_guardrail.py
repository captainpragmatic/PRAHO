"""#104 [M11]: every refund entry point is classified with its authorization mechanism.

The defect this pins down was a *count-of-one outlier*: ``invoice_refund`` was the only
view in ``apps/billing/views.py`` on ``@staff_required`` while 19 siblings used
``@billing_staff_required``, and its twin ``orders.views.order_refund`` carried the same
effective predicate under a third decorator name. Nothing failed; the wrong role simply got
through.

The invariant is deliberately narrow. "Every money-moving view carries a staff decorator"
would be false — customer payment endpoints and verified gateway webhooks move money
legitimately without one. Instead this enumerates the direct callers of ``RefundService``
and asserts each is gated by the mechanism it is supposed to be gated by. A new refund
entry point fails this test until it is classified here, which is the point.

Structure follows ``tests/users/test_staff_account_creation_guardrail.py``: AST over
production sources, a frozen record per site, and an exact expected set.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from django.test import SimpleTestCase

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOT = PLATFORM_ROOT / "apps"

REFUND_METHODS = frozenset({"refund_invoice", "refund_order"})

# The complete inventory of direct RefundService callers, each mapped to the mechanism that
# authorizes it. `billing_staff_api_required` denies in JSON (these endpoints return
# JsonResponse to clients that parse unconditionally). The portal API endpoint is reached by
# an authenticated *customer* over HMAC, so its gate is an in-view membership-role check.
EXPECTED_REFUND_ENTRY_POINTS: dict[str, str] = {
    "apps/billing/views.py:invoice_refund": "billing_staff_api_required",
    "apps/orders/views.py:order_refund": "billing_staff_api_required",
    "apps/billing/views.py:api_process_refund": "_resolve_authorized_refund_actor",
}

# Canary: the most recently classified entry point. A scan that drifts off it is broken.
NEWEST_KNOWN_ENTRY_POINT = "apps/billing/views.py:api_process_refund"


@dataclass(frozen=True)
class RefundCallSite:
    identifier: str
    line_number: int
    decorators: tuple[str, ...]
    body_names: frozenset[str]


def _iter_production_python_files() -> list[Path]:
    files = []
    for path in SCAN_ROOT.rglob("*.py"):
        relative = path.relative_to(PLATFORM_ROOT)
        if "tests" in relative.parts or path.name.startswith("test_") or "migrations" in relative.parts:
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


def _calls_refund_service(func: ast.FunctionDef | ast.AsyncFunctionDef) -> int | None:
    """Return the line of a direct ``RefundService.refund_*`` call, else None."""
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in REFUND_METHODS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "RefundService"
        ):
            return node.lineno
    return None


def _find_refund_call_sites() -> list[RefundCallSite]:
    sites: list[RefundCallSite] = []
    for path in _iter_production_python_files():
        source = path.read_text(encoding="utf-8")
        if "RefundService" not in source:
            continue
        tree = ast.parse(source, filename=str(path))
        relative = path.relative_to(PLATFORM_ROOT).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            line = _calls_refund_service(node)
            if line is None:
                continue
            sites.append(
                RefundCallSite(
                    identifier=f"{relative}:{node.name}",
                    line_number=line,
                    decorators=tuple(_decorator_name(d) for d in node.decorator_list),
                    body_names=frozenset(n.id for n in ast.walk(node) if isinstance(n, ast.Name)),
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
            if EXPECTED_REFUND_ENTRY_POINTS[site.identifier] not in set(site.decorators) | site.body_names
        ]
        self.assertEqual(
            unguarded,
            [],
            msg=(
                "A refund entry point lost its authorization mechanism. Refunds are a financial "
                "operation (ADR-0024): they require admin/billing/manager staff, or an "
                "owner/billing customer principal on the portal API. See #104 [M11]."
            ),
        )

    def test_no_refund_entry_point_relies_on_a_bare_staff_predicate(self) -> None:
        """``staff_required``/``staff_required_strict`` both reduce to ``is_staff_user``.

        That predicate admits ``support`` and bare ``is_staff`` accounts, which is exactly
        how the original defect shipped. Neither may guard a refund again.
        """
        bare_staff_decorators = {"staff_required", "staff_required_strict", "staff_member_required"}
        offenders = [
            f"{site.identifier} -> @{decorator}"
            for site in _find_refund_call_sites()
            for decorator in site.decorators
            if decorator in bare_staff_decorators
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
        offenders = [
            site.identifier
            for site in _find_refund_call_sites()
            if not _passes_actor(site)
        ]
        self.assertEqual(
            offenders,
            [],
            msg=(
                "A refund entry point calls RefundService without naming who issued it. That is "
                "how created_by stayed NULL since the first architecture commit."
            ),
        )


def _passes_actor(site: RefundCallSite) -> bool:
    """Whether this site's ``RefundService.refund_*`` call carries an ``actor=`` keyword."""
    path = PLATFORM_ROOT / site.identifier.split(":")[0]
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    target = site.identifier.split(":")[1]
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) or node.name != target:
            continue
        for call in ast.walk(node):
            if (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr in REFUND_METHODS
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "RefundService"
            ):
                return any(kw.arg == "actor" for kw in call.keywords)
    return False
