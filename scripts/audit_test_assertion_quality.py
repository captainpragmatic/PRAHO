#!/usr/bin/env python3
"""Find tests that request a page and assert only that it returned 200.

The Phase-4 analogue of the settings effect check (`lint_settings_coverage.py` check 5). Its evidence
comes from this repo: `reports.html` returned 200 while rendering none of four computed aggregates,
and `vat_report.html` returned 200 with two dead context keys and a 100x VAT error. A status-only
assertion passes all three, so such a test raises the coverage number without verifying anything.

What is NOT flagged, deliberately, because the distinction is the whole value of the check:

* A test asserting 4xx or 3xx. For access control, a redirect, or a refusal, the status code IS the
  behaviour under test - 253 of the 369 status-only tests in this repo are that kind, and treating
  them as defects would make the check noise.
* A test that asserts a database side effect, a template name, a JSON body, a mock's calls, or
  anything else that reads behaviour beyond the response code.
* A test whose assertions live in a helper it calls. One level of indirection is resolved, because a
  detector narrower than the style people write in under-reports forever.
* A 200 that IS the behaviour: a test whose only distinguishing act is authenticating. If the test
  sets credentials or logs in and then requests a page, its 200 proves that authentication or
  permission SUCCEEDS - as real an assertion as the matching refusal.
  `test_bearer_scheme_authenticates` beside `test_invalid_token_returns_401` is the shape.

  A test that ALSO sets up domain state, or sends a payload or query, is a different matter: it
  established a condition the page is supposed to reflect and then asserted nothing about it.
  `test_gdpr_dashboard_with_consent_date` sets `gdpr_consent_date`, renders, and checks only 200 -
  delete the date from the template and it still passes.

  Getting this boundary right took three attempts, which is worth recording. Flagging every
  status-only test gave 118 findings and was wrong: 94 were mock assertions or authentication
  results. Exempting any class that asserts a refusal ANYWHERE gave 24 and was also wrong, in the
  other direction - one login-redirect sibling exonerated every vacuous 200 in the class. The
  discriminating question is per-test: did this test vary something the response should show?

  The residual, stated rather than left to be found: a test that only logs in and renders a page is
  exempt, and `test_renders_empty` - which asserts nothing about the empty state it is named for - is
  structurally identical to `test_bearer_scheme_authenticates`. Only the name separates them, and a
  name is not a contract. So this check finds status-only tests that had a reason to assert more; it
  does not find every page whose rendering is unverified. That gap belongs to the route sweep.

Usage:
  python scripts/audit_test_assertion_quality.py                     # ratchet against the baseline
  python scripts/audit_test_assertion_quality.py --list              # print every finding
  python scripts/audit_test_assertion_quality.py --baseline FILE
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEST_DIRS = (
    PROJECT_ROOT / "services" / "platform" / "tests",
    PROJECT_ROOT / "services" / "portal" / "tests",
)
DEFAULT_BASELINE = PROJECT_ROOT / "scripts" / "status_only_test_baseline.txt"

REQUEST_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head"})

# Assertions that read something other than the status code, when their arguments say so.
CONTENT_ASSERTIONS = frozenset(
    {
        "assertContains",
        "assertNotContains",
        "assertInHTML",
        "assertTemplateUsed",
        "assertTemplateNotUsed",
        "assertJSONEqual",
        "assertIn",
        "assertNotIn",
        "assertEqual",
        "assertNotEqual",
        "assertQuerySetEqual",
        "assertQuerysetEqual",
        "assertTrue",
        "assertFalse",
        "assertIsNotNone",
        "assertIsNone",
        "assertGreater",
        "assertGreaterEqual",
        "assertLess",
        "assertLessEqual",
        "assertCountEqual",
        "assertListEqual",
        "assertDictEqual",
        "assertRegex",
        "assertAlmostEqual",
        "assertIsInstance",
        "assertNumQueries",
        "assertFormError",
    }
)
# A mock's call record is behaviour: `converge.assert_called_once_with(...)` pins what the view did
# far more tightly than any string in the rendered page.
MOCK_ASSERTIONS = frozenset(
    {
        "assert_called",
        "assert_called_once",
        "assert_called_with",
        "assert_called_once_with",
        "assert_any_call",
        "assert_has_calls",
        "assert_not_called",
        "assert_awaited",
    }
)
REDIRECT_ASSERTIONS = frozenset({"assertRedirects", "assertURLEqual"})

SUCCESS_CODES = frozenset({"200", "201", "204"})


def _called_attrs(node: ast.AST) -> set[str]:
    return {
        call.func.attr for call in ast.walk(node) if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
    }


def _issues_request(node: ast.AST) -> bool:
    """`self.client.get(...)` and friends, including `self.staff_client.post(...)`."""
    for call in ast.walk(node):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
            continue
        if call.func.attr not in REQUEST_METHODS:
            continue
        receiver = call.func.value
        if isinstance(receiver, ast.Attribute) and "client" in receiver.attr:
            return True
        if isinstance(receiver, ast.Name) and "client" in receiver.id:
            return True
    return False


def _reads_beyond_status(node: ast.AST) -> bool:
    """An assertion that reads something other than `status_code`."""
    for call in ast.walk(node):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
            continue
        if call.func.attr in MOCK_ASSERTIONS:
            return True
        if call.func.attr not in CONTENT_ASSERTIONS:
            continue
        rendered = " ".join(ast.dump(arg) for arg in call.args)
        if "status_code" not in rendered:
            return True
    return False


# Calls that establish domain state the page is then expected to reflect.
#
# User-creating helpers are deliberately NOT here. Creating the user a test then authenticates as is
# the identity act, not state the page should show, and conflating the two flagged
# `test_maintenance_gate.py::test_staff_still_pass_through` - a test whose 200 proves the maintenance
# middleware's staff bypass works, and which would be 503 if that bypass broke. They are handled by
# `_user_creation_is_all_identity` instead, which asks the discriminating question: was this user
# handed to a login call, or left as a subject the page is supposed to display?
_DOMAIN_STATE = re.compile(
    r"\.objects\.(?:create|bulk_create|get_or_create|update)\(|\.save\(|Factory\(|"
    r"\bcreate_(?:full_)?(?:customer|invoice|order|ticket)\("
)
_IDENTITY_FACTORY = re.compile(r"^create_(?:full_)?(?:user|staff_user|admin_user)$")
_LOGIN_METHODS = frozenset({"force_login", "login"})


def _factory_call_name(call: ast.Call) -> str | None:
    """The called name, when it is one of the user-creating helpers."""
    func = call.func
    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
    return name if isinstance(name, str) and _IDENTITY_FACTORY.match(name) else None


def _binding_key(target: ast.expr) -> str | None:
    """A stable key for an assignment target this module can trace.

    `x` for a bare name, and the final attribute for `self.x` - a receiver-qualified attribute is
    how almost every Django test in this repo binds a fixture (`self.staff = create_staff_user(...)`
    in `setUp`, or inline in the test itself). Anything else - subscripts, tuple unpacking - is left
    untracked, which is the conservative direction: an untracked binding cannot be credited as
    identity, so it falls back to being treated as domain state rather than silently exempted.
    """
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _referenced_keys(expr: ast.expr) -> set[str]:
    """Every name this expression touches, by the same key `_binding_key` would produce for it.

    `client.login(username=staff.username, password=...)` is exactly as much an identity act as
    `client.force_login(staff)` - Django's `login()` takes credential VALUES, not the user object,
    so the only way to connect `staff.username` back to `staff = create_staff_user(...)` is to walk
    into the attribute access rather than requiring the argument to be a bare name.
    """
    keys: set[str] = set()
    for node in ast.walk(expr):
        if isinstance(node, ast.Name):
            keys.add(node.id)
        elif isinstance(node, ast.Attribute):
            keys.add(node.attr)
    return keys


def _user_creation_is_all_identity(fn: ast.FunctionDef) -> bool:
    """True when every user this test creates is one it logs in as.

    All of these are written in this repo and mean the same thing:

        self.client.force_login(create_admin_user(username="x"))
        staff = create_staff_user(username="x"); self.client.force_login(staff)
        self.staff = create_staff_user(username="x"); self.client.force_login(self.staff)
        staff: User = create_staff_user(username="x"); self.client.force_login(staff)
        staff = create_staff_user(username="x"); self.client.login(username=staff.username, password="x")

    A user created and never authenticated as is different: it is a row the page is expected to
    display, so asserting only the status leaves the display unchecked.

    Reused names are resolved by line number, not by name alone: `user = create_staff_user(...)`,
    `force_login(user)`, then `user = create_user(...)` for an unrelated subject must credit only
    the FIRST creation (the one that reached the login call), not both - crediting both would let a
    genuinely new, unauthenticated-as subject hide behind a name that already earned its exemption.
    """
    bindings: dict[str, list[tuple[int, ast.Call]]] = {}
    for node in ast.walk(fn):
        target: ast.expr | None = None
        value: ast.expr | None = None
        lineno = 0
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value, lineno = node.targets[0], node.value, node.lineno
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value, lineno = node.target, node.value, node.lineno
        if target is None or value is None or not isinstance(value, ast.Call):
            continue
        key = _binding_key(target)
        if key is None or not _factory_call_name(value):
            continue
        bindings.setdefault(key, []).append((lineno, value))

    consumed: set[int] = set()
    for call in ast.walk(fn):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
            continue
        if call.func.attr not in _LOGIN_METHODS:
            continue
        for arg in (*call.args, *(kw.value for kw in call.keywords)):
            # Directly nested: `force_login(create_admin_user(...))` - the creation IS the argument.
            for node in ast.walk(arg):
                if isinstance(node, ast.Call) and _factory_call_name(node):
                    consumed.add(id(node))
            # Bound earlier: resolve each referenced key to its most recent assignment AT OR BEFORE
            # this call's line - the reaching definition, not every assignment ever made to that name.
            for key in _referenced_keys(arg):
                reaching = [pair for pair in bindings.get(key, []) if pair[0] <= call.lineno]
                if reaching:
                    consumed.add(id(max(reaching, key=lambda pair: pair[0])[1]))

    creations = [call for call in ast.walk(fn) if isinstance(call, ast.Call) and _factory_call_name(call)]
    return all(id(call) in consumed for call in creations)


def _varies_only_identity(source_lines: list[str], fn: ast.FunctionDef) -> bool:
    """True when the test's only distinguishing act is authenticating.

    Such a test's 200 is the authorisation result, not a placeholder for a missing assertion. A test
    that seeds domain state, or sends a payload or query string, has set up something the response is
    supposed to show - and asserting only the status leaves that unchecked.
    """
    body = "\n".join(source_lines[fn.lineno - 1 : (fn.end_lineno or fn.lineno)])
    if _DOMAIN_STATE.search(body):
        return False
    if not _user_creation_is_all_identity(fn):
        return False
    for call in ast.walk(fn):
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
            continue
        if call.func.attr not in REQUEST_METHODS:
            continue
        if len(call.args) > 1 or any(kw.arg == "data" for kw in call.keywords):
            return False
        first = call.args[0] if call.args else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str) and "?" in first.value:
            return False
        if isinstance(first, ast.JoinedStr | ast.BinOp):
            return False
    return True


def _helper_bodies(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("test")
    }


def _asserted_status_codes(source_lines: list[str], fn: ast.FunctionDef) -> set[str]:
    body = "\n".join(source_lines[fn.lineno - 1 : (fn.end_lineno or fn.lineno)])
    codes = set(re.findall(r"status_code,?\s*(?:==\s*)?(\d{3})", body))
    codes |= set(re.findall(r"status_code\s*,\s*(\d{3})", body))
    return codes


def scan_file(path: Path) -> list[str]:
    """`relative/path.py::test_name` for each test that asserts only a successful status."""
    source = path.read_text(errors="ignore")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    helpers = _helper_bodies(tree)
    findings: list[str] = []

    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef) or not fn.name.startswith("test"):
            continue
        if not _issues_request(fn):
            continue

        codes = _asserted_status_codes(lines, fn)
        touches_status = bool(codes) or bool(_called_attrs(fn) & REDIRECT_ASSERTIONS)
        if not touches_status:
            continue
        # A 4xx/3xx assertion is the behaviour, not a placeholder for one.
        if not codes or not codes <= SUCCESS_CODES:
            continue
        if _reads_beyond_status(fn):
            continue
        # One level of indirection: the assertions may live in a helper this test calls.
        if any(name in helpers and _reads_beyond_status(helpers[name]) for name in _called_attrs(fn)):
            continue
        if _varies_only_identity(lines, fn):
            continue
        findings.append(f"{path.relative_to(PROJECT_ROOT)}::{fn.name}")

    return findings


def scan_all() -> list[str]:
    findings: list[str] = []
    for directory in TEST_DIRS:
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("test_*.py")):
            findings.extend(scan_file(path))
    return sorted(findings)


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip() for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--list", action="store_true", help="print every finding, baselined or not")
    parser.add_argument("--write-baseline", action="store_true", help="record the current set")
    args = parser.parse_args()

    findings = scan_all()
    baseline = load_baseline(args.baseline)

    if args.write_baseline:
        header = (
            "# Tests that request a page and assert only that it returned 200.\n"
            "#\n"
            "# Such a test raises the coverage number without verifying anything: the page could\n"
            "# render none of what it computes and still pass. Two real examples from this repo -\n"
            "# `reports.html` returning 200 with none of four aggregates rendered, and `vat_report.html`\n"
            "# returning 200 with a 100x VAT error - were both invisible to status-only tests.\n"
            "#\n"
            "# Tests asserting 4xx or 3xx are NOT listed: for access control and redirects the status\n"
            "# code is the behaviour under test.\n"
            "#\n"
            "# A ratchet in both directions. A NEW status-only test fails this check; a listed one that\n"
            "# grows a real assertion fails until it is removed from the list.\n"
            "#\n"
            "# Fixing one means asserting a value the view computed - the figure on the page, the\n"
            "# template chosen, the row written - not adding `assertContains(response, '<html')`.\n"
            f"# Recorded {len(findings)} entries.\n"
        )
        args.baseline.write_text(header + "\n".join(findings) + "\n")
        print(f"baseline written: {len(findings)} entries")
        return 0

    if args.list:
        for finding in findings:
            print(("  " if finding in baseline else "NEW ") + finding)

    new = [f for f in findings if f not in baseline]
    fixed = sorted(baseline - set(findings))

    for finding in new:
        path, _, name = finding.partition("::")
        print(f"❌ [MEDIUM] {path} — {name} asserts only that the page returned 200.")
        print("           Assert a value the view computed, or the template it chose.")
    for finding in fixed:
        print(f"ℹ️  [LOW] {finding} now asserts more than a status. Remove it from the baseline.")

    print(f"\n{len(findings)} status-only test(s); {len(new)} new, {len(fixed)} fixed but still listed.")
    if new or fixed:
        return 1
    print("✅ No new status-only tests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
