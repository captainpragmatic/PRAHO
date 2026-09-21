"""Financial code may not acquire a new type-ignore comment without someone deciding to.

Two defects in this PR had the same root cause, and it was not a wrong key — it was a
*suppression*:

* ``refund_service.py`` read ``refund_data["initiated_by"]``, a key ``RefundData`` does not
  declare, so every refund recorded ``created_by = NULL``. mypy diagnosed it precisely; a
  2026-02-27 "comprehensive type safety cleanup" added ``# type: ignore[misc]`` instead of
  fixing it, turning a detectable bug into a permanent one.
* ``efactura/audit.py`` passed ``metadata=`` to ``BusinessEventData`` and ``severity=`` to
  ``AuditContext`` — neither dataclass declares those. Nine ``# type: ignore[call-arg]``
  comments suppressed the diagnostic while the constructor raised ``TypeError`` into a
  surrounding ``except Exception``, so the audit event was never written at all.

An undeclared-key AST scan would have caught the first and missed the second, and duplicates
what mypy already does. Guarding the suppression catches both, and the next one.

Note the repo's own `prevent-type-ignore` pre-commit hook is a substring scanner and so
cannot tell a suppression from prose about one — the reason this test reads real comment
tokens instead, and the reason the wording above avoids the literal phrase.

The inventory is deliberately a chore to update: a new suppression in billing code must be
added here, which is the point at which someone asks whether it should be fixed instead.
"""

from __future__ import annotations

import io
import tokenize
from pathlib import Path

from django.test import SimpleTestCase

PLATFORM_ROOT = Path(__file__).resolve().parents[2]
BILLING_ROOT = PLATFORM_ROOT / "apps" / "billing"

# Frozen inventory of accepted suppressions, by path relative to `apps/`. Counted from real
# comment tokens, never a substring scan: a type-ignore written inside a docstring is
# prose, not a suppression, and one such line already exists elsewhere in this codebase
# (`customers/customer_models.py`) waiting to inflate a naive grep.
EXPECTED_SUPPRESSIONS: dict[str, int] = {
    "billing/efactura/settings.py": 1,
    "billing/efactura/tasks.py": 5,
    "billing/efactura/working_days.py": 1,
    "billing/efactura/xml_builder.py": 3,
    "billing/gateways/stripe_gateway.py": 1,
    "billing/metering_service.py": 1,
    "billing/metering_tasks.py": 2,
    "billing/refund_service.py": 2,
    "billing/tax_models.py": 1,
    "billing/views.py": 6,
}

# Canary: the most recently added suppression, on the actor-id coercion in the refund API
# gate (#104). A scan that drifts off it — wrong root, wrong file filter, silently matching
# nothing — fails here rather than passing vacuously.
NEWEST_KNOWN_SUPPRESSION = ("billing/views.py", "call-overload")


def _iter_production_sources() -> list[Path]:
    return [
        path
        for path in sorted(BILLING_ROOT.rglob("*.py"))
        if "migrations" not in path.relative_to(PLATFORM_ROOT).parts
        and "tests" not in path.relative_to(PLATFORM_ROOT).parts
    ]


def _suppressions(path: Path) -> list[str]:
    """Real type-ignore comment tokens in a file, in source order."""
    source = path.read_text(encoding="utf-8")
    return [
        token.string
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT and "type: ignore" in token.string
    ]


class BillingTypeSuppressionInventoryTests(SimpleTestCase):
    """Every type-checker suppression in billing code is registered and counted."""

    def test_the_suppression_inventory_is_exactly_as_registered(self) -> None:
        found = {
            str(path.relative_to(PLATFORM_ROOT / "apps")): len(hits)
            for path in _iter_production_sources()
            if (hits := _suppressions(path))
        }

        self.assertEqual(
            found,
            EXPECTED_SUPPRESSIONS,
            msg=(
                "A billing module gained or lost a type-ignore comment. If you added one, ask "
                "whether the error it hides is real — that is exactly how `Refund.created_by` "
                "stayed NULL for the repository's entire history. If it is genuinely a stub gap, "
                "register it here."
            ),
        )

    def test_the_scan_found_the_newest_known_suppression(self) -> None:
        """Structural-Helper Integrity: a scan matching nothing must fail, not pass."""
        relative_path, error_code = NEWEST_KNOWN_SUPPRESSION
        comments = _suppressions(PLATFORM_ROOT / "apps" / relative_path)

        self.assertTrue(
            any(error_code in comment for comment in comments),
            msg=f"The scan no longer sees the known [{error_code}] suppression in {relative_path}.",
        )

    def test_the_refund_audit_fields_are_no_longer_suppressed(self) -> None:
        """The two lines this PR unsuppressed must stay unsuppressed.

        Reverting either fix would reintroduce the ignore, and the inventory counts above would
        move — but this states the specific contract, so the failure message names the defect
        rather than an arithmetic mismatch.
        """
        refund_service = (BILLING_ROOT / "refund_service.py").read_text(encoding="utf-8")
        self.assertIn("created_by=actor,", refund_service)
        self.assertNotIn("initiated_by", refund_service)

        efactura_audit = (BILLING_ROOT / "efactura" / "audit.py").read_text(encoding="utf-8")
        self.assertEqual(_suppressions(BILLING_ROOT / "efactura" / "audit.py"), [])
        self.assertNotIn("metadata={", efactura_audit.split("context=AuditContext(")[0])
