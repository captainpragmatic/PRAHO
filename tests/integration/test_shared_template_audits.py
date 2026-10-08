"""Default template gates must include the canonical shared UI templates."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Protocol, cast

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[2]


class _Finding(Protocol):
    code: str
    severity: str


class _Audit(Protocol):
    def discover_templates(self, paths: list[str] | None = None) -> list[Path]: ...

    def check_file(self, path: Path, *, verbose: bool = False) -> list[_Finding]: ...


def _load_audit(name: str) -> _Audit:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return cast("_Audit", module)


class SharedTemplateAuditTests(SimpleTestCase):
    def test_default_gates_discover_shared_ui_without_widening_explicit_paths(self) -> None:
        shared = set((ROOT / "shared/ui/templates").rglob("*.html"))
        self.assertIn(ROOT / "shared/ui/templates/components/card.html", shared)
        for name in ("audit_accessibility", "audit_dark_mode"):
            with self.subTest(audit=name):
                audit = _load_audit(name)
                discovered = audit.discover_templates()
                self.assertEqual(shared & set(discovered), shared)
                self.assertEqual(discovered, sorted(set(discovered)))
                explicit = "services/portal/templates/tickets/ticket_create.html"
                self.assertEqual(audit.discover_templates([explicit]), [ROOT / explicit])

    def test_shared_card_has_no_dark_mode_blockers(self) -> None:
        audit = _load_audit("audit_dark_mode")
        findings = audit.check_file(ROOT / "shared/ui/templates/components/card.html")
        self.assertEqual([finding.code for finding in findings if finding.severity == "blocker"], [])
