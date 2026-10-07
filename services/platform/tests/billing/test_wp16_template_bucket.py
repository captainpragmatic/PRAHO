"""Regression checks for the WP16 billing template bucket."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Protocol, cast
from unittest.mock import patch

from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]
TEMPLATE_ROOT = REPO_ROOT / "services" / "platform" / "templates"


class _Finding(Protocol):
    code: str
    severity: str
    line: int


class _Audit(Protocol):
    def check_file(self, path: Path) -> list[_Finding]: ...


def _findings(script: str, paths: tuple[str, ...], severities: frozenset[str]) -> list[tuple[str, str, int]]:
    spec = importlib.util.spec_from_file_location(f"_wp16_{script}", REPO_ROOT / "scripts" / f"{script}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    findings: list[tuple[str, str, int]] = []
    with patch.dict(sys.modules, {spec.name: module}):
        spec.loader.exec_module(module)
        audit = cast(_Audit, module)
        for relative in paths:
            path = TEMPLATE_ROOT / relative
            if not path.is_file():
                raise AssertionError(f"Missing bucket template: {relative}")
            findings.extend(
                (relative, finding.code, finding.line)
                for finding in audit.check_file(path)
                if finding.severity in severities
            )
    return findings


class BillingTemplateBucketTests(SimpleTestCase):
    def test_controls_have_accessible_names(self) -> None:
        paths = (
            "billing/billing_list.html",
            "billing/efactura_dashboard.html",
            "billing/invoice_form.html",
            "billing/proforma_form.html",
        )
        findings = _findings("audit_accessibility", paths, frozenset({"critical", "serious"}))
        self.assertEqual(findings, [])

    def test_styles_have_no_dark_mode_findings(self) -> None:
        paths = ("billing/invoice_detail.html",)
        findings = _findings("audit_dark_mode", paths, frozenset({"blocker", "warning"}))
        self.assertEqual(findings, [])
