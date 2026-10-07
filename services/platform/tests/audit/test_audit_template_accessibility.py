"""Regression checks for the WP16 audit template bucket."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from typing import Protocol, cast
from unittest.mock import patch

from django.template import Context, Template
from django.test import SimpleTestCase
from django.utils.translation import override

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


class AuditTemplateBucketTests(SimpleTestCase):
    def test_controls_have_accessible_names(self) -> None:
        paths = (
            "audit/alerts_dashboard.html",
            "audit/gdpr_dashboard.html",
            "audit/gdpr_management_dashboard.html",
            "audit/logs.html",
            "audit/partials/gdpr_export_detail.html",
            "audit/review_queue.html",
        )
        findings = _findings("audit_accessibility", paths, frozenset({"critical", "serious"}))
        self.assertEqual(findings, [])

    def test_styles_have_no_dark_mode_findings(self) -> None:
        paths = (
            "audit/alerts_dashboard.html",
            "audit/integrity_dashboard.html",
            "audit/partials/search_suggestions.html",
            "audit/retention_dashboard.html",
        )
        findings = _findings("audit_dark_mode", paths, frozenset({"blocker", "warning"}))
        self.assertEqual(findings, [])

    def test_rendered_date_range_inputs_have_accessible_names(self) -> None:
        source = (TEMPLATE_ROOT / "audit" / "logs.html").read_text(encoding="utf-8")
        includes = re.findall(r"\{% include 'components/input\.html' with [^\n]+ %\}", source)
        dates = [tag for tag in includes if "name='start_date'" in tag or "name='end_date'" in tag]
        self.assertEqual(len(dates), 2)
        with override("en"):
            rendered = Template("{% load i18n %}" + "\n".join(dates)).render(Context())
        self.assertIn('aria-label="Start date"', rendered)
        self.assertIn('aria-label="End date"', rendered)
        # The component reads input_type; passing type= silently rendered plain text inputs.
        self.assertEqual(rendered.count('type="date"'), 2)
