"""Regression checks for the WP16 billing template bucket."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Protocol, cast
from unittest.mock import patch

from django.template import Context, Template
from django.test import SimpleTestCase
from django.utils.translation import gettext, override

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


class _GeneratedControlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.controls: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"input", "select", "textarea"}:
            self.controls.append(dict(attrs))


class GeneratedProformaRowTests(SimpleTestCase):
    def test_added_rows_have_translated_accessible_names(self) -> None:
        source = (TEMPLATE_ROOT / "billing/proforma_form.html").read_text(encoding="utf-8")
        functions = re.findall(r"  function addLineItem\(\) \{.*?\n  \}", source, re.DOTALL)
        self.assertEqual(len(functions), 1, "Exercise the actual row-creation function")
        script = """
const vm = require("vm");
const rows = [];
const container = {
  insertAdjacentHTML: (_, html) => rows.push(html),
  lastElementChild: {
    querySelectorAll: () => [],
    querySelector: () => ({addEventListener: () => {}}),
  },
};
const context = {
  lineCounter: 1,
  currentCurrency: () => "EUR",
  calculateTotals: () => {},
  updateRemoveButtons: () => {},
  document: {getElementById: () => container},
};
vm.runInNewContext(process.argv[1], context);
context.addLineItem();
context.addLineItem();
process.stdout.write(JSON.stringify(rows));
"""
        labels = {
            "description": "Description",
            "domain_name": "Domain name",
            "quantity": "Quantity",
            "unit_price": "Unit Price",
            "vat_rate": "VAT Rate",
        }
        for language in ("en", "ro"):
            with self.subTest(language=language), override(language):
                function = Template("{% load i18n ui_components %}\n" + functions[0]).render(Context())
                result = subprocess.run(  # noqa: S603  # Fixed Node executable; rendered local function, no shell.
                    ["node", "-e", script, function],  # noqa: S607
                    check=True,
                    capture_output=True,
                    text=True,
                )
                rows = cast("list[str]", json.loads(result.stdout))
                self.assertEqual(len(rows), 2)
                for index, markup in enumerate(rows, start=1):
                    parser = _GeneratedControlParser()
                    parser.feed(markup)
                    self.assertEqual(len(parser.controls), 5)
                    expected = {f"line_{index}_{suffix}": gettext(label) for suffix, label in labels.items()}
                    self.assertEqual({control["name"] for control in parser.controls}, set(expected))
                    self.assertEqual(
                        {control["name"]: control.get("aria-label") for control in parser.controls},
                        expected,
                    )
