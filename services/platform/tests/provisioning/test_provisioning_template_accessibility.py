"""Regression checks for the WP16 provisioning template bucket."""

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


class ProvisioningTemplateBucketTests(SimpleTestCase):
    def test_controls_have_accessible_names(self) -> None:
        paths = (
            "provisioning/service_form.html",
            "provisioning/virtualmin/account_detail.html",
            "provisioning/virtualmin/accounts_list.html",
            "provisioning/virtualmin/migration_status.html",
            "provisioning/virtualmin/partials/job_status.html",
        )
        findings = _findings("audit_accessibility", paths, frozenset({"critical", "serious"}))
        self.assertEqual(findings, [])

    def test_styles_have_no_dark_mode_findings(self) -> None:
        paths = (
            "provisioning/partials/services_list.html",
            "provisioning/plan_list.html",
            "provisioning/service_detail.html",
        )
        findings = _findings("audit_dark_mode", paths, frozenset({"blocker", "warning"}))
        self.assertEqual(findings, [])
