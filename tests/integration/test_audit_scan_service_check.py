"""The audit coverage scan must be able to fail.

``service-no-audit`` was emitted as ``low`` while every caller scans at ``medium``, so it never
reported anything, and it decided "has an audit import" by looking for the text ``apps.audit``
anywhere in the file, so a comment or docstring was enough to pass.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path
from types import ModuleType

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "audit_coverage_scan.py"
PLATFORM_APPS = PROJECT_ROOT / "services" / "platform" / "apps"


def _scan() -> ModuleType:
    spec = importlib.util.spec_from_file_location("audit_coverage_scan", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # the scan's frozen dataclass resolves its annotations through it
    spec.loader.exec_module(module)
    return module


def _service_issues(tmp_path: Path, source: str, name: str = "widget_service.py") -> list[object]:
    """Scan one service file placed in a critical domain directory."""
    path = tmp_path / "apps" / "billing" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    issues, error = _scan().scan_file(path)
    assert error is None
    return [issue for issue in issues if issue.code == "service-no-audit"]


@pytest.mark.integration
class TestServiceNoAuditCheck:
    def test_a_comment_that_mentions_apps_audit_is_flagged(self, tmp_path: Path) -> None:
        issues = _service_issues(
            tmp_path,
            """
            # TODO: log through apps.audit.services once the flow settles
            def create_widget():
                return 1
            """,
        )

        assert len(issues) == 1

    def test_a_docstring_or_string_that_mentions_apps_audit_is_flagged(self, tmp_path: Path) -> None:
        issues = _service_issues(
            tmp_path,
            '''
            """Calls into apps.audit.services and log_security_event, in prose only."""
            NOTE = "from apps.audit.services import AuditService"
            ''',
        )

        assert len(issues) == 1

    def test_a_module_level_import_passes(self, tmp_path: Path) -> None:
        assert _service_issues(tmp_path, "from apps.audit.services import AuditService\n") == []
        assert _service_issues(tmp_path, "import apps.audit.services\n", name="other_service.py") == []

    def test_a_function_level_import_passes(self, tmp_path: Path) -> None:
        source = """
            def create_widget():
                from apps.audit.services import AuditService  # noqa: PLC0415
                return AuditService
            """

        assert _service_issues(tmp_path, source) == []

    def test_a_log_security_event_call_passes(self, tmp_path: Path) -> None:
        source = """
            from apps.common.security_decorators import log_security_event

            def create_widget():
                log_security_event("widget_created", {})
            """

        assert _service_issues(tmp_path, source) == []

    def test_the_finding_is_medium_so_the_default_scan_reports_it(self, tmp_path: Path) -> None:
        (issue,) = _service_issues(tmp_path, "def create_widget():\n    return 1\n")
        scan = _scan()

        assert issue.severity == "medium"
        assert scan.severity_at_least(issue.severity, scan.build_parser().parse_args([]).min_severity)

    def test_the_platform_tree_has_no_unjustified_service_without_audit(self) -> None:
        scan = _scan()
        issues = []
        for path in scan.iter_python_files([PLATFORM_APPS], {"__pycache__", "migrations", "tests"}):
            found, error = scan.scan_file(path)
            assert error is None, path
            issues.extend(issue for issue in found if issue.code == "service-no-audit")

        assert [issue.file for issue in issues] == []

    def test_every_allowlisted_service_exists_and_says_why(self) -> None:
        for relative, reason in _scan().SERVICE_NO_AUDIT_ALLOWLIST.items():
            assert (PLATFORM_APPS.parent / relative).is_file(), f"stale allowlist entry: {relative}"
            assert len(reason.split()) >= 4, f"{relative} needs a real reason"
