from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_lint_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "lint_template_components.py"
    spec = importlib.util.spec_from_file_location("lint_template_components", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Ensure decorators/dataclasses can resolve module metadata during exec.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def lint(monkeypatch, tmp_path):
    """Load the lint module and clear lru_cache between tests for isolation."""
    module = _load_lint_module()
    # Always reset the allowlist cache so monkeypatching takes effect cleanly.
    module.load_component_svg_allowlist.cache_clear()
    yield module
    module.load_component_svg_allowlist.cache_clear()


def test_tmpl009_flags_component_svg_not_allowlisted(tmp_path, lint, monkeypatch):
    component_file = tmp_path / "services" / "portal" / "templates" / "components" / "example.html"
    component_file.parent.mkdir(parents=True, exist_ok=True)
    component_file.write_text("<div><svg><path d='M0 0'></path></svg></div>", encoding="utf-8")

    allowlist = tmp_path / ".component-svg-allowlist"
    allowlist.write_text("", encoding="utf-8")

    monkeypatch.setattr(lint, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lint, "PORTAL_TEMPLATES", tmp_path / "services" / "portal" / "templates")
    monkeypatch.setattr(lint, "COMPONENT_DIR", tmp_path / "services" / "portal" / "templates" / "components")
    monkeypatch.setattr(lint, "COMPONENT_SVG_ALLOWLIST_FILE", allowlist)
    lint.load_component_svg_allowlist.cache_clear()

    violations = lint.scan_file(component_file)
    tmpl009 = [v for v in violations if v.code == "TMPL009"]
    assert len(tmpl009) == 1, f"Expected exactly 1 TMPL009 violation, got {len(tmpl009)}"
    assert tmpl009[0].file == component_file
    assert tmpl009[0].line == 1


def test_tmpl009_skips_allowlisted_component_svg(tmp_path, lint, monkeypatch):
    component_file = tmp_path / "services" / "portal" / "templates" / "components" / "spinner.html"
    component_file.parent.mkdir(parents=True, exist_ok=True)
    component_file.write_text("<span><svg><circle></circle></svg></span>", encoding="utf-8")

    allowlist = tmp_path / ".component-svg-allowlist"
    allowlist.write_text(
        "services/portal/templates/components/spinner.html | animated loading spinner\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(lint, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lint, "PORTAL_TEMPLATES", tmp_path / "services" / "portal" / "templates")
    monkeypatch.setattr(lint, "COMPONENT_DIR", tmp_path / "services" / "portal" / "templates" / "components")
    monkeypatch.setattr(lint, "COMPONENT_SVG_ALLOWLIST_FILE", allowlist)
    lint.load_component_svg_allowlist.cache_clear()

    violations = lint.scan_file(component_file)
    assert violations == [], f"Expected no violations for allowlisted component, got: {violations}"


def test_tmpl009_does_not_flag_feature_template_svg(tmp_path, lint, monkeypatch):
    """TMPL009 must NOT fire for feature templates (only applies to components/)."""
    feature_file = tmp_path / "services" / "portal" / "templates" / "billing" / "detail.html"
    feature_file.parent.mkdir(parents=True, exist_ok=True)
    feature_file.write_text("<div><svg><path d='M0 0'></path></svg></div>", encoding="utf-8")

    allowlist = tmp_path / ".component-svg-allowlist"
    allowlist.write_text("", encoding="utf-8")

    monkeypatch.setattr(lint, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lint, "PORTAL_TEMPLATES", tmp_path / "services" / "portal" / "templates")
    monkeypatch.setattr(lint, "COMPONENT_DIR", tmp_path / "services" / "portal" / "templates" / "components")
    monkeypatch.setattr(lint, "COMPONENT_SVG_ALLOWLIST_FILE", allowlist)
    lint.load_component_svg_allowlist.cache_clear()

    violations = lint.scan_file(feature_file)
    tmpl009 = [v for v in violations if v.code == "TMPL009"]
    assert tmpl009 == [], "TMPL009 must not fire for feature templates (only for components/)"


def _feature_file_with_one_blocker_and_one_warning(tmp_path: Path, lint, monkeypatch) -> Path:
    """One TMPL002 (blocker) and one TMPL005 (warning) - a raw button and a raw status color.

    is_feature_template() classifies by path relative to the (monkeypatched) PORTAL_TEMPLATES
    root, so the fixture file must live under it - a file under a bare tmp_path is relative to
    neither PORTAL_TEMPLATES nor COMPONENT_DIR and is silently skipped by both branches of
    scan_file, producing zero violations regardless of its content.
    """
    feature_file = tmp_path / "services" / "portal" / "templates" / "billing" / "detail.html"
    feature_file.parent.mkdir(parents=True, exist_ok=True)
    feature_file.write_text(
        '<button type="submit">Pay</button>\n<span class="bg-green-100">Paid</span>\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(lint, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lint, "PORTAL_TEMPLATES", tmp_path / "services" / "portal" / "templates")
    monkeypatch.setattr(lint, "COMPONENT_DIR", tmp_path / "services" / "portal" / "templates" / "components")
    return feature_file


def test_default_fail_on_reports_the_true_blocker_count_and_exits_1(tmp_path, lint, monkeypatch, capsys):
    feature_file = _feature_file_with_one_blocker_and_one_warning(tmp_path, lint, monkeypatch)
    monkeypatch.setattr(sys, "argv", ["lint_template_components.py", str(feature_file)])

    exit_code = lint.main()

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "1 blocker(s)  |  1 warning(s)" in out
    assert "1 violation(s) matching --fail-on codes found" in out


def test_all_codes_fail_on_does_not_reclassify_the_warning_as_a_blocker(tmp_path, lint, monkeypatch, capsys):
    """The severity/fail-count conflation this fix resolves: asking every code to also fail the
    build must not change what counts as a blocker in the printed breakdown - only the exit
    message's violation count, which legitimately covers both codes now."""
    feature_file = _feature_file_with_one_blocker_and_one_warning(tmp_path, lint, monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["lint_template_components.py", str(feature_file), "--fail-on", "TMPL001,TMPL002,TMPL003,TMPL004,TMPL005"],
    )

    exit_code = lint.main()

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "1 blocker(s)  |  1 warning(s)" in out, "the warning must stay a warning, not become a second blocker"
    assert "2 violation(s) matching --fail-on codes found" in out


def test_fail_on_excluding_every_present_code_exits_0_without_claiming_warnings_only(
    tmp_path, lint, monkeypatch, capsys
):
    """A selective --fail-on that matches nothing still exits 0, but real blockers exist that this
    run was simply never asked to fail on - the old "Warnings only" message was wrong here."""
    feature_file = _feature_file_with_one_blocker_and_one_warning(tmp_path, lint, monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["lint_template_components.py", str(feature_file), "--fail-on", "TMPL009"]
    )

    exit_code = lint.main()

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "1 blocker(s)  |  1 warning(s)" in out
    assert "Warnings only" not in out
    assert "2 violation(s) found, none matching --fail-on codes" in out
