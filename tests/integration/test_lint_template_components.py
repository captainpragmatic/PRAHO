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
