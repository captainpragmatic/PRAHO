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


# ===============================================================================
# tmpl-allow EXEMPTION MARKER
# ===============================================================================
#
# The Alpine-blocked buttons and the few buttons bound to page JS by exact child-element id
# (phase4-area-tickets:status_and_comments.html) can never pass TMPL002 - the generic {% button
# %}/{% input_field %} components can't carry Alpine directives through the security allowlist,
# or a caller-chosen id onto their fixed inner spans. Before this, lint_template_components.py had
# no way to mark either as an accepted exception: TMPL009 is the only code with any allowlist, and
# it's file-level (component SVG), not per-line. A `{# tmpl-allow CODE: reason #}` comment directly
# above the element is the per-line equivalent - explicit in the report (not silently dropped),
# and a stale marker (one whose line no longer violates CODE) fails the build, the same two-way
# ratchet as status_only_test_baseline.txt.


def _write_feature_file(tmp_path: Path, lint, monkeypatch, content: str) -> Path:
    feature_file = tmp_path / "services" / "portal" / "templates" / "billing" / "detail.html"
    feature_file.parent.mkdir(parents=True, exist_ok=True)
    feature_file.write_text(content, encoding="utf-8")
    monkeypatch.setattr(lint, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lint, "PORTAL_TEMPLATES", tmp_path / "services" / "portal" / "templates")
    monkeypatch.setattr(lint, "COMPONENT_DIR", tmp_path / "services" / "portal" / "templates" / "components")
    return feature_file


def test_marked_line_is_exempt_not_a_blocker(tmp_path, lint, monkeypatch):
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        '{# tmpl-allow TMPL002: Alpine @click rejected by the button attrs allowlist #}\n'
        '<button @click="open = true">Open</button>\n',
    )

    violations = lint.scan_file(feature_file)
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 1
    assert tmpl002[0].exempted is True
    assert "Alpine @click" in tmpl002[0].reason


def test_unmarked_line_is_still_a_blocker(tmp_path, lint, monkeypatch):
    feature_file = _write_feature_file(tmp_path, lint, monkeypatch, '<button type="submit">Pay</button>\n')

    violations = lint.scan_file(feature_file)
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 1
    assert tmpl002[0].exempted is False


def test_marker_for_a_different_code_does_not_exempt(tmp_path, lint, monkeypatch):
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        "{# tmpl-allow TMPL001: unrelated reason #}\n"
        '<button type="submit">Pay</button>\n',
    )

    violations = lint.scan_file(feature_file)
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 1
    assert tmpl002[0].exempted is False


def test_marker_two_lines_up_does_not_apply(tmp_path, lint, monkeypatch):
    """The marker must sit directly above the element - skipping a line (e.g. a blank line or
    an unrelated attribute continuation) must not exempt it, or the marker would silently cover
    whatever the next TMPL002 hit in the file turns out to be."""
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        "{# tmpl-allow TMPL002: reason #}\n"
        "\n"
        '<button type="submit">Pay</button>\n',
    )

    violations = lint.scan_file(feature_file)
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 1
    assert tmpl002[0].exempted is False


def test_stale_marker_with_no_matching_violation_is_an_error(tmp_path, lint, monkeypatch):
    """A marker whose element was fixed (or deleted) but the marker was left behind must fail -
    otherwise the exemption list only ever grows, and a future raw element reusing that exact
    line number would be silently exempted without anyone writing a new marker for it."""
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        "{# tmpl-allow TMPL002: reason #}\n"
        '{% button "Pay" %}\n',
    )

    violations = lint.scan_file(feature_file)
    stale = [v for v in violations if v.code == "TMPL_ALLOW_STALE"]
    assert len(stale) == 1
    assert stale[0].severity == lint.SEVERITY_BLOCKER


def test_marker_with_no_reason_is_an_error(tmp_path, lint, monkeypatch):
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        "{# tmpl-allow TMPL002: #}\n"
        '<button type="submit">Pay</button>\n',
    )

    violations = lint.scan_file(feature_file)
    no_reason = [v for v in violations if v.code == "TMPL_ALLOW_NO_REASON"]
    assert len(no_reason) == 1
    assert no_reason[0].severity == lint.SEVERITY_BLOCKER
    # The element itself must still be reported too - a malformed marker is not a free pass.
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 1
    assert tmpl002[0].exempted is False


def test_exempted_violations_are_reported_but_not_counted_as_blockers(tmp_path, lint, monkeypatch, capsys):
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        '{# tmpl-allow TMPL002: Alpine @click rejected by the button attrs allowlist #}\n'
        '<button @click="open = true">Open</button>\n',
    )
    monkeypatch.setattr(sys, "argv", ["lint_template_components.py", str(feature_file)])

    exit_code = lint.main()

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "0 blocker(s)" in out
    assert "1 exempted" in out
    assert "Only exempted violations found" in out


def test_marker_text_mentioning_an_element_does_not_self_match(tmp_path, lint, monkeypatch):
    """codex finding: a marker's own reason is free-form prose, not template code - if it
    happens to mention a raw element by name, the marker's own line must not also be scanned
    for TMPL001-004, or the comment itself becomes a second, unexempted violation."""
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        "{# tmpl-allow TMPL002: raw <button> needed for Alpine click handler #}\n"
        '<button @click="open = true">Open</button>\n',
    )

    violations = lint.scan_file(feature_file)
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 1, f"the marker line itself must not also be scanned, got: {violations}"
    assert tmpl002[0].line == 2
    assert tmpl002[0].exempted is True


def test_two_markers_on_one_line_is_an_error_not_a_silent_first_match(tmp_path, lint, monkeypatch):
    """codex finding: _find_tmpl_allow_markers used .search(), which only validates the first
    marker on a line - a second marker (even one with an empty reason) was silently ignored."""
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        '{# tmpl-allow TMPL002: Alpine #} {# tmpl-allow TMPL001: #}\n'
        '<button type="submit">Pay</button>\n',
    )

    violations = lint.scan_file(feature_file)
    no_reason = [v for v in violations if v.code == "TMPL_ALLOW_NO_REASON"]
    assert len(no_reason) == 1
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 1
    assert tmpl002[0].exempted is False, "a rejected multi-marker line must not exempt anything"
