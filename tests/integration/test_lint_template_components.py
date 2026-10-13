from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol, cast
from unittest.mock import patch

import pytest
from django.test import SimpleTestCase


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
    monkeypatch.setattr(sys, "argv", ["lint_template_components.py", str(feature_file), "--fail-on", "TMPL009"])

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
        "{# tmpl-allow TMPL002: Alpine @click rejected by the button attrs allowlist #}\n"
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
        '{# tmpl-allow TMPL001: unrelated reason #}\n<button type="submit">Pay</button>\n',
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
        '{# tmpl-allow TMPL002: reason #}\n\n<button type="submit">Pay</button>\n',
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
        '{# tmpl-allow TMPL002: reason #}\n{% button "Pay" %}\n',
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
        '{# tmpl-allow TMPL002: #}\n<button type="submit">Pay</button>\n',
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
        "{# tmpl-allow TMPL002: Alpine @click rejected by the button attrs allowlist #}\n"
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
        '{# tmpl-allow TMPL002: Alpine #} {# tmpl-allow TMPL001: #}\n<button type="submit">Pay</button>\n',
    )

    violations = lint.scan_file(feature_file)
    no_reason = [v for v in violations if v.code == "TMPL_ALLOW_NO_REASON"]
    assert len(no_reason) == 1
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 1
    assert tmpl002[0].exempted is False, "a rejected multi-marker line must not exempt anything"


def test_real_element_sharing_a_line_with_a_marker_is_still_reported(tmp_path, lint, monkeypatch):
    """Copilot review: a marker is only "clean" (exempts the element below it) when it is the
    line's entire content. `<input> {# tmpl-allow TMPL002: reason #}` previously counted as a
    marker-only line just because .search() found marker text anywhere on it, so the real
    <input> sharing that line went completely unscanned - not a blocker, not exempted, just
    gone."""
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        '<input type="text" name="f"> {# tmpl-allow TMPL002: unrelated reason #}\n',
    )

    violations = lint.scan_file(feature_file)
    tmpl001 = [v for v in violations if v.code == "TMPL001"]
    assert len(tmpl001) == 1, f"the <input> sharing the marker's line must still be reported, got: {violations}"
    assert tmpl001[0].exempted is False


def test_real_element_on_the_same_line_as_a_marker_meant_for_the_next_line_is_still_reported(
    tmp_path, lint, monkeypatch
):
    """A same-line marker exempts its own button, which remains explicitly reported.

    Its reason cannot redirect the exemption onto the following line.
    """
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        '<button type="button">x</button> {# tmpl-allow TMPL002: for the next one #}\n'
        '<button @click="y = true">Open</button>\n',
    )

    violations = lint.scan_file(feature_file)
    tmpl002_by_line = {v.line: v for v in violations if v.code == "TMPL002"}
    assert 1 in tmpl002_by_line, f"the button sharing the marker's own line must still be reported, got: {violations}"
    assert tmpl002_by_line[1].exempted is True
    assert 2 in tmpl002_by_line
    assert tmpl002_by_line[2].exempted is False, "a same-line marker must not exempt the following line"


def test_second_matching_element_on_an_exempted_line_is_not_also_exempted(tmp_path, lint, monkeypatch):
    """codex finding: two raw <button>s on the one line below a marker used to collapse into a
    single Violation record (search() fires once per line regardless of match count), so
    exempting that record silently approved both buttons from one marker meant for one."""
    feature_file = _write_feature_file(
        tmp_path,
        lint,
        monkeypatch,
        "{# tmpl-allow TMPL002: only the first one #}\n"
        '<button type="button">A</button><button type="button">B</button>\n',
    )

    violations = lint.scan_file(feature_file)
    tmpl002 = [v for v in violations if v.code == "TMPL002"]
    assert len(tmpl002) == 2, f"both buttons must be reported as separate records, got: {violations}"
    assert tmpl002[0].exempted is True
    assert tmpl002[1].exempted is False, "only the first matching element on the line may be exempted"


class _ReviewViolation(Protocol):
    code: str
    line: int
    exempted: bool
    reason: str


class _ReviewLint(Protocol):
    def scan_file(self, path: Path) -> list[_ReviewViolation]: ...


class TemplateReviewRegressionTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        # resolve(): on macOS /tmp is a symlink, and scan_file compares resolved paths against REPO_ROOT.
        self.root = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.lint = cast("_ReviewLint", _load_lint_module())
        templates = self.root / "services/portal/templates"
        self.enterContext(
            patch.multiple(
                self.lint,
                REPO_ROOT=self.root,
                PORTAL_TEMPLATES=templates,
                COMPONENT_DIR=templates / "components",
                COMPONENT_SVG_ALLOWLIST_FILE=self.root / ".component-svg-allowlist",
            )
        )
        self.templates = templates

    def seed(self, relative: str, content: str) -> Path:
        path = self.templates / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_conditional_event_handlers_are_detected_at_the_original_line(self) -> None:
        cases = (
            ('<button {% if enabled %}onclick="run()"{% endif %}>Run</button>', 2),
            ('<button {% if enabled %}onclick="run()"{% else %}onfocus="focus()"{% endif %}>Run</button>', 2),
            ('<button\n{% if enabled %}onclick="run()"{% endif %}>Run</button>', 2),
            ('<button {% if\n enabled %}onclick="run()"{% endif %}>Run</button>', 2),
        )
        for markup, expected_line in cases:
            with self.subTest(markup=markup):
                path = self.seed(
                    "components/conditional.html",
                    "\n"
                    + markup
                    + '\n<div onkeydown="next()"></div>\n'
                    + """<script src="{% static 'component.js' %}"></script>\n""",
                )
                handlers = [finding for finding in self.lint.scan_file(path) if finding.code == "TMPL007"]
                self.assertEqual([finding.line for finding in handlers], [expected_line, 3 + markup.count("\n")])

    def test_two_marker_placements_exempt_two_elements_without_reuse(self) -> None:
        cases = (
            ("TMPL001", '<input name="a"><input name="b">', '<input name="c">'),
            ("TMPL002", "<button>A</button><button>B</button>", "<button>C</button>"),
            ("TMPL003", "<select></select><select></select>", "<select></select>"),
            ("TMPL004", "<textarea></textarea><textarea></textarea>", "<textarea></textarea>"),
        )
        for code, pair, third in cases:
            for extra in ("", third):
                with self.subTest(code=code, extra=extra):
                    path = self.seed(
                        "billing/allowances.html",
                        f"{{# tmpl-allow {code}: standalone allowance #}}\n"
                        f"{pair}{extra} {{# tmpl-allow {code}: inline allowance #}}\n",
                    )
                    findings = self.lint.scan_file(path)
                    matches = [finding for finding in findings if finding.code == code]
                    expected = [True, True] + ([False] if extra else [])
                    self.assertEqual([finding.exempted for finding in matches], expected)
                    self.assertEqual(
                        [finding.reason for finding in matches[:2]], ["inline allowance", "standalone allowance"]
                    )
                    self.assertEqual([finding.line for finding in matches], [2] * len(expected))
                    self.assertEqual([finding for finding in findings if finding.code == "TMPL_ALLOW_STALE"], [])

    def test_conditional_json_types_do_not_hide_executable_component_scripts(self) -> None:
        cases = (
            '<script {% if as_json %}type="application/json"{% endif %}>window.run()</script>',
            '<script {% if as_json %}type="application/ld+json"{% endif %}>window.run()</script>',
            '<script {% if as_json %}type="application/json"{% else %}type="text/javascript"{% endif %}>run()</script>',
            '<script type="{% if as_json %}application/json{% endif %}">window.run()</script>',
            '<script\n{% if as_json %}type="application/json"{% endif %}>window.run()</script>',
            '<script {% for kind in types %}type="application/json"{% endfor %}>window.run()</script>',
            # The browser keeps the first of duplicate attributes, so a conditional executable type wins
            '<script {% if executable %}type="text/javascript"{% endif %} type="application/json">run()</script>',
            '<script {% if executable %}TYPE="module"{% endif %}\ntype="application/ld+json">run()</script>',
        )
        for markup in cases:
            with self.subTest(markup=markup):
                path = self.seed("components/conditional_json.html", "\n" + markup)
                findings = [finding for finding in self.lint.scan_file(path) if finding.code == "TMPL007"]
                self.assertEqual([finding.line for finding in findings], [2])
        for markup in (
            '<script type="application/json">{"value": 1}</script>',
            '<script type="application/ld+json">{"value": 1}</script>',
            '<script type="application/json" {% if enabled %}data-extra="yes"{% endif %}>{"value": 1}</script>',
            '{% if enabled %}<script type="application/json">{"value": 1}</script>{% endif %}',
        ):
            with self.subTest(unconditional=markup):
                path = self.seed("components/unconditional_json.html", markup)
                findings = [finding for finding in self.lint.scan_file(path) if finding.code == "TMPL007"]
                self.assertEqual(findings, [])


# ===============================================================================
# Platform and shared templates are scanned too (#622)
# ===============================================================================
#
# The scanner knew only the portal's template root. A Platform or shared template, whether
# found by the walk or passed explicitly by the pre-commit hook, was "neither a feature
# template nor a component" and was skipped with no output, so 422 blockers in Platform
# templates never reached any gate.


def _three_roots(tmp_path: Path, lint, monkeypatch) -> tuple[Path, Path, Path]:
    portal = tmp_path / "services" / "portal" / "templates"
    platform = tmp_path / "services" / "platform" / "templates"
    shared = tmp_path / "shared" / "ui" / "templates"
    monkeypatch.setattr(lint, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(lint, "PORTAL_TEMPLATES", portal)
    monkeypatch.setattr(lint, "COMPONENT_DIR", portal / "components")
    # raising=False: on a scanner that predates these roots the test fails on its assertions,
    # which is the behaviour under test, rather than on a missing attribute.
    monkeypatch.setattr(lint, "PLATFORM_TEMPLATES", platform, raising=False)
    monkeypatch.setattr(lint, "SHARED_TEMPLATES", shared, raising=False)
    return portal, platform, shared


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_platform_feature_template_with_a_raw_button_is_a_blocker(tmp_path, lint, monkeypatch):
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(platform / "billing" / "invoice_detail.html", '<button type="submit">Pay</button>\n')

    blockers = [v for v in lint.scan_file(page) if v.code == "TMPL002"]

    assert [(v.severity, v.line, v.exempted) for v in blockers] == [(lint.SEVERITY_BLOCKER, 1, False)]


def test_platform_component_is_checked_as_a_component(tmp_path, lint, monkeypatch):
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    component = _write(platform / "components" / "widget.html", "<style>.a { color: red; }</style>\n<button>Go</button>\n")

    codes = {v.code for v in lint.scan_file(component)}

    assert "TMPL006" in codes  # component rule applies
    assert "TMPL002" not in codes  # components may render raw form elements


def test_shared_component_is_checked_as_a_component(tmp_path, lint, monkeypatch):
    _, _, shared = _three_roots(tmp_path, lint, monkeypatch)
    component = _write(shared / "components" / "field.html", '<input type="text">\n<div onclick="go()"></div>\n')

    codes = {v.code for v in lint.scan_file(component)}

    assert "TMPL007" in codes
    assert "TMPL001" not in codes


def test_shared_feature_template_is_a_feature_template(tmp_path, lint, monkeypatch):
    _, _, shared = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(shared / "legal" / "terms.html", "<select name='lang'></select>\n")

    assert [v.code for v in lint.scan_file(page)] == ["TMPL003"]


def test_main_without_arguments_scans_every_root(tmp_path, lint, monkeypatch, capsys):
    portal, platform, shared = _three_roots(tmp_path, lint, monkeypatch)
    expected = {
        _write(portal / "dashboard.html", "<p>ok</p>\n"),
        _write(platform / "customers" / "list.html", "<p>ok</p>\n"),
        _write(shared / "legal" / "privacy.html", "<textarea></textarea>\n"),  # the last root walked
    }
    scanned: list[Path] = []
    real_scan_file = lint.scan_file

    def recording_scan_file(path: Path):
        scanned.append(path)
        return real_scan_file(path)

    monkeypatch.setattr(lint, "scan_file", recording_scan_file)
    monkeypatch.setattr(sys, "argv", ["lint_template_components.py"])

    exit_code = lint.main()

    assert len(scanned) == 3, scanned
    assert set(scanned) == expected
    assert exit_code == 1
    assert "shared/ui/templates/legal/privacy.html" in capsys.readouterr().out


def test_an_explicit_platform_path_is_scanned(tmp_path, lint, monkeypatch, capsys):
    """The pre-commit hook passes staged files explicitly; a Platform one must not be skipped."""
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(platform / "orders" / "order_form.html", '<input type="number" name="qty">\n')
    monkeypatch.setattr(sys, "argv", ["lint_template_components.py", str(page)])

    exit_code = lint.main()

    assert exit_code == 1
    assert "services/platform/templates/orders/order_form.html:1 [TMPL001]" in capsys.readouterr().out


# ===============================================================================
# A template tag split across lines renders as text (TMPL011)
# ===============================================================================
#
# Django's lexer recognises `{% %}`, `{{ }}` and `{# #}` only on one line. A tag split across
# lines is not an error: it is output as plain text. The portal checkout showed a developer
# comment to customers this way, and the shared table header emitted `hx-get` on every
# column. The other checks matched tags with DOTALL patterns, so they read split tags as valid.


def test_a_split_block_tag_is_a_blocker_at_each_opening_line(tmp_path, lint, monkeypatch):
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(
        platform / "billing" / "list.html",
        '<div class="a" {%\n  if sort_url %}hx-get="{{ sort_url }}"{%\n  endif %}>\n</div>\n',
    )

    split = [v for v in lint.scan_file(page) if v.code == "TMPL011"]

    assert [(v.severity, v.line, v.exempted) for v in split] == [
        (lint.SEVERITY_BLOCKER, 1, False),
        (lint.SEVERITY_BLOCKER, 2, False),
    ]


def test_a_split_variable_and_a_split_comment_are_blockers(tmp_path, lint, monkeypatch):
    portal, _, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(portal / "orders" / "checkout.html", "<p>{{\n  name }}</p>\n{# a note\n   continued #}\n")

    assert [v.line for v in lint.scan_file(page) if v.code == "TMPL011"] == [1, 3]


def test_one_line_tags_and_comment_or_verbatim_blocks_are_not_flagged(tmp_path, lint, monkeypatch):
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(
        platform / "help" / "page.html",
        "{% if a %}<p>{{ b }}</p>{% endif %}{# one line #}\n"
        "{% comment %}\n  write {% if %} or {{ x\n{% endcomment %}\n"
        '{% verbatim %}\n  const t = "{{";\n{% endverbatim %}\n',
    )

    assert [v for v in lint.scan_file(page) if v.code == "TMPL011"] == []


def test_a_literal_opener_is_written_with_templatetag_or_verbatim(tmp_path, lint, monkeypatch):
    """The escape routes a page uses when it really needs `{{` in its output."""
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(
        platform / "help" / "script.html",
        '<script nonce="{{ csp_nonce }}">\n'
        '  const open = "{% templatetag openvariable %}";\n'
        "</script>\n"
        "{% verbatim snippet %}\n  const t = `{{ name`;\n{% endverbatim snippet %}\n",
    )

    assert [v for v in lint.scan_file(page) if v.code == "TMPL011"] == []


def test_a_named_verbatim_block_ends_only_at_its_own_terminator(tmp_path, lint, monkeypatch):
    """Django ends `{% verbatim name %}` only at `{% endverbatim name %}`; an unnamed one is literal text."""
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(
        platform / "help" / "named.html",
        "{% verbatim example %}\n"
        "  {% endverbatim %} is shown as text here\n"
        '  const open = "{{";\n'
        "{% endverbatim example %}\n"
        "<p>{{\n  name }}</p>\n",
    )

    assert [v.line for v in lint.scan_file(page) if v.code == "TMPL011"] == [5]


def test_a_bare_literal_opener_in_a_script_is_flagged(tmp_path, lint, monkeypatch):
    """Django outputs it as text too, so the check cannot tell it from a split tag: write it explicitly."""
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(platform / "help" / "script.html", '<script>\n  const open = "{{";\n</script>\n')

    assert [v.line for v in lint.scan_file(page) if v.code == "TMPL011"] == [2]


def test_a_tmpl_allow_marker_cannot_exempt_a_split_tag(tmp_path, lint, monkeypatch):
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(
        platform / "billing" / "list.html",
        "{# tmpl-allow TMPL011: wrapped by a formatter #}\n<p>{{\n  name }}</p>\n",
    )

    violations = lint.scan_file(page)

    assert [(v.line, v.exempted) for v in violations if v.code == "TMPL011"] == [(2, False)]
    assert [v.line for v in violations if v.code == "TMPL_ALLOW_STALE"] == [1]


def test_a_split_tag_in_a_component_is_a_blocker(tmp_path, lint, monkeypatch):
    _, _, shared = _three_roots(tmp_path, lint, monkeypatch)
    component = _write(shared / "components" / "table.html", "<th {%\n  if sortable %}aria-sort{% endif %}></th>\n")

    assert [(v.line, v.severity) for v in lint.scan_file(component) if v.code == "TMPL011"] == [
        (1, lint.SEVERITY_BLOCKER)
    ]


def test_a_split_tag_fails_the_default_gate(tmp_path, lint, monkeypatch, capsys):
    _, platform, _ = _three_roots(tmp_path, lint, monkeypatch)
    page = _write(platform / "billing" / "list.html", "<p>{{\n  name }}</p>\n")
    monkeypatch.setattr(sys, "argv", ["lint_template_components.py", str(page)])

    assert lint.main() == 1
    assert "services/platform/templates/billing/list.html:1 [TMPL011]" in capsys.readouterr().out


def test_no_template_in_the_repository_has_a_split_tag(lint):
    templates = sorted(path for root, _ in lint.template_roots() for path in root.rglob("*.html"))
    # The walk must reach the live case this check was written for, so a broken walk cannot pass.
    assert any(path.as_posix().endswith("services/portal/templates/orders/checkout.html") for path in templates)

    split = [
        f"{v.file.relative_to(lint.REPO_ROOT)}:{v.line}"
        for path in templates
        for v in lint.scan_file(path)
        if v.code == "TMPL011"
    ]

    assert split == []
