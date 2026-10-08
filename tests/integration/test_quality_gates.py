"""Seeded regressions for the cross-service template quality detectors."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from typing import Protocol, cast
from unittest.mock import patch

from django.template import Context, Engine
from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Finding(Protocol):
    code: str
    severity: str
    line: int


class _TemplateFinding(_Finding, Protocol):
    exempted: bool
    reason: str


def _load_script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(f"_quality_gate_{name}", REPO_ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses need their defining module registered during execution.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestQualityGates(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Resolve: macOS /tmp is a symlink, and the linters compare resolved paths.
        self.root = Path(self.enterContext(TemporaryDirectory())).resolve()
        self.a11y = _load_script("audit_accessibility")
        self.dm = _load_script("audit_dark_mode")
        self.tmpl = _load_script("lint_template_components")
        portal = self.root / "services" / "portal" / "templates"
        platform = self.root / "services" / "platform" / "templates"
        for module in (self.a11y, self.dm, self.tmpl):
            self.enterContext(patch.object(module, "REPO_ROOT", self.root))
            self.enterContext(patch.object(module, "PORTAL_TEMPLATES", portal))
        for module in (self.a11y, self.dm):
            self.enterContext(patch.object(module, "PLATFORM_TEMPLATES", platform))
        self.enterContext(patch.object(self.tmpl, "COMPONENT_DIR", portal / "components"))
        self.enterContext(
            patch.object(self.tmpl, "COMPONENT_SVG_ALLOWLIST_FILE", self.root / ".component-svg-allowlist")
        )
        # create=True lets the discovery assertion reproduce the missing shared root on the parent.
        self.enterContext(
            patch.object(self.a11y, "SHARED_TEMPLATES", self.root / "shared" / "ui" / "templates", create=True)
        )

    def _seed(self, content: str, name: str = "fixture.html", tree: str = "services/portal/templates") -> Path:
        path = self.root / tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _check(self, module: ModuleType, path: Path) -> list[_Finding]:
        check = cast(Callable[[Path], list[_Finding]], module.check_file)
        return check(path)

    def _scan(self, path: Path) -> list[_TemplateFinding]:
        scan = cast(Callable[[Path], list[_TemplateFinding]], self.tmpl.scan_file)
        return scan(path)

    def _lines(self, findings: list[_Finding], code: str) -> list[int]:
        return sorted(finding.line for finding in findings if finding.code == code)

    def test_link_text_translation_boundaries(self) -> None:
        path = self._seed(
            '<a href="/">{% trans "Open" %}</a>\n'
            "<a href=\"/\">{% translate 'Open' %}</a>\n"
            '<a href="/">{% blocktrans %}Open {{ name }}{% endblocktrans %}</a>\n'
            '<a href="/">{{ caption }}</a>\n'
            '<a href="/">{% trans "" %}</a>\n'
            '<a href="/">{% translate " " %}</a>\n'
            '<a href="/">{{ }}</a>\n'
            '<a href="/">{% blocktrans %}{% endblocktrans %}</a>\n'
        )
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y002"), [5, 6, 7, 8])

    def test_hidden_inputs_are_ignored(self) -> None:
        path = self._seed('<input type="hidden" name="token">\n<input TYPE=hidden name=other>\n')
        self.assertEqual(self._check(self.a11y, path), [])

    def test_wrapping_labels_need_text(self) -> None:
        path = self._seed(
            '<label>Name <input name="name"></label>\n'
            '<label><input name="agree">{% trans "Agree" %}</label>\n'
            '<label><input name="empty"></label>\n'
            '<label>\n  <span>{{ caption }}</span>\n  <input name="nested">\n</label>\n'
        )
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y003"), [3])

    def test_id_requires_an_associated_label(self) -> None:
        path = self._seed(
            '<input id="orphan">\n'
            '<input id="named">\n'
            '<label for="named">{% trans "Name" %}</label>\n'
            '<input aria-label="Search">\n'
            '<input aria-labelledby="heading">\n'
            '<input id="blank"><label for="blank"></label>\n'
            '<input aria-label="">\n'
            '<select id="unlabelled-select"></select>\n'
            '<textarea id="unlabelled-textarea"></textarea>\n'
        )
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y003"), [1, 6, 7, 8, 9])

    def test_components_require_nonempty_label_arguments(self) -> None:
        path = self._seed(
            '{% input_field "name" %}\n'
            '{% checkbox_field "agree" %}\n'
            '{% select_field "choice" %}\n'
            '{% textarea_field "notes" %}\n'
            '{% filter_select "status" choices %}\n'
            '{% input_field "empty" label="" %}\n'
            '{% input_field "blank" aria_label=" " %}\n'
            '{% input_field "named" label="Name" %}\n'
            '{% checkbox_field "labelled" label=caption %}\n'
            '{% input_field "search" aria_label="Search" %}\n'
            '{% input_field "labelled" label="Name" %}<input name="raw">\n'
        )
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y003"), [1, 2, 3, 4, 5, 6, 7, 11])

    def test_discovery_includes_shared_ui(self) -> None:
        portal = self._seed('<input id="portal-orphan">')
        platform = self._seed('<input id="platform-orphan">', tree="services/platform/templates")
        shared = self._seed('<input id="shared-orphan">', tree="shared/ui/templates")
        discover = cast(Callable[[], list[Path]], self.a11y.discover_templates)
        self.assertEqual(discover(), sorted([portal, platform, shared]))
        self.assertEqual(self._lines(self._check(self.a11y, shared), "A11Y003"), [1])

    def test_rendered_controls_are_checked_for_actual_labels(self) -> None:
        for service in ("platform", "portal"):
            engine = Engine(
                dirs=[str(REPO_ROOT / "shared" / "ui" / "templates")],
                libraries={
                    "ui_components": f"services.{service}.apps.ui.templatetags.ui_components",
                    "static": "django.templatetags.static",
                },
            )
            for tag in (
                'input_field "name"',
                'input_field "choice" input_type="select"',
                'input_field "notes" input_type="textarea"',
                'checkbox_field "agree"',
            ):
                with self.subTest(service=service, tag=tag):
                    labelled = engine.from_string("{% load ui_components %}{% " + tag + ' label="Name" %}')
                    path = self._seed(labelled.render(Context({})), name="rendered.html")
                    self.assertEqual(self._check(self.a11y, path), [])
                    unlabelled = engine.from_string("{% load ui_components %}{% " + tag + " %}")
                    path = self._seed(unlabelled.render(Context({})), name="rendered.html")
                    self.assertEqual([v.code for v in self._check(self.a11y, path)], ["A11Y003"])

    def test_one_image_marker_exempts_only_one_element(self) -> None:
        path = self._seed(
            "{# a11y-allow A11Y001: decorative exception #}\n"
            '<img src="one"><img src="two">\n'
            '<img src="three"><img src="four">\n'
        )
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y001"), [2, 3, 3])

    def test_one_link_marker_exempts_only_one_element(self) -> None:
        empty = '<a href="/"></a>'
        icon = '<a href="/"><svg class="icon" /></a>'
        for links in (empty + empty, icon + icon, empty + icon, icon + empty):
            with self.subTest(links=links):
                path = self._seed("{# a11y-allow A11Y002: deliberate exception #}\n" + links + "\n" + links + "\n")
                self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y002"), [2, 3, 3])

    def test_aria_label_is_rendered_on_each_input_branch(self) -> None:
        for service in ("platform", "portal"):
            engine = Engine(
                dirs=[str(REPO_ROOT / "shared" / "ui" / "templates")],
                libraries={
                    "ui_components": f"services.{service}.apps.ui.templatetags.ui_components",
                    "static": "django.templatetags.static",
                },
            )
            for input_type in ("select", "textarea", "text", "radio"):
                with self.subTest(service=service, input_type=input_type):
                    source = '{% input_field "control" input_type="' + input_type + '" aria_label="Accessible name" %}'
                    rendered = engine.from_string("{% load ui_components %}" + source).render(Context({}))
                    self.assertIn('aria-label="Accessible name"', rendered)
                    for content in (source, rendered):
                        path = self._seed(content, name="aria-labelled.html")
                        self.assertEqual(self._check(self.a11y, path), [])

    def test_components_without_aria_label_support_require_a_label(self) -> None:
        for tag in ('checkbox_field "agree"', 'filter_select "status" choices'):
            with self.subTest(tag=tag):
                path = self._seed(
                    "{% " + tag + ' aria_label="Unsupported name" %}\n{% ' + tag + ' label="Visible name" %}\n'
                )
                self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y003"), [1])

    def test_hidden_component_inputs_are_ignored_in_source_and_rendered_output(self) -> None:
        for service in ("platform", "portal"):
            engine = Engine(
                dirs=[str(REPO_ROOT / "shared" / "ui" / "templates")],
                libraries={
                    "ui_components": f"services.{service}.apps.ui.templatetags.ui_components",
                    "static": "django.templatetags.static",
                },
            )
            source = (
                '{% input_field "token" input_type="hidden" %}\n'
                "{% input_field 'other-token' input_type='hidden' %}\n"
                '{% input_field "visible" input_type="text" %}\n'
            )
            rendered = engine.from_string("{% load ui_components %}" + source).render(Context({}))
            self.assertIn('type="hidden"', rendered)
            for kind, content in (("source", source), ("rendered", rendered)):
                with self.subTest(service=service, kind=kind):
                    path = self._seed(content, name="hidden-controls.html")
                    self.assertEqual([v.code for v in self._check(self.a11y, path)], ["A11Y003"])

    def test_captured_translations_do_not_supply_link_text(self) -> None:
        path = self._seed(
            '<a href="/">{% trans "Name" as name %}</a>\n'
            "<a href=\"/\">{% translate 'Name' as name %}</a>\n"
            '<a href="/">{% trans "Name" as name %}{{ name }}</a>\n'
            '<a href="/">{% trans "Use as name" %}</a>\n'
        )
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y002"), [1, 2])

    def test_captured_translations_do_not_supply_label_text(self) -> None:
        path = self._seed(
            '<label>{% trans "Name" as name %}<input name="first"></label>\n'
            "<label>{% translate 'Name' as name %}<input name=\"second\"></label>\n"
            '<label for="third">{% trans "Name" as name %}</label><input id="third">\n'
            '<label for="fourth">{% translate \'Name\' as name %}</label><input id="fourth">\n'
            '<label>{% trans "Name" as name %}{{ name }}<input name="labelled"></label>\n'
            '<label>{% trans "Use as name" %}<input name="literal"></label>\n'
        )
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y003"), [1, 2, 3, 4])

    def test_whitespace_only_component_labels_are_empty(self) -> None:
        for key in ("label", "aria_label"):
            for value in ('_(" ")', "_(' ')", 'gettext(" ")', "gettext(' ')", '" "', "' '"):
                with self.subTest(key=key, value=value):
                    path = self._seed(
                        '{% input_field "blank" ' + key + "=" + value + " %}\n"
                        '{% input_field "named" ' + key + '=_("Name") %}\n'
                        '{% input_field "dynamic" ' + key + "=caption %}\n"
                        '{% input_field "literal" ' + key + '=_("None") %}\n'
                    )
                    self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y003"), [1])

    def test_filtered_component_names_match_rendered_names(self) -> None:
        values = (
            ('"Name"|capfirst', "Name"),
            ("'Name'|lower|capfirst", "Name"),
            ('_("Name")|capfirst', "Name"),
            ("_('Name')|lower|capfirst", "Name"),
            ('"Name|Surname"|capfirst', "Name|Surname"),
            ('"Name"|default:"use as name|fallback"|capfirst', "Name"),
        )
        for service in ("platform", "portal"):
            engine = Engine(
                dirs=[str(REPO_ROOT / "shared" / "ui" / "templates")],
                libraries={
                    "ui_components": f"services.{service}.apps.ui.templatetags.ui_components",
                    "static": "django.templatetags.static",
                },
            )
            for key in ("label", "aria_label"):
                for value, expected in values:
                    source = '{% input_field "control" ' + key + "=" + value + " %}"
                    rendered = engine.from_string("{% load ui_components %}" + source).render(Context({}))
                    if key == "aria_label":
                        self.assertIn('aria-label="' + expected + '"', rendered)
                    else:
                        self.assertIn(expected, rendered)
                    for kind, content in (("source", source), ("rendered", rendered)):
                        with self.subTest(service=service, key=key, value=value, kind=kind):
                            path = self._seed(content, name="filtered-names.html")
                            self.assertEqual(self._check(self.a11y, path), [])

    def test_filtered_blank_component_names_are_empty(self) -> None:
        for key in ("label", "aria_label"):
            for value in ('" "|capfirst', "' '|lower", '_(" ")|capfirst', "_(' ')|lower|capfirst"):
                with self.subTest(key=key, value=value):
                    path = self._seed('{% input_field "blank" ' + key + "=" + value + " %}\n")
                    self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y003"), [1])

    def test_capture_options_do_not_supply_link_text(self) -> None:
        engine = Engine(libraries={"i18n": "django.templatetags.i18n"})
        for tag in ("trans", "translate"):
            for options in (
                "as name noop",
                'as name context "greeting"',
                "noop as name",
                'context "greeting" as name',
            ):
                capture = "{% " + tag + ' "Name" ' + options + " %}"
                source = (
                    '<a href="/">' + capture + "</a>\n"
                    '<a href="/">' + capture + "{{ name }}</a>\n"
                    '<a href="/">{% ' + tag + ' "Name" context "use as name" %}</a>\n'
                )
                rendered = engine.from_string("{% load i18n %}" + source).render(Context({}))
                for kind, content in (("source", source), ("rendered", rendered)):
                    with self.subTest(tag=tag, options=options, kind=kind):
                        path = self._seed(content, name="captured-links.html")
                        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y002"), [1])

    def test_capture_options_do_not_supply_label_text(self) -> None:
        engine = Engine(libraries={"i18n": "django.templatetags.i18n"})
        for tag in ("trans", "translate"):
            for options in (
                "as name noop",
                'as name context "greeting"',
                "noop as name",
                'context "greeting" as name',
            ):
                capture = "{% " + tag + " 'Name' " + options + " %}"
                source = (
                    "<label>" + capture + '<input name="first"></label>\n'
                    '<label for="second">' + capture + '</label><input id="second">\n'
                    "<label>" + capture + '{{ name }}<input name="named"></label>\n'
                    "<label>{% " + tag + ' "Name" context "use as name" %}<input name="literal"></label>\n'
                )
                rendered = engine.from_string("{% load i18n %}" + source).render(Context({}))
                for kind, content in (("source", source), ("rendered", rendered)):
                    with self.subTest(tag=tag, options=options, kind=kind):
                        path = self._seed(content, name="captured-labels.html")
                        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y003"), [1, 2])

    def test_one_button_marker_exempts_only_one_element(self) -> None:
        buttons = '<button><svg class="icon" /></button>' * 2
        path = self._seed("{# a11y-allow A11Y005: deliberate exception #}\n" + buttons + "\n" + buttons + "\n")
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y005"), [2, 3, 3])

    def test_element_markers_exempt_only_one_matching_element(self) -> None:
        cases = (
            ("A11Y004", "<html><html>"),
            (
                "A11Y006",
                '<div onclick="open()"></div>'
                '<span onclick="open()" role="button" tabindex="0"></span>'
                '<p onclick="open()"></p>',
            ),
            ("A11Y007", '<input aria-label="Name" autofocus>' * 2),
            ("A11Y008", "<table></table>" * 2),
            ("A11Y009", '<button tabindex="1">One</button><button tabindex="2">Two</button>'),
            ("A11Y010", '<button aria-hidden="true">One</button><button aria-hidden="true">Two</button>'),
        )
        for code, elements in cases:
            with self.subTest(code=code):
                prefix = '<input aria-label="First" autofocus>\n' if code == "A11Y007" else ""
                path = self._seed(
                    prefix + "{# a11y-allow " + code + ": deliberate exception #}\n" + elements + "\n" + elements + "\n"
                )
                offset = prefix.count("\n")
                self.assertEqual(self._lines(self._check(self.a11y, path), code), [2 + offset, 3 + offset, 3 + offset])

    def test_table_captions_only_name_their_own_element(self) -> None:
        path = self._seed(
            "<table><caption>Named</caption></table><table></table>\n<table><caption>Other</caption></table>\n"
        )
        self.assertEqual(self._lines(self._check(self.a11y, path), "A11Y008"), [1])

    def test_emails_directory_is_skipped_without_skipping_similar_names(self) -> None:
        email = self._seed('<p style="color: red">Welcome</p>', name="emails/welcome.html")
        page = self._seed('<p style="color: red">Welcome</p>', name="email_assets/page.html")
        self.assertEqual(self._check(self.dm, email), [])
        self.assertEqual([v.code for v in self._check(self.dm, page)], ["DM004"])

    def test_tmpl_allow_accepts_punctuation_and_only_exempts_one_element(self) -> None:
        reason = "Issue #123: keep <button>, @click & state (for now)."
        path = self._seed("{# tmpl-allow TMPL002: " + reason + " #}\n<button>First</button><button>Second</button>\n")
        buttons = [v for v in self._scan(path) if v.code == "TMPL002"]
        self.assertEqual([v.exempted for v in buttons], [True, False])
        self.assertEqual(buttons[0].reason, reason)

    def test_malformed_tmpl_markers_warn_and_exempt_nothing(self) -> None:
        path = self._seed(
            "{# tmpl-allow TMPL002 missing colon #}\n<button>Open</button>\n"
            "{# tmpl-allow BAD: reason #}\n<button>Open</button>\n"
            "{# tmpl-allow TMPL002: #}\n<button>Open</button>\n"
            "{# tmpl-allow TMPL002: first #} {# tmpl-allow TMPL002: second #}\n<button>Open</button>\n"
            "{# tmpl-allow TMPL002: missing terminator\n<button>Open</button>\n"
        )
        findings = self._scan(path)
        warnings = [(v.line, v.severity) for v in findings if v.code == "TMPL010"]
        self.assertEqual(warnings, [(1, "warning"), (3, "warning"), (5, "warning"), (7, "warning"), (9, "warning")])
        self.assertEqual([v.exempted for v in findings if v.code == "TMPL002"], [False] * 5)
        component = self._seed("{# tmpl-allow BAD: reason #}", name="components/bad.html")
        self.assertEqual([(v.code, v.severity) for v in self._scan(component)], [("TMPL010", "warning")])

    def test_a11y_allow_is_scoped_to_the_next_line_and_matching_code(self) -> None:
        path = self._seed(
            "{# a11y-allow A11Y003: deliberate #1 & legacy control #}\n"
            '<input name="first"><input name="second">\n'
            "{# a11y-allow A11Y002: icon #2 #}\n"
            '<a href="/"></a>\n'
            '<a href="/"></a>\n'
            "{# a11y-allow A11Y001: wrong code #}\n"
            '<input name="wrong-code">\n'
            "{# a11y-allow A11Y003: too far away #}\n"
            "\n"
            '<input name="too-far">\n'
        )
        findings = self._check(self.a11y, path)
        self.assertEqual(self._lines(findings, "A11Y003"), [2, 7, 10])
        self.assertEqual(self._lines(findings, "A11Y002"), [5])

    def test_dm_allow_is_scoped_to_the_next_line_and_matching_code(self) -> None:
        path = self._seed(
            "{# dm-allow DM004: QR #1 & contrast #}\n"
            '<p style="color: black"></p><p style="color: white"></p>\n'
            '<p style="color: black"></p>\n'
            "{# dm-allow DM001: wrong code #}\n"
            '<p style="color: black"></p>\n'
            "{# dm-allow DM004: too far away #}\n"
            "\n"
            '<p style="color: black"></p>\n'
        )
        self.assertEqual(self._lines(self._check(self.dm, path), "DM004"), [2, 3, 5, 8])

    def test_marker_reason_is_not_a_dark_variant(self) -> None:
        path = self._seed(
            "{# dm-allow DM004: QR #1 cannot use dark:bg-black #}\n"
            '<p class="bg-white" style="color: black"></p>\n'
            '<div class="bg-white"></div>\n'
        )
        findings = self._check(self.dm, path)
        self.assertEqual([(v.code, v.line) for v in findings], [("DM001", 2), ("DM001", 3)])

    def test_malformed_a11y_markers_warn_without_hiding_findings(self) -> None:
        path = self._seed(
            "{# a11y-allow A11Y003 missing colon #}\n<input name=first>\n"
            "{# a11y-allow A11Y003: #}\n<input name=second>\n"
            "{# a11y-allow A11Y003: first #} {# a11y-allow A11Y003: second #}\n<input name=third>\n"
            "{# a11y-allow BAD: reason #}\n<input name=fourth>\n"
            "{# a11y-allow A11Y003: missing terminator\n<input name=fifth>\n"
        )
        findings = self._check(self.a11y, path)
        self.assertEqual(
            [(v.line, v.severity) for v in findings if v.code == "A11Y011"],
            [(1, "warning"), (3, "warning"), (5, "warning"), (7, "warning"), (9, "warning")],
        )
        self.assertEqual(self._lines(findings, "A11Y003"), [2, 4, 6, 8, 10])

    def test_malformed_dm_markers_warn_without_hiding_findings(self) -> None:
        path = self._seed(
            "{# dm-allow DM004 missing colon #}\n<p style='color: black'></p>\n"
            "{# dm-allow DM004: #}\n<p style='color: black'></p>\n"
            "{# dm-allow DM004: first #} {# dm-allow DM004: second #}\n<p style='color: black'></p>\n"
            "{# dm-allow BAD: reason #}\n<p style='color: black'></p>\n"
            "{# dm-allow DM004: missing terminator\n<p style='color: black'></p>\n"
        )
        findings = self._check(self.dm, path)
        self.assertEqual(
            [(v.line, v.severity) for v in findings if v.code == "DM006"],
            [(1, "warning"), (3, "warning"), (5, "warning"), (7, "warning"), (9, "warning")],
        )
        self.assertEqual(self._lines(findings, "DM004"), [2, 4, 6, 8, 10])

    def test_tmpl005_allow_is_scoped_and_checked(self) -> None:
        path = self._seed(
            "{# tmpl-allow TMPL005: Issue #605 keeps this status colour #}\n"
            '<span class="bg-green-100">Paid</span>\n'
            '<span class="bg-red-100">Unpaid</span>\n'
            "{# tmpl-allow TMPL005: obsolete status colour #}\n"
            '{% badge "Paid" variant="success" %}\n'
            "{# tmpl-allow TMPL005: #}\n"
            '<span class="bg-yellow-100">Pending</span>\n'
        )
        findings = self._scan(path)
        colours = [v for v in findings if v.code == "TMPL005"]
        self.assertEqual([(v.line, v.exempted) for v in colours], [(2, True), (3, False), (7, False)])
        self.assertEqual(colours[0].reason, "Issue #605 keeps this status colour")
        self.assertEqual(self._lines(findings, "TMPL_ALLOW_STALE"), [4])
        self.assertEqual(self._lines(findings, "TMPL_ALLOW_NO_REASON"), [6])
        self.assertEqual(self._lines(findings, "TMPL010"), [6])

    def test_tmpl005_allow_controls_the_requested_exit_code(self) -> None:
        marked = self._seed(
            '{# tmpl-allow TMPL005: intentional status colour #}\n<span class="bg-green-100">Paid</span>\n',
            name="marked.html",
        )
        unmarked = self._seed('<span class="bg-green-100">Paid</span>\n', name="unmarked.html")
        stale = self._seed(
            "{# tmpl-allow TMPL005: obsolete status colour #}\n<p>Paid</p>\n",
            name="stale.html",
        )
        main = cast(Callable[[], int], self.tmpl.main)
        for path, expected in ((marked, 0), (unmarked, 1), (stale, 1)):
            with (
                self.subTest(path=path.name),
                patch.object(
                    sys,
                    "argv",
                    [
                        "lint_template_components.py",
                        str(path),
                        "--fail-on",
                        "TMPL005,TMPL_ALLOW_STALE,TMPL_ALLOW_NO_REASON",
                    ],
                ),
            ):
                self.assertEqual(main(), expected)

    def test_tmpl_markers_support_both_placements_without_leaking(self) -> None:
        elements = {
            "TMPL001": '<input name="name">',
            "TMPL002": "<button>Open</button>",
            "TMPL003": "<select></select>",
            "TMPL004": "<textarea></textarea>",
            "TMPL005": '<span class="bg-green-100">Paid</span>',
        }
        for code, element in elements.items():
            marker = "{# tmpl-allow " + code + ": Issue #605 mentions <input> and bg-red-100 #}"
            for placement in ("above", "before", "after"):
                if placement == "above":
                    content = marker + "\n" + element * 2 + "\n" + element + "\n"
                    element_line = 2
                else:
                    marked = marker + element * 2 if placement == "before" else element * 2 + marker
                    content = marked + "\n" + element + "\n"
                    element_line = 1
                with self.subTest(code=code, placement=placement):
                    findings = self._scan(self._seed(content))
                    matching = [v for v in findings if v.code == code]
                    self.assertEqual(
                        [(v.line, v.exempted) for v in matching],
                        [(element_line, True), (element_line, False), (element_line + 1, False)],
                    )
                    self.assertEqual(
                        [v.code for v in findings if v.code in {"TMPL010", "TMPL_ALLOW_STALE", "TMPL_ALLOW_NO_REASON"}],
                        [],
                    )

    def test_audit_markers_support_both_placements_without_leaking(self) -> None:
        cases = (
            (self.a11y, "a11y-allow", "A11Y003", '<input name="name">'),
            (self.dm, "dm-allow", "DM004", '<p style="color: black"></p>'),
        )
        for module, prefix, code, element in cases:
            marker = "{# " + prefix + " " + code + ": Issue #605 mentions <input> and dark:bg-black #}"
            for placement in ("above", "before", "after"):
                if placement == "above":
                    content = marker + "\n" + element * 2 + "\n" + element + "\n"
                    element_line = 2
                else:
                    marked = marker + element * 2 if placement == "before" else element * 2 + marker
                    content = marked + "\n" + element + "\n"
                    element_line = 1
                with self.subTest(prefix=prefix, placement=placement):
                    findings = self._check(module, self._seed(content))
                    self.assertEqual(
                        [(v.code, v.line) for v in findings],
                        [(code, element_line), (code, element_line + 1)],
                    )

    def test_same_line_malformed_markers_warn_without_exempting(self) -> None:
        cases = (
            (self.tmpl, "tmpl-allow", "TMPL002", "TMPL010", "<button>Open</button>"),
            (self.a11y, "a11y-allow", "A11Y003", "A11Y011", '<input name="name">'),
            (self.dm, "dm-allow", "DM004", "DM006", '<p style="color: black"></p>'),
        )
        for module, prefix, code, warning, element in cases:
            markers = (
                "{# " + prefix + " " + code + ": intentional #}",
                "{# " + prefix + " " + code + ": #}",
                "{# " + prefix + " " + code + ": first #} {# " + prefix + " " + code + ": second #}",
                "{# " + prefix + " " + code + " missing colon #}",
            )
            content = "".join(element + marker + "\n" for marker in markers) + element + "\n"
            with self.subTest(prefix=prefix):
                path = self._seed(content)
                if module is self.tmpl:
                    template_findings = self._scan(path)
                    self.assertEqual(
                        [v.exempted for v in template_findings if v.code == code],
                        [True, False, False, False, False],
                    )
                    self.assertEqual(self._lines(template_findings, "TMPL_ALLOW_NO_REASON"), [2, 3])
                    self.assertEqual(self._lines(template_findings, "TMPL_ALLOW_STALE"), [])
                    findings: list[_Finding] = list(template_findings)
                else:
                    findings = self._check(module, path)
                    self.assertEqual(self._lines(findings, code), [2, 3, 4, 5])
                self.assertEqual(
                    [(v.line, v.severity) for v in findings if v.code == warning],
                    [(2, "warning"), (3, "warning"), (4, "warning")],
                )

    def test_tmpl007_distinguishes_external_scripts_from_inline_execution(self) -> None:
        path = self._seed(
            """<script src="{% static 'js/component.js' %}"></script>\n"""
            "<script\n"
            '  src="/static/js/component.js"></script>\n'
            "<script src=/static/js/component.js></script>\n"
            '<script type="application/json">{"enabled": true}</script>\n'
            "<script>window.inline = true;</script>\n"
            '<script src="/static/js/component.js"></script><script>window.other = true;</script>\n'
            '<script data-src="/static/js/component.js">window.stillInline = true;</script>\n'
            '<script src="/static/js/component.js">window.body = true;</script>\n'
            '<button onclick="window.inline = true;">Run</button>\n',
            name="components/scripts.html",
        )
        self.assertEqual(self._lines(self._scan(path), "TMPL007"), [6, 7, 8, 9, 10])

    def test_default_fail_sets_do_not_include_marker_warnings_or_minor_tables(self) -> None:
        a11y = self._seed("{# a11y-allow BAD: reason #}\n<table></table>\n", name="a11y.html")
        dm = self._seed("{# dm-allow BAD: reason #}\n<p>Plain</p>\n", name="dm.html")
        self.assertEqual(
            sorted((v.code, v.severity) for v in self._check(self.a11y, a11y)),
            [("A11Y008", "minor"), ("A11Y011", "warning")],
        )
        self.assertEqual([(v.code, v.severity) for v in self._check(self.dm, dm)], [("DM006", "warning")])
        for module, path in ((self.a11y, a11y), (self.dm, dm)):
            main = cast(Callable[[], int], module.main)
            with (
                self.subTest(script=module.__name__),
                patch.object(sys, "argv", [module.__name__, str(path), "--verbose"]),
            ):
                self.assertEqual(main(), 0)
