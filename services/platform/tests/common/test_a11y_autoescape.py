"""Source/render parity for component names inside nested autoescape blocks."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast
from unittest.mock import patch

from django.template import Context, Engine
from django.test import SimpleTestCase
from django.utils.translation import override

REPO_ROOT = Path(__file__).resolve().parents[4]


class _Finding(Protocol):
    code: str
    line: int


class ComponentAutoescapeTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.enterContext(patch.object(sys, "path", [str(REPO_ROOT), *sys.path]))
        spec = importlib.util.spec_from_file_location(
            "_autoescape_a11y", REPO_ROOT / "scripts" / "audit_accessibility.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        self.enterContext(patch.dict(sys.modules, {spec.name: module}))
        spec.loader.exec_module(module)
        self.check_file = cast(Callable[[Path], list[_Finding]], module.check_file)
        self.enterContext(override("en"))

    def _findings(self, content: str) -> list[_Finding]:
        # Mock only file I/O; exercise the public detector on source and real HTML.
        with patch.object(Path, "read_text", return_value=content):
            return self.check_file(REPO_ROOT / "autoescape-names.html")

    def _assert_parity(self, source: str, expected_lines: list[int]) -> None:
        expected_codes = ["A11Y003"] * len(expected_lines)
        for service in ("platform", "portal"):
            with self.subTest(service=service):
                engine = Engine(
                    dirs=[str(REPO_ROOT / "shared" / "ui" / "templates")],
                    libraries={
                        "ui_components": f"services.{service}.apps.ui.templatetags.ui_components",
                        "static": "django.templatetags.static",
                    },
                )
                rendered = engine.from_string("{% load ui_components %}" + source).render(Context({}))
                self.assertEqual([finding.code for finding in self._findings(rendered)], expected_codes)
                findings = self._findings(source)
                self.assertEqual([finding.code for finding in findings], expected_codes)
                self.assertEqual([finding.line for finding in findings], expected_lines)

    def test_autoescape_off_markup_only_label_matches_rendered_control(self) -> None:
        self._assert_parity(
            '{% autoescape off %}{% input_field "markup" label=""|default:"<b></b>"|upper %}'
            '{% input_field "named" label=""|default:"<b>Name</b>"|upper %}'
            '{% input_field "escaped" label=""|default:"<b></b>"|force_escape %}{% endautoescape %}',
            [1],
        )

    def test_autoescape_off_entity_only_aria_label_matches_rendered_control(self) -> None:
        self._assert_parity(
            '{% autoescape off %}{% input_field "entity" aria_label=""|default:"&#160;"|upper %}'
            '{% input_field "named" aria_label=""|default:"Name" %}'
            '{% input_field "escaped" aria_label=""|default:"&#160;"|force_escape %}{% endautoescape %}',
            [1],
        )

    def test_nested_autoescape_restores_parent_states_on_the_same_line(self) -> None:
        for key, value in (("label", "<b></b>"), ("aria_label", "&#160;")):
            with self.subTest(key=key):
                argument = key + '=""|default:"' + value + '"|upper'
                source = (
                    '{% input_field "initial" ' + argument + " %}"
                    "{% autoescape off %}"
                    '{% input_field "outer_off" ' + argument + " %}"
                    "{% autoescape on %}"
                    '{% input_field "inner_on" ' + argument + " %}"
                    "{% autoescape off %}"
                    '{% input_field "inner_off" ' + argument + " %}"
                    "{% endautoescape %}"
                    '{% input_field "restored_on" ' + argument + " %}"
                    "{% endautoescape %}"
                    '{% input_field "restored_off" ' + argument + " %}"
                    "{% endautoescape %}"
                    '{% input_field "restored_default" ' + argument + " %}"
                )
                self._assert_parity(source, [1, 1, 1])

    def test_comments_preserve_autoescape_state_and_finding_line(self) -> None:
        self._assert_parity(
            "{% autoescape off %}\n"
            "{# {% autoescape on %} #}\n"
            '{% input_field "markup" label=""|default:"<b></b>"|upper %}\n'
            "{% endautoescape %}\n"
            "{% autoescape   on %}\n"
            '{% input_field "escaped" label=""|default:"<b></b>"|upper %}\n'
            "{% endautoescape %}\n",
            [3],
        )

    def test_block_comments_do_not_change_autoescape_state(self) -> None:
        for mode, ignored_mode, expected_lines in (("on", "off", []), ("off", "on", [5])):
            for key, value in (("label", "<b></b>"), ("aria_label", "&#160;")):
                with self.subTest(mode=mode, key=key):
                    self._assert_parity(
                        "{% autoescape " + mode + " %}\n"
                        "{% comment ignored tags %}\n"
                        "{% autoescape " + ignored_mode + " %}\n"
                        "{% endcomment %}\n"
                        '{% input_field "control" ' + key + '=""|default:"' + value + '"|upper %}\n'
                        "{% endautoescape %}\n",
                        expected_lines,
                    )

    def test_verbatim_tags_do_not_change_autoescape_state(self) -> None:
        for block in ("verbatim", "verbatim example"):
            for mode, ignored_mode, expected_lines in (("on", "off", []), ("off", "on", [5])):
                with self.subTest(block=block, mode=mode):
                    self._assert_parity(
                        "{% autoescape " + mode + " %}\n"
                        "{% " + block + " %}\n"
                        "{% autoescape " + ignored_mode + " %}\n"
                        "{% end" + block + " %}\n"
                        '{% input_field "control" label=""|default:"<b></b>"|upper %}\n'
                        "{% endautoescape %}\n",
                        expected_lines,
                    )

    def test_variable_tag_literal_does_not_hide_the_next_component(self) -> None:
        self._assert_parity(
            '{{ "{%" }}\n{% input_field "unlabelled" %}\n{% input_field "named" label="Name" %}\n',
            [2],
        )

    def test_nested_autoescape_restores_states_after_ignored_tags(self) -> None:
        for block in ("comment", "verbatim example"):
            for key, value in (("label", "<b></b>"), ("aria_label", "&#160;")):
                with self.subTest(block=block, key=key):
                    argument = key + '=""|default:"' + value + '"|upper'
                    self._assert_parity(
                        "{% autoescape off %}\n"
                        '{% input_field "outer_off" ' + argument + " %}\n"
                        "{% autoescape on %}\n"
                        "{% " + block + " %}\n"
                        "{% autoescape off %}\n"
                        "{% end" + block + " %}\n"
                        '{% input_field "inner_on" ' + argument + " %}\n"
                        "{% autoescape off %}\n"
                        '{% input_field "inner_off" ' + argument + " %}\n"
                        "{% endautoescape %}\n"
                        '{% input_field "restored_on" ' + argument + " %}\n"
                        "{% endautoescape %}\n"
                        '{% input_field "restored_off" ' + argument + " %}\n"
                        "{% endautoescape %}\n"
                        '{% input_field "default_on" ' + argument + " %}\n",
                        [2, 9, 13],
                    )

    def test_comment_block_controls_are_not_checked(self) -> None:
        self._assert_parity(
            "{% comment %}\n"
            '{% input_field "ignored" %}\n'
            '<input name="ignored-raw">\n'
            "{% endcomment %}\n"
            '{% input_field "unlabelled" %}\n'
            '{% input_field "named" label="Name" %}\n',
            [5],
        )
