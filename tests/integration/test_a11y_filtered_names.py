"""Regression coverage for filtered component names in source and rendered HTML."""

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

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Finding(Protocol):
    code: str


class FilteredComponentNameTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        spec = importlib.util.spec_from_file_location(
            "_filtered_names_a11y", REPO_ROOT / "scripts" / "audit_accessibility.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        self.enterContext(patch.dict(sys.modules, {spec.name: module}))
        spec.loader.exec_module(module)
        self.check_file = cast(Callable[[Path], list[_Finding]], module.check_file)
        self.enterContext(override("en"))

    def _codes(self, content: str) -> list[str]:
        # Mock only file I/O; exercise the actual public detector entry point.
        with patch.object(Path, "read_text", return_value=content):
            return [finding.code for finding in self.check_file(REPO_ROOT / "filtered-names.html")]

    def _assert_cases(self, cases: tuple[tuple[str, str | None, bool], ...]) -> None:
        for service in ("platform", "portal"):
            engine = Engine(
                dirs=[str(REPO_ROOT / "shared" / "ui" / "templates")],
                libraries={
                    "ui_components": f"services.{service}.apps.ui.templatetags.ui_components",
                    "static": "django.templatetags.static",
                },
            )
            for key in ("label", "aria_label"):
                for value, name, source_has_name in cases:
                    source = '{% input_field "control" ' + key + "=" + value + " %}"
                    rendered = engine.from_string("{% load ui_components %}" + source).render(
                        Context({"caption": "Name"})
                    )
                    with self.subTest(service=service, key=key, value=value, kind="rendered"):
                        self.assertEqual(self._codes(rendered), [] if name is not None else ["A11Y003"])
                        if name is not None:
                            self.assertIn(name, rendered)
                            if key == "aria_label":
                                self.assertIn('aria-label="' + name + '"', rendered)
                    with self.subTest(service=service, key=key, value=value, kind="source"):
                        self.assertEqual(self._codes(source), [] if source_has_name else ["A11Y003"])

    def test_erasing_filters_are_flagged_and_capfirst_preserves_names(self) -> None:
        self._assert_cases(
            (
                ('"Name"|cut:"Name"', None, False),
                ('"Name"|slice:":0"', None, False),
                ("'Name'|slice:':0'", None, False),
                ('_("Name")|cut:"Name"', None, False),
                ('"Name"|lower|cut:"name"|capfirst', None, False),
                ('"name"|capfirst', "Name", True),
                ('_("name")|capfirst', "Name", True),
                ('"Name|Surname"|lower|capfirst', "Name|surname", True),
                # Even a non-erasing use is outside the literal allowlist.
                ('"Name"|cut:"x"', "Name", False),
                ("caption", "Name", True),
                ("caption|capfirst", "Name", True),
            )
        )

    def test_allowlisted_filters_check_text_after_stripping(self) -> None:
        self._assert_cases(
            (
                ('"<b></b>"|striptags', None, False),
                ('"<b> </b>"|striptags|capfirst', None, False),
                ('"<b></b>"|safe|escape|striptags', None, False),
                ('"<b>Name</b>"|striptags|capfirst', "Name", True),
                ('"Name"|lower', "name", True),
                ('"name"|upper', "NAME", True),
                ('"full name"|title', "Full Name", True),
                ('"Name"|escape', "Name", True),
                ('"Name"|force_escape', "Name", True),
                ('"Name"|safe', "Name", True),
                ('"<b></b>"|force_escape|striptags', "&lt;b&gt;&lt;/b&gt;", True),
            )
        )

    def test_default_requires_a_nonblank_literal_fallback(self) -> None:
        self._assert_cases(
            (
                ('""|default:"Name"|capfirst', "Name", True),
                ('""|default:_("Name")', "Name", True),
                ('"<b></b>"|striptags|default:"Name"', "Name", True),
                ('"Name"|default:"use as name|fallback"|capfirst', "Name", True),
                ('""|default:""', None, False),
                ('""|default:" "', None, False),
                ('" "|default:"Name"', None, False),
                ('"Name"|default:""', "Name", False),
                ('""|default:caption', "Name", False),
                ('""|default:"Name"|slice:":0"', None, False),
            )
        )
