"""Accessibility diagnostics require a located token before using its line number."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast
from unittest.mock import patch

from django.template.base import Token, TokenType
from django.test import SimpleTestCase

REPO_ROOT = Path(__file__).resolve().parents[4]


class _Finding(Protocol):
    code: str
    line: int


class TokenLineTests(SimpleTestCase):
    def setUp(self) -> None:
        super().setUp()
        spec = importlib.util.spec_from_file_location(
            "_token_lines_a11y", REPO_ROOT / "scripts" / "audit_accessibility.py"
        )
        assert spec is not None and spec.loader is not None
        self.module = importlib.util.module_from_spec(spec)
        self.enterContext(patch.dict(sys.modules, {spec.name: self.module}))
        spec.loader.exec_module(self.module)
        self.form_source = cast(Callable[[list[Token]], str], self.module._form_label_source)
        self.check_labels = cast(Callable[[str, Path], list[_Finding]], self.module._check_form_labels)

    def test_unlocated_html_is_ignored_without_shifting_located_html(self) -> None:
        tokens = [
            Token(TokenType.TEXT, '<input name="unlocated">', lineno=None),
            Token(TokenType.TEXT, '<input name="located">', lineno=3),
        ]
        try:
            source = self.form_source(tokens)
        except TypeError:
            self.fail("Tokens without a line number must be ignored when reconstructing form HTML.")
        self.assertEqual(source, '\n\n<input name="located">')

    def test_unlocated_component_is_ignored_but_located_violation_is_retained(self) -> None:
        tokens = [
            (Token(TokenType.BLOCK, 'input_field "unlocated"', lineno=None), True),
            (Token(TokenType.BLOCK, 'input_field "located"', lineno=3), True),
        ]
        with patch.object(self.module, "_component_fields_with_autoescape", return_value=iter(tokens)):
            findings = self.check_labels('\n\n{% input_field "located" %}', REPO_ROOT / "token-lines.html")
        self.assertEqual([(finding.code, finding.line) for finding in findings], [("A11Y003", 3)])
