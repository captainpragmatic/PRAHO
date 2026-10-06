"""Shared catalog ownership and cross-service collision guards."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import polib
from django.test import SimpleTestCase
from django.utils.translation.template import templatize

ROOT = Path(__file__).resolve().parents[4]
SHARED_PO = ROOT / "shared/ui/locale/ro/LC_MESSAGES/django.po"
_LITERAL = r"""u?(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
_MESSAGES = re.compile(rf"\b(gettext|_|pgettext)\(({_LITERAL})(?:,\s*({_LITERAL}))?\)", re.DOTALL)
MessageKey = tuple[str | None, str]
_BLOCK_MESSAGE = "\n            %(start_index)s\u2013%(end_index)s of %(count)s results\n          "


def _decode(literal: str) -> str:
    value: object = ast.literal_eval(literal)
    if not isinstance(value, str):
        raise AssertionError(f"Non-string translation: {literal}")
    return value


def _shared_msgids() -> set[MessageKey]:
    messages: set[MessageKey] = set()
    for path in (ROOT / "shared/ui/templates").rglob("*.html"):
        for function, first, second in _MESSAGES.findall(templatize(path.read_text(encoding="utf-8"))):
            if function == "pgettext":
                messages.add((_decode(first), _decode(second)))
            else:
                messages.add((None, _decode(first)))
    return messages


def _entries(path: Path) -> dict[MessageKey, polib.POEntry]:
    return {(entry.msgctxt, entry.msgid): entry for entry in polib.pofile(str(path)) if not entry.obsolete}


class SharedCatalogTests(SimpleTestCase):
    def test_catalog_covers_every_shared_template_msgid(self) -> None:
        messages = _shared_msgids()
        self.assertEqual(len(list((ROOT / "shared/ui/templates").rglob("*.html"))), 25)
        self.assertEqual(len(messages), 28)  # badge "Close" shares the modal msgid
        self.assertTrue(SHARED_PO.is_file(), "Shared Romanian catalog is missing")
        self.assertIn((None, _BLOCK_MESSAGE), messages)
        self.assertIn(("form action", "Save"), messages)
        self.assertIn((None, "Toggle section"), messages)
        entries = _entries(SHARED_PO)
        for message in sorted(messages, key=lambda key: (key[0] or "", key[1])):
            with self.subTest(message=message):
                self.assertIn(message, entries)
                self.assertTrue(entries[message].msgstr.strip(), "Romanian translation is empty")
                self.assertNotIn("fuzzy", entries[message].flags)

    def test_service_duplicates_match_the_shared_translation(self) -> None:
        messages = _shared_msgids()
        platform = _entries(ROOT / "services/platform/locale/ro/LC_MESSAGES/django.po")
        portal = _entries(ROOT / "services/portal/locale/ro/LC_MESSAGES/django.po")
        for message in sorted(messages & platform.keys() & portal.keys(), key=lambda key: (key[0] or "", key[1])):
            with self.subTest(message=message):
                self.assertEqual(platform[message].msgstr, portal[message].msgstr)
        self.assertTrue(SHARED_PO.is_file(), "Shared Romanian catalog is missing")
        shared = _entries(SHARED_PO)
        for service, entries in (("platform", platform), ("portal", portal)):
            for message in sorted(messages & entries.keys(), key=lambda key: (key[0] or "", key[1])):
                with self.subTest(service=service, message=message):
                    self.assertIn(message, shared)
                    self.assertEqual(entries[message].msgstr, shared[message].msgstr)
                    self.assertNotIn("fuzzy", entries[message].flags)
