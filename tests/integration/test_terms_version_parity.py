"""Both services name the same Terms of Service version, and it moves with the text.

Platform records the version a customer accepts; the portal shows it on /terms/. Neither can
import the other (service isolation), so each keeps a copy in apps/common/legal.py, read here
with `ast`. The text both pages render is one shared template and its Romanian translations, pinned by hash: changing it
without a new version would let customers accept different terms under an old version.
"""

import ast
import hashlib
from pathlib import Path
from unittest import TestCase

import polib

REPO_ROOT = Path(__file__).resolve().parents[2]
TERMS_TEXT = REPO_ROOT / "shared" / "ui" / "templates" / "legal" / "terms_of_service_content.html"
SHARED_PO = REPO_ROOT / "shared" / "ui" / "locale" / "ro" / "LC_MESSAGES" / "django.po"
VERSION_MODULES = {
    service: REPO_ROOT / "services" / service / "apps" / "common" / "legal.py" for service in ("platform", "portal")
}

# The text the current version names, Romanian translations included. On a change to either:
# bump TERMS_OF_SERVICE_VERSION in both services, then record the new hash here.
TERMS_TEXT_SHA256 = {"2024-12-27": "94b4461411cd827c871635220564f04743e89e2172a622a6885f07326ebcf451"}


def _terms_text_digest() -> str:
    """The template and its Romanian translations: what a customer accepts, in either language.

    Line endings are dropped from the template, so a CRLF checkout hashes the same text.
    """
    digest = hashlib.sha256(TERMS_TEXT.read_bytes().replace(b"\r", b""))
    for entry in sorted(
        (
            e
            for e in polib.pofile(str(SHARED_PO))
            if not e.obsolete and any(TERMS_TEXT.name in f for f, _ in e.occurrences)
        ),
        key=lambda e: (e.msgctxt or "", e.msgid),
    ):
        digest.update(f"\0{entry.msgctxt or ''}\0{entry.msgid}\0{entry.msgstr}".encode())
    return digest.hexdigest()


def _version(path: Path) -> str:
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "TERMS_OF_SERVICE_VERSION" for t in node.targets
        ):
            value = ast.literal_eval(node.value)
            assert isinstance(value, str)
            return value
    raise AssertionError(f"TERMS_OF_SERVICE_VERSION is not assigned at module level in {path}")


class TermsVersionParityTests(TestCase):
    def test_both_services_name_the_same_version(self) -> None:
        self.assertEqual(_version(VERSION_MODULES["portal"]), _version(VERSION_MODULES["platform"]))

    def test_the_terms_text_is_the_text_its_version_names(self) -> None:
        version = _version(VERSION_MODULES["platform"])
        self.assertIn(version, TERMS_TEXT_SHA256, "a new version needs its text hash recorded")
        self.assertEqual(
            _terms_text_digest(),
            TERMS_TEXT_SHA256[version],
            "the terms text changed: bump TERMS_OF_SERVICE_VERSION in both services",
        )
