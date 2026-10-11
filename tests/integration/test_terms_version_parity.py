"""Both services name the same Terms of Service version, and it moves with the text.

Platform records the version a customer accepts; the portal shows it on /terms/. Neither can
import the other (service isolation), so each keeps a copy in apps/common/legal.py, read here
with `ast`. The text both pages render is one shared template, pinned by hash: changing it
without a new version would let customers accept different terms under an old version.
"""

import ast
import hashlib
from pathlib import Path
from unittest import TestCase

REPO_ROOT = Path(__file__).resolve().parents[2]
TERMS_TEXT = REPO_ROOT / "shared" / "ui" / "templates" / "legal" / "terms_of_service_content.html"
VERSION_MODULES = {
    service: REPO_ROOT / "services" / service / "apps" / "common" / "legal.py" for service in ("platform", "portal")
}

# The text the current version names. On a change to the terms: bump TERMS_OF_SERVICE_VERSION
# in both services, then record the new hash here.
TERMS_TEXT_SHA256 = {"2024-12-27": "0bdf13c4fbc931d09774de5a2c30205cdc06a8affc4c46fa6b4be48cfe9a12d6"}


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
            hashlib.sha256(TERMS_TEXT.read_bytes()).hexdigest(),
            TERMS_TEXT_SHA256[version],
            "the terms text changed: bump TERMS_OF_SERVICE_VERSION in both services",
        )
