"""The portal's password-length checks must match what the Platform enforces (#557).

The portal cannot import Platform settings (service isolation), so its forms carry their
own copy of the minimum. The change-password form drifted to 8 while the Platform
required 12, and customers were told a shorter password was fine. Both values are read
from source with `ast` because the two halves cannot be imported into one process.
"""

import ast
from pathlib import Path
from unittest import TestCase

REPO_ROOT = Path(__file__).resolve().parents[2]
PLATFORM_SETTINGS = REPO_ROOT / "services" / "platform" / "config" / "settings" / "base.py"
PORTAL_FORMS = REPO_ROOT / "services" / "portal" / "apps" / "users" / "forms.py"


def _assigned_value(path: Path, name: str) -> object:
    for node in ast.parse(path.read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not assigned at module level in {path}")


def _platform_min_length() -> int:
    validators = _assigned_value(PLATFORM_SETTINGS, "AUTH_PASSWORD_VALIDATORS")
    assert isinstance(validators, list)
    for validator in validators:
        if validator["NAME"].endswith(".MinimumLengthValidator"):
            return int(validator["OPTIONS"]["min_length"])
    raise AssertionError("the Platform no longer configures MinimumLengthValidator")


class TestPasswordMinimumLengthParity(TestCase):
    def test_portal_minimum_matches_the_platform_validator(self) -> None:
        self.assertEqual(_assigned_value(PORTAL_FORMS, "REGISTRATION_PASSWORD_MIN_LENGTH"), _platform_min_length())
