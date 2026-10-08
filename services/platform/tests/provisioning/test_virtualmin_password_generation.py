"""Generated Virtualmin account passwords always pass the API parameter validator.

The password travels to Virtualmin as an API parameter, and every parameter value is checked
against the injection heuristics in SecureInputValidator. A random password containing "--" (an
SQL-comment heuristic) used to be rejected there, failing about 1 in 350 provisions permanently.
"""

from collections.abc import Iterator
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.common.validators import SecureInputValidator
from apps.provisioning.virtualmin_service import VirtualminProvisioningService


class _ScriptedSecrets:
    """A secrets stand-in whose choice() returns scripted characters and whose shuffle keeps order."""

    def __init__(self, characters: str) -> None:
        self._characters: Iterator[str] = iter(characters)

    def choice(self, _population: str) -> str:
        return next(self._characters)

    def SystemRandom(self) -> "_ScriptedSecrets":  # noqa: N802 -- mirrors secrets.SystemRandom
        return self

    def shuffle(self, _items: list[str]) -> None:
        return None


class VirtualminPasswordGenerationTests(SimpleTestCase):
    def setUp(self) -> None:
        self.service = VirtualminProvisioningService.__new__(VirtualminProvisioningService)

    def test_a_candidate_the_parameter_validator_rejects_is_regenerated(self) -> None:
        rejected = "aA1--bbbbbbbbbbb"  # "--" trips the SQL-comment heuristic
        accepted = "cC2!dddddddddddd"
        # A discarded candidate is not an attack: it must not raise a security alert
        with (
            patch("apps.provisioning.virtualmin_service.secrets", _ScriptedSecrets(rejected + accepted)),
            self.assertNoLogs("apps.common.validators", level="WARNING"),
        ):
            password = self.service._generate_secure_password()

        self.assertEqual(password, accepted)

    def test_every_generated_password_passes_the_parameter_validator(self) -> None:
        for _ in range(2000):
            password = self.service._generate_secure_password()
            SecureInputValidator._check_malicious_patterns(password)
            self.assertEqual(len(password), 16)
