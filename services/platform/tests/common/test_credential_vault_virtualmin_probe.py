"""The credential check that precedes a Virtualmin rotation sends a command Virtualmin accepts.

`_test_credential` probed new Virtualmin credentials with `list-domains {"format": "json"}`. Virtualmin
8.3 refuses that ("Unknown parameter --format") with HTTP 200 and a failure envelope, and the check
treated any non-error result as a pass, so a refused probe read as "the credential works". The probe
now sends a parameter the command has, and only an explicit success counts.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.common.credential_vault import CredentialVault
from apps.common.types import Result
from tests.provisioning.test_cov_virtualmin_gateway_listing import http_response

# What the lab node (Virtualmin 8.3.0) answers to the two forms of the probe.
UNKNOWN_FORMAT = {
    "status": "failure",
    "command": "list-domains",
    "error": "Unknown parameter --format",
}
DOMAIN_LISTING = {"status": "success", "command": "list-domains", "data": []}
ACCESS_DENIED = {"status": "failure", "command": "list-domains", "error": "Access denied"}


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class VirtualminCredentialProbeTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.sent: list[dict[str, object]] = []

    def _virtualmin(self, accepted: dict[str, object]) -> AbstractContextManager[object]:
        """A transport that refuses the old `format` parameter like the real node and answers `accepted` otherwise."""

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("dict[str, object]", kwargs["params"])
            self.sent.append(params)
            return http_response(UNKNOWN_FORMAT if "format" in params else accepted)

        return patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport)

    def _probe(self) -> Result[bool, str]:
        return CredentialVault()._test_credential("virtualmin", "node.example.com", "api-user", "api-password")

    def test_the_probe_sends_no_parameter_virtualmin_refuses(self) -> None:
        with self._virtualmin(DOMAIN_LISTING):
            result = self._probe()

        self.assertEqual([params["program"] for params in self.sent], ["list-domains"])
        self.assertNotIn("format", self.sent[0])
        self.assertTrue(result.is_ok())

    def test_a_refused_probe_is_not_a_working_credential(self) -> None:
        with self._virtualmin(ACCESS_DENIED):
            result = self._probe()

        self.assertTrue(result.is_err())
