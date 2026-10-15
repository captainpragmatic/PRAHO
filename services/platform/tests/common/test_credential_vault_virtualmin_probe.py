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
from tests.helpers.recorded_virtualmin import recorded_http_response

# What the lab node (Virtualmin 8.3.0) answered in the contract suite: list-domains with name-only is
# accepted, with format it is refused ("Unknown parameter --format"), and a refusal of any kind is a
# 200 failure envelope.


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class VirtualminCredentialProbeTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.sent: list[dict[str, object]] = []

    def _virtualmin(self, accepted_case: str) -> AbstractContextManager[object]:
        """A transport that refuses the old `format` parameter like the real node and answers `accepted_case` otherwise."""

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("dict[str, object]", kwargs["params"])
            self.sent.append(params)
            return recorded_http_response("list-domains", "unknown_parameter" if "format" in params else accepted_case)

        return patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport)

    def _probe(self) -> Result[bool, str]:
        return CredentialVault()._test_credential("virtualmin", "node.example.com", "api-user", "api-password")

    def test_the_probe_sends_no_parameter_virtualmin_refuses(self) -> None:
        with self._virtualmin("name_only"):
            result = self._probe()

        self.assertEqual([params["program"] for params in self.sent], ["list-domains"])
        self.assertNotIn("format", self.sent[0])
        self.assertTrue(result.is_ok())

    def test_a_refused_probe_is_not_a_working_credential(self) -> None:
        with self._virtualmin("absent_domain"):
            result = self._probe()

        self.assertTrue(result.is_err())
