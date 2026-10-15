"""ANAF company lookup: recorded v9 answers, caching, call spacing and the transport switch.

The fixtures are ANAF's own answers (tests/billing/fixtures/PROVENANCE.md). ANAF answers a
request with nothing found with HTTP 404 and its ordinary body, which is an answer, not an outage.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from requests import HTTPError

from apps.billing.gateways.anaf_gateway import ANAF_API_URL, ANAF_POLICY, AnafGateway

FIXTURES = Path(__file__).parent / "fixtures"
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
FOUND = "14399840"
UNKNOWN = "99999992"


def recorded(name: str, status: int) -> MagicMock:
    """ANAF's recorded answer; raise_for_status() raises for an error status, as requests does."""
    response = MagicMock(status_code=status)
    response.json.return_value = json.loads((FIXTURES / name).read_text())
    if status >= 400:
        response.raise_for_status.side_effect = HTTPError(f"{status}")
    return response


@override_settings(ANAF_TRANSPORT_ENABLED=True, CACHES=LOCMEM)
class AnafGatewayTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def lookup(self, cuis: list[str], response: MagicMock) -> tuple[Any, MagicMock]:
        with (
            patch("apps.billing.gateways.anaf_gateway.safe_request", return_value=response) as request,
            patch("apps.common.counters.claim", return_value=True),
        ):
            return AnafGateway.lookup(cuis), request

    def test_parses_recorded_v9_found_and_notfound_and_never_connects_when_transport_disabled(self) -> None:
        result, request = self.lookup([f"RO{FOUND}", UNKNOWN], recorded("anaf_v9_found.json", 200))
        self.assertTrue(result.api_available)
        company = result.companies[FOUND]
        self.assertEqual(company.name, "DANTE INTERNATIONAL SA")
        self.assertEqual(company.registration_number, "J2002000372404")
        self.assertTrue(company.vat_registered)
        self.assertTrue(company.active)
        self.assertEqual((company.city, company.county, company.postal_code), (
            "Sector 6 Mun. Bucureşti", "MUNICIPIUL BUCUREŞTI", "60787"
        ))
        self.assertEqual(company.street, "Şos. Virtuţii 148, spatiul E47")
        self.assertEqual(result.not_found, frozenset({UNKNOWN}))
        args, kwargs = request.call_args
        self.assertEqual(args, ("POST", ANAF_API_URL))
        self.assertIs(kwargs["policy"], ANAF_POLICY)
        self.assertEqual([entry["cui"] for entry in kwargs["json"]], [int(FOUND), int(UNKNOWN)])

        cache.clear()
        result, _ = self.lookup([UNKNOWN], recorded("anaf_v9_not_found.json", 404))
        self.assertTrue(result.api_available, "a 404 carrying ANAF's answer is not an outage")
        self.assertEqual((result.companies, result.not_found), ({}, frozenset({UNKNOWN})))

        cache.clear()
        with override_settings(ANAF_TRANSPORT_ENABLED=False):
            result, request = self.lookup([FOUND], recorded("anaf_v9_found.json", 200))
        request.assert_not_called()
        self.assertFalse(result.api_available)

    def test_answers_are_cached_and_a_cached_lookup_never_connects(self) -> None:
        self.lookup([FOUND, UNKNOWN], recorded("anaf_v9_found.json", 200))
        result, request = self.lookup([FOUND, UNKNOWN], MagicMock(status_code=500))
        request.assert_not_called()
        self.assertEqual((set(result.companies), result.not_found), ({FOUND}, frozenset({UNKNOWN})))

    def test_an_outage_or_an_unanswered_cui_is_unavailable_and_not_cached(self) -> None:
        down = MagicMock(status_code=503)
        down.raise_for_status.side_effect = RuntimeError("503")
        result, _ = self.lookup([FOUND], down)
        self.assertFalse(result.api_available)
        # ANAF answered, but not for this CUI.
        result, _ = self.lookup(["18547290"], recorded("anaf_v9_found.json", 200))
        self.assertFalse(result.api_available)
        self.assertIsNone(cache.get("anaf:18547290"))

    def test_calls_are_spaced_at_least_a_second_apart(self) -> None:
        with patch("apps.billing.gateways.anaf_gateway.safe_request", return_value=recorded("anaf_v9_found.json", 200)):
            first = AnafGateway.lookup([FOUND])
            second = AnafGateway.lookup(["18547290"])
        self.assertTrue(first.api_available)
        self.assertTrue(second.rate_limited)
        self.assertFalse(second.api_available)

    def test_refuses_an_invalid_cui_or_more_than_a_hundred(self) -> None:
        for cuis in (["14399841"], [FOUND] * 101):
            with self.subTest(count=len(cuis)), self.assertRaises(ValueError):
                AnafGateway.lookup(cuis)
