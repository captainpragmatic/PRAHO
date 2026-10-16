"""The registration page offers to fill in a company's details from ANAF's register.

The button and /company-lookup/ exist only while Platform's public defaults offer the lookup, so
the portal never needs to know the operator's country. The lookup needs a solved proof-of-work
while ALTCHA is on, like the registration itself.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from altcha import Challenge, Payload, solve_challenge
from django.test import TestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.common import altcha
from apps.common.localisation import LocalisationDefaults
from apps.common.localisation_services import _validated_payload

COMPANY = {"cui": "14399840", "name": "DANTE INTERNATIONAL SA", "vat_number": "RO14399840"}


def solved() -> str:
    challenge = Challenge.from_dict(altcha.new_challenge())
    solution = solve_challenge(challenge)
    assert solution is not None
    return Payload(challenge, solution).to_base64()


def offered(available: bool) -> Any:
    return patch("apps.users.views.company_lookup_available", return_value=available)


class CompanyLookupViewTests(TestCase):
    url = "/company-lookup/"

    def post(self, data: dict[str, str], result: dict[str, Any] | Exception | None = None) -> tuple[Any, MagicMock]:
        with offered(True), patch("apps.users.views.api_client.company_lookup") as lookup:
            if isinstance(result, Exception):
                lookup.side_effect = result
            else:
                lookup.return_value = result or {}
            return self.client.post(self.url, data), lookup

    def test_absent_unless_platform_offers_it(self) -> None:
        with offered(False):
            self.assertEqual(self.client.post(self.url, {"cui": "14399840"}).status_code, 404)

    def test_a_found_company_is_returned_for_the_form(self) -> None:
        response, lookup = self.post({"cui": "RO 14399840"}, {"available": True, "found": True, "company": COMPANY})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"company": COMPANY})
        self.assertEqual(lookup.call_args.args, ("14399840",))

    def test_not_found_unavailable_busy_and_invalid(self) -> None:
        cases = [
            ({"available": True, "found": False}, 404),
            ({"available": False}, 503),
            (PlatformAPIError("busy", status_code=429), 429),
            (PlatformAPIError("refused", status_code=400), 400),
        ]
        for result, status in cases:
            with self.subTest(status=status):
                response, _ = self.post({"cui": "14399840"}, result)
                self.assertEqual(response.status_code, status)
                self.assertTrue(response.json()["error"])
        response, lookup = self.post({"cui": "not a cui"})
        self.assertEqual(response.status_code, 400)
        lookup.assert_not_called()

    @override_settings(ALTCHA_ENABLED=True, ALTCHA_COST=1)
    def test_needs_a_solved_proof_of_work_once(self) -> None:
        found = {"available": True, "found": True, "company": COMPANY}
        response, lookup = self.post({"cui": "14399840"}, found)
        self.assertEqual(response.status_code, 400)
        lookup.assert_not_called()
        payload = solved()
        self.assertEqual(self.post({"cui": "14399840", "altcha": payload}, found)[0].status_code, 200)
        self.assertEqual(self.post({"cui": "14399840", "altcha": payload}, found)[0].status_code, 400)


class CompanyLookupButtonTests(TestCase):
    def test_the_registration_page_shows_the_button_only_when_offered(self) -> None:
        for available in (True, False):
            with self.subTest(available=available), offered(available):
                page = self.client.get("/register/").content.decode()
                self.assertIs("company-lookup-button" in page, available)
                self.assertIs("js/company-lookup.js" in page, available)


PAYLOAD: dict[str, Any] = {
    "success": True,
    "localisation": LocalisationDefaults().customer_payload(),
    "company": {
        "legal_name": "Example SRL",
        "email_support": "support@example.com",
        "email_privacy": "privacy@example.com",
        "email_finance": "",
        "phone": "",
    },
}


class PublicDefaultsFeaturesTests(TestCase):
    def test_an_older_platform_without_features_offers_none(self) -> None:
        self.assertEqual(_validated_payload(PAYLOAD)["features"], {"company_lookup": False})

    def test_offered_features_are_read_and_anything_else_is_refused(self) -> None:
        self.assertEqual(
            _validated_payload({**PAYLOAD, "features": {"company_lookup": True}})["features"],
            {"company_lookup": True},
        )
        for features in ({"company_lookup": "yes"}, {"unknown": True}, ["company_lookup"]):
            with self.subTest(features=features), self.assertRaises(ValueError):
                _validated_payload({**PAYLOAD, "features": features})
