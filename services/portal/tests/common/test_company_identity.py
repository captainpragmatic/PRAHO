"""Public company identity and localisation share one validated payload cache."""

from __future__ import annotations

import re
import time
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.sessions.backends.base import SessionBase
from django.template import engines
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, override_settings
from django.utils.translation import override

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.localisation import LocalisationDefaults
from apps.common.localisation_services import get_localisation_defaults

CATALOG_COMPANY = {
    "legal_name": "PragmaticHost SRL",
    "email_support": "support@pragmatichost.com",
    "email_privacy": "privacy@pragmatichost.com",
    "email_finance": "",
    "phone": "",
}
CONFIGURED_COMPANY = {
    "legal_name": "Portal Identity SRL",
    "email_support": "support-identity@example.test",
    "email_privacy": "privacy-identity@example.test",
    "email_finance": "finance-identity@example.test",
    "phone": "+40721123456",
}
CONTACT_TEMPLATES = {
    "403.html": ("email_support",),
    "404.html": ("email_support",),
    "500.html": ("email_support",),
    "billing/proforma_detail.html": ("email_support",),
    "legal/cookie_policy.html": ("email_privacy",),
    "orders/order_confirmation.html": ("email_support",),
    "services/service_detail.html": ("email_support", "email_finance"),
    "services/service_request_action.html": ("email_support",),
    "users/mfa_management.html": ("email_support",),
    "users/privacy_dashboard.html": ("email_privacy",),
}
RAW_CONTROL = re.compile(
    r"<(?:button|select|textarea)\b|<input\b(?![^>]*type=(?:['\"]hidden['\"]|hidden\b))",
    re.IGNORECASE,
)


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class PortalCompanyIdentityTests(SimpleTestCase):
    def setUp(self) -> None:
        from django.core.cache import cache  # noqa: PLC0415

        cache.clear()
        self.addCleanup(cache.clear)
        self.cache = cache

    def payload(self, *, country: str = "DE", company: dict[str, str] | None = None) -> dict[str, object]:
        return {
            "success": True,
            "localisation": {**LocalisationDefaults().customer_payload(), "default_country": country},
            "company": dict(CONFIGURED_COMPANY if company is None else company),
        }

    def identity_text(self) -> str:
        request = RequestFactory().get("/")
        request.session = SessionBase()
        template = engines["django"].from_string(
            "{{ company.legal_name }}|{{ company.email_support }}|{{ company.email_privacy }}|"
            "{{ company.email_finance }}|{{ company.phone }}"
        )
        return template.render({}, request=request)

    def assert_identity(self, expected: dict[str, str]) -> None:
        self.assertEqual(self.identity_text(), "|".join(expected.values()))

    def test_cold_outage_uses_the_mirrored_catalog_defaults(self) -> None:
        with patch.object(api_client, "get_localisation_defaults", side_effect=PlatformAPIError("offline")):
            self.assert_identity(CATALOG_COMPANY)
            self.assertEqual(
                get_localisation_defaults().customer_payload(),
                LocalisationDefaults().customer_payload(),
            )
        self.assertEqual(settings.COMPANY_IDENTITY_DEFAULTS, CATALOG_COMPANY)

    def test_success_and_warm_cache_share_both_blocks_until_sixty_seconds(self) -> None:
        now = time.time()
        changed = {**CONFIGURED_COMPANY, "legal_name": "Refreshed Identity SRL"}
        with patch.object(
            api_client,
            "get_localisation_defaults",
            side_effect=[self.payload(), self.payload(country="FR", company=changed)],
        ):
            with patch("time.time", return_value=now):
                self.assertEqual(get_localisation_defaults().default_country, "DE")
                self.assert_identity(CONFIGURED_COMPANY)
            with patch("time.time", return_value=now + 59):
                self.assert_identity(CONFIGURED_COMPANY)
                self.assertEqual(get_localisation_defaults().default_country, "DE")
            with patch("time.time", return_value=now + 60):
                self.assert_identity(changed)
                self.assertEqual(get_localisation_defaults().default_country, "FR")

    def test_last_good_survives_outage_but_expires_without_sliding(self) -> None:
        now = time.time()
        with patch.object(api_client, "get_localisation_defaults", return_value=self.payload()) as reader:
            with patch("time.time", return_value=now):
                self.assertEqual(get_localisation_defaults().default_country, "DE")
                self.assert_identity(CONFIGURED_COMPANY)
            reader.side_effect = PlatformAPIError("offline")
            for elapsed in (60, 3540):
                with self.subTest(elapsed=elapsed), patch("time.time", return_value=now + elapsed):
                    self.assert_identity(CONFIGURED_COMPANY)
                    self.assertEqual(get_localisation_defaults().default_country, "DE")
            with patch("time.time", return_value=now + 3600):
                self.assert_identity(CATALOG_COMPANY)
                self.assertEqual(get_localisation_defaults().default_country, "RO")

    def test_malformed_payload_cannot_replace_either_last_good_block(self) -> None:
        valid = self.payload()
        corruptions: list[dict[str, object]] = []

        missing_company = self.payload(country="FR")
        del missing_company["company"]
        corruptions.append(missing_company)
        corruptions.append(
            self.payload(country="FR", company={**CONFIGURED_COMPANY, "email_noreply": "private@example.test"})
        )
        corruptions.append(self.payload(country="FR", company={**CONFIGURED_COMPANY, "email_support": "not-an-email"}))
        corruptions.append(
            {
                "success": True,
                "localisation": {**LocalisationDefaults().customer_payload(), "default_country": "FR"},
                "company": {**CONFIGURED_COMPANY, "phone": 123},
            }
        )
        corruptions.append({"success": True, "localisation": {}, "company": CONFIGURED_COMPANY})
        corruptions.append({"success": False, **{key: value for key, value in valid.items() if key != "success"}})

        now = time.time()
        for malformed in corruptions:
            with self.subTest(payload=malformed):
                self.cache.clear()
                with patch.object(api_client, "get_localisation_defaults", side_effect=[deepcopy(valid), malformed]):
                    with patch("time.time", return_value=now):
                        self.assertEqual(get_localisation_defaults().default_country, "DE")
                    with patch("time.time", return_value=now + 60):
                        self.assertEqual(get_localisation_defaults().default_country, "DE")
                        self.assert_identity(CONFIGURED_COMPANY)

    def test_each_contact_template_renders_configured_identity_in_en_and_ro(self) -> None:
        self.assertEqual(len(CONTACT_TEMPLATES), 10)
        self.assertIn("users/privacy_dashboard.html", CONTACT_TEMPLATES)
        context: dict[str, object] = {
            "service_id": 42,
            "service": {"status": "active", "service_name": "Identity test"},
            "proforma": {
                "number": "PF-2099-0001",
                "status": "draft",
                "currency": {"code": "EUR"},
                "subtotal_cents": 10000,
                "tax_cents": 2100,
                "total_cents": 12100,
            },
            "order": {"status": "completed", "order_number": "ORDER-2099-0001"},
            "mfa_enabled": True,
            "can_manage": True,
        }
        with patch.object(api_client, "get_localisation_defaults", return_value=self.payload()):
            for language in ("en", "ro"):
                for template_name, fields in CONTACT_TEMPLATES.items():
                    with self.subTest(language=language, template=template_name), override(language):
                        request = RequestFactory().get("/")
                        request.session = SessionBase()
                        html = render_to_string(template_name, context, request=request)
                        for field in fields:
                            self.assertIn(CONFIGURED_COMPANY[field], html)
                        self.assertNotIn("@pragmatichost.com", html)

    def test_no_portal_template_contains_a_hardcoded_contact_address(self) -> None:
        root = Path(settings.BASE_DIR) / "templates"
        offenders = sorted(
            str(path.relative_to(root))
            for path in root.rglob("*.html")
            if "@pragmatichost.com" in path.read_text(encoding="utf-8")
        )
        self.assertEqual(offenders, [])

    def test_touched_templates_have_no_raw_controls_and_keep_payment_bindings(self) -> None:
        root = Path(settings.BASE_DIR) / "templates"
        offenders = [
            name for name in CONTACT_TEMPLATES if RAW_CONTROL.search((root / name).read_text(encoding="utf-8"))
        ]
        self.assertEqual(offenders, [])

        request = RequestFactory().get("/")
        request.session = SessionBase()
        with patch.object(api_client, "get_localisation_defaults", return_value=self.payload()):
            html = render_to_string(
                "orders/order_confirmation.html",
                {
                    "order": {
                        "status": "awaiting_payment",
                        "payment_method": "bank_transfer",
                        "order_number": "ORDER-2099-0001",
                        "total": "100.00",
                        "currency_code": "RON",
                    },
                    "payment_info": {"client_secret": "test-secret"},
                    "stripe_config": {"publishable_key": "test-key"},
                    "bank_details": {"iban": "RO49AAAA1B31007593840000", "beneficiary": "Identity SRL"},
                },
                request=request,
            )
        for binding in ('id="submit"', 'id="button-text"', 'id="spinner"', '@click="copy()"', ':title="title"'):
            self.assertIn(binding, html)
