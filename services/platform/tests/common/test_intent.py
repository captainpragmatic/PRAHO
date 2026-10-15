"""clean_intent keeps only known keys with valid values (apps.common.intent, identical in both services)."""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.common.intent import ATTRIBUTION_KEYS, clean_intent


class CleanIntentTests(SimpleTestCase):
    def test_valid_values_are_kept_and_normalised(self) -> None:
        raw = {
            "product": "Web-Hosting-Pro",
            "period": "annual",
            "domain": "Example.RO.",
            "domain_mode": "transfer",
            "offer_ref": "launch_2026",
            "utm_source": "  newsletter ",
            "utm_medium": "email",
            "utm_campaign": "autumn\nsale",
            "referrer": "https://www.Example.com/blog/post?id=1#top",
        }
        self.assertEqual(
            clean_intent(raw),
            {
                "product": "web-hosting-pro",
                "period": "annual",
                "domain": "example.ro",
                "domain_mode": "transfer",
                "offer_ref": "launch_2026",
                "utm_source": "newsletter",
                "utm_medium": "email",
                "utm_campaign": "autumn sale",
                # The referring site only, never its path or query.
                "referrer": "https://www.example.com",
            },
        )

    def test_unknown_keys_and_invalid_values_are_dropped(self) -> None:
        raw = {
            "product": "../admin",
            "period": "weekly",
            "domain": "localhost",
            "domain_mode": "steal",
            "offer_ref": "x" * 65,
            "utm_source": "a" * 101,
            "utm_medium": "null\x00byte",
            "referrer": "javascript:alert(1)",
            "is_staff": "true",
            "utm_campaign": 42,
        }
        with self.assertLogs("apps.common.intent", "INFO") as logs:
            self.assertEqual(clean_intent(raw), {})
        self.assertIn("is_staff", logs.output[0])

    def test_keys_restrict_what_is_kept(self) -> None:
        raw = {"product": "web-hosting", "utm_source": "ads"}
        self.assertEqual(clean_intent(raw, ATTRIBUTION_KEYS), {"utm_source": "ads"})
