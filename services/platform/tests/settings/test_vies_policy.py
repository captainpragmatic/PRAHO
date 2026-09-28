"""Keep outage grace inside the entitlement lifetime and declare every policy."""

from django.core.cache import cache
from django.test import TestCase

from apps.billing.config import get_vies_evidence_max_age_days, get_vies_outage_grace_days
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SystemSetting


class VIESPolicyTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_catalog_defaults_and_effective_clocks_leave_no_stale_grace_window(self) -> None:
        expected = {
            "billing.vies_evidence_max_age_days": 30,
            "billing.vies_outage_grace_days": 14,
            "billing.reverse_charge_requires_consultation_reference": True,
            "billing.reverse_charge_requires_name_match": True,
        }
        for key, default in expected.items():
            self.assertEqual(CATALOG_BY_KEY[key].default, default)
        self.assertGreater(get_vies_evidence_max_age_days(), get_vies_outage_grace_days())
        for key, value in (
            ("billing.vies_evidence_max_age_days", 5),
            ("billing.vies_outage_grace_days", 14),
        ):
            SystemSetting.objects.update_or_create(
                key=key,
                defaults={"value": value, "default_value": value, "data_type": "integer", "name": key},
            )
        cache.clear()
        self.assertEqual(get_vies_evidence_max_age_days(), 5)
        self.assertEqual(get_vies_outage_grace_days(), 4)
