"""Domain-renewal notice policy wiring and progression tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase

from apps.customers.models import Customer
from apps.domains.models import TLD, Domain, Registrar
from apps.domains.services import DomainNotificationService
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


class DomainRenewalNoticePolicyTests(TestCase):
    """The operator schedule must drive each threshold exactly once."""

    now = datetime(2026, 7, 24, 10, 0, tzinfo=UTC)

    def setUp(self) -> None:
        cache.clear()
        self.tld = TLD.objects.create(
            extension="com",
            description=".com",
            registration_price_cents=1000,
            renewal_price_cents=1000,
            transfer_price_cents=1000,
        )
        self.registrar = Registrar.objects.create(
            name="notice-registrar",
            display_name="Notice Registrar",
            website_url="https://example.test",
            api_endpoint="https://api.example.test",
        )
        self.customer = Customer.objects.create(
            name="Notice Customer",
            company_name="Notice Customer",
            primary_email="notices@example.test",
            customer_type="company",
        )

    def _domain(self, name: str, days_until_expiry: int, *, last_period: int = 0) -> Domain:
        return Domain.objects.create(
            name=name,
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
            expires_at=self.now + timedelta(days=days_until_expiry),
            renewal_notices_sent=last_period,
        )

    @patch("apps.domains.services.timezone.now")
    def test_custom_schedule_selects_only_configured_thresholds(self, mock_now) -> None:
        mock_now.return_value = self.now
        result = SettingsService.update_setting("domains.renewal_notice_schedule_days", ["45", "10", "2"])
        self.assertTrue(result.is_ok(), result)
        included = self._domain("included.example", 10)
        self._domain("default-only.example", 14)

        due_ids = set(DomainNotificationService.get_domains_needing_renewal_notice().values_list("pk", flat=True))

        self.assertEqual(due_ids, {included.pk})

    @patch("apps.domains.services.timezone.now")
    def test_later_threshold_remains_due_after_earlier_notice(self, mock_now) -> None:
        mock_now.return_value = self.now
        domain = self._domain("progression.example", 14, last_period=30)

        self.assertIn(domain, DomainNotificationService.get_domains_needing_renewal_notice())

        DomainNotificationService.mark_renewal_notice_sent(domain, 14)
        self.assertNotIn(domain, DomainNotificationService.get_domains_needing_renewal_notice())

    def test_marking_notice_records_the_current_threshold(self) -> None:
        domain = self._domain("last-period.example", 14, last_period=30)

        DomainNotificationService.mark_renewal_notice_sent(domain, 14)

        domain.refresh_from_db()
        self.assertEqual(domain.renewal_notices_sent, 14)

    @patch("apps.domains.services.timezone.now")
    def test_corrupt_empty_schedule_falls_back_instead_of_selecting_every_domain(self, mock_now) -> None:
        mock_now.return_value = self.now
        SystemSetting.objects.create(
            key="domains.renewal_notice_schedule_days",
            category="domains",
            name="Corrupt schedule",
            description="Corrupt schedule",
            data_type="list",
            value=[],
            default_value=[30, 14, 7, 3, 1],
        )
        cache.clear()
        due = self._domain("safe-default.example", 14)
        self._domain("unrelated.example", 9)

        due_ids = set(DomainNotificationService.get_domains_needing_renewal_notice().values_list("pk", flat=True))

        self.assertEqual(due_ids, {due.pk})
