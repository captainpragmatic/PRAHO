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


class DomainRenewalNoticeTaskTests(TestCase):
    """The scheduled worker must send, mark, and report truthfully."""

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
            name="notice-task-registrar",
            display_name="Notice Task Registrar",
            website_url="https://example.test",
            api_endpoint="https://api.example.test",
        )
        self.customer = Customer.objects.create(
            name="Notice Task Customer",
            company_name="Notice Task Customer",
            primary_email="notice-task@example.test",
            customer_type="company",
        )

    def _domain(self, name: str, days_until_expiry: int) -> Domain:
        return Domain.objects.create(
            name=name,
            tld=self.tld,
            registrar=self.registrar,
            customer=self.customer,
            status="active",
            expires_at=self.now + timedelta(days=days_until_expiry),
        )

    @patch("apps.domains.services.timezone.now")
    @patch("apps.notifications.services.NotificationService.send_customer_notification", return_value=True)
    def test_task_sends_and_marks_only_matched_thresholds(self, mock_send, mock_now) -> None:
        mock_now.return_value = self.now
        due = self._domain("expiring-now.com", 30)
        self._domain("expiring-later.com", 60)
        from apps.domains.tasks import process_domain_renewal_notices  # noqa: PLC0415

        result = process_domain_renewal_notices()

        self.assertTrue(result["success"], result)
        self.assertEqual(result["notified"], 1)
        self.assertEqual(result["errors"], 0)
        mock_send.assert_called_once()
        kwargs = mock_send.call_args.kwargs
        self.assertEqual(kwargs["customer_id"], str(self.customer.id))
        self.assertEqual(kwargs["notification_type"], "domain_renewal_notice")
        self.assertEqual(kwargs["context"]["domain_name"], "expiring-now.com")
        self.assertEqual(kwargs["context"]["days_until_expiry"], 30)
        due.refresh_from_db()
        self.assertEqual(due.renewal_notices_sent, 30)
        self.assertIsNotNone(due.last_renewal_notice)

    @patch("apps.domains.services.timezone.now")
    @patch("apps.notifications.services.NotificationService.send_customer_notification", return_value=False)
    def test_task_reports_send_failures_and_leaves_domain_unmarked(self, mock_send, mock_now) -> None:
        mock_now.return_value = self.now
        due = self._domain("expiring-fail.com", 30)
        from apps.domains.tasks import process_domain_renewal_notices  # noqa: PLC0415

        result = process_domain_renewal_notices()

        self.assertFalse(result["success"])
        self.assertEqual(result["notified"], 0)
        self.assertEqual(result["errors"], 1)
        self.assertIn("1 errors", result["message"])
        due.refresh_from_db()
        self.assertEqual(due.renewal_notices_sent, 0, "a failed send must stay eligible for the next run")

    def test_schedule_registration_is_idempotent(self) -> None:
        from django_q.models import Schedule  # noqa: PLC0415

        from apps.domains.tasks import setup_domain_scheduled_tasks  # noqa: PLC0415

        first = setup_domain_scheduled_tasks()
        second = setup_domain_scheduled_tasks()

        self.assertEqual(
            first,
            {
                "renewal_notices": "created",
                "reconcile_pending": "created",
            },
        )
        self.assertEqual(
            second,
            {
                "renewal_notices": "already_exists",
                "reconcile_pending": "already_exists",
            },
        )
        self.assertEqual(Schedule.objects.filter(name="domains-renewal-notices").count(), 1)
