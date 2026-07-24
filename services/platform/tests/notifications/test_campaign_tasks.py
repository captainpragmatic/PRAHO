"""Regression tests for notification campaign audience selection."""

from django.test import TestCase

from apps.notifications.models import EmailCampaign, EmailTemplate
from apps.notifications.tasks import _get_campaign_recipients
from tests.factories import CustomerFactory


class CampaignAudienceRecipientTests(TestCase):
    """Campaign audience names must describe the queryset they actually select."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.template = EmailTemplate.objects.create(
            key="campaign-audience-regression",
            locale="en",
            subject="Campaign",
            body_html="<p>Campaign</p>",
            body_text="Campaign",
            is_active=True,
            category="marketing",
        )
        cls.active_customer = CustomerFactory(
            company_name="Active Customer",
            primary_email="active@example.com",
            status="active",
            marketing_consent=True,
        )
        cls.inactive_customer = CustomerFactory(
            company_name="Inactive Customer",
            primary_email="inactive@example.com",
            status="inactive",
            marketing_consent=True,
        )

    def _recipient_emails(self, audience: str) -> set[str]:
        campaign = EmailCampaign.objects.create(
            name=f"{audience} campaign",
            template=self.template,
            audience=audience,
            requires_consent=True,
        )
        return {email for email, _context in _get_campaign_recipients(campaign)}

    def test_inactive_audience_selects_only_inactive_customers(self) -> None:
        self.assertEqual(self._recipient_emails("inactive_customers"), {"inactive@example.com"})

    def test_all_customers_audience_includes_active_and_inactive_customers(self) -> None:
        self.assertEqual(
            self._recipient_emails("all_customers"),
            {"active@example.com", "inactive@example.com"},
        )

    def test_active_audience_selects_only_active_customers(self) -> None:
        self.assertEqual(self._recipient_emails("active_customers"), {"active@example.com"})

    def test_unimplemented_trial_expiring_audience_fails_closed(self) -> None:
        """Never turn an unsupported audience into an accidental broadcast."""
        self.assertEqual(self._recipient_emails("trial_expiring"), set())
