"""
Tests for customer background tasks (TODO flush implementation).

Covers: process_customer_feedback, start_customer_onboarding,
cleanup_inactive_customers, send_customer_welcome_email,
and all helper functions (_detect_feedback_category, _detect_feedback_sentiment,
_get_customer_locale, _send_reactivation_email).
"""

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.tasks import (
    _detect_feedback_category,
    _detect_feedback_sentiment,
    _get_customer_locale,
    cleanup_inactive_customers,
    process_customer_feedback,
    send_customer_welcome_email,
    start_customer_onboarding,
)
from config.settings.test import LOCMEM_TEST_CACHE


class FeedbackCategoryDetectionTests(TestCase):
    """Tests for _detect_feedback_category helper."""

    def test_detects_billing_category(self) -> None:
        assert _detect_feedback_category("I have a problem with my invoice payment") == "billing"

    def test_detects_technical_category(self) -> None:
        assert _detect_feedback_category("The server is down and showing error") == "technical"

    def test_detects_praise_category(self) -> None:
        assert _detect_feedback_category("Thank you, excellent service!") == "praise"

    def test_detects_complaint_category(self) -> None:
        assert _detect_feedback_category("This is terrible, very disappointed") == "complaint"

    def test_detects_feature_request_category(self) -> None:
        assert _detect_feedback_category("I wish you would add this feature") == "feature_request"

    def test_returns_general_for_no_keywords(self) -> None:
        assert _detect_feedback_category("Hello, just checking in") == "general"

    def test_detects_romanian_billing_keywords(self) -> None:
        assert _detect_feedback_category("Am o problema cu factura si plata") == "billing"

    def test_detects_romanian_praise_keywords(self) -> None:
        assert _detect_feedback_category("Multumesc pentru serviciu excelent") == "praise"

    def test_highest_score_wins_when_multiple_categories(self) -> None:
        # "invoice payment error" has 2 billing + 1 technical = billing wins
        result = _detect_feedback_category("invoice payment error on server")
        assert result == "billing"

    def test_empty_content_returns_general(self) -> None:
        assert _detect_feedback_category("") == "general"


class FeedbackSentimentDetectionTests(TestCase):
    """Tests for _detect_feedback_sentiment helper."""

    def test_positive_sentiment(self) -> None:
        assert _detect_feedback_sentiment("great excellent awesome") == "positive"

    def test_negative_sentiment(self) -> None:
        assert _detect_feedback_sentiment("terrible broken awful") == "negative"

    def test_neutral_sentiment(self) -> None:
        assert _detect_feedback_sentiment("I need to check my account") == "neutral"

    def test_mixed_defaults_to_neutral(self) -> None:
        # Equal positive and negative = neutral
        assert _detect_feedback_sentiment("great but terrible") == "neutral"

    def test_romanian_positive(self) -> None:
        assert _detect_feedback_sentiment("multumesc super minunat") == "positive"

    def test_romanian_negative(self) -> None:
        assert _detect_feedback_sentiment("prost rau dezamagit") == "negative"


class GetCustomerLocaleTests(TestCase):
    """Tests for _get_customer_locale helper."""

    def test_defaults_to_ro(self) -> None:
        """Romanian hosting provider defaults to Romanian locale."""
        customer = MagicMock()
        customer.memberships.filter.return_value.select_related.return_value.first.return_value = None
        assert _get_customer_locale(customer) == "ro"

    def test_returns_user_language_en(self) -> None:
        membership = MagicMock()
        membership.user.profile.preferred_language = "en"
        customer = MagicMock()
        customer.memberships.filter.return_value.select_related.return_value.first.return_value = membership
        assert _get_customer_locale(customer) == "en"

    def test_returns_user_language_ro(self) -> None:
        membership = MagicMock()
        membership.user.profile.preferred_language = "ro"
        customer = MagicMock()
        customer.memberships.filter.return_value.select_related.return_value.first.return_value = membership
        assert _get_customer_locale(customer) == "ro"

    def test_handles_exception_gracefully(self) -> None:
        customer = MagicMock()
        customer.memberships.filter.side_effect = Exception("DB error")
        assert _get_customer_locale(customer) == "ro"


class ProcessCustomerFeedbackTests(TestCase):
    """Tests for process_customer_feedback task."""

    @patch("apps.customers.tasks.AuditService")
    def test_processes_feedback_with_category_and_sentiment(self, mock_audit: MagicMock) -> None:
        mock_note = MagicMock()
        mock_note.id = "note-123"
        mock_note.content = "The server is down, terrible experience"
        mock_note.note_type = "complaint"
        mock_note.customer.id = "cust-456"
        mock_note.customer.name = "Test Customer"
        mock_note.created_at.isoformat.return_value = "2026-03-07T00:00:00"

        with patch("apps.customers.models.CustomerNote") as mock_note_cls:
            mock_note_cls.objects.select_related.return_value.get.return_value = mock_note
            result = process_customer_feedback("note-123")

        assert result["success"] is True
        assert result["category"] == "technical"
        assert result["sentiment"] == "negative"
        mock_audit.log_simple_event.assert_called_once()
        metadata = mock_audit.log_simple_event.call_args[1]["metadata"]
        assert metadata["detected_category"] == "technical"
        assert metadata["detected_sentiment"] == "negative"

    def test_returns_error_for_nonexistent_note(self) -> None:
        with patch("apps.customers.models.CustomerNote") as mock_note_cls:
            mock_note_cls.objects.select_related.return_value.get.side_effect = Exception("Not found")
            mock_note_cls.DoesNotExist = Exception
            result = process_customer_feedback("nonexistent")

        assert result["success"] is False
        assert "error" in result


class StartCustomerOnboardingTests(TestCase):
    """Tests for start_customer_onboarding task."""

    def _make_customer(
        self,
        has_phone: bool = True,
        has_address: bool = True,
        has_billing: bool = True,
        has_tax: bool = True,
        is_business: bool = False,
    ) -> MagicMock:
        customer = MagicMock()
        customer.id = "cust-123"
        customer.customer_type = "company" if is_business else "individual"
        customer.primary_phone = "+40712345679" if has_phone else "+40712345678"  # Default = incomplete
        customer.get_display_name.return_value = "Test Customer"
        customer.meta = {}
        customer.addresses.exists.return_value = has_address

        billing_profile = MagicMock() if has_billing else None
        customer.get_billing_profile.return_value = billing_profile

        tax_profile = MagicMock() if has_tax else None
        if tax_profile:
            tax_profile.vat_number = "RO12345678"
        customer.get_tax_profile.return_value = tax_profile

        return customer

    def _patch_customer_cls(self, mock_customer_cls: MagicMock, customer: MagicMock) -> None:
        """Wire up all Customer ORM mock chains needed by start_customer_onboarding."""
        # Initial fetch: select_related(...).prefetch_related(...).get(...)
        mock_customer_cls.objects.select_related.return_value.prefetch_related.return_value.get.return_value = customer
        # Locked save: select_for_update().get(...)  — must return same mock so .meta is shared
        mock_customer_cls.objects.select_for_update.return_value.get.return_value = customer
        # Default phone value used for "incomplete phone" check
        mock_customer_cls._meta.get_field.return_value.default = "+40712345678"

    @patch("apps.customers.tasks.AuditService")
    def test_all_steps_completed_individual(self, mock_audit: MagicMock) -> None:
        customer = self._make_customer()
        with patch("apps.customers.models.Customer") as mock_customer_cls:
            self._patch_customer_cls(mock_customer_cls, customer)
            result = start_customer_onboarding("cust-123")

        assert result["success"] is True
        assert result["is_complete"] is True
        assert result["onboarding_steps"]["welcome_email"] == "completed"
        assert result["onboarding_steps"]["complete_tax_information"] == "not_required"
        customer.save.assert_called_once()

    @patch("apps.customers.tasks.AuditService")
    def test_incomplete_contact_details(self, mock_audit: MagicMock) -> None:
        customer = self._make_customer(has_phone=False, has_address=False)
        with patch("apps.customers.models.Customer") as mock_customer_cls:
            self._patch_customer_cls(mock_customer_cls, customer)
            result = start_customer_onboarding("cust-123")

        assert result["success"] is True
        assert result["is_complete"] is False
        assert result["onboarding_steps"]["verify_contact_details"] == "incomplete"

    @patch("apps.customers.tasks.AuditService")
    def test_missing_billing_profile(self, mock_audit: MagicMock) -> None:
        customer = self._make_customer(has_billing=False)
        with patch("apps.customers.models.Customer") as mock_customer_cls:
            self._patch_customer_cls(mock_customer_cls, customer)
            result = start_customer_onboarding("cust-123")

        assert result["is_complete"] is False
        assert result["onboarding_steps"]["setup_billing_profile"] == "incomplete"

    @patch("apps.customers.tasks.AuditService")
    def test_business_missing_tax_info(self, mock_audit: MagicMock) -> None:
        customer = self._make_customer(is_business=True, has_tax=False)
        with patch("apps.customers.models.Customer") as mock_customer_cls:
            self._patch_customer_cls(mock_customer_cls, customer)
            result = start_customer_onboarding("cust-123")

        assert result["is_complete"] is False
        assert result["onboarding_steps"]["complete_tax_information"] == "incomplete"

    @patch("apps.customers.tasks.AuditService")
    def test_pfa_requires_tax_info(self, mock_audit: MagicMock) -> None:
        customer = self._make_customer(is_business=False, has_tax=True)
        customer.customer_type = "pfa"
        with patch("apps.customers.models.Customer") as mock_customer_cls:
            self._patch_customer_cls(mock_customer_cls, customer)
            result = start_customer_onboarding("cust-123")

        assert result["onboarding_steps"]["complete_tax_information"] == "completed"

    def test_nonexistent_customer(self) -> None:
        with patch("apps.customers.models.Customer") as mock_customer_cls:
            mock_customer_cls.objects.select_related.return_value.prefetch_related.return_value.get.side_effect = (
                Exception("Not found")
            )
            result = start_customer_onboarding("nonexistent")

        assert result["success"] is False

    @patch("apps.customers.tasks.AuditService")
    def test_stores_onboarding_in_meta(self, mock_audit: MagicMock) -> None:
        customer = self._make_customer()
        with patch("apps.customers.models.Customer") as mock_customer_cls:
            self._patch_customer_cls(mock_customer_cls, customer)
            start_customer_onboarding("cust-123")

        assert "onboarding" in customer.meta
        assert "started_at" in customer.meta["onboarding"]
        assert customer.meta["onboarding"]["is_complete"] is True


class CleanupInactiveCustomersTests(TestCase):
    """Tests for cleanup_inactive_customers task."""

    def setUp(self) -> None:
        cache.clear()

    @patch("apps.customers.tasks._send_reactivation_email", return_value=True)
    @patch("apps.tickets.models.Ticket")
    @patch("apps.provisioning.models.Service")
    @patch("apps.customers.models.Customer")
    def test_sends_reactivation_email(
        self,
        mock_customer_cls: MagicMock,
        mock_service_cls: MagicMock,
        mock_ticket_cls: MagicMock,
        mock_send: MagicMock,
    ) -> None:
        customer = MagicMock()
        customer.id = "cust-1"
        customer.meta = {}
        customer.primary_email = "test@example.com"
        customer.get_display_name.return_value = "Test"
        customer.created_at.date.return_value = (timezone.now() - timedelta(days=400)).date()
        customer.memberships.filter.return_value.values_list.return_value.order_by.return_value.first.return_value = (
            None
        )

        mock_customer_cls.objects.filter.return_value.count.return_value = 10
        candidates_qs = MagicMock()
        candidates_qs.__getitem__ = MagicMock(return_value=[customer])
        mock_customer_cls.objects.filter.return_value.exclude.return_value.exclude.return_value = candidates_qs

        mock_service_cls.objects.filter.return_value.exists.return_value = False
        mock_ticket_cls.objects.filter.return_value.exists.return_value = False

        result = cleanup_inactive_customers()

        assert result["success"] is True
        assert result["results"]["emails_sent"] == 1
        mock_send.assert_called_once_with(customer)

    @patch("apps.tickets.models.Ticket")
    @patch("apps.provisioning.models.Service")
    @patch("apps.customers.models.Customer")
    def test_skips_customers_with_active_services(
        self,
        mock_customer_cls: MagicMock,
        mock_service_cls: MagicMock,
        mock_ticket_cls: MagicMock,
    ) -> None:
        customer = MagicMock()
        customer.id = "cust-1"
        customer.meta = {}

        mock_customer_cls.objects.filter.return_value.count.return_value = 10
        candidates_qs = MagicMock()
        candidates_qs.__getitem__ = MagicMock(return_value=[customer])
        mock_customer_cls.objects.filter.return_value.exclude.return_value.exclude.return_value = candidates_qs

        mock_service_cls.objects.filter.return_value.exists.return_value = True  # Has active services

        result = cleanup_inactive_customers()

        assert result["success"] is True
        assert result["results"]["skipped_active_services"] == 1
        assert result["results"]["emails_sent"] == 0

    @patch("apps.tickets.models.Ticket")
    @patch("apps.provisioning.models.Service")
    @patch("apps.customers.models.Customer")
    def test_skips_customers_with_open_tickets(
        self,
        mock_customer_cls: MagicMock,
        mock_service_cls: MagicMock,
        mock_ticket_cls: MagicMock,
    ) -> None:
        customer = MagicMock()
        customer.id = "cust-1"
        customer.meta = {}

        mock_customer_cls.objects.filter.return_value.count.return_value = 10
        candidates_qs = MagicMock()
        candidates_qs.__getitem__ = MagicMock(return_value=[customer])
        mock_customer_cls.objects.filter.return_value.exclude.return_value.exclude.return_value = candidates_qs

        mock_service_cls.objects.filter.return_value.exists.return_value = False
        mock_ticket_cls.objects.filter.return_value.exists.return_value = True  # Has open tickets

        result = cleanup_inactive_customers()

        assert result["success"] is True
        assert result["results"]["skipped_open_tickets"] == 1

    @patch("apps.customers.tasks._send_reactivation_email", return_value=True)
    @patch("apps.tickets.models.Ticket")
    @patch("apps.provisioning.models.Service")
    @patch("apps.customers.models.Customer")
    def test_respects_90_day_cooldown(
        self,
        mock_customer_cls: MagicMock,
        mock_service_cls: MagicMock,
        mock_ticket_cls: MagicMock,
        mock_send: MagicMock,
    ) -> None:
        customer = MagicMock()
        customer.id = "cust-1"
        # Last reactivation email sent 30 days ago (within 90-day cooldown)
        customer.meta = {"last_reactivation_email": (timezone.now() - timedelta(days=30)).isoformat()}
        customer.get_display_name.return_value = "Test"
        customer.created_at.date.return_value = (timezone.now() - timedelta(days=400)).date()

        mock_customer_cls.objects.filter.return_value.count.return_value = 10
        candidates_qs = MagicMock()
        candidates_qs.__getitem__ = MagicMock(return_value=[customer])
        mock_customer_cls.objects.filter.return_value.exclude.return_value.exclude.return_value = candidates_qs

        mock_service_cls.objects.filter.return_value.exists.return_value = False
        mock_ticket_cls.objects.filter.return_value.exists.return_value = False

        result = cleanup_inactive_customers()

        assert result["success"] is True
        assert result["results"]["skipped_cooldown"] == 1
        mock_send.assert_not_called()

    @override_settings(CACHES=LOCMEM_TEST_CACHE)
    def test_concurrent_lock_prevents_double_run(self) -> None:
        cache.clear()
        cache.add("customer_cleanup_lock", True, 3600)
        result = cleanup_inactive_customers()
        assert result["message"] == "Already running"


class SendCustomerWelcomeEmailTests(TestCase):
    """Tests for send_customer_welcome_email task."""

    @patch("apps.customers.tasks._get_customer_locale", return_value="ro")
    @patch("apps.customers.tasks.AuditService")
    @patch("apps.notifications.services.EmailService")
    @patch("apps.customers.models.Customer")
    def test_sends_via_email_service(
        self,
        mock_customer_cls: MagicMock,
        mock_email_service: MagicMock,
        mock_audit: MagicMock,
        mock_locale: MagicMock,
    ) -> None:
        customer = MagicMock()
        customer.id = "cust-123"
        customer.primary_email = "test@example.com"
        customer.get_display_name.return_value = "Test Customer"
        mock_customer_cls.objects.get.return_value = customer

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.message_id = "msg-123"
        mock_email_service.send_template_email.return_value = mock_result

        result = send_customer_welcome_email("cust-123")

        assert result["success"] is True
        assert result["locale"] == "ro"
        mock_email_service.send_template_email.assert_called_once()
        call_kwargs = mock_email_service.send_template_email.call_args[1]
        assert call_kwargs["template_key"] == "customer_welcome"
        assert call_kwargs["recipient"] == "test@example.com"
        assert call_kwargs["async_send"] is False

    @patch("apps.customers.tasks._get_customer_locale", return_value="en")
    @patch("apps.customers.tasks.AuditService")
    @patch("apps.notifications.services.EmailService")
    @patch("apps.customers.models.Customer")
    def test_handles_email_failure(
        self,
        mock_customer_cls: MagicMock,
        mock_email_service: MagicMock,
        mock_audit: MagicMock,
        mock_locale: MagicMock,
    ) -> None:
        customer = MagicMock()
        customer.id = "cust-123"
        customer.primary_email = "test@example.com"
        customer.get_display_name.return_value = "Test Customer"
        mock_customer_cls.objects.get.return_value = customer

        mock_result = MagicMock()
        mock_result.success = False
        mock_result.message_id = None
        mock_email_service.send_template_email.return_value = mock_result

        result = send_customer_welcome_email("cust-123")

        assert result["success"] is False
        assert "failed" in result["message"].lower()

    def test_nonexistent_customer(self) -> None:
        with patch("apps.customers.models.Customer") as mock_customer_cls:
            mock_customer_cls.objects.get.side_effect = Exception("Not found")
            result = send_customer_welcome_email("nonexistent")

        assert result["success"] is False
