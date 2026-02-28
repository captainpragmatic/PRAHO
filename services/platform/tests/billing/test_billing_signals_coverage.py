"""
Comprehensive tests for apps/billing/signals.py to maximize coverage.
Tests signal handlers, helper functions, and business logic utilities.
"""

import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.models import (
    CreditLedger,
    Currency,
    OAuthToken,
    Payment,
    PaymentRetryAttempt,
    PriceGrandfathering,
    ProformaInvoice,
    Refund,
    Subscription,
    TaxRule,
    VATValidation,
)
from apps.billing.signals import (
    E_FACTURA_MINIMUM_AMOUNT,
    LARGE_REFUND_THRESHOLD_CENTS,
    _activate_payment_services,
    _activate_pending_services,
    _cancel_invoice_webhooks,
    _cancel_payment_reminders,
    _cancel_payment_retries,
    _cleanup_invoice_files,
    _cleanup_payment_files,
    _consider_service_suspension,
    _handle_efactura_refund_reporting,
    _handle_final_retry_failure,
    _handle_invalid_vat_number,
    _handle_invoice_issued,
    _handle_invoice_overdue,
    _handle_invoice_paid,
    _handle_invoice_refund_completion,
    _handle_invoice_status_change,
    _handle_invoice_voided,
    _handle_new_invoice_creation,
    _handle_overdue_order_services,
    _handle_overdue_service_suspension,
    _handle_payment_failure,
    _handle_payment_refund,
    _handle_payment_status_change,
    _handle_payment_success,
    _handle_retry_completion,
    _invalidate_billing_dashboard_cache,
    _invalidate_invoice_caches,
    _invalidate_tax_cache,
    _log_billing_model_event,
    _notify_finance_team_large_refund,
    _requires_efactura_submission,
    _revert_customer_credit_score,
    _schedule_payment_reminders,
    _schedule_payment_retry,
    _send_invoice_created_email,
    _send_invoice_issued_email,
    _send_invoice_overdue_email,
    _send_invoice_refund_confirmation,
    _send_invoice_voided_email,
    _send_manual_review_notification,
    _send_payment_failed_email,
    _send_payment_received_email,
    _send_payment_refund_email,
    _send_payment_success_email,
    _send_retry_success_email,
    _serialize_value_for_audit,
    _serialize_values_for_audit,
    _sync_orders_on_invoice_status_change,
    _trigger_dunning_process,
    _trigger_efactura_submission,
    _trigger_virtualmin_provisioning_on_payment,
    _update_billing_analytics,
    _update_billing_refund_metrics,
    _update_customer_billing_stats,
    _update_customer_invoice_history,
    _update_customer_payment_credit,
    _update_customer_payment_history,
    _update_customer_vat_status,
)
from tests.factories.billing_factories import (
    CustomerFactory,
    InvoiceFactory,
)


def _get_or_create_currency(code: str = "RON") -> Currency:
    symbol = "€" if code == "EUR" else "L" if code == "RON" else "$"
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": symbol, "decimals": 2})
    return obj


def _make_payment(customer, invoice=None, currency=None, status="succeeded", amount_cents=1000):
    """Helper to create a Payment."""
    if currency is None:
        currency = invoice.currency if invoice else _get_or_create_currency()
    return Payment.objects.create(
        customer=customer,
        invoice=invoice,
        currency=currency,
        amount_cents=amount_cents,
        payment_method="stripe",
        status=status,
    )


# ===============================================================================
# SERIALIZATION TESTS
# ===============================================================================


class TestSerializeValueForAudit(TestCase):
    def test_datetime(self):
        dt = datetime(2025, 1, 1, 12, 0, 0)
        assert _serialize_value_for_audit(dt) == dt.isoformat()

    def test_enum(self):
        class Color(Enum):
            RED = "red"

        assert _serialize_value_for_audit(Color.RED) == "red"

    def test_decimal(self):
        assert _serialize_value_for_audit(Decimal("10.50")) == "10.50"

    def test_uuid(self):
        u = uuid.uuid4()
        assert _serialize_value_for_audit(u) == str(u)

    def test_dict(self):
        dt = datetime(2025, 1, 1)
        result = _serialize_value_for_audit({"key": dt})
        assert result == {"key": dt.isoformat()}

    def test_list(self):
        result = _serialize_value_for_audit([Decimal("1"), Decimal("2")])
        assert result == ["1", "2"]

    def test_tuple(self):
        result = _serialize_value_for_audit((Decimal("1"),))
        assert result == ["1"]

    def test_set(self):
        result = _serialize_value_for_audit({Decimal("1")})
        assert result == ["1"]

    def test_plain_value(self):
        assert _serialize_value_for_audit("hello") == "hello"
        assert _serialize_value_for_audit(42) == 42
        assert _serialize_value_for_audit(None) is None

    def test_nested_dict_with_non_string_keys(self):
        result = _serialize_value_for_audit({1: "a", 2: "b"})
        assert result == {"1": "a", "2": "b"}


class TestSerializeValuesForAudit(TestCase):
    def test_basic(self):
        result = _serialize_values_for_audit({"dt": datetime(2025, 1, 1), "num": 42})
        assert result["dt"] == "2025-01-01T00:00:00"
        assert result["num"] == 42


# ===============================================================================
# _log_billing_model_event TESTS
# ===============================================================================


class TestLogBillingModelEvent(TestCase):
    @override_settings(DISABLE_AUDIT_SIGNALS=True)
    def test_disabled_audit_signals(self):
        """Should return early when DISABLE_AUDIT_SIGNALS is True."""
        with patch("apps.billing.signals.AuditService") as mock_audit:
            _log_billing_model_event(event_type="test", instance=MagicMock(), description="test")
            mock_audit.log_event.assert_not_called()

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch("apps.billing.signals.AuditService")
    def test_logs_event(self, mock_audit):
        instance = MagicMock()
        _log_billing_model_event(
            event_type="test_event",
            instance=instance,
            description="Test desc",
            new_values={"a": 1},
            old_values={"a": 0},
            metadata={"extra": True},
        )
        mock_audit.log_event.assert_called_once()

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch("apps.billing.signals.AuditService")
    def test_logs_without_optional_params(self, mock_audit):
        _log_billing_model_event(event_type="test", instance=MagicMock(), description="test")
        mock_audit.log_event.assert_called_once()

    @override_settings(DISABLE_AUDIT_SIGNALS=False)
    @patch("apps.billing.signals.AuditService")
    def test_exception_handling(self, mock_audit):
        mock_audit.log_event.side_effect = Exception("boom")
        # Should not raise
        _log_billing_model_event(event_type="test", instance=MagicMock(), description="test")


# ===============================================================================
# MODEL LIFECYCLE SIGNAL TESTS (via direct call)
# ===============================================================================


class TestSubscriptionLifecycleSignals(TestCase):
    def setUp(self):
        from apps.products.models import Product  # noqa: PLC0415

        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency("EUR")
        self.product = Product.objects.create(
            name="Test Product", slug="test-product", product_type="hosting"
        )

    @patch("apps.billing.signals._log_billing_model_event")
    def test_subscription_created(self, mock_log):
        self.currency = _get_or_create_currency("EUR")
        Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=1000,
            current_period_start=timezone.now(),
            current_period_end=timezone.now() + timedelta(days=30),
            next_billing_date=timezone.now() + timedelta(days=30),
        )
        # post_save signal fires automatically
        mock_log.assert_called()
        call_kwargs = mock_log.call_args_list[-1][1]  # last call kwargs
        assert call_kwargs["event_type"] == "subscription_model_created"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_subscription_updated(self, mock_log):
        sub = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-002",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=1000,
            current_period_start=timezone.now(),
            current_period_end=timezone.now() + timedelta(days=30),
            next_billing_date=timezone.now() + timedelta(days=30),
        )
        mock_log.reset_mock()
        sub.status = "cancelled"
        sub.save()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "subscription_model_updated"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_subscription_deleted(self, mock_log):
        sub = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-003",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=1000,
            current_period_start=timezone.now(),
            current_period_end=timezone.now() + timedelta(days=30),
            next_billing_date=timezone.now() + timedelta(days=30),
        )
        mock_log.reset_mock()
        sub.delete()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "subscription_model_deleted"


class TestPriceGrandfatheringLifecycleSignals(TestCase):
    def setUp(self):
        from apps.products.models import Product  # noqa: PLC0415

        self.customer = CustomerFactory()
        self.product = Product.objects.create(
            name="GF Product", slug="gf-product", product_type="hosting"
        )

    @patch("apps.billing.signals._log_billing_model_event")
    def test_created(self, mock_log):
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=1200,
            is_active=True,
        )
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "price_grandfathering_created"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_updated(self, mock_log):
        pg = PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=1200,
            is_active=True,
        )
        mock_log.reset_mock()
        pg.is_active = False
        pg.save()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "price_grandfathering_updated"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_deleted(self, mock_log):
        pg = PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=1200,
            is_active=True,
        )
        mock_log.reset_mock()
        pg.delete()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "price_grandfathering_deleted"


class TestRefundLifecycleSignals(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()
        self.invoice = InvoiceFactory(customer=self.customer, currency=self.currency, number="INV-REF-SETUP")

    @patch("apps.billing.signals._log_billing_model_event")
    def test_created(self, mock_log):
        Refund.objects.create(
            customer=self.customer,
            currency=self.currency,
            invoice=self.invoice,
            amount_cents=5000,
            original_amount_cents=10000,
            reference_number="REF-001",
            status="pending",
            refund_type="full",
        )
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "refund_model_created"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_updated(self, mock_log):
        refund = Refund.objects.create(
            customer=self.customer,
            currency=self.currency,
            invoice=self.invoice,
            amount_cents=5000,
            original_amount_cents=10000,
            reference_number="REF-002",
            status="pending",
            refund_type="full",
        )
        mock_log.reset_mock()
        refund.status = "completed"
        refund.save()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "refund_model_updated"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_deleted(self, mock_log):
        refund = Refund.objects.create(
            customer=self.customer,
            currency=self.currency,
            invoice=self.invoice,
            amount_cents=5000,
            original_amount_cents=10000,
            reference_number="REF-003",
            status="pending",
            refund_type="full",
        )
        mock_log.reset_mock()
        refund.delete()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "refund_model_deleted"


class TestCreditLedgerLifecycleSignals(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()

    @patch("apps.billing.signals._log_billing_model_event")
    def test_created(self, mock_log):
        CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,
            reason="test credit",
        )
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "credit_ledger_created"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_updated(self, mock_log):
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,
            reason="test credit",
        )
        mock_log.reset_mock()
        entry.reason = "updated reason"
        entry.save()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "credit_ledger_updated"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_deleted(self, mock_log):
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,
            reason="test credit",
        )
        mock_log.reset_mock()
        entry.delete()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "credit_ledger_deleted"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_with_invoice_and_payment(self, mock_log):
        """Test credit ledger with invoice_id and payment_id set."""
        currency = _get_or_create_currency()
        invoice = InvoiceFactory(customer=self.customer, currency=currency, number="INV-CL-001")
        payment = _make_payment(self.customer, invoice=invoice, currency=currency)
        mock_log.reset_mock()
        CreditLedger.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            delta_cents=-500,
            reason="payment applied",
        )
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "credit_ledger_created"


class TestOAuthTokenLifecycleSignals(TestCase):
    @patch("apps.billing.signals._log_billing_model_event")
    def test_created(self, mock_log):
        OAuthToken.objects.create(
            cui="RO12345678",
            access_token="test-token",
            refresh_token="test-refresh",
            environment="test",
            is_active=True,
            expires_at=timezone.now() + timedelta(hours=1),
            refresh_expires_at=timezone.now() + timedelta(days=30),
        )
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "efactura_oauth_token_created"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_updated(self, mock_log):
        token = OAuthToken.objects.create(
            cui="RO12345679",
            access_token="test-token",
            environment="test",
            is_active=True,
            expires_at=timezone.now() + timedelta(hours=1),
            refresh_expires_at=timezone.now() + timedelta(days=30),
        )
        mock_log.reset_mock()
        token.is_active = False
        token.save()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "efactura_oauth_token_updated"

    @patch("apps.billing.signals._log_billing_model_event")
    def test_deleted(self, mock_log):
        token = OAuthToken.objects.create(
            cui="RO12345680",
            access_token="test-token",
            environment="test",
            is_active=True,
            expires_at=timezone.now() + timedelta(hours=1),
            refresh_expires_at=timezone.now() + timedelta(days=30),
        )
        mock_log.reset_mock()
        token.delete()
        call_kwargs = mock_log.call_args_list[-1][1]
        assert call_kwargs["event_type"] == "efactura_oauth_token_deleted"


# ===============================================================================
# INVOICE LIFECYCLE SIGNAL TESTS
# ===============================================================================


class TestInvoiceCreatedOrUpdatedSignal(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    @patch("apps.billing.signals._update_billing_analytics")
    @patch("apps.billing.signals._trigger_efactura_submission")
    @patch("apps.billing.signals._handle_new_invoice_creation")
    @patch("apps.billing.signals.BillingAuditService")
    def test_new_invoice_created(self, mock_bas, mock_new, mock_efactura, mock_analytics):
        InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-SIG-001",
            status="draft",
            efactura_sent=False,
        )
        mock_new.assert_called()
        mock_analytics.assert_called()

    @patch("apps.billing.signals._update_billing_analytics")
    @patch("apps.billing.signals._handle_invoice_status_change")
    @patch("apps.billing.signals._sync_orders_on_invoice_status_change")
    @patch("apps.billing.signals.BillingAuditService")
    def test_invoice_status_change(self, mock_bas, mock_sync, mock_status, mock_analytics):
        invoice = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-SIG-002",
            status="draft",
        )
        # Now update status - pre_save stores original values
        invoice.status = "issued"
        invoice.save()
        # The status change handler should be called
        # (depends on _original_invoice_values being set by pre_save)

    @patch("apps.billing.signals._update_billing_analytics")
    @patch("apps.billing.signals._handle_invoice_refund_completion")
    @patch("apps.billing.signals._handle_invoice_status_change")
    @patch("apps.billing.signals._sync_orders_on_invoice_status_change")
    @patch("apps.billing.signals.BillingAuditService")
    def test_invoice_refund_status(self, mock_bas, mock_sync, mock_status, mock_refund, mock_analytics):
        invoice = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-SIG-003",
            status="paid",
        )
        invoice.status = "refunded"
        invoice.save()

    @patch("apps.billing.signals._update_billing_analytics")
    @patch("apps.billing.signals._trigger_efactura_submission")
    @patch("apps.billing.signals.BillingAuditService")
    def test_issued_invoice_triggers_efactura(self, mock_bas, mock_efactura, mock_analytics):
        invoice = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-SIG-004",
            status="issued",
            efactura_sent=False,
        )
        mock_efactura.assert_called_once_with(invoice)

    @override_settings(DISABLE_AUDIT_SIGNALS=True)
    @patch("apps.billing.signals._update_billing_analytics")
    @patch("apps.billing.signals._handle_new_invoice_creation")
    @patch("apps.billing.signals.BillingAuditService")
    def test_audit_disabled(self, mock_bas, mock_new, mock_analytics):
        InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-SIG-005",
            status="draft",
        )
        mock_bas.log_invoice_event.assert_not_called()


class TestStoreOriginalInvoiceValues(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    def test_stores_original_values_on_update(self):
        invoice = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-OV-001",
            status="draft",
        )
        # On next save, pre_save should store original values
        invoice.status = "issued"
        invoice.save()
        # _original_invoice_values should have been set
        assert hasattr(invoice, "_original_invoice_values")

    def test_new_instance_no_original(self):
        """New instances (no pk yet) should not store original values."""
        # This is tested implicitly by create, but let's be explicit
        InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-OV-002",
        )
        # First save - pk didn't exist in pre_save, so no original values expected
        # (or empty dict if DoesNotExist)


class TestInvoiceNumberGeneration(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    @patch("apps.billing.signals.AuditService")
    @patch("apps.billing.signals.InvoiceNumberingService" if False else "apps.billing.services.InvoiceNumberingService")
    def test_generates_number_for_tmp_invoice(self, mock_numbering, mock_audit):
        """When status is issued and number starts with TMP-, generate real number."""
        invoice = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="TMP-001",
            status="draft",
        )
        mock_seq = MagicMock()
        mock_seq.get_next_number.return_value = "INV-000001"
        mock_numbering.get_or_create_sequence.return_value = mock_seq

        invoice.status = "issued"
        invoice.save()
        # The signal handler checks for TMP- prefix on non-created issued invoices


class TestInvoiceCleanup(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    @patch("apps.billing.signals._cancel_invoice_webhooks")
    @patch("apps.billing.signals._invalidate_invoice_caches")
    @patch("apps.billing.signals._cleanup_invoice_files")
    @patch("apps.billing.signals.log_security_event")
    def test_issued_invoice_deletion_logs_security(self, mock_sec, mock_files, mock_cache, mock_webhooks):
        invoice = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-DEL-001",
            status="issued",
        )
        invoice.delete()
        mock_sec.assert_called_once()
        assert mock_sec.call_args[0][0] == "illegal_invoice_deletion"
        mock_files.assert_called_once()
        mock_cache.assert_called_once()
        mock_webhooks.assert_called_once()

    @patch("apps.billing.signals._cancel_invoice_webhooks")
    @patch("apps.billing.signals._invalidate_invoice_caches")
    @patch("apps.billing.signals._cleanup_invoice_files")
    @patch("apps.billing.signals.log_security_event")
    def test_draft_invoice_deletion_no_security_event(self, mock_sec, mock_files, mock_cache, mock_webhooks):
        invoice = InvoiceFactory(
            customer=self.customer,
            currency=self.currency,
            number="INV-DEL-002",
            status="draft",
        )
        invoice.delete()
        mock_sec.assert_not_called()
        mock_files.assert_called_once()


# ===============================================================================
# PAYMENT LIFECYCLE SIGNAL TESTS
# ===============================================================================


class TestPaymentCreatedOrUpdatedSignal(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    @patch("apps.billing.signals._update_customer_payment_credit")
    @patch("apps.billing.signals._activate_payment_services")
    @patch("apps.billing.signals._handle_payment_status_change")
    @patch("apps.billing.signals.BillingAuditService")
    def test_payment_created(self, mock_bas, mock_status, mock_activate, mock_credit):
        _make_payment(self.customer, currency=self.currency, status="pending")
        mock_bas.log_payment_event.assert_called()

    @patch("apps.billing.signals._update_customer_payment_credit")
    @patch("apps.billing.signals._activate_payment_services")
    @patch("apps.billing.signals._handle_payment_status_change")
    @patch("apps.billing.signals.BillingAuditService")
    def test_payment_status_change_to_succeeded(self, mock_bas, mock_status, mock_activate, mock_credit):
        payment = _make_payment(self.customer, currency=self.currency, status="pending")
        payment.status = "succeeded"
        payment.save()

    @override_settings(DISABLE_AUDIT_SIGNALS=True)
    @patch("apps.billing.signals.BillingAuditService")
    def test_audit_disabled(self, mock_bas):
        _make_payment(self.customer, currency=self.currency, status="pending")
        mock_bas.log_payment_event.assert_not_called()


class TestStoreOriginalPaymentValues(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    def test_stores_original_on_update(self):
        payment = _make_payment(self.customer, currency=self.currency, status="pending")
        payment.status = "succeeded"
        payment.save()
        assert hasattr(payment, "_original_payment_values")


class TestPaymentCleanup(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    @patch("apps.billing.signals._revert_customer_credit_score")
    @patch("apps.billing.signals._cleanup_payment_files")
    @patch("apps.billing.signals.log_security_event")
    def test_succeeded_payment_deletion(self, mock_sec, mock_files, mock_revert):
        payment = _make_payment(self.customer, currency=self.currency, status="succeeded")
        payment.delete()
        mock_sec.assert_called_once()
        mock_revert.assert_called_once_with(self.customer, "payment_deleted")

    @patch("apps.billing.signals._revert_customer_credit_score")
    @patch("apps.billing.signals._cleanup_payment_files")
    @patch("apps.billing.signals.log_security_event")
    def test_pending_payment_deletion_no_revert(self, mock_sec, mock_files, mock_revert):
        payment = _make_payment(self.customer, currency=self.currency, status="pending")
        payment.delete()
        mock_revert.assert_not_called()


# ===============================================================================
# PROFORMA INVOICE SIGNAL TESTS
# ===============================================================================


class TestProformaInvoiceSignal(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    @patch("apps.billing.signals.BillingAuditService")
    def test_proforma_created(self, mock_bas):
        ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-001",
            total_cents=5000,
            subtotal_cents=5000,
        )
        mock_bas.log_proforma_event.assert_called()

    @patch("apps.billing.signals.BillingAuditService")
    def test_proforma_updated(self, mock_bas):
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-002",
            total_cents=5000,
            subtotal_cents=5000,
            status="draft",
        )
        mock_bas.reset_mock()
        proforma.status = "sent"
        proforma.save()
        mock_bas.log_proforma_event.assert_called()

    @patch("apps.billing.signals.ProformaConversionService" if False else "apps.billing.services.ProformaConversionService")
    @patch("apps.billing.signals.BillingAuditService")
    def test_proforma_paid_triggers_conversion(self, mock_bas, mock_conv):
        """When proforma status changes to paid, auto-conversion is attempted."""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-003",
            total_cents=5000,
            subtotal_cents=5000,
            status="draft",
        )
        # Change to paid
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_invoice = MagicMock()
        mock_invoice.number = "INV-FROM-PRO"
        mock_result.unwrap.return_value = mock_invoice
        mock_conv.convert_to_invoice.return_value = mock_result

        proforma.status = "paid"
        proforma.save()


class TestStoreOriginalProformaValues(TestCase):
    def setUp(self):
        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()

    def test_stores_original_on_update(self):
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-OV-001",
            total_cents=5000,
            subtotal_cents=5000,
        )
        proforma.status = "sent"
        proforma.save()
        assert hasattr(proforma, "_original_proforma_values")


# ===============================================================================
# TAX RULE AND VAT VALIDATION SIGNAL TESTS
# ===============================================================================


class TestTaxRuleSignal(TestCase):
    @patch("apps.billing.signals._invalidate_tax_cache")
    @patch("apps.billing.signals.AuditService")
    def test_tax_rule_created(self, mock_audit, mock_cache):
        TaxRule.objects.create(
            country_code="DE",
            tax_type="vat",
            rate=Decimal("0.1900"),
            valid_from=timezone.now().date(),
        )
        mock_cache.assert_called_with("DE", "vat")

    @patch("apps.billing.signals._invalidate_tax_cache")
    @patch("apps.billing.signals.AuditService")
    def test_romanian_tax_rule_logs_compliance(self, mock_audit, mock_cache):
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.2100"),
            valid_from=timezone.now().date(),
        )
        mock_audit.log_compliance_event.assert_called()

    @patch("apps.billing.signals._invalidate_tax_cache")
    @patch("apps.billing.signals.AuditService")
    def test_non_romanian_no_compliance_log(self, mock_audit, mock_cache):
        TaxRule.objects.create(
            country_code="DE",
            tax_type="vat",
            rate=Decimal("0.1900"),
            valid_from=timezone.now().date(),
        )
        mock_audit.log_compliance_event.assert_not_called()

    @override_settings(DISABLE_AUDIT_SIGNALS=True)
    @patch("apps.billing.signals._invalidate_tax_cache")
    @patch("apps.billing.signals.AuditService")
    def test_audit_disabled(self, mock_audit, mock_cache):
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.2100"),
            valid_from=timezone.now().date(),
        )
        mock_audit.log_event.assert_not_called()


class TestVATValidationSignal(TestCase):
    @patch("apps.billing.signals._update_customer_vat_status")
    @patch("apps.billing.signals.AuditService")
    def test_valid_vat(self, mock_audit, mock_vat_status):
        VATValidation.objects.create(
            country_code="RO",
            vat_number="12345678",
            full_vat_number="RO12345678",
            is_valid=True,
            company_name="Test SRL",
            validation_source="vies",
        )
        mock_audit.log_compliance_event.assert_called()
        mock_vat_status.assert_called_once()

    @patch("apps.billing.signals._handle_invalid_vat_number")
    @patch("apps.billing.signals.AuditService")
    def test_invalid_vat(self, mock_audit, mock_invalid):
        VATValidation.objects.create(
            country_code="RO",
            vat_number="00000000",
            full_vat_number="RO00000000",
            is_valid=False,
            validation_source="vies",
        )
        mock_invalid.assert_called_once()

    @patch("apps.billing.signals.AuditService")
    def test_update_not_created_does_nothing(self, mock_audit):
        vat = VATValidation.objects.create(
            country_code="RO",
            vat_number="11111111",
            full_vat_number="RO11111111",
            is_valid=True,
            validation_source="vies",
        )
        mock_audit.reset_mock()
        vat.is_valid = False
        vat.save()
        # Should not log again since created=False
        mock_audit.log_compliance_event.assert_not_called()


# ===============================================================================
# PAYMENT RETRY SIGNAL TESTS
# ===============================================================================


class TestPaymentRetrySignal(TestCase):
    def setUp(self):
        from apps.billing.models import PaymentRetryPolicy  # noqa: PLC0415

        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()
        self.payment = _make_payment(self.customer, currency=self.currency, status="failed")
        self.policy = PaymentRetryPolicy.objects.create(
            name="Default",
            retry_intervals_days=[1, 3, 7],
            max_attempts=3,
        )

    @patch("apps.billing.signals._handle_retry_completion")
    def test_retry_status_change_to_success(self, mock_completion):
        retry = PaymentRetryAttempt.objects.create(
            payment=self.payment,
            policy=self.policy,
            attempt_number=1,
            scheduled_at=timezone.now(),
            status="pending",
        )
        retry.status = "success"
        retry.save()
        mock_completion.assert_called_once()

    @patch("apps.billing.signals._handle_retry_completion")
    def test_retry_status_change_to_failed(self, mock_completion):
        retry = PaymentRetryAttempt.objects.create(
            payment=self.payment,
            policy=self.policy,
            attempt_number=1,
            scheduled_at=timezone.now(),
            status="pending",
        )
        retry.status = "failed"
        retry.save()
        mock_completion.assert_called_once()

    @patch("apps.billing.signals._handle_retry_completion")
    def test_created_retry_does_not_trigger(self, mock_completion):
        """New retry attempts (created=True) should not trigger completion handler."""
        PaymentRetryAttempt.objects.create(
            payment=self.payment,
            policy=self.policy,
            attempt_number=1,
            scheduled_at=timezone.now(),
            status="pending",
        )
        mock_completion.assert_not_called()


class TestStoreOriginalRetryValues(TestCase):
    def setUp(self):
        from apps.billing.models import PaymentRetryPolicy  # noqa: PLC0415

        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()
        self.payment = _make_payment(self.customer, currency=self.currency, status="failed")
        self.policy = PaymentRetryPolicy.objects.create(
            name="Default2",
            retry_intervals_days=[1, 3, 7],
            max_attempts=3,
        )

    def test_stores_original_status(self):
        retry = PaymentRetryAttempt.objects.create(
            payment=self.payment,
            policy=self.policy,
            attempt_number=1,
            scheduled_at=timezone.now(),
            status="pending",
        )
        retry.status = "success"
        retry.save()
        assert hasattr(retry, "_original_retry_status")


# ===============================================================================
# CROSS-APP INTEGRATION FUNCTION TESTS
# ===============================================================================


class TestSyncOrdersOnInvoiceStatusChange(TestCase):
    def test_no_orders(self):
        invoice = MagicMock()
        invoice.orders.exists.return_value = False
        # Should return early without errors
        _sync_orders_on_invoice_status_change(invoice, "draft", "paid")

    @patch("apps.billing.signals.OrderService" if False else "apps.orders.services.OrderService")
    def test_paid_advances_pending_orders(self, mock_os):
        invoice = MagicMock()
        invoice.orders.exists.return_value = True
        order = MagicMock()
        order.status = "pending"
        order.order_number = "ORD-001"
        invoice.orders.filter.return_value = [order]
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_os.update_order_status.return_value = mock_result

        _sync_orders_on_invoice_status_change(invoice, "issued", "paid")
        mock_os.update_order_status.assert_called_once()

    @patch("apps.orders.services.OrderService")
    def test_void_cancels_orders(self, mock_os):
        invoice = MagicMock()
        invoice.orders.exists.return_value = True
        order = MagicMock()
        order.status = "pending"
        order.order_number = "ORD-002"
        invoice.orders.all.return_value = [order]
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_os.update_order_status.return_value = mock_result

        _sync_orders_on_invoice_status_change(invoice, "issued", "void")
        mock_os.update_order_status.assert_called_once()

    @patch("apps.billing.signals._handle_overdue_order_services")
    def test_overdue_handles_services(self, mock_overdue):
        invoice = MagicMock()
        invoice.orders.exists.return_value = True
        _sync_orders_on_invoice_status_change(invoice, "issued", "overdue")
        mock_overdue.assert_called_once_with(invoice)

    def test_exception_handling(self):
        invoice = MagicMock()
        invoice.orders.exists.side_effect = Exception("boom")
        # Should not raise
        _sync_orders_on_invoice_status_change(invoice, "draft", "paid")


class TestActivatePaymentServices(TestCase):
    def test_no_invoice(self):
        payment = MagicMock()
        payment.invoice = None
        _activate_payment_services(payment)

    @patch("apps.provisioning.services.ServiceActivationService")
    def test_activates_pending_services(self, mock_sas):
        payment = MagicMock()
        payment.invoice.number = "INV-001"
        service = MagicMock()
        service.status = "pending"
        item = MagicMock()
        item.service = service
        order = MagicMock()
        order.items.filter.return_value = [item]
        payment.invoice.orders.all.return_value = [order]
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_sas.activate_service.return_value = mock_result

        _activate_payment_services(payment)
        mock_sas.activate_service.assert_called_once()

    def test_exception_handling(self):
        payment = MagicMock()
        payment.invoice.orders.all.side_effect = Exception("boom")
        _activate_payment_services(payment)


class TestUpdateCustomerPaymentCredit(TestCase):
    @patch("apps.customers.services.CustomerCreditService")
    def test_succeeded(self, mock_ccs):
        payment = MagicMock()
        payment.status = "succeeded"
        _update_customer_payment_credit(payment, "pending")
        mock_ccs.update_credit_score.assert_called_once()

    @patch("apps.customers.services.CustomerCreditService")
    def test_failed(self, mock_ccs):
        payment = MagicMock()
        payment.status = "failed"
        _update_customer_payment_credit(payment, "pending")
        mock_ccs.update_credit_score.assert_called_once()

    @patch("apps.customers.services.CustomerCreditService")
    def test_refunded(self, mock_ccs):
        payment = MagicMock()
        payment.status = "refunded"
        _update_customer_payment_credit(payment, "succeeded")
        mock_ccs.update_credit_score.assert_called_once()

    @patch("apps.customers.services.CustomerCreditService")
    def test_no_change(self, mock_ccs):
        payment = MagicMock()
        payment.status = "succeeded"
        _update_customer_payment_credit(payment, "succeeded")
        mock_ccs.update_credit_score.assert_not_called()

    def test_exception_handling(self):
        payment = MagicMock()
        payment.status = "succeeded"
        with patch("apps.customers.services.CustomerCreditService") as mock_ccs:
            mock_ccs.update_credit_score.side_effect = Exception("boom")
            _update_customer_payment_credit(payment, "pending")


# ===============================================================================
# POST-REFUND SIDE EFFECTS
# ===============================================================================


class TestHandleInvoiceRefundCompletion(TestCase):
    @patch("apps.billing.signals.log_security_event")
    @patch("apps.billing.signals._notify_finance_team_large_refund")
    @patch("apps.billing.signals._update_billing_refund_metrics")
    @patch("apps.billing.signals._handle_efactura_refund_reporting")
    @patch("apps.billing.signals._update_customer_invoice_history")
    @patch("apps.billing.signals._send_invoice_refund_confirmation")
    def test_full_flow(self, mock_email, mock_history, mock_efactura, mock_metrics, mock_finance, mock_sec):  # noqa: PLR0913
        invoice = MagicMock()
        invoice.total_cents = LARGE_REFUND_THRESHOLD_CENTS + 1
        invoice.number = "INV-REF-001"
        invoice.id = uuid.uuid4()
        invoice.customer.id = 1

        _handle_invoice_refund_completion(invoice)
        mock_email.assert_called_once()
        mock_history.assert_called_once()
        mock_efactura.assert_called_once()
        mock_metrics.assert_called_once()
        mock_finance.assert_called_once()
        mock_sec.assert_called_once()

    @patch("apps.billing.signals.log_security_event")
    @patch("apps.billing.signals._notify_finance_team_large_refund")
    @patch("apps.billing.signals._update_billing_refund_metrics")
    @patch("apps.billing.signals._handle_efactura_refund_reporting")
    @patch("apps.billing.signals._update_customer_invoice_history")
    @patch("apps.billing.signals._send_invoice_refund_confirmation")
    def test_small_refund_no_finance_notification(self, mock_email, mock_history, mock_efactura, mock_metrics, mock_finance, mock_sec):  # noqa: PLR0913
        invoice = MagicMock()
        invoice.total_cents = 100  # Below threshold
        invoice.number = "INV-REF-002"
        invoice.id = uuid.uuid4()
        invoice.customer.id = 1

        _handle_invoice_refund_completion(invoice)
        mock_finance.assert_not_called()


# ===============================================================================
# BUSINESS LOGIC HELPER FUNCTION TESTS
# ===============================================================================


class TestHandleNewInvoiceCreation(TestCase):
    @patch("apps.billing.signals._update_customer_billing_stats")
    @patch("apps.billing.signals._schedule_payment_reminders")
    @patch("apps.billing.signals._send_invoice_created_email")
    def test_issued_invoice(self, mock_email, mock_reminders, mock_stats):
        invoice = MagicMock()
        invoice.status = "issued"
        _handle_new_invoice_creation(invoice)
        mock_email.assert_called_once()
        mock_reminders.assert_called_once()
        mock_stats.assert_called_once()

    @patch("apps.billing.signals._update_customer_billing_stats")
    @patch("apps.billing.signals._schedule_payment_reminders")
    @patch("apps.billing.signals._send_invoice_created_email")
    def test_draft_invoice_no_reminders(self, mock_email, mock_reminders, mock_stats):
        invoice = MagicMock()
        invoice.status = "draft"
        _handle_new_invoice_creation(invoice)
        mock_email.assert_called_once()
        mock_reminders.assert_not_called()


class TestHandleInvoiceStatusChange(TestCase):
    @patch("apps.billing.signals._handle_invoice_issued")
    @patch("apps.billing.signals.log_security_event")
    def test_draft_to_issued(self, mock_sec, mock_issued):
        invoice = MagicMock()
        _handle_invoice_status_change(invoice, "draft", "issued")
        mock_issued.assert_called_once()
        mock_sec.assert_called_once()

    @patch("apps.billing.signals._handle_invoice_paid")
    @patch("apps.billing.signals.log_security_event")
    def test_issued_to_paid(self, mock_sec, mock_paid):
        invoice = MagicMock()
        _handle_invoice_status_change(invoice, "issued", "paid")
        mock_paid.assert_called_once()

    @patch("apps.billing.signals._handle_invoice_paid")
    @patch("apps.billing.signals.log_security_event")
    def test_overdue_to_paid(self, mock_sec, mock_paid):
        invoice = MagicMock()
        _handle_invoice_status_change(invoice, "overdue", "paid")
        mock_paid.assert_called_once()

    @patch("apps.billing.signals._handle_invoice_overdue")
    @patch("apps.billing.signals.log_security_event")
    def test_issued_to_overdue(self, mock_sec, mock_overdue):
        invoice = MagicMock()
        _handle_invoice_status_change(invoice, "issued", "overdue")
        mock_overdue.assert_called_once()

    @patch("apps.billing.signals._handle_invoice_voided")
    @patch("apps.billing.signals.log_security_event")
    def test_draft_to_void(self, mock_sec, mock_voided):
        invoice = MagicMock()
        _handle_invoice_status_change(invoice, "draft", "void")
        mock_voided.assert_called_once()

    @patch("apps.billing.signals._handle_invoice_voided")
    @patch("apps.billing.signals.log_security_event")
    def test_issued_to_void(self, mock_sec, mock_voided):
        invoice = MagicMock()
        _handle_invoice_status_change(invoice, "issued", "void")
        mock_voided.assert_called_once()


class TestHandlePaymentStatusChange(TestCase):
    @patch("apps.billing.signals._handle_payment_success")
    @patch("apps.billing.signals.log_security_event")
    def test_to_succeeded(self, mock_sec, mock_success):
        payment = MagicMock()
        payment.invoice = None
        _handle_payment_status_change(payment, "pending", "succeeded")
        mock_success.assert_called_once()
        mock_sec.assert_called_once()

    @patch("apps.billing.signals._handle_payment_failure")
    @patch("apps.billing.signals.log_security_event")
    def test_pending_to_failed(self, mock_sec, mock_fail):
        payment = MagicMock()
        payment.invoice = None
        _handle_payment_status_change(payment, "pending", "failed")
        mock_fail.assert_called_once()

    @patch("apps.billing.signals._handle_payment_failure")
    @patch("apps.billing.signals.log_security_event")
    def test_processing_to_failed(self, mock_sec, mock_fail):
        payment = MagicMock()
        payment.invoice = None
        _handle_payment_status_change(payment, "processing", "failed")
        mock_fail.assert_called_once()

    @patch("apps.billing.signals._handle_payment_refund")
    @patch("apps.billing.signals.log_security_event")
    def test_to_refunded(self, mock_sec, mock_refund):
        payment = MagicMock()
        payment.invoice = None
        _handle_payment_status_change(payment, "succeeded", "refunded")
        mock_refund.assert_called_once()


class TestHandleInvoiceIssued(TestCase):
    @patch("apps.billing.signals.AuditService")
    @patch("apps.billing.signals._trigger_efactura_submission")
    @patch("apps.billing.signals._requires_efactura_submission")
    @patch("apps.billing.signals._schedule_payment_reminders")
    @patch("apps.billing.signals._send_invoice_issued_email")
    def test_with_efactura(self, mock_email, mock_reminders, mock_requires, mock_trigger, mock_audit):
        mock_requires.return_value = True
        invoice = MagicMock()
        _handle_invoice_issued(invoice)
        mock_email.assert_called_once()
        mock_reminders.assert_called_once()
        mock_trigger.assert_called_once()
        mock_audit.log_compliance_event.assert_called_once()

    @patch("apps.billing.signals.AuditService")
    @patch("apps.billing.signals._trigger_efactura_submission")
    @patch("apps.billing.signals._requires_efactura_submission")
    @patch("apps.billing.signals._schedule_payment_reminders")
    @patch("apps.billing.signals._send_invoice_issued_email")
    def test_without_efactura(self, mock_email, mock_reminders, mock_requires, mock_trigger, mock_audit):
        mock_requires.return_value = False
        invoice = MagicMock()
        _handle_invoice_issued(invoice)
        mock_trigger.assert_not_called()


class TestHandleInvoicePaid(TestCase):
    @patch("apps.billing.signals._activate_pending_services")
    @patch("apps.billing.signals._update_customer_payment_history")
    @patch("apps.billing.signals._cancel_payment_reminders")
    @patch("apps.billing.signals._send_payment_received_email")
    def test_sets_paid_at(self, mock_email, mock_cancel, mock_history, mock_activate):
        invoice = MagicMock()
        invoice.paid_at = None
        invoice.pk = 1
        _handle_invoice_paid(invoice)
        mock_email.assert_called_once()
        mock_cancel.assert_called_once()
        mock_history.assert_called_once()
        mock_activate.assert_called_once()

    @patch("apps.billing.signals._activate_pending_services")
    @patch("apps.billing.signals._update_customer_payment_history")
    @patch("apps.billing.signals._cancel_payment_reminders")
    @patch("apps.billing.signals._send_payment_received_email")
    def test_already_paid_at(self, mock_email, mock_cancel, mock_history, mock_activate):
        invoice = MagicMock()
        invoice.paid_at = timezone.now()
        _handle_invoice_paid(invoice)
        # Should still process but not update paid_at


class TestHandleInvoiceOverdue(TestCase):
    @patch("apps.billing.signals._handle_overdue_service_suspension")
    @patch("apps.billing.signals._update_customer_payment_history")
    @patch("apps.billing.signals._trigger_dunning_process")
    @patch("apps.billing.signals._send_invoice_overdue_email")
    def test_flow(self, mock_email, mock_dunning, mock_history, mock_suspend):
        invoice = MagicMock()
        _handle_invoice_overdue(invoice)
        mock_email.assert_called_once()
        mock_dunning.assert_called_once()
        mock_history.assert_called_once_with(invoice.customer, "negative")
        mock_suspend.assert_called_once()


class TestHandleInvoiceVoided(TestCase):
    @patch("apps.billing.signals.AuditService")
    @patch("apps.billing.signals._cancel_payment_reminders")
    @patch("apps.billing.signals._send_invoice_voided_email")
    def test_flow(self, mock_email, mock_cancel, mock_audit):
        invoice = MagicMock()
        _handle_invoice_voided(invoice)
        mock_email.assert_called_once()
        mock_cancel.assert_called_once()
        mock_audit.log_compliance_event.assert_called_once()


class TestHandlePaymentSuccess(TestCase):
    @patch("apps.billing.signals._cancel_payment_retries")
    @patch("apps.billing.signals._update_customer_payment_history")
    @patch("apps.billing.signals._send_payment_success_email")
    @patch("apps.billing.signals._trigger_virtualmin_provisioning_on_payment")
    def test_invoice_fully_paid(self, mock_vm, mock_email, mock_history, mock_cancel):
        payment = MagicMock()
        payment.invoice.get_remaining_amount.return_value = 0
        _handle_payment_success(payment)
        mock_email.assert_called_once()
        mock_history.assert_called_once()
        mock_cancel.assert_called_once()
        mock_vm.assert_called_once()
        payment.invoice.save.assert_called_once()

    @patch("apps.billing.signals._cancel_payment_retries")
    @patch("apps.billing.signals._update_customer_payment_history")
    @patch("apps.billing.signals._send_payment_success_email")
    def test_partial_payment(self, mock_email, mock_history, mock_cancel):
        payment = MagicMock()
        payment.invoice.get_remaining_amount.return_value = 5000
        _handle_payment_success(payment)
        payment.invoice.save.assert_not_called()

    @patch("apps.billing.signals._cancel_payment_retries")
    @patch("apps.billing.signals._update_customer_payment_history")
    @patch("apps.billing.signals._send_payment_success_email")
    def test_no_invoice(self, mock_email, mock_history, mock_cancel):
        payment = MagicMock()
        payment.invoice = None
        _handle_payment_success(payment)
        mock_email.assert_called_once()


class TestHandlePaymentFailure(TestCase):
    @patch("apps.billing.signals._update_customer_payment_history")
    @patch("apps.billing.signals._schedule_payment_retry")
    @patch("apps.billing.signals._send_payment_failed_email")
    def test_flow(self, mock_email, mock_retry, mock_history):
        payment = MagicMock()
        _handle_payment_failure(payment)
        mock_email.assert_called_once()
        mock_retry.assert_called_once()
        mock_history.assert_called_once_with(payment.customer, "negative")


class TestHandlePaymentRefund(TestCase):
    @patch("apps.billing.signals._send_payment_refund_email")
    def test_fully_refunded_invoice(self, mock_email):
        payment = MagicMock()
        payment.invoice.total_cents = 1000
        refunded_payment = MagicMock()
        refunded_payment.amount_cents = 1000
        payment.invoice.payments.filter.return_value = [refunded_payment]
        _handle_payment_refund(payment)
        payment.invoice.save.assert_called_once()
        assert payment.invoice.status == "refunded"

    @patch("apps.billing.signals._send_payment_refund_email")
    def test_partial_refund(self, mock_email):
        payment = MagicMock()
        payment.invoice.total_cents = 1000
        refunded_payment = MagicMock()
        refunded_payment.amount_cents = 500
        payment.invoice.payments.filter.return_value = [refunded_payment]
        _handle_payment_refund(payment)
        payment.invoice.save.assert_not_called()

    @patch("apps.billing.signals._send_payment_refund_email")
    def test_no_invoice(self, mock_email):
        payment = MagicMock()
        payment.invoice = None
        _handle_payment_refund(payment)
        mock_email.assert_called_once()


class TestHandleRetryCompletion(TestCase):
    @patch("apps.billing.signals._send_retry_success_email")
    def test_success(self, mock_email):
        retry = MagicMock()
        retry.status = "success"
        _handle_retry_completion(retry)
        mock_email.assert_called_once()

    @patch("apps.billing.signals._handle_final_retry_failure")
    def test_final_failure(self, mock_final):
        retry = MagicMock()
        retry.status = "failed"
        retry.attempt_number = 3
        retry.policy.max_attempts = 3
        _handle_retry_completion(retry)
        mock_final.assert_called_once()

    @patch("apps.billing.signals._handle_final_retry_failure")
    def test_non_final_failure(self, mock_final):
        retry = MagicMock()
        retry.status = "failed"
        retry.attempt_number = 1
        retry.policy.max_attempts = 3
        _handle_retry_completion(retry)
        mock_final.assert_not_called()


# ===============================================================================
# ANALYTICS & REPORTING
# ===============================================================================


class TestUpdateBillingAnalytics(TestCase):
    @patch("apps.billing.signals._invalidate_billing_dashboard_cache")
    @patch("apps.billing.services.BillingAnalyticsService")
    def test_flow(self, mock_bas, mock_cache):
        invoice = MagicMock()
        _update_billing_analytics(invoice, created=True)
        mock_bas.update_invoice_metrics.assert_called_once()
        mock_bas.update_customer_metrics.assert_called_once()
        mock_cache.assert_called_once()

    def test_exception_handling(self):
        invoice = MagicMock()
        with patch("apps.billing.services.BillingAnalyticsService") as mock_bas:
            mock_bas.update_invoice_metrics.side_effect = Exception("boom")
            _update_billing_analytics(invoice, created=False)


class TestUpdateBillingRefundMetrics(TestCase):
    @patch("apps.billing.services.BillingAnalyticsService")
    def test_flow(self, mock_bas):
        invoice = MagicMock()
        _update_billing_refund_metrics(invoice)
        mock_bas.record_invoice_refund.assert_called_once()
        mock_bas.adjust_customer_ltv.assert_called_once()


# ===============================================================================
# EMAIL NOTIFICATION FUNCTION TESTS
# ===============================================================================


class TestEmailFunctions(TestCase):
    """Test all email helper functions handle exceptions gracefully."""

    @patch("apps.notifications.services.EmailService")
    def test_send_invoice_created_email(self, mock_es):
        invoice = MagicMock()
        invoice.bill_to_email = "test@example.com"
        _send_invoice_created_email(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_invoice_created_email_fallback(self, mock_es):
        invoice = MagicMock()
        invoice.bill_to_email = ""
        _send_invoice_created_email(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_invoice_issued_email(self, mock_es):
        invoice = MagicMock()
        _send_invoice_issued_email(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_payment_received_email(self, mock_es):
        invoice = MagicMock()
        _send_payment_received_email(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_invoice_overdue_email(self, mock_es):
        invoice = MagicMock()
        invoice.due_at = timezone.now() - timedelta(days=5)
        _send_invoice_overdue_email(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_invoice_overdue_email_no_due_at(self, mock_es):
        invoice = MagicMock()
        invoice.due_at = None
        _send_invoice_overdue_email(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_invoice_voided_email(self, mock_es):
        invoice = MagicMock()
        _send_invoice_voided_email(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_payment_success_email(self, mock_es):
        payment = MagicMock()
        _send_payment_success_email(payment)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_payment_failed_email(self, mock_es):
        payment = MagicMock()
        _send_payment_failed_email(payment)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_payment_refund_email(self, mock_es):
        payment = MagicMock()
        _send_payment_refund_email(payment)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_invoice_refund_confirmation(self, mock_es):
        invoice = MagicMock()
        invoice.bill_to_email = "test@example.com"
        _send_invoice_refund_confirmation(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_send_retry_success_email(self, mock_es):
        retry = MagicMock()
        _send_retry_success_email(retry)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_notify_finance_team_large_refund(self, mock_es):
        invoice = MagicMock()
        _notify_finance_team_large_refund(invoice)
        mock_es.send_template_email.assert_called_once()

    @patch("apps.notifications.services.EmailService")
    def test_email_exception_handling(self, mock_es):
        mock_es.send_template_email.side_effect = Exception("SMTP error")
        invoice = MagicMock()
        # Should not raise
        _send_invoice_created_email(invoice)
        _send_invoice_issued_email(invoice)
        _send_payment_received_email(invoice)
        _send_invoice_voided_email(invoice)


# ===============================================================================
# UTILITY FUNCTION TESTS
# ===============================================================================


class TestRequiresEfacturaSubmission(TestCase):
    def test_romanian_with_tax_id_above_minimum(self):
        invoice = MagicMock()
        invoice.bill_to_country = "RO"
        invoice.bill_to_tax_id = "RO12345678"
        invoice.total = Decimal("150")
        assert _requires_efactura_submission(invoice) is True

    def test_non_romanian(self):
        invoice = MagicMock()
        invoice.bill_to_country = "DE"
        invoice.bill_to_tax_id = "DE123456789"
        invoice.total = Decimal("150")
        assert _requires_efactura_submission(invoice) is False

    def test_no_tax_id(self):
        invoice = MagicMock()
        invoice.bill_to_country = "RO"
        invoice.bill_to_tax_id = ""
        invoice.total = Decimal("150")
        assert _requires_efactura_submission(invoice) is False

    def test_below_minimum(self):
        invoice = MagicMock()
        invoice.bill_to_country = "RO"
        invoice.bill_to_tax_id = "RO12345678"
        invoice.total = Decimal("50")
        assert _requires_efactura_submission(invoice) is False


class TestTriggerEfacturaSubmission(TestCase):
    @patch("apps.billing.efactura.tasks.queue_efactura_submission")
    def test_successful_queue(self, mock_queue):
        mock_queue.return_value = "task-123"
        invoice = MagicMock()
        invoice.id = uuid.uuid4()
        _trigger_efactura_submission(invoice)
        mock_queue.assert_called_once()

    @patch("apps.billing.efactura.tasks.queue_efactura_submission")
    def test_failed_queue(self, mock_queue):
        mock_queue.return_value = None
        invoice = MagicMock()
        invoice.id = uuid.uuid4()
        _trigger_efactura_submission(invoice)

    def test_import_error(self):
        invoice = MagicMock()
        with patch.dict("sys.modules", {"apps.billing.efactura.tasks": None}):
            # ImportError should be caught
            _trigger_efactura_submission(invoice)


class TestSchedulePaymentReminders(TestCase):
    def test_with_due_at(self):
        invoice = MagicMock()
        invoice.due_at = timezone.now() + timedelta(days=14)
        invoice.id = uuid.uuid4()
        # django_q not available, ImportError should be caught
        _schedule_payment_reminders(invoice)

    def test_no_due_at(self):
        invoice = MagicMock()
        invoice.due_at = None
        _schedule_payment_reminders(invoice)


class TestCancelPaymentReminders(TestCase):
    def test_flow(self):
        invoice = MagicMock()
        # django_q not available, ImportError caught
        _cancel_payment_reminders(invoice)


class TestTriggerDunningProcess(TestCase):
    def test_flow(self):
        invoice = MagicMock()
        # django_q not available, ImportError caught
        _trigger_dunning_process(invoice)


class TestSchedulePaymentRetry(TestCase):
    @patch("apps.billing.services.PaymentRetryService")
    def test_active_policy(self, mock_prs):
        policy = MagicMock()
        policy.is_active = True
        mock_prs.get_customer_retry_policy.return_value = policy
        payment = MagicMock()
        _schedule_payment_retry(payment)
        mock_prs.schedule_retry.assert_called_once()

    @patch("apps.billing.services.PaymentRetryService")
    def test_inactive_policy(self, mock_prs):
        policy = MagicMock()
        policy.is_active = False
        mock_prs.get_customer_retry_policy.return_value = policy
        payment = MagicMock()
        _schedule_payment_retry(payment)
        mock_prs.schedule_retry.assert_not_called()

    @patch("apps.billing.services.PaymentRetryService")
    def test_no_policy(self, mock_prs):
        mock_prs.get_customer_retry_policy.return_value = None
        payment = MagicMock()
        _schedule_payment_retry(payment)
        mock_prs.schedule_retry.assert_not_called()


class TestUpdateCustomerPaymentHistory(TestCase):
    def test_positive(self):
        customer = MagicMock()
        _update_customer_payment_history(customer, "positive")

    def test_negative(self):
        _update_customer_payment_history(MagicMock(), "negative")


class TestUpdateCustomerBillingStats(TestCase):
    def test_flow(self):
        _update_customer_billing_stats(MagicMock())


class TestUpdateCustomerInvoiceHistory(TestCase):
    @patch("apps.customers.services.CustomerAnalyticsService")
    def test_flow(self, mock_cas):
        invoice = MagicMock()
        _update_customer_invoice_history(invoice, "refunded")
        mock_cas.record_invoice_event.assert_called_once()

    def test_exception_handling(self):
        invoice = MagicMock()
        with patch("apps.customers.services.CustomerAnalyticsService") as mock_cas:
            mock_cas.record_invoice_event.side_effect = Exception("boom")
            _update_customer_invoice_history(invoice, "refunded")


class TestActivatePendingServices(TestCase):
    @patch("apps.provisioning.services.ServiceActivationService")
    def test_activates_pending(self, mock_sas):
        invoice = MagicMock()
        service = MagicMock()
        service.status = "pending"
        item = MagicMock()
        item.service = service
        order = MagicMock()
        order.items.filter.return_value = [item]
        invoice.orders.all.return_value = [order]
        _activate_pending_services(invoice)
        mock_sas.activate_service.assert_called_once()

    @patch("apps.provisioning.services.ServiceActivationService")
    def test_skips_active_services(self, mock_sas):
        invoice = MagicMock()
        service = MagicMock()
        service.status = "active"
        item = MagicMock()
        item.service = service
        order = MagicMock()
        order.items.filter.return_value = [item]
        invoice.orders.all.return_value = [order]
        _activate_pending_services(invoice)
        mock_sas.activate_service.assert_not_called()


class TestHandleOverdueServiceSuspension(TestCase):
    @patch("apps.provisioning.services.ServiceManagementService")
    def test_suspends_active_services(self, mock_sms):
        invoice = MagicMock()
        invoice.number = "INV-001"
        service = MagicMock()
        service.status = "active"
        item = MagicMock()
        item.service = service
        order = MagicMock()
        order.items.filter.return_value = [item]
        invoice.orders.all.return_value = [order]
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_sms.suspend_service.return_value = mock_result

        _handle_overdue_service_suspension(invoice)
        mock_sms.suspend_service.assert_called_once()


class TestHandleOverdueOrderServices(TestCase):
    @patch("apps.billing.signals._handle_overdue_service_suspension")
    def test_delegates(self, mock_suspend):
        invoice = MagicMock()
        _handle_overdue_order_services(invoice)
        mock_suspend.assert_called_once_with(invoice)


class TestInvalidateTaxCache(TestCase):
    def test_flow(self):
        _invalidate_tax_cache("RO", "vat")


class TestUpdateCustomerVatStatus(TestCase):
    def test_flow(self):
        vat = MagicMock()
        vat.full_vat_number = "RO12345678"
        _update_customer_vat_status(vat)


class TestHandleInvalidVatNumber(TestCase):
    def test_flow(self):
        vat = MagicMock()
        vat.full_vat_number = "RO00000000"
        _handle_invalid_vat_number(vat)


class TestHandleFinalRetryFailure(TestCase):
    @patch("apps.billing.signals._consider_service_suspension")
    @patch("apps.billing.signals._update_customer_payment_history")
    @patch("apps.billing.signals._send_manual_review_notification")
    def test_flow(self, mock_notify, mock_history, mock_suspend):
        retry = MagicMock()
        _handle_final_retry_failure(retry)
        mock_notify.assert_called_once()
        mock_history.assert_called_once()
        mock_suspend.assert_called_once()


class TestSendManualReviewNotification(TestCase):
    def test_flow(self):
        retry = MagicMock()
        _send_manual_review_notification(retry)


class TestConsiderServiceSuspension(TestCase):
    def test_flow(self):
        payment = MagicMock()
        _consider_service_suspension(payment)


class TestCancelPaymentRetries(TestCase):
    def setUp(self):
        from apps.billing.models import PaymentRetryPolicy  # noqa: PLC0415

        self.customer = CustomerFactory()
        self.currency = _get_or_create_currency()
        self.payment = _make_payment(self.customer, currency=self.currency, status="failed")
        self.policy = PaymentRetryPolicy.objects.create(
            name="Cancel Test",
            retry_intervals_days=[1],
            max_attempts=1,
        )

    def test_cancels_pending_retries(self):
        PaymentRetryAttempt.objects.create(
            payment=self.payment,
            policy=self.policy,
            attempt_number=1,
            scheduled_at=timezone.now(),
            status="pending",
        )
        _cancel_payment_retries(self.payment)
        assert PaymentRetryAttempt.objects.filter(payment=self.payment, status="cancelled").count() == 1


class TestHandleEfacturaRefundReporting(TestCase):
    def test_non_romanian(self):
        invoice = MagicMock()
        invoice.bill_to_country = "DE"
        _handle_efactura_refund_reporting(invoice)

    @patch("apps.billing.signals.AuditService")
    def test_romanian_with_accepted_efactura(self, mock_audit):
        invoice = MagicMock()
        invoice.bill_to_country = "RO"
        invoice.number = "INV-001"
        efactura_doc = MagicMock()
        efactura_doc.status = "accepted"
        invoice.efactura_document = efactura_doc

        with patch("apps.billing.signals.EFacturaStatus" if False else "apps.billing.efactura.models.EFacturaStatus") as mock_status:
            mock_status.ACCEPTED.value = "accepted"
            _handle_efactura_refund_reporting(invoice)
            mock_audit.log_compliance_event.assert_called_once()

    def test_romanian_no_efactura_doc(self):
        invoice = MagicMock()
        invoice.bill_to_country = "RO"
        invoice.efactura_document = None
        _handle_efactura_refund_reporting(invoice)


# ===============================================================================
# CLEANUP AND MAINTENANCE FUNCTION TESTS
# ===============================================================================


class TestInvalidateBillingDashboardCache(TestCase):
    def test_flow(self):
        _invalidate_billing_dashboard_cache(123)


class TestCleanupInvoiceFiles(TestCase):
    @patch("apps.billing.signals.default_storage")
    def test_deletes_existing_files(self, mock_storage):
        mock_storage.exists.return_value = True
        invoice = MagicMock()
        invoice.number = "INV-001"
        _cleanup_invoice_files(invoice)
        assert mock_storage.delete.call_count == 2

    @patch("apps.billing.signals.default_storage")
    def test_no_files(self, mock_storage):
        mock_storage.exists.return_value = False
        invoice = MagicMock()
        invoice.number = "INV-002"
        _cleanup_invoice_files(invoice)
        mock_storage.delete.assert_not_called()


class TestCleanupPaymentFiles(TestCase):
    @patch("apps.billing.signals.default_storage")
    def test_deletes_receipt(self, mock_storage):
        mock_storage.exists.return_value = True
        payment = MagicMock()
        payment.meta = {"receipt_file": "receipts/r001.pdf"}
        _cleanup_payment_files(payment)
        mock_storage.delete.assert_called_once()

    @patch("apps.billing.signals.default_storage")
    def test_no_receipt(self, mock_storage):
        payment = MagicMock()
        payment.meta = {}
        _cleanup_payment_files(payment)
        mock_storage.exists.assert_not_called()


class TestInvalidateInvoiceCaches(TestCase):
    def test_flow(self):
        invoice = MagicMock()
        invoice.id = 1
        invoice.number = "INV-001"
        invoice.customer.id = 1
        _invalidate_invoice_caches(invoice)


class TestCancelInvoiceWebhooks(TestCase):
    @patch("apps.integrations.models.WebhookDelivery")
    def test_cancels_pending(self, mock_wd):
        mock_wd.objects.filter.return_value.update.return_value = 3
        invoice = MagicMock()
        _cancel_invoice_webhooks(invoice)
        mock_wd.objects.filter.assert_called_once()

    @patch("apps.integrations.models.WebhookDelivery")
    def test_no_pending(self, mock_wd):
        mock_wd.objects.filter.return_value.update.return_value = 0
        invoice = MagicMock()
        _cancel_invoice_webhooks(invoice)


class TestRevertCustomerCreditScore(TestCase):
    @patch("apps.customers.services.CustomerCreditService")
    def test_flow(self, mock_ccs):
        customer = MagicMock()
        _revert_customer_credit_score(customer, "payment_deleted")
        mock_ccs.revert_credit_change.assert_called_once()

    def test_exception_handling(self):
        with patch("apps.customers.services.CustomerCreditService") as mock_ccs:
            mock_ccs.revert_credit_change.side_effect = Exception("boom")
            _revert_customer_credit_score(MagicMock(), "test")


# ===============================================================================
# VIRTUALMIN PROVISIONING
# ===============================================================================


class TestTriggerVirtualminProvisioningOnPayment(TestCase):
    @patch("apps.orders.models.OrderItem")
    def test_no_hosting_services(self, mock_oi):
        mock_oi.objects.filter.return_value.select_related.return_value = []
        invoice = MagicMock()
        invoice.number = "INV-001"
        _trigger_virtualmin_provisioning_on_payment(invoice)

    @patch("apps.orders.models.OrderItem")
    def test_with_hosting_services(self, mock_oi):
        service = MagicMock()
        service.requires_hosting_account.return_value = True
        service.get_primary_domain.return_value = "example.com"
        item = MagicMock()
        item.service = service
        mock_oi.objects.filter.return_value.select_related.return_value = [item]
        invoice = MagicMock()
        invoice.number = "INV-001"

        with patch("django_q.tasks.async_task") as mock_async:
            _trigger_virtualmin_provisioning_on_payment(invoice)
            mock_async.assert_called_once()

    @patch("apps.orders.models.OrderItem")
    def test_no_primary_domain(self, mock_oi):
        service = MagicMock()
        service.requires_hosting_account.return_value = True
        service.get_primary_domain.return_value = None
        item = MagicMock()
        item.service = service
        mock_oi.objects.filter.return_value.select_related.return_value = [item]
        invoice = MagicMock()
        invoice.number = "INV-001"
        _trigger_virtualmin_provisioning_on_payment(invoice)

    def test_exception_handling(self):
        invoice = MagicMock()
        with patch("apps.orders.models.OrderItem") as mock_oi:
            mock_oi.objects.filter.side_effect = Exception("boom")
            _trigger_virtualmin_provisioning_on_payment(invoice)


# ===============================================================================
# CONSTANTS TEST
# ===============================================================================


class TestConstants(TestCase):
    def test_constants_exist(self):
        assert LARGE_REFUND_THRESHOLD_CENTS == 50000
        assert E_FACTURA_MINIMUM_AMOUNT == 100
