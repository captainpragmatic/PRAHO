import unittest
from unittest.mock import patch

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from apps.billing.services import InvoiceViewService, RecurringPaymentsService


class BillingServicesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = InvoiceViewService()

    @patch('apps.billing.services.PlatformAPIClient.post')
    def test_get_customer_invoices_calls_correct_endpoint(self, mock_post):
        mock_post.return_value = {
            'success': True,
            'invoices': [
                {
                    'id': 1,
                    'number': 'INV-000001',
                    'status': 'issued',
                    'total_cents': 1000,
                    'currency': {'id': 1, 'code': 'RON', 'name': 'Romanian Leu', 'symbol': 'lei', 'decimals': 2},
                    'due_at': '2025-01-01T00:00:00Z',
                    'created_at': '2024-01-01T00:00:00Z',
                }
            ],
        }

        docs = self.service.get_customer_invoices(customer_id=123, user_id=7)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0].number, 'INV-000001')
        mock_post.assert_called_once()
        called_endpoint = mock_post.call_args.args[0]
        self.assertEqual(called_endpoint, '/billing/invoices/')

    @patch('apps.billing.services.PlatformAPIClient.post')
    def test_get_customer_proformas_calls_correct_endpoint(self, mock_post):
        mock_post.return_value = {
            'success': True,
            'proformas': [
                {
                    'id': 2,
                    'number': 'PRO-000001',
                    'status': 'sent',
                    'total_cents': 2000,
                    'currency': {'id': 1, 'code': 'RON', 'name': 'Romanian Leu', 'symbol': 'lei', 'decimals': 2},
                    'valid_until': '2025-01-10T00:00:00Z',
                    'created_at': '2024-01-02T00:00:00Z',
                }
            ],
        }

        docs = self.service.get_customer_proformas(customer_id=123, user_id=7)
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0].number, 'PRO-000001')
        mock_post.assert_called_once()
        called_endpoint = mock_post.call_args.args[0]
        self.assertEqual(called_endpoint, '/billing/proformas/')


class RefundServiceTests(unittest.TestCase):
    """Tests for InvoiceViewService.request_refund."""

    def setUp(self) -> None:
        self.service = InvoiceViewService()

    @patch('apps.billing.services.PlatformAPIClient.process_refund')
    @patch('apps.billing.services.PlatformAPIClient.post')
    def test_request_refund_success(self, mock_post, mock_refund):
        # Mock get_invoice_detail (calls post internally)
        mock_post.return_value = {
            'success': True,
            'invoice': {
                'id': 42,
                'number': 'INV-000001',
                'status': 'paid',
                'total_cents': 5000,
                'currency': {'id': 1, 'code': 'RON', 'name': 'Romanian Leu', 'symbol': 'lei', 'decimals': 2},
                'due_at': '2025-01-01T00:00:00Z',
                'created_at': '2024-01-01T00:00:00Z',
            },
        }
        mock_refund.return_value = {
            'success': True,
            'refund_id': 'ref-123',
            'amount_refunded_cents': 5000,
        }

        result = self.service.request_refund(
            invoice_number='INV-000001',
            customer_id=123,
            user_id=7,
            reason='customer_request',
        )

        self.assertTrue(result['success'])
        self.assertEqual(result['refund_id'], 'ref-123')
        mock_refund.assert_called_once()
        # Verify invoice_id was passed correctly
        call_kwargs = mock_refund.call_args
        self.assertEqual(call_kwargs.kwargs.get('invoice_id') or call_kwargs[1].get('invoice_id'), 42)

    @patch('apps.billing.services.PlatformAPIClient.post')
    def test_request_refund_invoice_not_found(self, mock_post):
        mock_post.return_value = {'success': False, 'error': 'Invoice not found'}

        result = self.service.request_refund(
            invoice_number='INV-INVALID',
            customer_id=123,
            user_id=7,
        )

        self.assertFalse(result['success'])
        self.assertIn('not found', result['error'].lower())

    @patch('apps.billing.services.PlatformAPIClient.process_refund')
    @patch('apps.billing.services.PlatformAPIClient.post')
    def test_request_refund_partial(self, mock_post, mock_refund):
        mock_post.return_value = {
            'success': True,
            'invoice': {
                'id': 42,
                'number': 'INV-000001',
                'status': 'paid',
                'total_cents': 10000,
                'currency': {'id': 1, 'code': 'RON', 'name': 'Romanian Leu', 'symbol': 'lei', 'decimals': 2},
                'due_at': '2025-01-01T00:00:00Z',
                'created_at': '2024-01-01T00:00:00Z',
            },
        }
        mock_refund.return_value = {
            'success': True,
            'refund_id': 'ref-partial',
            'amount_refunded_cents': 3000,
        }

        result = self.service.request_refund(
            invoice_number='INV-000001',
            customer_id=123,
            user_id=7,
            amount_cents=3000,
            reason='service_failure',
        )

        self.assertTrue(result['success'])
        # Verify partial refund type was set
        call_kwargs = mock_refund.call_args
        self.assertEqual(
            call_kwargs.kwargs.get('refund_type') or call_kwargs[1].get('refund_type'),
            'partial',
        )

    @patch('apps.billing.services.PlatformAPIClient.process_refund')
    @patch('apps.billing.services.PlatformAPIClient.post')
    def test_request_refund_api_error(self, mock_post, mock_refund):
        mock_post.return_value = {
            'success': True,
            'invoice': {
                'id': 42,
                'number': 'INV-000001',
                'status': 'paid',
                'total_cents': 5000,
                'currency': {'id': 1, 'code': 'RON', 'name': 'Romanian Leu', 'symbol': 'lei', 'decimals': 2},
                'due_at': '2025-01-01T00:00:00Z',
                'created_at': '2024-01-01T00:00:00Z',
            },
        }
        mock_refund.side_effect = Exception('Platform API unavailable')

        result = self.service.request_refund(
            invoice_number='INV-000001',
            customer_id=123,
            user_id=7,
        )

        self.assertFalse(result['success'])


class RecurringPaymentsClientTests(unittest.TestCase):
    """Portal calls only PRAHO-owned recurring-payment endpoints."""

    @patch("apps.billing.services.PlatformAPIClient.post")
    def test_overview_uses_hmac_body_identity(self, mock_post):
        mock_post.return_value = {"success": True, "payment_methods": [], "subscriptions": []}

        result = RecurringPaymentsService().overview(customer_id=42, user_id=7)

        self.assertTrue(result["success"])
        mock_post.assert_called_once_with(
            "/billing/recurring-payments/",
            data={"customer_id": 42, "action": "recurring_payment_overview"},
            user_id=7,
        )

    @patch("apps.billing.services.PlatformAPIClient.post")
    def test_begin_and_complete_authorization_use_typed_endpoints(self, mock_post):
        mock_post.side_effect = [
            {"success": True, "setup_intent_id": "seti_portal", "client_secret": "secret"},
            {"success": True, "authorization_id": "auth_portal"},
        ]
        service = RecurringPaymentsService()

        begin = service.begin_authorization(
            customer_id=42,
            user_id=7,
            payment_method_id=9,
            terms_accepted=True,
            terms_version="2026-07-17",
        )
        complete = service.complete_authorization(
            customer_id=42,
            user_id=7,
            payment_method_id=9,
            setup_intent_id="seti_portal",
        )

        self.assertTrue(begin["success"])
        self.assertTrue(complete["success"])
        self.assertEqual(mock_post.call_args_list[0].args[0], "/billing/recurring-payments/authorize/begin/")
        self.assertEqual(
            mock_post.call_args_list[0].kwargs["data"],
            {
                "customer_id": 42,
                "action": "begin_recurring_authorization",
                "payment_method_id": 9,
                "terms_accepted": True,
                "terms_version": "2026-07-17",
            },
        )
        self.assertEqual(mock_post.call_args_list[1].args[0], "/billing/recurring-payments/authorize/complete/")

    @patch("apps.billing.services.PlatformAPIClient.post")
    def test_subscription_toggle_and_mandate_withdrawal_are_distinct(self, mock_post):
        mock_post.return_value = {"success": True}
        service = RecurringPaymentsService()

        service.set_subscription_auto_payment(
            customer_id=42,
            user_id=7,
            subscription_id="sub_local",
            authorization_id="auth_local",
            enabled=False,
        )
        service.withdraw_authorization(customer_id=42, user_id=7, authorization_id="auth_local")

        self.assertEqual(
            mock_post.call_args_list[0].args[0],
            "/billing/recurring-payments/subscriptions/auto-payment/",
        )
        self.assertEqual(
            mock_post.call_args_list[1].args[0],
            "/billing/recurring-payments/authorize/withdraw/",
        )

    @patch('apps.api_client.services.PlatformAPIClient.post_billing')
    def test_process_refund_calls_correct_endpoint(self, mock_post):

        mock_post.return_value = {
            'success': True,
            'refund_id': 'ref_123',
            'amount_refunded_cents': 5000,
        }

        client = PlatformAPIClient()
        result = client.process_refund(invoice_id=1, amount_cents=5000, reason='test', user_id='7')

        self.assertTrue(result['success'])
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[0][0], 'process-refund/')
        data = call_args[1].get('data') or call_args[0][1] if len(call_args[0]) > 1 else call_args[1]['data']
        self.assertEqual(data['invoice_id'], 1)
        self.assertEqual(data['amount_cents'], 5000)


class BillingRateLimitPropagationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = InvoiceViewService()

    @patch("apps.billing.services.PlatformAPIClient.post")
    def test_get_customer_invoices_reraises_rate_limit_error(self, mock_post):
        mock_post.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=5, is_rate_limited=True
        )

        with self.assertRaises(PlatformAPIError):
            self.service.get_customer_invoices(customer_id=1, user_id=2)

    @patch("apps.billing.services.PlatformAPIClient.post")
    def test_get_customer_proformas_reraises_rate_limit_error(self, mock_post):
        mock_post.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=5, is_rate_limited=True
        )

        with self.assertRaises(PlatformAPIError):
            self.service.get_customer_proformas(customer_id=1, user_id=2)

    @patch("apps.billing.services.PlatformAPIClient.post")
    def test_get_invoice_summary_reraises_rate_limit_error(self, mock_post):
        mock_post.side_effect = PlatformAPIError(
            "Too many requests", status_code=429, retry_after=5, is_rate_limited=True
        )

        with self.assertRaises(PlatformAPIError):
            self.service.get_invoice_summary(customer_id=1, user_id=2)
