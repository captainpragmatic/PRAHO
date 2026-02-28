import unittest
from unittest.mock import patch

from apps.api_client.services import PlatformAPIClient
from apps.billing.services import InvoiceViewService


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


class PaymentMethodsServiceTests(unittest.TestCase):
    """Tests for InvoiceViewService.get_payment_methods."""

    def setUp(self) -> None:
        self.service = InvoiceViewService()

    @patch('apps.billing.services.PlatformAPIClient.get_payment_methods')
    def test_get_payment_methods_success(self, mock_get):
        mock_get.return_value = {
            'success': True,
            'payment_methods': [
                {'type': 'card', 'name': 'Stripe', 'supports_recurring': True},
                {'type': 'bank_transfer', 'name': 'Bank Transfer', 'supports_recurring': False},
            ],
        }

        methods = self.service.get_payment_methods(customer_id=123, user_id=7)
        self.assertEqual(len(methods), 2)
        self.assertEqual(methods[0]['type'], 'card')
        mock_get.assert_called_once_with(customer_id='123', user_id='7')

    @patch('apps.billing.services.PlatformAPIClient.get_payment_methods')
    def test_get_payment_methods_api_failure(self, mock_get):
        mock_get.return_value = {'success': False, 'error': 'Service unavailable'}

        methods = self.service.get_payment_methods(customer_id=123, user_id=7)
        self.assertEqual(methods, [])

    @patch('apps.billing.services.PlatformAPIClient.get_payment_methods')
    def test_get_payment_methods_exception(self, mock_get):
        mock_get.side_effect = Exception('Connection error')

        methods = self.service.get_payment_methods(customer_id=123, user_id=7)
        self.assertEqual(methods, [])


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


class SubscriptionClientTests(unittest.TestCase):
    """Tests for PlatformAPIClient.create_subscription."""

    @patch('apps.api_client.services.PlatformAPIClient.post_billing')
    def test_create_subscription_calls_correct_endpoint(self, mock_post):

        mock_post.return_value = {
            'success': True,
            'subscription_id': 'sub_123',
            'status': 'active',
        }

        client = PlatformAPIClient()
        result = client.create_subscription(
            customer_id='42',
            price_id='price_hosting_monthly',
            billing_cycle='monthly',
            user_id=7,
        )

        self.assertTrue(result['success'])
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[0][0], 'create-subscription/')
        data = call_args[1].get('data') or call_args[0][1] if len(call_args[0]) > 1 else call_args[1]['data']
        self.assertEqual(data['customer_id'], '42')
        self.assertEqual(data['price_id'], 'price_hosting_monthly')

    @patch('apps.api_client.services.PlatformAPIClient.get_billing')
    def test_get_payment_methods_calls_correct_endpoint(self, mock_get):

        mock_get.return_value = {
            'success': True,
            'payment_methods': [{'type': 'card'}],
        }

        client = PlatformAPIClient()
        result = client.get_payment_methods(customer_id='42', user_id='7')

        self.assertTrue(result['success'])
        mock_get.assert_called_once_with('payment-methods/42/', user_id='7')

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
