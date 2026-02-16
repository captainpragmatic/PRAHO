import unittest
from unittest.mock import patch, MagicMock

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
