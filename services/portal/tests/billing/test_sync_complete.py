"""A manual invoice refresh must not report a partial result as a full sync."""

from unittest.mock import patch

from django.test import SimpleTestCase

from apps.api_client.services import PlatformAPIError
from apps.billing.services import BillingDataSyncService


def row(pk):
    return {
        "id": pk,
        "number": f"INV-{pk}",
        "status": "issued",
        "total_cents": 12100,
        "currency": {"id": "RON", "code": "RON", "name": "Romanian Leu", "symbol": "lei", "decimals": 2},
        "created_at": "2026-09-18T00:00:00Z",
    }


class InvoiceSyncContracts(SimpleTestCase):
    def test_collects_every_page_using_same_identity(self):
        service = BillingDataSyncService()
        responses = [
            {"success": True, "invoices": [row(1)], "pagination": {"has_next": True, "current_page": 1}},
            {"success": True, "invoices": [row(2)], "pagination": {"has_next": False, "current_page": 2}},
        ]
        with patch.object(service.api_client, "post", side_effect=responses) as post:
            invoices = service.sync_customer_invoices(101, 7)
        self.assertEqual([i.number for i in invoices], ["INV-1", "INV-2"])
        self.assertEqual([call.kwargs["data"]["page"] for call in post.call_args_list], [1, 2])
        for call in post.call_args_list:
            self.assertEqual(call.kwargs["data"]["customer_id"], 101)
            self.assertEqual(call.kwargs["data"]["user_id"], 7)

    def test_failed_or_repeated_page_never_returns_partial_success(self):
        service = BillingDataSyncService()
        first = {"success": True, "invoices": [row(1)], "pagination": {"has_next": True, "current_page": 1}}
        for last in ({"success": False}, first):
            with (
                patch.object(service.api_client, "post", side_effect=[first, last]),
                self.assertRaises(PlatformAPIError),
            ):
                service.sync_customer_invoices(101, 7)
