"""
Portal Billing Services - Direct Platform API Integration
Handles fetching billing data directly from the platform service via API.
NO DATABASE QUERIES - Pure API-only communication.

Security guidelines:
- All customer/user-scoped requests use POST with an HMAC-signed JSON body
  that includes 'user_id' and 'customer_id'. Do not place identities in URL or
  query parameters (prevents ID enumeration).
- GET is used only for public/non-identity resources (e.g., currencies list).
"""

from __future__ import annotations

import logging
from typing import Any

from apps.api_client.services import PlatformAPIClient

from .schemas import Currency, Invoice, Proforma
from .serializers import (
    create_currency_from_api,
    create_invoice_from_api,
    create_invoice_summary_from_api,
    create_proforma_from_api,
)

logger = logging.getLogger(__name__)


class InvoiceViewService:
    """Service for retrieving and displaying invoice data directly from Platform API"""

    def __init__(self) -> None:
        self.api_client = PlatformAPIClient()

    def get_customer_invoices(self, customer_id: int, user_id: int, force_sync: bool = False) -> list[Invoice]:
        """Get invoices for a customer directly from Platform API"""
        try:
            # Debug logging reduced after stabilization
            # Call Platform API directly
            response = self.api_client.post(
                "/billing/invoices/", data={"customer_id": customer_id, "user_id": user_id, "action": "get_invoices"}
            )

            if not response.get("success"):
                logger.error(f"🔥 [Invoice API] Failed to fetch invoices: {response}")
                return []

            invoices_data = response.get("invoices", [])
            # Debug logging reduced after stabilization
            invoices = []

            # Convert API response to dataclass instances
            for invoice_data in invoices_data:
                try:
                    invoice = create_invoice_from_api(invoice_data)
                    invoices.append(invoice)
                except Exception as e:
                    logger.error(f"🔥 [Invoice API] Failed to parse invoice {invoice_data.get('id')}: {e}")
                    continue

            logger.info(f"✅ [Invoice API] Retrieved {len(invoices)} invoices for customer {customer_id}")
            return invoices

        except Exception as e:
            logger.error(f"🔥 [Invoice API] Error retrieving invoices for customer {customer_id}: {e}")
            return []

    def get_invoice_detail(
        self, invoice_number: str, customer_id: int, user_id: int, force_sync: bool = False
    ) -> Invoice | None:
        """Get invoice details by number directly from Platform API"""
        try:
            # Debug logging reduced after stabilization
            # Call Platform API directly
            response = self.api_client.post(
                f"/billing/invoices/{invoice_number}/",
                data={"customer_id": customer_id, "user_id": user_id, "action": "get_invoice_detail"},
            )

            if not response.get("success"):
                logger.error(f"🔥 [Invoice API] Failed to fetch invoice {invoice_number}: {response}")
                return None

            invoice_data = response.get("invoice")
            if not invoice_data:
                logger.warning(f"⚠️ [Invoice API] No invoice data for {invoice_number}")
                return None

            # Get line items if included
            lines_data = invoice_data.get("lines", [])

            # Convert API response to dataclass instance
            invoice = create_invoice_from_api(invoice_data, lines_data)

            logger.info(f"✅ [Invoice API] Retrieved invoice {invoice_number} for customer {customer_id}")
            return invoice

        except Exception as e:
            logger.error(f"🔥 [Invoice API] Error retrieving invoice {invoice_number}: {e}")
            return None

    def get_invoice_summary(self, customer_id: int, user_id: int) -> dict[str, Any]:
        """Get invoice summary statistics directly from Platform API"""
        try:
            # Debug logging reduced after stabilization
            # Call Platform API directly
            response = self.api_client.post(
                "/billing/summary/", data={"customer_id": customer_id, "user_id": user_id, "action": "get_summary"}
            )

            if not response.get("success"):
                logger.error(f"🔥 [Invoice API] Failed to fetch summary: {response}")
                return self._empty_summary()

            summary_data = response.get("summary", {})

            # Convert API response to dataclass and then dict for template compatibility
            try:
                summary = create_invoice_summary_from_api(summary_data)

                # Convert to dict format expected by templates
                return {
                    "total_invoices": summary.total_invoices,
                    "draft_invoices": summary.draft_invoices,
                    "issued_invoices": summary.issued_invoices,
                    "overdue_invoices": summary.overdue_invoices,
                    "paid_invoices": summary.paid_invoices,
                    "total_amount_due": summary.total_amount_due_cents,  # Keep in cents for consistency
                    "recent_invoices": summary.recent_invoices,
                }

            except Exception as e:
                logger.error(f"🔥 [Invoice API] Failed to parse summary for customer {customer_id}: {e}")
                return self._empty_summary()

        except Exception as e:
            logger.error(f"🔥 [Invoice API] Error retrieving summary for customer {customer_id}: {e}")
            return self._empty_summary()

    def get_customer_proformas(self, customer_id: int, user_id: int, force_sync: bool = False) -> list[Proforma]:
        """Get proformas for a customer directly from Platform API"""
        try:
            # Debug logging reduced after stabilization
            # Call Platform API directly
            response = self.api_client.post(
                "/billing/proformas/", data={"customer_id": customer_id, "user_id": user_id, "action": "get_proformas"}
            )

            if not response.get("success"):
                logger.error(f"🔥 [Proforma API] Failed to fetch proformas: {response}")
                return []

            proformas_data = response.get("proformas", [])
            # Debug logging reduced after stabilization
            proformas = []

            # Convert API response to dataclass instances
            for proforma_data in proformas_data:
                try:
                    proforma = create_proforma_from_api(proforma_data)
                    proformas.append(proforma)
                except Exception as e:
                    logger.error(f"🔥 [Proforma API] Failed to parse proforma {proforma_data.get('id')}: {e}")
                    continue

            logger.info(f"✅ [Proforma API] Retrieved {len(proformas)} proformas for customer {customer_id}")
            return proformas

        except Exception as e:
            logger.error(f"🔥 [Proforma API] Error retrieving proformas for customer {customer_id}: {e}")
            return []

    def get_proforma_detail(
        self, proforma_number: str, customer_id: int, user_id: int, force_sync: bool = False
    ) -> Proforma | None:
        """Get proforma details by number directly from Platform API"""
        try:
            # Call Platform API directly
            response = self.api_client.post(
                f"/billing/proformas/{proforma_number}/",
                data={"customer_id": customer_id, "user_id": user_id, "action": "get_proforma_detail"},
            )

            if not response.get("success"):
                logger.error(f"🔥 [Proforma API] Failed to fetch proforma {proforma_number}: {response}")
                return None

            proforma_data = response.get("proforma")
            if not proforma_data:
                logger.warning(f"⚠️ [Proforma API] No proforma data for {proforma_number}")
                return None

            # DEBUG: Log the actual data structure to understand the issue
            logger.debug(
                f"🔍 [Proforma API] Received proforma_data keys: {list(proforma_data.keys()) if proforma_data else 'None'}"
            )
            logger.debug(f"🔍 [Proforma API] Proforma data: {proforma_data}")

            # Get line items if included
            lines_data = proforma_data.get("lines", [])

            # Convert API response to dataclass instance
            try:
                # DEBUG: Check data before calling serializer
                logger.debug(
                    f"🔍 [Proforma API] About to call create_proforma_from_api with keys: {list(proforma_data.keys()) if proforma_data else 'None'}"
                )
                logger.debug(
                    f"🔍 [Proforma API] ID field check: {'id' in proforma_data if proforma_data else 'No data'}"
                )
                if proforma_data and "id" in proforma_data:
                    logger.debug(
                        f"🔍 [Proforma API] ID value type: {type(proforma_data['id'])}, value: {proforma_data['id']}"
                    )

                proforma = create_proforma_from_api(proforma_data, lines_data)

                logger.info(f"✅ [Proforma API] Retrieved proforma {proforma_number} for customer {customer_id}")
                return proforma
            except KeyError as e:
                logger.error(f"🔥 [Proforma API] KeyError in create_proforma_from_api: {e}")
                logger.error(
                    f"🔍 [Proforma API] Available keys: {list(proforma_data.keys()) if proforma_data else 'None'}"
                )
                raise e
            except Exception as e:
                logger.error(f"🔥 [Proforma API] Unexpected error in create_proforma_from_api: {e}")
                raise e

        except Exception as e:
            logger.error(f"🔥 [Proforma API] Error retrieving proforma {proforma_number}: {e}")
            return None

    def get_invoice_pdf(self, invoice_number: str, customer_id: int, user_id: int | None = None) -> bytes:
        """Get invoice PDF directly from Platform API"""
        try:
            # Use binary request to get raw PDF data
            pdf_data = self.api_client._make_binary_request(
                "POST",
                f"/billing/invoices/{invoice_number}/pdf/",
                data={"customer_id": customer_id, "user_id": user_id},
            )

            logger.info(f"✅ [Invoice PDF] Retrieved PDF for invoice {invoice_number}")
            return pdf_data

        except Exception as e:
            logger.error(f"🔥 [Invoice PDF] Error retrieving PDF for invoice {invoice_number}: {e}")
            raise e

    def get_proforma_pdf(self, proforma_number: str, customer_id: int, user_id: int | None = None) -> bytes:
        """Get proforma PDF directly from Platform API"""
        try:
            # Use binary request to get raw PDF data
            pdf_data = self.api_client._make_binary_request(
                "POST",
                f"/billing/proformas/{proforma_number}/pdf/",
                data={"customer_id": customer_id, "user_id": user_id},
            )

            logger.info(f"✅ [Proforma PDF] Retrieved PDF for proforma {proforma_number}")
            return pdf_data

        except Exception as e:
            logger.error(f"🔥 [Proforma PDF] Error retrieving PDF for proforma {proforma_number}: {e}")
            raise e

    def _empty_summary(self) -> dict[str, Any]:
        """Return empty summary in case of errors"""
        return {
            "total_invoices": 0,
            "draft_invoices": 0,
            "issued_invoices": 0,
            "overdue_invoices": 0,
            "paid_invoices": 0,
            "total_amount_due": 0,
            "recent_invoices": [],
        }


class BillingDataSyncService:
    """Service for manual sync operations (simplified for API-only approach)"""

    def __init__(self) -> None:
        self.api_client = PlatformAPIClient()

    def sync_customer_invoices(self, customer_id: int, user_id: int) -> list[Invoice]:
        """
        'Sync' invoices by fetching fresh data from Platform API
        No local storage - just returns fresh API data
        """
        try:
            # In API-only mode, 'sync' just means fetching fresh data
            invoice_service = InvoiceViewService()
            invoices = invoice_service.get_customer_invoices(customer_id, user_id, force_sync=True)

            logger.info(f"✅ [Billing Sync] Fetched {len(invoices)} fresh invoices for customer {customer_id}")
            return invoices

        except Exception as e:
            logger.error(f"🔥 [Billing Sync] Sync error for customer {customer_id}: {e}")
            return []

    def get_currencies(self) -> list[Currency]:
        """Get available currencies from Platform API"""
        try:
            response = self.api_client.get("/billing/currencies/")

            if not response.get("success"):
                logger.error(f"🔥 [Currency API] Failed to fetch currencies: {response}")
                return []

            currencies_data = response.get("currencies", [])
            currencies = []

            for currency_data in currencies_data:
                try:
                    currency = create_currency_from_api(currency_data)
                    currencies.append(currency)
                except Exception as e:
                    logger.error(f"🔥 [Currency API] Failed to parse currency {currency_data.get('id')}: {e}")
                    continue

            logger.info(f"✅ [Currency API] Retrieved {len(currencies)} currencies")
            return currencies

        except Exception as e:
            logger.error(f"🔥 [Currency API] Error retrieving currencies: {e}")
            return []


# Backwards compatibility helper - since templates might expect some methods
class BillingAPIHelper:
    """Helper class for common billing operations"""

    @staticmethod
    def format_amount(cents: int, currency_code: str = "RON") -> str:
        """Format amount in cents to display string"""
        return f"{cents / 100:.2f} {currency_code}"

    @staticmethod
    def get_status_display(status: str) -> str:
        """Get human-readable status"""
        status_map = {
            "draft": "Draft",
            "issued": "Issued",
            "paid": "Paid",
            "overdue": "Overdue",
            "void": "Void",
            "refunded": "Refunded",
        }
        return status_map.get(status, status.title())

    @staticmethod
    def get_status_class(status: str) -> str:
        """Get CSS class for status"""
        status_classes = {
            "draft": "bg-gray-100 text-gray-800",
            "issued": "bg-blue-100 text-blue-800",
            "paid": "bg-green-100 text-green-800",
            "overdue": "bg-red-100 text-red-800",
            "void": "bg-gray-100 text-gray-600",
            "refunded": "bg-yellow-100 text-yellow-800",
        }
        return status_classes.get(status, "bg-gray-100 text-gray-800")
