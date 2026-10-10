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
from http import HTTPStatus
from typing import Any

from apps.api_client.services import PlatformAPIClient, PlatformAPIError, quote_path_segment

from .schemas import BillingDocumentPage, Currency, Invoice, Proforma
from .serializers import (
    create_currency_from_api,
    create_invoice_from_api,
    create_invoice_summary_from_api,
    create_proforma_from_api,
)

logger = logging.getLogger(__name__)


class GiftCardPurchaseService:
    """Keep customer identities inside the signed body for all gift purchase operations."""

    def __init__(self, customer_id: int, user_id: int) -> None:
        self.customer_id = customer_id
        self.user_id = user_id
        self.api_client = PlatformAPIClient()

    def call(self, action: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        if action not in {"catalog", "purchases", "create", "detail", "funding", "refresh", "reveal", "resend"}:
            raise ValueError("Unsupported gift purchase action")
        result = self.api_client.post(
            f"/billing/gift-cards/{action}/",
            data={**(data or {}), "customer_id": self.customer_id, "user_id": self.user_id},
        )
        if result.get("success") is not True:
            raise PlatformAPIError("Gift card request could not be completed", response_data=result)
        return result

    def stripe_public_key(self) -> str:
        result = self.api_client.get_billing("stripe-config/", user_id=self.user_id)
        key = result.get("config", {}).get("publishable_key")
        if result.get("success") is not True or not isinstance(key, str) or not key:
            raise PlatformAPIError("Card payments are unavailable")
        return key


def _raise_if_degraded(exc: Exception) -> None:
    """Re-raise a degraded-platform error so the view can say what happened.

    Widened from `_raise_if_rate_limited`, which only ever re-raised throttles: a maintenance 503
    fell through and this module returned an empty page instead, rendering as "you have no
    documents" with nothing to explain it.

    Use this ONLY where the caller has a handler that renders the maintenance state. Widening a
    propagation changes behaviour for the newly propagated case, and a caller that previously could
    not receive an exception will not start handling one just because the name changed - see
    `_raise_if_rate_limited` below.
    """
    if isinstance(exc, PlatformAPIError) and exc.is_degraded:
        raise exc


def _raise_if_rate_limited(exc: Exception) -> None:
    """Re-raise a throttle only, leaving a maintenance 503 to this module's graceful return.

    Kept deliberately, for call sites whose callers have no exception handler and whose existing
    degraded return is already the right customer-facing answer. Widening every site to
    `_raise_if_degraded` was mechanical and wrong: the recurring-payment endpoints below already
    answered "temporarily unavailable" in their JSON contract, and making them raise turned five
    uncaught callers into 500s - a worse outcome than the empty-state bug being fixed.
    """
    if isinstance(exc, PlatformAPIError) and exc.is_rate_limited:
        raise exc


class InvoiceViewService:
    """Service for retrieving and displaying invoice data directly from Platform API"""

    def __init__(self) -> None:
        self.api_client = PlatformAPIClient()

    def get_customer_documents(  # noqa: PLR0913
        self,
        customer_id: int,
        user_id: int,
        page: int = 1,
        limit: int = 20,
        document_type: str = "all",
        status: str = "",
        search: str = "",
        force_sync: bool = False,
    ) -> BillingDocumentPage:
        """Get an authoritative filtered page across invoices and proformas."""
        try:
            request_data: dict[str, Any] = {
                "customer_id": customer_id,
                "user_id": user_id,
                "action": "get_billing_documents",
                "page": page,
                "limit": limit,
                "document_type": document_type,
                "status": status,
                "search": search,
            }
            if force_sync:
                request_data["force_sync"] = True
            response = self.api_client.post("/billing/documents/", data=request_data)
            if not response.get("success"):
                logger.error("Failed to fetch billing documents: %s", response)
                return BillingDocumentPage()

            documents: list[Invoice | Proforma] = []
            for document_data in response.get("documents", []):
                try:
                    if document_data.get("document_type") == "proforma":
                        documents.append(create_proforma_from_api(document_data))
                    else:
                        documents.append(create_invoice_from_api(document_data))
                except Exception as error:
                    logger.error("Failed to parse billing document %s: %s", document_data.get("id"), error)

            pagination = response.get("pagination", {})
            summary = response.get("summary", {})
            return BillingDocumentPage(
                documents=documents,
                current_page=int(pagination.get("current_page", 1)),
                page_size=int(pagination.get("limit", limit)),
                total_items=int(pagination.get("total_items", 0)),
                invoice_count=int(summary.get("invoice_count", 0)),
                proforma_count=int(summary.get("proforma_count", 0)),
                unpaid_invoice_count=int(summary.get("unpaid_invoice_count", 0)),
            )
        except Exception as error:
            logger.error("Error retrieving billing documents for customer %s: %s", customer_id, error)
            _raise_if_degraded(error)
            return BillingDocumentPage()

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
            _raise_if_degraded(e)
            return []

    def _fetch_document(self, kind: str, number: str, customer_id: int, user_id: int) -> dict[str, Any] | None:
        """Platform's record of one invoice or proforma, or None when there is no such document.

        Platform answers 404 for a number that does not exist or is not this customer's, and only
        that means "not found". Any other failure (an outage, a server error, an answer that says
        success without the document) raises: the views say the document could not be loaded,
        rather than wrongly telling the customer it does not exist.
        """
        try:
            segment = quote_path_segment(number)
        except ValueError:
            return None  # a number that cannot be one path segment names no document
        try:
            response = self.api_client.post(
                f"/billing/{kind}s/{segment}/",
                data={"customer_id": customer_id, "user_id": user_id, "action": f"get_{kind}_detail"},
            )
        except PlatformAPIError as error:
            if error.status_code == HTTPStatus.NOT_FOUND:
                logger.info(f"✅ [Billing API] Platform has no {kind} {number} for customer {customer_id}")
                return None
            raise
        document = response.get(kind) if response.get("success") is True else None
        if not isinstance(document, dict) or not document:
            raise PlatformAPIError(f"Platform answered the {kind} lookup without the {kind}", response_data=response)
        return document

    def get_invoice_detail(
        self, invoice_number: str, customer_id: int, user_id: int, force_sync: bool = False
    ) -> Invoice | None:
        """One invoice from Platform, or None when it does not exist; any other failure raises."""
        invoice_data = self._fetch_document("invoice", invoice_number, customer_id, user_id)
        if invoice_data is None:
            return None
        invoice = create_invoice_from_api(invoice_data, invoice_data.get("lines", []))
        logger.info(f"✅ [Invoice API] Retrieved invoice {invoice_number} for customer {customer_id}")
        return invoice

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
                    "currency_code": summary.currency_code,
                    "amount_due_by_currency": summary.amount_due_by_currency,
                    "credit_balance_by_currency": summary.credit_balance_by_currency,
                    "spendable_credit_by_currency": summary.spendable_credit_by_currency,
                    "credit_balances": [
                        {
                            "currency_code": code,
                            "recorded_cents": amount,
                            "spendable_cents": summary.spendable_credit_by_currency.get(code),
                        }
                        for code, amount in summary.credit_balance_by_currency.items()
                    ],
                    "held_credit_entries": summary.held_credit_entries,
                    "credit_spending_on_hold": summary.credit_spending_on_hold,
                    "summary_available": True,
                    "recent_invoices": summary.recent_invoices,
                }

            except Exception as e:
                logger.error(f"🔥 [Invoice API] Failed to parse summary for customer {customer_id}: {e}")
                _raise_if_degraded(e)
                return self._empty_summary()

        except Exception as e:
            logger.error(f"🔥 [Invoice API] Error retrieving summary for customer {customer_id}: {e}")
            _raise_if_degraded(e)
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
            _raise_if_degraded(e)
            return []

    def get_proforma_detail(
        self, proforma_number: str, customer_id: int, user_id: int, force_sync: bool = False
    ) -> Proforma | None:
        """One proforma from Platform, or None when it does not exist; any other failure raises."""
        proforma_data = self._fetch_document("proforma", proforma_number, customer_id, user_id)
        if proforma_data is None:
            return None
        proforma = create_proforma_from_api(proforma_data, proforma_data.get("lines", []))
        logger.info(f"✅ [Proforma API] Retrieved proforma {proforma_number} for customer {customer_id}")
        return proforma

    def get_invoice_pdf(self, invoice_number: str, customer_id: int, user_id: int | None = None) -> bytes:
        """Get invoice PDF directly from Platform API"""
        try:
            # Use binary request to get raw PDF data
            pdf_data = self.api_client._make_binary_request(
                "POST",
                f"/billing/invoices/{quote_path_segment(invoice_number)}/pdf/",
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
                f"/billing/proformas/{quote_path_segment(proforma_number)}/pdf/",
                data={"customer_id": customer_id, "user_id": user_id},
            )

            logger.info(f"✅ [Proforma PDF] Retrieved PDF for proforma {proforma_number}")
            return pdf_data

        except Exception as e:
            logger.error(f"🔥 [Proforma PDF] Error retrieving PDF for proforma {proforma_number}: {e}")
            raise e

    @staticmethod
    def _empty_summary() -> dict[str, Any]:
        """Return empty summary in case of errors"""
        return {
            "total_invoices": 0,
            "draft_invoices": 0,
            "issued_invoices": 0,
            "overdue_invoices": 0,
            "paid_invoices": 0,
            "total_amount_due": None,
            "currency_code": None,
            "amount_due_by_currency": {},
            "credit_balance_by_currency": {},
            "spendable_credit_by_currency": {},
            "credit_balances": [],
            "held_credit_entries": [],
            "credit_spending_on_hold": False,
            "summary_available": False,
            "recent_invoices": [],
        }


class RecurringPaymentsService:
    """Portal boundary for customer-managed PRAHO recurring payments."""

    def __init__(self) -> None:
        self.api_client = PlatformAPIClient()

    def _post(self, endpoint: str, *, customer_id: int, user_id: int, data: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.api_client.post(
                endpoint,
                data={"customer_id": customer_id, **data},
                user_id=user_id,
            )
        except Exception as error:
            # Rate limiting only. `recurring_payments_view` and the four JSON mutation endpoints
            # beneath it have no exception handler, and this dict IS their contract.
            _raise_if_rate_limited(error)
            logger.error("Recurring-payment API call failed for customer %s: %s", customer_id, error)
            return {"success": False, "error": "Recurring-payment service is temporarily unavailable"}

    def overview(self, *, customer_id: int, user_id: int) -> dict[str, Any]:
        return self._post(
            "/billing/recurring-payments/",
            customer_id=customer_id,
            user_id=user_id,
            data={"action": "recurring_payment_overview"},
        )

    def begin_authorization(
        self,
        *,
        customer_id: int,
        user_id: int,
        payment_method_id: int,
        terms_accepted: bool,
        terms_version: str,
    ) -> dict[str, Any]:
        return self._post(
            "/billing/recurring-payments/authorize/begin/",
            customer_id=customer_id,
            user_id=user_id,
            data={
                "action": "begin_recurring_authorization",
                "payment_method_id": payment_method_id,
                "terms_accepted": terms_accepted,
                "terms_version": terms_version,
            },
        )

    def complete_authorization(
        self,
        *,
        customer_id: int,
        user_id: int,
        payment_method_id: int,
        setup_intent_id: str,
    ) -> dict[str, Any]:
        return self._post(
            "/billing/recurring-payments/authorize/complete/",
            customer_id=customer_id,
            user_id=user_id,
            data={
                "action": "complete_recurring_authorization",
                "payment_method_id": payment_method_id,
                "setup_intent_id": setup_intent_id,
            },
        )

    def withdraw_authorization(self, *, customer_id: int, user_id: int, authorization_id: str) -> dict[str, Any]:
        return self._post(
            "/billing/recurring-payments/authorize/withdraw/",
            customer_id=customer_id,
            user_id=user_id,
            data={"action": "withdraw_recurring_authorization", "authorization_id": authorization_id},
        )

    def set_subscription_auto_payment(
        self,
        *,
        customer_id: int,
        user_id: int,
        subscription_id: str,
        authorization_id: str | None,
        enabled: bool,
    ) -> dict[str, Any]:
        return self._post(
            "/billing/recurring-payments/subscriptions/auto-payment/",
            customer_id=customer_id,
            user_id=user_id,
            data={
                "action": "set_subscription_auto_payment",
                "subscription_id": subscription_id,
                "authorization_id": authorization_id,
                "enabled": enabled,
            },
        )


class BillingDataSyncService:
    """Service for manual sync operations (simplified for API-only approach)"""

    def __init__(self) -> None:
        self.api_client = PlatformAPIClient()

    def sync_customer_invoices(self, customer_id: int, user_id: int) -> list[Invoice]:
        """Fetch every invoice page; a partial/failed refresh is never success."""
        invoices: list[Invoice] = []
        page = 1
        while True:
            response = self.api_client.post(
                "/billing/invoices/",
                data={
                    "customer_id": customer_id,
                    "user_id": user_id,
                    "action": "get_invoices",
                    "page": page,
                    "limit": 100,
                    "force_sync": True,
                },
            )
            if response.get("success") is not True:
                raise PlatformAPIError("Unable to refresh invoices")
            rows = response.get("invoices")
            pagination = response.get("pagination")
            if (
                not isinstance(rows, list)
                or not isinstance(pagination, dict)
                or type(pagination.get("current_page")) is not int
                or not isinstance(pagination.get("has_next"), bool)
            ):
                raise PlatformAPIError("Incomplete invoice refresh metadata")
            if pagination["current_page"] != page:
                raise PlatformAPIError("Unexpected invoice page during refresh")
            invoices.extend(create_invoice_from_api(row) for row in rows)
            if not pagination["has_next"]:
                return invoices
            if not rows:
                raise PlatformAPIError("Incomplete invoice refresh")
            page += 1

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
            _raise_if_degraded(e)
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
