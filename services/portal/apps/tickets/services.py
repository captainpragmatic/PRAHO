# ===============================================================================
# TICKETS API CLIENT SERVICE - CUSTOMER SUPPORT INTEGRATION 🎫
# ===============================================================================

import logging
from dataclasses import dataclass
from typing import Any, cast

from django.utils import timezone

from apps.api_client.services import PlatformAPIClient, PlatformAPIError

logger = logging.getLogger(__name__)


def _raise_if_rate_limited(exc: Exception) -> None:
    """Re-raise rate-limited errors so views can show appropriate feedback."""
    if isinstance(exc, PlatformAPIError) and exc.is_rate_limited:
        raise exc


def _empty_tickets_summary() -> dict[str, Any]:
    """Canonical zero-shape for tickets summary fallback paths.

    Matches the keys emitted by the platform handler at
    services/platform/apps/api/tickets/views.py:475-555 so consumers
    (dashboard, account_health) get the same key set whether the call
    succeeded or fell back to this empty result. Without shape parity,
    consumers' .get('waiting_on_customer', 0) silently returns 0 only
    on the fallback path while the success path supplies a real count
    — the exact divergence flagged in PR #164 review finding H5.
    """
    return {
        "total_tickets": 0,
        "open_tickets": 0,
        "pending_tickets": 0,
        "waiting_on_customer": 0,
        "resolved_tickets": 0,
        "average_response_time_hours": 0.0,
        "satisfaction_rating": 0.0,
        "recent_tickets": [],
    }


@dataclass
class TicketFilters:
    """Filter parameters for ticket listing"""

    page: int = 1
    status: str = ""
    priority: str = ""
    search: str = ""


@dataclass
class TicketCreateRequest:
    """Parameters for creating a new ticket"""

    title: str
    description: str
    priority: str = "normal"
    category: str = ""
    related_service: int | None = None


class TicketsAPIClient(PlatformAPIClient):
    """
    Customer support tickets API client for portal service.

    Provides customer-only access to their support tickets:
    - List customer tickets
    - View ticket details
    - Create new tickets
    - Reply to tickets
    - View ticket status
    """

    def get_customer_tickets(
        self, customer_id: int, user_id: int, filters: TicketFilters | None = None
    ) -> dict[str, Any]:
        """
        Get paginated list of tickets for a specific customer.

        Args:
            customer_id: Customer ID for filtering tickets
            user_id: User ID making the request
            filters: Optional filters for pagination and search

        Returns:
            Dict containing tickets list and pagination info
        """
        if filters is None:
            filters = TicketFilters()

        try:
            request_data: dict[str, Any] = {
                "customer_id": customer_id,
                "user_id": user_id,
                "page": filters.page,
                "page_size": 20,  # Customer portal pagination
            }

            if filters.status:
                request_data["status"] = filters.status
            if filters.priority:
                request_data["priority"] = filters.priority
            if filters.search:
                request_data["search"] = filters.search

            response = self._make_request("POST", "/tickets/", data=request_data, idempotent=True)

            # Transform platform API response format to expected portal format
            if response.get("success") and "data" in response:
                platform_data = response["data"]
                adapted_response = {
                    "results": platform_data.get("tickets", []),
                    "count": platform_data.get("pagination", {}).get("total", 0),
                    "next": platform_data.get("pagination", {}).get("has_next"),
                    "previous": platform_data.get("pagination", {}).get("has_previous"),
                }
                logger.info(
                    f"✅ [Tickets API] Retrieved tickets for customer {customer_id}: {adapted_response.get('count', 0)} total"
                )
                return adapted_response
            else:
                logger.warning(f"⚠️ [Tickets API] Unexpected response format: {response}")
                return {"results": [], "count": 0}

        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error retrieving tickets for customer {customer_id}: {e}")
            raise

    def get_ticket_detail(self, customer_id: int, user_id: int, ticket_id: int) -> dict[str, Any]:
        """
        Get detailed ticket information for customer view.

        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            ticket_id: Ticket ID to retrieve

        Returns:
            Dict containing ticket details and comments
        """
        try:
            data = {"customer_id": customer_id, "user_id": user_id}
            response = self._make_request("POST", f"/tickets/{ticket_id}/", data=data, idempotent=True)

            logger.info(f"✅ [Tickets API] Retrieved ticket {ticket_id} details for customer {customer_id}")
            return response

        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error retrieving ticket {ticket_id} for customer {customer_id}: {e}")
            raise

    def create_ticket(self, customer_id: int, user_id: int, request: TicketCreateRequest) -> dict[str, Any]:  # type: ignore[override]
        """
        Create a new support ticket for customer.

        Args:
            customer_id: Customer ID creating the ticket
            user_id: User ID for HMAC authentication
            request: Ticket creation parameters

        Returns:
            Dict containing created ticket information
        """
        try:
            # Get user info for contact fields (portal should have user session data)
            # For now, we'll use basic fallback values
            data = {
                "customer_id": customer_id,  # Required for HMAC auth, filtered out by platform
                "user_id": user_id,  # Required for HMAC auth, filtered out by platform
                "action": "create_ticket",  # Required for HMAC auth, filtered out by platform
                "timestamp": int(timezone.now().timestamp()),  # Required for HMAC auth, filtered out by platform
                # Actual ticket creation fields
                "title": request.title,
                "description": request.description,
                "priority": request.priority,
                # contact_email and contact_person will be automatically populated by platform from authenticated customer
            }

            # Map category strings to platform category IDs
            if request.category:
                category_mapping = {
                    "technical": 1,  # Technical Support
                    "billing": 3,  # Billing Question
                    "hosting": 2,  # Technical Issue
                    "domain": 2,  # Technical Issue
                    "email": 2,  # Technical Issue
                }
                data["category"] = category_mapping.get(request.category, 1)  # Default to Technical Support

            if request.related_service:
                data["related_service"] = request.related_service

            logger.debug(f"🔍 [Tickets API] Sending ticket data: {data}")
            response = self._make_request("POST", "/tickets/create/", data=data)

            # Extract ticket data from platform API response format
            if response.get("success") and "data" in response and "ticket" in response["data"]:
                ticket_data = response["data"]["ticket"]
                logger.info(f"✅ [Tickets API] Created ticket {ticket_data.get('id')} for customer {customer_id}")
                return cast(dict[str, Any], ticket_data)
            else:
                logger.error(f"🔥 [Tickets API] Unexpected response format: {response}")
                raise PlatformAPIError(f"Unexpected response format: {response}")

        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error creating ticket for customer {customer_id}: {e}")
            raise

    def add_ticket_reply(
        self, customer_id: int, user_id: int, ticket_id: int, message: str, attachments: list[Any] | None = None
    ) -> dict[str, Any]:
        """
        Add customer reply to existing ticket.

        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            ticket_id: Ticket ID to reply to
            message: Reply message content
            attachments: Optional list of file attachments

        Returns:
            Dict containing reply information
        """
        try:
            data = {
                "customer_id": customer_id,
                "user_id": user_id,
                "content": message,  # Platform API expects 'content' field
                "is_internal": False,  # Customer replies are always public
            }

            if attachments:
                data["attachments"] = attachments

            response = self._make_request("POST", f"/tickets/{ticket_id}/reply/", data=data)

            logger.info(f"✅ [Tickets API] Added reply to ticket {ticket_id} for customer {customer_id}")
            return response

        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error adding reply to ticket {ticket_id} for customer {customer_id}: {e}")
            raise

    def get_ticket_replies(self, customer_id: int, user_id: int, ticket_id: int) -> list[dict[str, Any]]:
        """
        Get all replies for a ticket (customer view - excludes internal notes).

        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            ticket_id: Ticket ID to get replies for

        Returns:
            List of reply dictionaries
        """
        try:
            data = {"customer_id": customer_id, "user_id": user_id}
            response = self._make_request("POST", f"/tickets/{ticket_id}/reply/", data=data, idempotent=True)

            logger.info(f"✅ [Tickets API] Retrieved replies for ticket {ticket_id} for customer {customer_id}")
            return cast(list[dict[str, Any]], response.get("replies", []))

        except PlatformAPIError as e:
            logger.error(
                f"🔥 [Tickets API] Error retrieving replies for ticket {ticket_id} for customer {customer_id}: {e}"
            )
            raise

    def get_tickets_summary(self, customer_id: int, user_id: int) -> dict[str, Any]:
        """
        Get ticket summary statistics for customer dashboard.

        Args:
            customer_id: Customer ID for statistics

        Returns:
            Dict containing ticket counts by status
        """
        try:
            data = {"customer_id": customer_id, "user_id": user_id}
            response = self._make_request("POST", "/tickets/summary/", data=data, idempotent=True)

            # Extract data from platform API response format (same as other methods)
            if response.get("success") and "data" in response:
                summary_data = response["data"]
                logger.info(f"✅ [Tickets API] Retrieved ticket summary for customer {customer_id}")
                return cast(dict[str, Any], summary_data)
            else:
                logger.warning(f"⚠️ [Tickets API] Unexpected summary response format: {response}")
                return _empty_tickets_summary()

        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets API] Error retrieving ticket summary for customer {customer_id}: {e}")
            _raise_if_rate_limited(e)
            # Return empty summary on error to avoid breaking dashboard
            return _empty_tickets_summary()


# Global instance for easy importing
tickets_api = TicketsAPIClient()
