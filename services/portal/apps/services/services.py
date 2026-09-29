"""
Services API Client (customer-facing "My Services")

Security guidelines:
- All customer/user-scoped calls MUST use POST with an HMAC-signed JSON body
  that includes 'user_id' and 'customer_id'. Avoid putting identities in URL
  or query parameters to prevent ID enumeration.
- GET is reserved for public/non-identity endpoints (e.g., /api/services/plans/),
  which accept optional filters but no customer/user identity.
"""

# ===============================================================================
# SERVICES API CLIENT SERVICE - CUSTOMER HOSTING MANAGEMENT 🔧
# ===============================================================================

import logging
from typing import Any, cast
from uuid import UUID

from django.utils.dateparse import parse_date, parse_datetime

from apps.api_client.services import PlatformAPIClient, PlatformAPIError

logger = logging.getLogger(__name__)


def _service_request_receipt(response: dict[str, Any]) -> dict[str, Any]:
    """Accept only a usable customer receipt, excluding private review metadata."""
    data = response.get("data")
    if response.get("success") is not True or not isinstance(data, dict):
        raise PlatformAPIError("Invalid service request receipt")

    request_id = data.get("request_id")
    ticket_id = data.get("ticket_id")
    ticket_number = data.get("ticket_number")
    if (
        not isinstance(request_id, str)
        or not isinstance(ticket_id, int)
        or isinstance(ticket_id, bool)
        or ticket_id <= 0
        or not isinstance(ticket_number, str)
        or not ticket_number.strip()
    ):
        raise PlatformAPIError("Invalid service request receipt")
    try:
        request_id = str(UUID(request_id))
    except ValueError as exc:
        raise PlatformAPIError("Invalid service request receipt") from exc

    return {"request_id": request_id, "ticket_id": ticket_id, "ticket_number": ticket_number}


def _raise_if_degraded(exc: Exception) -> None:
    """Re-raise a degraded-platform error so the view can say what happened.

    Renamed from the throttle-only version, which re-raised a 429 and let a maintenance 503 fall
    through to the graceful returns below. During a window the dashboard badge therefore read
    "0 active services", the plans list was empty and the usage panel showed zeros - the reported
    bug exactly, in the one app the widening skipped. `services_table.html` already carried an
    `{% elif maintenance %}` arm that could never fire for these paths.

    The callers were checked one at a time rather than widened mechanically, because that mistake
    on this branch turned five uncaught callers into 500s. Each of the four sites below has a
    handler that renders the maintenance state; `get_customer_services`, `get_service_detail` and
    `request_service_action` already re-raised everything, which is why the services LIST page
    worked and hid the rest.
    """
    if isinstance(exc, PlatformAPIError) and exc.is_degraded:
        raise exc


def _unavailable_usage(period: str) -> dict[str, Any]:
    """Canonical shape for a usage panel that could not be filled.

    `error` is the key `services/partials/usage_chart.html` branches on, and BOTH fallback returns in
    `get_service_usage` omitted it. Its error arm was therefore unreachable, and a platform failure
    rendered a chart of zeros indistinguishable from a service that genuinely used nothing - the same
    "a failure shown as data" defect as the maintenance bug, one floor down and for every 5xx.

    The zeros stay, for any consumer that reads the numbers without asking whether they are real. One
    function rather than two literals because the two had already diverged in exactly this key.
    """
    return {
        "error": True,
        "bandwidth_used": 0,
        "bandwidth_limit": 0,
        "storage_used": 0,
        "storage_limit": 0,
        "period": period,
    }


def _empty_services_summary() -> dict[str, Any]:
    """Canonical zero-shape for services summary fallback paths.

    Matches the keys emitted by the platform handler at
    services/platform/apps/api/services/views.py:264-277. Consumers
    (dashboard active_services badge, account_health expiring_soon /
    suspended_services banner) get the same key set whether the call
    succeeded or fell back to this empty result. PR #164 review
    finding H6: previous fallback dicts omitted expiring_soon and
    overdue, silently suppressing the expiring-services banner during
    platform outages.
    """
    return {
        "total_services": 0,
        "active_services": 0,
        "suspended_services": 0,
        "pending_services": 0,
        "overdue": 0,
        "expiring_soon": 0,
        # None means "counts unknown" — the services view hides tab badges
        # instead of rendering fabricated zeros next to a failed/absent summary.
        "status_counts": None,
        "total_monthly_cost": 0.0,
        "total_monthly_cost_with_vat": 0.0,
        "total_disk_usage_gb": 0.0,
        "total_bandwidth_usage_gb": 0.0,
        "service_types": {},
        "recent_services": [],
    }


def _parse_service_dates(service: dict[str, Any]) -> None:
    """Convert ISO API dates before date-aware template formatters receive them."""
    for field in ("next_billing_date", "expires_at", "activated_at", "created_at", "updated_at"):
        value = service.get(field)
        if isinstance(value, str):
            try:
                parsed = parse_date(value) or parse_datetime(value)
            except ValueError as exc:
                raise PlatformAPIError(f"Invalid service date: {field}") from exc
            if parsed is None:
                raise PlatformAPIError(f"Invalid service date: {field}")
            service[field] = parsed


class ServicesAPIClient(PlatformAPIClient):
    """
    Customer hosting services API client for portal service.

    Provides customer-only access to their hosting services:
    - List customer services
    - View service details
    - View service status and usage
    - Service management (limited customer actions)
    """

    def get_customer_services(  # type: ignore[override]  # noqa: PLR0913 -- explicit filters preserve the existing client API
        self,
        customer_id: int,
        user_id: int,
        page: int = 1,
        status: str = "",
        service_type: str = "",
        *,
        search: str = "",
    ) -> dict[str, Any]:
        """
        Get paginated list of hosting services for a specific customer.

        Args:
            customer_id: Customer ID for filtering services
            user_id: User ID for HMAC authentication
            page: Page number for pagination
            status: Filter by a value from the platform Service status choices
            service_type: Filter by service type (shared, vps, dedicated, etc.)

        Returns:
            Dict containing services list and pagination info
        """
        try:
            data: dict[str, Any] = {
                "customer_id": customer_id,
                "user_id": user_id,
                "page": page,
                "limit": 20,
            }

            if search:
                data["search"] = search
            if status:
                data["status"] = status
            if service_type:
                data["service_type"] = service_type

            response = self._make_request("POST", "/services/", user_id=user_id, data=data, idempotent=True)

            # Transform platform API response format to expected portal format
            if response.get("success") and "data" in response:
                platform_data = response["data"]
                services = platform_data.get("services", [])
                # Ensure currency_code defaults to RON for template rendering
                for svc in services:
                    svc.setdefault("currency_code", "RON")
                    _parse_service_dates(svc)
                adapted_response = {
                    "results": services,
                    "count": platform_data.get("pagination", {}).get("total", 0),
                    "stats": platform_data.get("stats", {}),
                }
                logger.info(
                    f"✅ [Services API] Retrieved services for customer {customer_id}: {adapted_response.get('count', 0)} total"
                )
                return adapted_response
            else:
                logger.warning(f"⚠️ [Services API] Unexpected response format: {response}")
                return {"results": [], "count": 0}

        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving services for customer {customer_id}: {e}")
            raise

    def get_service_detail(self, customer_id: int, user_id: int, service_id: int) -> dict[str, Any]:
        """
        Get detailed service information for customer view.

        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            service_id: Service ID to retrieve

        Returns:
            Dict containing service details, plan info, and configuration
        """
        try:
            data = {"customer_id": customer_id, "user_id": user_id}
            response = self._make_request(
                "POST", f"/services/{service_id}/", user_id=user_id, data=data, idempotent=True
            )

            # Extract service data from nested platform API response
            if response.get("success") and "data" in response and "service" in response["data"]:
                service_data = response["data"]["service"]
                service_data.setdefault("currency_code", "RON")
                _parse_service_dates(service_data)
                logger.info(f"✅ [Services API] Retrieved service {service_id} details for customer {customer_id}")
                return cast(dict[str, Any], service_data)
            else:
                logger.warning(f"⚠️ [Services API] Unexpected service detail response format: {response}")
                return {}

        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving service {service_id} for customer {customer_id}: {e}")
            raise

    def get_service_usage(self, customer_id: int, user_id: int, service_id: int, period: str = "30d") -> dict[str, Any]:
        """
        Get service usage statistics for customer view.

        Args:
            customer_id: Customer ID for authorization
            user_id: User ID for HMAC authentication
            service_id: Service ID to get usage for
            period: Usage period (7d, 30d, 90d)

        Returns:
            Dict containing usage statistics (bandwidth, storage, etc.)
        """
        try:
            data = {"customer_id": customer_id, "user_id": user_id, "period": period}
            response = self._make_request(
                "POST", f"/services/{service_id}/usage/", user_id=user_id, data=data, idempotent=True
            )

            # Extract usage data from nested platform API response
            if response.get("success") and "data" in response and "usage" in response["data"]:
                usage_data = response["data"]["usage"]
                logger.info(f"✅ [Services API] Retrieved usage for service {service_id} for customer {customer_id}")
                return cast(dict[str, Any], usage_data)
            else:
                logger.warning(f"⚠️ [Services API] Unexpected usage response format: {response}")
                return _unavailable_usage(period)

        except PlatformAPIError as e:
            logger.error(
                f"🔥 [Services API] Error retrieving usage for service {service_id} for customer {customer_id}: {e}"
            )
            _raise_if_degraded(e)
            # Not raising keeps the page up; the marker is what stops it lying about the numbers.
            return _unavailable_usage(period)

    def get_services_summary(self, customer_id: int, user_id: int) -> dict[str, Any]:
        """
        Get services summary statistics for customer dashboard.

        Args:
            customer_id: Customer ID for statistics
            user_id: User ID for HMAC authentication

        Returns:
            Dict containing service counts by status and type
        """
        try:
            data = {"customer_id": customer_id, "user_id": user_id}
            response = self._make_request("POST", "/services/summary/", user_id=user_id, data=data, idempotent=True)

            # Extract summary data from nested response structure
            if response.get("success") and "data" in response and "summary" in response["data"]:
                summary_data = response["data"]["summary"]
                # An older platform may omit status_counts (independent deploys),
                # and a non-dict must never reach the view: badges render only
                # from a real per-status map, otherwise they are hidden.
                status_counts = summary_data.get("status_counts")
                summary_data["status_counts"] = status_counts if isinstance(status_counts, dict) else None
                logger.info(
                    f"✅ [Services API] Retrieved services summary for customer {customer_id}: {summary_data.get('active_services', 0)} active"
                )
                return cast(dict[str, Any], summary_data)
            else:
                logger.warning(f"⚠️ [Services API] Unexpected summary response format: {response}")
                return _empty_services_summary()

        except PlatformAPIError as e:
            logger.error(f"🔥 [Services API] Error retrieving services summary for customer {customer_id}: {e}")
            _raise_if_degraded(e)
            # Return empty summary on error
            return _empty_services_summary()

    def get_service_domains(self, customer_id: int, service_id: int) -> list[dict[str, Any]]:
        """
        Get domains associated with a specific service.

        Args:
            customer_id: Customer ID for authorization
            service_id: Service ID to get domains for

        Returns:
            List of domain dictionaries
        """
        try:
            data = {"customer_id": customer_id}
            response = self._make_request("POST", f"/services/{service_id}/domains/", data=data, idempotent=True)

            logger.info(f"✅ [Services API] Retrieved domains for service {service_id} for customer {customer_id}")
            return cast(list[dict[str, Any]], response.get("domains", []))

        except PlatformAPIError as e:
            _raise_if_degraded(e)
            # Domains API endpoint not yet implemented on platform (returns 404).
            # Gracefully degrade — log as warning, not error.
            http_not_found = 404
            log_level = logger.warning if getattr(e, "status_code", 500) == http_not_found else logger.error
            log_level(
                f"⚠️ [Services API] Could not retrieve domains for service {service_id} for customer {customer_id}: {e}"
            )
            return []

    def request_service_action(  # noqa: PLR0913 -- signed identity and submission receipt are required for this mutation
        self,
        customer_id: int,
        user_id: int,
        service_id: int,
        action: str,
        reason: str = "",
        *,
        submission_id: str,
    ) -> dict[str, Any]:
        """
        Request service action (customer-available actions only).
        Creates a service request that staff must approve.

        Args:
            customer_id: Customer ID for authorization
            user_id: Acting user whose membership Platform must verify
            service_id: Service ID to perform action on
            action: One of the four customer request actions
            reason: Optional reason for the request
            submission_id: Stable form UUID, retained when the outcome is unknown

        Returns:
            Receipt containing request_id, ticket_id, and ticket_number only
        """
        try:
            # Only allow customer-safe actions
            allowed_actions = ["upgrade_request", "downgrade_request", "suspend_request", "cancel_request"]
            if action not in allowed_actions:
                raise PlatformAPIError(f"Action '{action}' not allowed for customer requests")

            data = {
                "customer_id": customer_id,
                "user_id": user_id,
                "action": action,
                "reason": reason,
                "submission_id": submission_id,
            }

            # Writes are not automatically retried. A deliberate retry uses the same submission UUID.
            response = self._make_request("POST", f"/services/{service_id}/actions/", user_id=user_id, data=data)
            receipt = _service_request_receipt(response)

            logger.info(
                f"✅ [Services API] Requested action '{action}' for service {service_id} by customer {customer_id}"
            )
            return receipt

        except PlatformAPIError as e:
            logger.error(
                f"🔥 [Services API] Error requesting action '{action}' for service {service_id} by customer {customer_id}: {e}"
            )
            raise

    def get_available_plans(self, customer_id: int, service_type: str = "") -> list[dict[str, Any]]:
        """
        Get available hosting plans for customer (for upgrades/downgrades).

        Args:
            customer_id: Customer ID for authorization
            service_type: Optional filter by service type

        Returns:
            List of available plan dictionaries
        """
        try:
            # Platform expects GET /api/services/plans/ with optional plan_type filter
            params = {}
            if service_type:
                params["plan_type"] = service_type

            response = self._make_request("GET", "/services/plans/", params=params)

            logger.info(f"✅ [Services API] Retrieved available plans for customer {customer_id}")
            return cast(list[dict[str, Any]], response.get("data", {}).get("plans", []))

        except PlatformAPIError as e:
            _raise_if_degraded(e)
            logger.error(f"🔥 [Services API] Error retrieving plans for customer {customer_id}: {e}")
            return []


# Global instance for easy importing
services_api = ServicesAPIClient()
