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
import re
from typing import Any, cast
from uuid import UUID

from django.utils.dateparse import parse_date, parse_datetime
from django.utils.timezone import is_aware

from apps.api_client.services import PlatformAPIClient, PlatformAPIError

logger = logging.getLogger(__name__)

_DNS_COMPONENTS = frozenset({"apex", "www", "caa", "dnssec", "mx"})
_DNS_STATES = frozenset({"healthy", "broken", "unknown", "not_applicable"})
_DNS_PUBLIC_STATES = _DNS_STATES | {"unavailable", "maintenance"}
_DNS_FIELDS = frozenset(
    {"version", "state", "dns_path", "pending", "stale", "checked_at", "account_name", "instructions", "components"}
)
_MAX_DNS_INSTRUCTIONS = 8


def _dns_checked_at(value: object) -> bool:
    if value is None:
        return False
    try:
        parsed = parse_datetime(value) if isinstance(value, str) else None
    except ValueError as error:
        raise PlatformAPIError("DNS status is unavailable") from error
    if parsed is None or not is_aware(parsed):
        raise PlatformAPIError("DNS status is unavailable")
    return True


def _dns_receipt_components(status: dict[str, Any]) -> set[str]:
    components = status["components"]
    if not isinstance(components, dict) or not set(components) <= _DNS_COMPONENTS:
        raise PlatformAPIError("DNS status is unavailable")
    states = set()
    for component in components.values():
        if (
            not isinstance(component, dict)
            or not isinstance(component.get("state"), str)
            or component["state"] not in _DNS_STATES
            or not isinstance(component.get("code"), str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,79}", component["code"]) is None
        ):
            raise PlatformAPIError("DNS status is unavailable")
        states.add(component["state"])
    return states


def _dns_receipt_instructions(status: dict[str, Any]) -> None:
    account_name = status["account_name"]
    if account_name is not None and (not isinstance(account_name, str) or not account_name.strip()):
        raise PlatformAPIError("DNS status is unavailable")
    instructions = status["instructions"]
    if not isinstance(instructions, list) or len(instructions) > _MAX_DNS_INSTRUCTIONS:
        raise PlatformAPIError("DNS status is unavailable")
    for record in instructions:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("type"), str)
            or record["type"] not in {"CNAME", "ALIAS"}
            or not isinstance(record.get("name"), str)
            or not record["name"].strip()
            or not isinstance(record.get("value"), str)
            or record["value"] != account_name
        ):
            raise PlatformAPIError("DNS status is unavailable")


def _dns_status_receipt(response: object) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise PlatformAPIError("DNS status is unavailable")
    data = response.get("data")
    status = data.get("dns_status") if isinstance(data, dict) else None
    if (
        response.get("success") is not True
        or not isinstance(status, dict)
        or not status.keys() >= _DNS_FIELDS
        or type(status.get("version")) is not int
        or status.get("version") != 1
        or not isinstance(status.get("state"), str)
        or status.get("state") not in _DNS_PUBLIC_STATES
        or not isinstance(status["dns_path"], str)
        or re.fullmatch(r"[a-z][a-z0-9_]{0,79}", status["dns_path"]) is None
        or type(status["pending"]) is not bool
        or type(status["stale"]) is not bool
        or ("queued" in status and type(status["queued"]) is not bool)
    ):
        raise PlatformAPIError("DNS status is unavailable")
    dated = _dns_checked_at(status["checked_at"])
    states = _dns_receipt_components(status)
    _dns_receipt_instructions(status)
    if status["state"] in {"healthy", "broken"} and (not dated or set(status["components"]) != _DNS_COMPONENTS):
        raise PlatformAPIError("DNS status is unavailable")
    if status["state"] == "healthy" and (
        not status["account_name"] or "healthy" not in states or not states <= {"healthy", "not_applicable"}
    ):
        raise PlatformAPIError("DNS status is unavailable")
    return status


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
        "currency_code": None,
        "total_monthly_cost": None,
        "total_monthly_cost_with_vat": None,
        "monthly_costs_by_currency": [],
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

    def get_customer_services(  # noqa: PLR0913 -- explicit filters preserve the existing client API
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
                for svc in services:
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

    def get_service_dns_status(self, customer_id: int, user_id: int, service_id: int) -> dict[str, Any]:
        """Read the cached tenant-scoped result; DNS runs only in Platform workers."""
        response = self._make_request(
            "POST",
            f"/services/{service_id}/dns-status/",
            user_id=user_id,
            data={"customer_id": customer_id, "user_id": user_id},
            idempotent=True,
        )
        return _dns_status_receipt(response)

    def recheck_service_dns(self, customer_id: int, user_id: int, service_id: int) -> dict[str, Any]:
        """Request a deduplicated background check under Platform's current membership role."""
        response = self._make_request(
            "POST",
            f"/services/{service_id}/dns-status/recheck/",
            user_id=user_id,
            data={"customer_id": customer_id, "user_id": user_id},
            idempotent=True,
        )
        return _dns_status_receipt(response)

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

    def get_service_domains(self, customer_id: int, user_id: int, service_id: int) -> list[dict[str, object]]:
        """Get domain relationships for the customer's service using the signed user identity."""
        try:
            data = {"customer_id": customer_id, "user_id": user_id}
            response = self._make_request(
                "POST", f"/services/{service_id}/domains/", user_id=user_id, data=data, idempotent=True
            )

            logger.info(f"✅ [Services API] Retrieved domains for service {service_id} for customer {customer_id}")
            return cast(list[dict[str, object]], response.get("data", {}).get("domains", []))

        except PlatformAPIError as e:
            _raise_if_degraded(e)
            logger.error(
                "🔥 [Services API] Could not retrieve domains for service %s for customer %s: %s",
                service_id,
                customer_id,
                e,
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
