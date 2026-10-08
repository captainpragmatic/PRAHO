"""
ANAF API Quota Tracking for e-Factura.

Tracks API usage per CUI to comply with ANAF rate limits:
- /stare: 100 queries per message per day
- /lista (simple): 1500 queries per CUI per day
- /lista (paginated): 100,000 queries per CUI per day
- /descarcare: 10 downloads per message per day
- Global: 1000 calls per minute

All limits are configurable via the settings module.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import wraps
from typing import TYPE_CHECKING, Any

from django.db import router, transaction
from django.utils import timezone

from apps.common import counters

from .settings import efactura_settings

if TYPE_CHECKING:
    pass

import inspect

from .settings import ROMANIA_TIMEZONE

logger = logging.getLogger(__name__)


class QuotaEndpoint(StrEnum):
    """ANAF API endpoints with quotas."""

    UPLOAD = "upload"
    STATUS = "stare"
    LIST_SIMPLE = "lista_simple"
    LIST_PAGINATED = "lista_paginated"
    DOWNLOAD = "descarcare"
    VALIDATE = "validare"
    CONVERT_PDF = "convert_pdf"


class QuotaExceededError(Exception):
    """Raised when API quota is exceeded."""

    def __init__(
        self,
        endpoint: QuotaEndpoint,
        cui: str,
        current: int,
        limit: int,
        reset_at: str | None = None,
    ):
        self.endpoint = endpoint
        self.cui = cui
        self.current = current
        self.limit = limit
        self.reset_at = reset_at

        super().__init__(
            f"Quota exceeded for {endpoint.value}: {current}/{limit} (CUI: {cui}, resets: {reset_at or 'tomorrow'})"
        )


@dataclass
class QuotaStatus:
    """Status of a quota."""

    endpoint: QuotaEndpoint
    cui: str
    message_id: str | None
    current: int
    limit: int
    remaining: int
    reset_at: str

    @property
    def is_exceeded(self) -> bool:
        return self.current >= self.limit

    @property
    def usage_percent(self) -> float:
        if self.limit == 0:
            return 100.0
        return (self.current / self.limit) * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint.value,
            "cui": self.cui,
            "message_id": self.message_id,
            "current": self.current,
            "limit": self.limit,
            "remaining": self.remaining,
            "reset_at": self.reset_at,
            "usage_percent": round(self.usage_percent, 2),
        }


class ANAFQuotaTracker:
    """
    Track ANAF API quotas per CUI and message.

    Uses the shared database counter store for distributed tracking.
    All limits are read from EFacturaSettings.

    Usage:
        tracker = ANAFQuotaTracker()

        # Check before making a call
        if tracker.can_call(QuotaEndpoint.STATUS, cui, message_id):
            # Make the API call
            tracker.increment(QuotaEndpoint.STATUS, cui, message_id)

        # Or use the decorator
        @tracker.rate_limited(QuotaEndpoint.STATUS)
        def check_status(cui, message_id):
            ...
    """

    CACHE_PREFIX = "efactura_quota"
    CACHE_VERSION = 1

    # Keys for minute-based rate limiting
    MINUTE_WINDOW_SECONDS = 60

    def __init__(self, settings: Any = None):
        """Initialize quota tracker with optional settings override."""
        self._settings = settings or efactura_settings

    def _get_limits(self) -> dict[QuotaEndpoint, int]:
        """Get current limits from settings."""
        return {
            QuotaEndpoint.UPLOAD: 0,  # No limit for invoice uploads
            QuotaEndpoint.STATUS: self._settings.rate_limit_status_per_message_day,
            QuotaEndpoint.LIST_SIMPLE: self._settings.rate_limit_list_simple_per_day,
            QuotaEndpoint.LIST_PAGINATED: self._settings.rate_limit_list_paginated_per_day,
            QuotaEndpoint.DOWNLOAD: self._settings.rate_limit_download_per_message_day,
            QuotaEndpoint.VALIDATE: 0,  # No documented limit
            QuotaEndpoint.CONVERT_PDF: 0,  # No documented limit
        }

    def _get_cache_key(
        self,
        endpoint: QuotaEndpoint,
        cui: str,
        message_id: str | None = None,
        date_str: str | None = None,
    ) -> str:
        """Generate cache key for quota tracking."""
        if date_str is None:
            date_str = timezone.now().astimezone(ROMANIA_TIMEZONE).strftime("%Y%m%d")

        if message_id and endpoint in (QuotaEndpoint.STATUS, QuotaEndpoint.DOWNLOAD):
            # Per-message quotas
            return f"{self.CACHE_PREFIX}:v{self.CACHE_VERSION}:{endpoint.value}:{cui}:{message_id}:{date_str}"
        else:
            # Per-CUI quotas
            return f"{self.CACHE_PREFIX}:v{self.CACHE_VERSION}:{endpoint.value}:{cui}:{date_str}"

    def _get_global_minute_key(self) -> str:
        """Get cache key for global minute rate limit."""
        minute = int(time.time() // 60)
        return f"{self.CACHE_PREFIX}:v{self.CACHE_VERSION}:global:minute:{minute}"

    def _get_reset_time(self) -> str:
        """Get next reset time (midnight Romanian time)."""
        now = timezone.now().astimezone(ROMANIA_TIMEZONE)
        tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return tomorrow.isoformat()

    def get_current_usage(
        self,
        endpoint: QuotaEndpoint,
        cui: str,
        message_id: str | None = None,
    ) -> int:
        """Get current usage count for endpoint."""
        cache_key = self._get_cache_key(endpoint, cui, message_id)
        return counters.peek(cache_key)

    def get_limit(self, endpoint: QuotaEndpoint) -> int:
        """Get limit for endpoint from settings."""
        limits = self._get_limits()
        return limits.get(endpoint, 0)

    def get_status(
        self,
        endpoint: QuotaEndpoint,
        cui: str,
        message_id: str | None = None,
    ) -> QuotaStatus:
        """Get quota status for endpoint."""
        current = self.get_current_usage(endpoint, cui, message_id)
        limit = self.get_limit(endpoint)
        remaining = max(0, limit - current) if limit > 0 else float("inf")

        return QuotaStatus(
            endpoint=endpoint,
            cui=cui,
            message_id=message_id,
            current=current,
            limit=limit,
            remaining=int(remaining) if remaining != float("inf") else -1,
            reset_at=self._get_reset_time(),
        )

    def can_call(
        self,
        endpoint: QuotaEndpoint,
        cui: str,
        message_id: str | None = None,
    ) -> bool:
        """
        Check if an API call can be made without exceeding quota.

        Args:
            endpoint: API endpoint
            cui: Company CUI
            message_id: Message ID (for per-message quotas)

        Returns:
            True if call is allowed
        """
        # Check global minute limit
        if not self._check_global_limit():
            return False

        limit = self.get_limit(endpoint)
        if limit == 0:
            # No limit configured
            return True

        current = self.get_current_usage(endpoint, cui, message_id)
        return current < limit

    def _check_global_limit(self) -> bool:
        """Check global minute rate limit."""
        global_limit = self._settings.rate_limit_global_per_minute
        if global_limit == 0:
            return True

        key = self._get_global_minute_key()
        current = counters.peek(key)
        return current < global_limit

    def increment(
        self,
        endpoint: QuotaEndpoint,
        cui: str,
        message_id: str | None = None,
        count: int = 1,
    ) -> int:
        """
        Increment usage counter for endpoint.

        Args:
            endpoint: API endpoint
            cui: Company CUI
            message_id: Message ID (for per-message quotas)
            count: Number to increment by

        Returns:
            New usage count
        """
        if count < 1:
            raise ValueError("Quota increments must be positive")
        # Increment endpoint-specific counter
        cache_key = self._get_cache_key(endpoint, cui, message_id)
        timeout = self._seconds_until_midnight()

        new_value = counters.increment(cache_key, timeout, delta=count)

        # Increment global minute counter.
        global_key = self._get_global_minute_key()
        counters.increment(global_key, self.MINUTE_WINDOW_SECONDS, delta=count)

        logger.debug(f"Quota increment: {endpoint.value} for {cui} (message: {message_id}) = {new_value}")

        return new_value

    def check_and_increment(
        self,
        endpoint: QuotaEndpoint,
        cui: str,
        message_id: str | None = None,
    ) -> QuotaStatus:
        """
        Check quota and increment if allowed.

        Raises:
            QuotaExceededError: If quota is exceeded
        """
        global_limit = self._settings.rate_limit_global_per_minute
        limit = self.get_limit(endpoint)
        global_key = self._get_global_minute_key()
        endpoint_key = self._get_cache_key(endpoint, cui, message_id)
        reset_at = self._get_reset_time()
        timeout = self._seconds_until_midnight()

        # Both increments use the write database and roll back together on any refusal or store failure.
        # The global row is always acquired first, so callers cannot deadlock across endpoint rows.
        from apps.common.models import Counter  # noqa: PLC0415  # ADR-0007: cross-app model import

        with transaction.atomic(using=router.db_for_write(Counter)):
            global_count = counters.increment(global_key, self.MINUTE_WINDOW_SECONDS)
            if global_limit > 0 and global_count > global_limit:
                minute = int(global_key.rsplit(":", 1)[-1])
                raise QuotaExceededError(
                    endpoint=endpoint,
                    cui=cui,
                    current=global_count - 1,
                    limit=global_limit,
                    reset_at=datetime.fromtimestamp((minute + 1) * 60, tz=UTC).isoformat(),
                )

            current = counters.increment(endpoint_key, timeout)
            if limit > 0 and current > limit:
                raise QuotaExceededError(
                    endpoint=endpoint,
                    cui=cui,
                    current=current - 1,
                    limit=limit,
                    reset_at=reset_at,
                )

        return QuotaStatus(
            endpoint=endpoint,
            cui=cui,
            message_id=message_id,
            current=current,
            limit=limit,
            remaining=max(0, limit - current) if limit > 0 else -1,
            reset_at=reset_at,
        )

    def _seconds_until_midnight(self) -> int:
        """Get seconds until midnight Romanian time."""
        now = timezone.now().astimezone(ROMANIA_TIMEZONE)
        tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        # Same-tzinfo subtraction is wall-clock and ignores the DST offset change; compare instants.
        return int(tomorrow.timestamp() - now.timestamp())

    def get_all_quotas(self, cui: str) -> dict[str, QuotaStatus]:
        """Get status of all quotas for a CUI."""
        return {endpoint.value: self.get_status(endpoint, cui) for endpoint in QuotaEndpoint}

    def reset_quota(
        self,
        endpoint: QuotaEndpoint,
        cui: str,
        message_id: str | None = None,
    ) -> None:
        """Reset quota counter (for testing or admin use)."""
        cache_key = self._get_cache_key(endpoint, cui, message_id)
        counters.reset(cache_key)
        logger.info("✅ [ANAFQuota] Reset quota: %s for %s", endpoint.value, cui)

    def rate_limited(
        self,
        endpoint: QuotaEndpoint,
        cui_param: str = "cui",
        message_id_param: str = "message_id",
    ) -> Callable[..., Any]:
        """
        Decorator to enforce rate limits on functions.

        Args:
            endpoint: API endpoint
            cui_param: Name of the CUI parameter in the function
            message_id_param: Name of the message_id parameter (optional)

        Usage:
            @quota_tracker.rate_limited(QuotaEndpoint.STATUS)
            def check_status(cui: str, message_id: str):
                ...
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Extract CUI from kwargs or args
                cui = kwargs.get(cui_param)
                if cui is None and args:
                    # Try to get from args based on function signature
                    sig = inspect.signature(func)
                    params = list(sig.parameters.keys())
                    if cui_param in params:
                        idx = params.index(cui_param)
                        if idx < len(args):
                            cui = args[idx]

                if not cui:
                    # Fallback to company CUI from settings
                    cui = self._settings.company_cui

                # Extract message_id if applicable
                message_id = kwargs.get(message_id_param)
                if (
                    message_id is None
                    and args
                    and endpoint
                    in (
                        QuotaEndpoint.STATUS,
                        QuotaEndpoint.DOWNLOAD,
                    )
                ):
                    sig = inspect.signature(func)
                    params = list(sig.parameters.keys())
                    if message_id_param in params:
                        idx = params.index(message_id_param)
                        if idx < len(args):
                            message_id = args[idx]

                # Check and increment quota
                self.check_and_increment(endpoint, cui, message_id)

                return func(*args, **kwargs)

            return wrapper

        return decorator


# Module-level quota tracker instance
quota_tracker = ANAFQuotaTracker()
