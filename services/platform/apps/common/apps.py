"""
Common app configuration for PRAHO Platform
Shared utilities, types, and middleware.
"""

import logging
import socket

from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from apps.common.performance.rate_limiting import validate_throttle_class_scopes, validate_throttle_rate_map

logger = logging.getLogger(__name__)


class CommonConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.common"
    verbose_name = "Common Utilities"

    def ready(self) -> None:
        _validate_internal_service_domains()
        _validate_throttle_rates_at_startup()


def _validate_internal_service_domains() -> None:
    """Warn at startup if INTERNAL_SERVICE_ALLOWED_DOMAINS contains unreachable hosts."""
    domains: list[str] = getattr(settings, "INTERNAL_SERVICE_ALLOWED_DOMAINS", [])
    if not domains:
        return

    for domain in domains:
        try:
            socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except (socket.gaierror, OSError):
            logger.warning(
                "⚠️ [OutboundHTTP] INTERNAL_SERVICE_ALLOWED_DOMAINS contains "
                "unreachable host: %s — inter-service requests to this host will fail",
                domain,
            )


def _validate_throttle_rates_at_startup() -> None:
    """Fail fast on invalid DRF throttle rates from env/config."""
    rest_framework = getattr(settings, "REST_FRAMEWORK", {})
    throttle_rates = rest_framework.get("DEFAULT_THROTTLE_RATES", {})
    if not isinstance(throttle_rates, dict):
        raise ImproperlyConfigured("REST_FRAMEWORK.DEFAULT_THROTTLE_RATES must be a dict")
    validate_throttle_rate_map(throttle_rates)

    default_classes = rest_framework.get("DEFAULT_THROTTLE_CLASSES", [])
    if not isinstance(default_classes, list):
        raise ImproperlyConfigured("REST_FRAMEWORK.DEFAULT_THROTTLE_CLASSES must be a list")

    # Global defaults + known per-view throttle classes must all have valid scopes.
    scoped_class_paths = [
        *default_classes,
        "apps.api.core.throttling.StandardAPIThrottle",
        "apps.api.core.throttling.BurstAPIThrottle",
        "apps.api.core.throttling.AuthThrottle",
        "apps.api.orders.views.OrderCreateThrottle",
        "apps.api.orders.views.OrderCalculateThrottle",
        "apps.api.orders.views.OrderListThrottle",
        "apps.api.orders.views.ProductCatalogThrottle",
        "rest_framework.throttling.AnonRateThrottle",
    ]
    validate_throttle_class_scopes(scoped_class_paths, throttle_rates)
