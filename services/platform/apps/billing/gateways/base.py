"""
Base Payment Gateway for PRAHO Platform
Abstract interface for all payment gateway implementations.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar, TypedDict

from django.conf import settings

logger = logging.getLogger(__name__)


# ===============================================================================
# TYPE DEFINITIONS
# ===============================================================================


class PaymentIntentResult(TypedDict):
    """Result from payment intent creation"""
    success: bool
    payment_intent_id: str
    client_secret: str | None
    error: str | None


class PaymentConfirmResult(TypedDict):
    """Result from payment confirmation"""
    success: bool
    status: str  # succeeded, failed, requires_action, etc.
    error: str | None


class SubscriptionResult(TypedDict):
    """Result from subscription creation"""
    success: bool
    subscription_id: str | None
    status: str | None
    error: str | None


# ===============================================================================
# ABSTRACT BASE GATEWAY
# ===============================================================================


class BasePaymentGateway(ABC):
    """
    🏛️ Abstract base class for all payment gateways

    Provides unified interface for:
    - Payment intent creation and confirmation
    - Subscription management
    - Payment method handling
    - Webhook event processing
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"apps.billing.gateways.{self.__class__.__name__.lower()}")

    @property
    @abstractmethod
    def gateway_name(self) -> str:
        """Gateway identifier (e.g., 'stripe', 'paypal')"""

    @abstractmethod
    def create_payment_intent(
        self,
        order_id: str,
        amount_cents: int,
        currency: str = 'RON',
        customer_id: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> PaymentIntentResult:
        """
        Create payment intent for immediate payment

        Args:
            order_id: PRAHO order ID
            amount_cents: Amount in cents
            currency: ISO currency code (default: RON)
            customer_id: Gateway customer ID (optional)
            metadata: Additional metadata

        Returns:
            PaymentIntentResult with success status and client_secret
        """

    @abstractmethod
    def confirm_payment(self, payment_intent_id: str) -> PaymentConfirmResult:
        """
        Confirm payment intent status

        Args:
            payment_intent_id: Gateway payment intent ID

        Returns:
            PaymentConfirmResult with payment status
        """

    @abstractmethod
    def create_subscription(
        self,
        customer_id: str,
        price_id: str,
        metadata: dict[str, Any] | None = None
    ) -> SubscriptionResult:
        """
        Create recurring subscription

        Args:
            customer_id: Gateway customer ID
            price_id: Gateway price/plan ID
            metadata: Additional metadata

        Returns:
            SubscriptionResult with subscription details
        """

    @abstractmethod
    def cancel_subscription(self, subscription_id: str) -> bool:
        """
        Cancel recurring subscription

        Args:
            subscription_id: Gateway subscription ID

        Returns:
            True if cancelled successfully
        """

    @abstractmethod
    def handle_webhook_event(self, event_type: str, event_data: dict[str, Any]) -> tuple[bool, str]:
        """
        Process webhook event from payment gateway

        Args:
            event_type: Event type identifier
            event_data: Event payload data

        Returns:
            (success, message) tuple
        """

    def validate_configuration(self) -> bool:
        """
        Validate gateway configuration (API keys, etc.)
        Override in subclasses for specific validation.

        Returns:
            True if configuration is valid
        """
        return True


# ===============================================================================
# GATEWAY FACTORY
# ===============================================================================


class PaymentGatewayFactory:
    """
    🏭 Factory for creating payment gateway instances

    Supports dynamic gateway selection based on configuration.
    """

    _gateways: ClassVar[dict[str, type[BasePaymentGateway]]] = {}

    @classmethod
    def register_gateway(cls, gateway_name: str, gateway_class: type[BasePaymentGateway]) -> None:
        """Register a payment gateway class"""
        cls._gateways[gateway_name] = gateway_class

    @classmethod
    def create_gateway(cls, gateway_name: str) -> BasePaymentGateway:
        """
        Create payment gateway instance

        Args:
            gateway_name: Gateway identifier ('stripe', 'paypal', etc.)

        Returns:
            Configured gateway instance

        Raises:
            ValueError: If gateway not found or not configured
        """
        if gateway_name not in cls._gateways:
            raise ValueError(f"Payment gateway '{gateway_name}' not registered")

        gateway_class = cls._gateways[gateway_name]
        gateway = gateway_class()

        # Validate configuration
        if not gateway.validate_configuration():
            raise ValueError(f"Payment gateway '{gateway_name}' not properly configured")

        logger.info(f"✅ Created {gateway_name} payment gateway")
        return gateway

    @classmethod
    def get_default_gateway(cls) -> BasePaymentGateway:
        """
        Get default payment gateway from settings

        Returns:
            Default configured gateway instance
        """
        default_gateway = getattr(settings, 'DEFAULT_PAYMENT_GATEWAY', 'stripe')
        return cls.create_gateway(default_gateway)

    @classmethod
    def list_available_gateways(cls) -> list[str]:
        """List all registered gateway names"""
        return list(cls._gateways.keys())
