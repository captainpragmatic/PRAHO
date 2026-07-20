"""
Base Payment Gateway for PRAHO Platform
Abstract interface for all payment gateway implementations.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, ClassVar, NotRequired, TypedDict

from django.conf import settings

logger = logging.getLogger(__name__)


# ===============================================================================
# TYPE DEFINITIONS
# ===============================================================================


# Payment methods that support gateway refunds — add new gateways here
GATEWAY_PAYMENT_METHODS: frozenset[str] = frozenset({"stripe"})


class PaymentIntentResult(TypedDict):
    """Result from payment intent creation"""

    success: bool
    payment_intent_id: str
    client_secret: str | None
    error: str | None
    retryable: NotRequired[bool]


class PaymentConfirmResult(TypedDict):
    """Result from payment confirmation"""

    success: bool
    status: str  # succeeded, failed, requires_action, etc.
    error: str | None
    amount_received: NotRequired[int]
    currency: NotRequired[str]
    customer_id: NotRequired[str | None]
    payment_method_id: NotRequired[str | None]
    metadata: NotRequired[dict[str, Any]]


class SetupIntentResult(TypedDict):
    """Result from preparing a customer-present saved-card authorization."""

    success: bool
    setup_intent_id: str
    client_secret: str | None
    error: str | None


class SetupIntentStatusResult(TypedDict):
    """Server-retrieved SetupIntent facts used to activate a local mandate."""

    success: bool
    setup_intent_id: str
    status: str
    customer_id: str | None
    payment_method_id: str | None
    usage: str
    metadata: dict[str, Any]
    error: str | None


class RefundResult(TypedDict):
    """Result from payment refund"""

    success: bool
    refund_id: str | None
    amount_refunded_cents: int
    status: str
    error: str | None


class RefundStatusResult(TypedDict):
    """Authoritative gateway facts for one refund."""

    success: bool
    refund_id: str
    payment_intent_id: str
    amount_cents: int
    currency: str
    status: str
    reason: str | None
    failure_reason: str | None
    error: str | None


class RefundListResult(TypedDict):
    """Result from listing recent gateway refunds."""

    success: bool
    refunds: list[RefundStatusResult]
    error: str | None


# ===============================================================================
# ABSTRACT BASE GATEWAY
# ===============================================================================


class BasePaymentGateway(ABC):
    """
    🏛️ Abstract base class for all payment gateways

    Provides a payment-processing boundary for intents, refunds, and webhooks.
    PRAHO owns subscriptions, billing schedules, and entitlement state.
    """

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"apps.billing.gateways.{self.__class__.__name__.lower()}")

    @property
    @abstractmethod
    def gateway_name(self) -> str:
        """Gateway identifier (e.g., 'stripe', 'paypal')"""

    @abstractmethod
    def create_payment_intent(  # noqa: PLR0913  # Explicit gateway payment fields plus idempotency contract
        self,
        order_id: str,
        amount_cents: int,
        currency: str = "RON",
        customer_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> PaymentIntentResult:
        """
        Create payment intent for immediate payment

        Args:
            order_id: PRAHO order ID
            amount_cents: Amount in cents
            currency: ISO currency code (default: RON)
            customer_id: Gateway customer ID (optional)
            metadata: Additional metadata
            idempotency_key: Stable gateway key for one PRAHO payment attempt

        Returns:
            PaymentIntentResult with success status and client_secret
        """

    @abstractmethod
    def create_off_session_payment_intent(  # noqa: PLR0913
        self,
        document_id: str,
        document_type: str,
        amount_cents: int,
        currency: str,
        customer_id: str,
        payment_method_id: str,
        metadata: dict[str, Any] | None = None,
        *,
        idempotency_key: str,
    ) -> PaymentIntentResult:
        """Create and confirm a saved-method payment for a typed PRAHO document."""

    @abstractmethod
    def create_setup_intent(
        self,
        *,
        customer_id: str,
        payment_method_id: str,
        metadata: dict[str, Any],
    ) -> SetupIntentResult:
        """Prepare customer-present authentication for future off-session charges."""

    @abstractmethod
    def retrieve_setup_intent(self, setup_intent_id: str) -> SetupIntentStatusResult:
        """Retrieve authoritative setup facts from the payment processor."""

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
    def refund_payment(
        self,
        gateway_txn_id: str,
        amount_cents: int | None = None,
        reason: str = "requested_by_customer",
        *,
        idempotency_key: str | None = None,
    ) -> RefundResult:
        """
        Refund a payment via the gateway.

        Args:
            gateway_txn_id: Gateway transaction/payment intent ID
            amount_cents: Amount to refund in cents (None = full refund)
            reason: Refund reason code

        Returns:
            RefundResult with success status and refund details
        """

    @abstractmethod
    def retrieve_refund(self, refund_id: str) -> RefundStatusResult:
        """Retrieve authoritative facts for one gateway refund."""

    @abstractmethod
    def list_refunds(self, *, created_gte: int, limit: int = 100) -> RefundListResult:
        """List all recent refunds, using limit as the provider page size."""

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
        default_gateway = getattr(settings, "DEFAULT_PAYMENT_GATEWAY", "stripe")
        return cls.create_gateway(default_gateway)

    @classmethod
    def list_available_gateways(cls) -> list[str]:
        """List all registered gateway names"""
        return list(cls._gateways.keys())
