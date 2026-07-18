"""
Stripe Payment Gateway for PRAHO Platform
Production-ready Stripe integration with Romanian compliance.
"""

from __future__ import annotations

import logging
import types
from typing import Any

from .base import (
    BasePaymentGateway,
    PaymentConfirmResult,
    PaymentGatewayFactory,
    PaymentIntentResult,
    RefundResult,
    SetupIntentResult,
    SetupIntentStatusResult,
)

logger = logging.getLogger(__name__)


# ===============================================================================
# STRIPE GATEWAY IMPLEMENTATION
# ===============================================================================


class StripeGateway(BasePaymentGateway):
    """
    💳 Stripe payment gateway implementation

    Features payment intents, refunds, and webhook handling. PRAHO owns the
    recurring billing schedule and uses off-session PaymentIntents to collect it.
    """

    def __init__(self) -> None:
        super().__init__()
        self._stripe: types.ModuleType = None  # type: ignore[assignment]  # Set by _initialize_stripe; raises on failure
        self._initialize_stripe()

    def _initialize_stripe(self) -> None:
        """Initialize Stripe SDK with API keys from settings system"""
        try:
            import stripe  # Deferred: optional dependency  # noqa: PLC0415  # Deferred: avoids circular import

            from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
                SettingsService,  # Deferred: optional dependency  # Deferred: avoids circular import
            )

            # Get encrypted Stripe secret key from settings system
            api_key = SettingsService.get_setting("integrations.stripe_secret_key")
            if not api_key:
                raise ValueError("Stripe secret key not configured in settings system")

            stripe.api_key = str(api_key)
            self._stripe = stripe

            # Set API version for consistency
            stripe.api_version = "2023-10-16"

            self.logger.info("✅ Stripe SDK initialized successfully from settings system")

        except ImportError as e:
            raise ImportError("Stripe library not installed. Run: pip install stripe") from e
        except Exception as e:
            self.logger.error(f"🔥 Failed to initialize Stripe: {e}")
            raise

    @property
    def gateway_name(self) -> str:
        return "stripe"

    def validate_configuration(self) -> bool:
        """Validate Stripe configuration from settings system"""
        try:
            from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
                SettingsService,  # Deferred: runtime config  # Deferred: avoids circular import
            )

            # Check if Stripe integration is enabled
            stripe_enabled = SettingsService.get_setting("integrations.stripe_enabled", default=False)
            if not stripe_enabled:
                self.logger.warning("⚠️ Stripe integration is disabled in settings")
                return False

            # Check required encrypted settings
            secret_key = SettingsService.get_setting("integrations.stripe_secret_key")
            publishable_key = SettingsService.get_setting("integrations.stripe_publishable_key")
            webhook_secret = SettingsService.get_setting("integrations.stripe_webhook_secret")

            if not secret_key:
                self.logger.error("❌ Stripe secret key not configured in settings system")
                return False

            if not publishable_key:
                self.logger.error("❌ Stripe publishable key not configured in settings system")
                return False

            if not webhook_secret:
                self.logger.warning("⚠️ Stripe webhook secret not configured - webhooks will fail")

            # Test API connection
            self._stripe.Account.retrieve()
            self.logger.info("✅ Stripe configuration valid from settings system")
            return True

        except Exception as e:
            self.logger.error(f"❌ Stripe configuration invalid: {e}")
            return False

    def create_payment_intent(  # noqa: PLR0913  # Mirrors the typed immediate-payment gateway contract
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
        Create Stripe Payment Intent

        Args:
            order_id: PRAHO order ID
            amount_cents: Amount in cents (e.g., 2999 for 29.99 RON)
            currency: ISO currency code (RON, EUR, USD)
            customer_id: Stripe customer ID (optional)
            metadata: Additional metadata
            idempotency_key: Stable Stripe retry key (optional)

        Returns:
            PaymentIntentResult with client_secret for frontend
        """
        try:
            # Prepare payment intent parameters
            payment_intent_params = {
                "amount": amount_cents,
                "currency": currency.lower(),
                "automatic_payment_methods": {"enabled": True},
                "metadata": {
                    **(metadata or {}),
                    "praho_order_id": order_id,
                    "platform": "PRAHO",
                    "vat_rate": "21%",  # Romanian VAT rate
                },
                # Romanian business compliance
                "statement_descriptor_suffix": "PRAHO",
                "receipt_email": None,  # Will be set from customer data
            }

            # Add customer if provided
            if customer_id:
                payment_intent_params["customer"] = customer_id
            if idempotency_key:
                payment_intent_params["idempotency_key"] = idempotency_key

            # Create payment intent
            if idempotency_key:
                payment_intent_params["idempotency_key"] = idempotency_key
            payment_intent = self._stripe.PaymentIntent.create(**payment_intent_params)

            self.logger.info(
                f"✅ Created Stripe PaymentIntent {payment_intent.id} for order {order_id} ({amount_cents} {currency})"
            )

            return PaymentIntentResult(
                success=True,
                payment_intent_id=payment_intent.id,
                client_secret=payment_intent.client_secret,
                error=None,
            )

        except self._stripe.error.StripeError as e:
            self.logger.error(f"🔥 Stripe PaymentIntent creation failed: {e}")
            return PaymentIntentResult(success=False, payment_intent_id="", client_secret=None, error=str(e))
        except Exception as e:
            self.logger.error(f"🔥 Unexpected error creating PaymentIntent: {e}")
            return PaymentIntentResult(
                success=False, payment_intent_id="", client_secret=None, error=f"Unexpected error: {e}"
            )

    def confirm_payment(self, payment_intent_id: str) -> PaymentConfirmResult:
        """
        Retrieve and confirm payment intent status

        Args:
            payment_intent_id: Stripe PaymentIntent ID

        Returns:
            PaymentConfirmResult with current status
        """
        try:
            payment_intent = self._stripe.PaymentIntent.retrieve(payment_intent_id)

            self.logger.info(f"💳 Payment {payment_intent_id} status: {payment_intent.status}")

            result = PaymentConfirmResult(success=True, status=payment_intent.status, error=None)
            # TDA-1: Only include amount_received when Stripe provides it (NotRequired[int]).
            amount = getattr(payment_intent, "amount_received", None)
            if amount is not None:
                result["amount_received"] = amount
            currency = getattr(payment_intent, "currency", None)
            if currency is not None:
                result["currency"] = str(currency)
            customer = getattr(payment_intent, "customer", None)
            result["customer_id"] = getattr(customer, "id", customer)
            payment_method = getattr(payment_intent, "payment_method", None)
            result["payment_method_id"] = getattr(payment_method, "id", payment_method)
            metadata = getattr(payment_intent, "metadata", None)
            if metadata is not None:
                result["metadata"] = dict(metadata)
            return result

        except self._stripe.error.StripeError as e:
            self.logger.error(f"🔥 Failed to retrieve PaymentIntent {payment_intent_id}: {e}")
            return PaymentConfirmResult(success=False, status="error", error=str(e))
        except Exception as e:
            self.logger.error(f"🔥 Unexpected error confirming payment: {e}")
            return PaymentConfirmResult(success=False, status="error", error=f"Unexpected error: {e}")

    def create_setup_intent(
        self,
        *,
        customer_id: str,
        payment_method_id: str,
        metadata: dict[str, Any],
    ) -> SetupIntentResult:
        """Create an unconfirmed card SetupIntent for browser-driven SCA."""
        try:
            setup_intent = self._stripe.SetupIntent.create(
                customer=customer_id,
                payment_method=payment_method_id,
                payment_method_types=["card"],
                usage="off_session",
                metadata=metadata,
            )
            return SetupIntentResult(
                success=True,
                setup_intent_id=setup_intent.id,
                client_secret=setup_intent.client_secret,
                error=None,
            )
        except self._stripe.error.StripeError as e:
            self.logger.warning("Stripe SetupIntent creation failed for customer %s: %s", customer_id, e)
            return SetupIntentResult(success=False, setup_intent_id="", client_secret=None, error=str(e))
        except Exception as e:
            self.logger.error("Unexpected SetupIntent creation error for customer %s: %s", customer_id, e)
            return SetupIntentResult(
                success=False,
                setup_intent_id="",
                client_secret=None,
                error=f"Unexpected error: {e}",
            )

    def retrieve_setup_intent(self, setup_intent_id: str) -> SetupIntentStatusResult:
        """Retrieve processor facts after the browser completes card setup."""
        try:
            setup_intent = self._stripe.SetupIntent.retrieve(setup_intent_id)
            customer = getattr(setup_intent, "customer", None)
            payment_method = getattr(setup_intent, "payment_method", None)
            return SetupIntentStatusResult(
                success=True,
                setup_intent_id=str(setup_intent.id),
                status=str(setup_intent.status),
                customer_id=getattr(customer, "id", customer),
                payment_method_id=getattr(payment_method, "id", payment_method),
                usage=str(getattr(setup_intent, "usage", "")),
                metadata=dict(getattr(setup_intent, "metadata", {}) or {}),
                error=None,
            )
        except self._stripe.error.StripeError as e:
            self.logger.warning("Stripe SetupIntent retrieval failed for %s: %s", setup_intent_id, e)
            return SetupIntentStatusResult(
                success=False,
                setup_intent_id=setup_intent_id,
                status="error",
                customer_id=None,
                payment_method_id=None,
                usage="",
                metadata={},
                error=str(e),
            )
        except Exception as e:
            self.logger.error("Unexpected SetupIntent retrieval error for %s: %s", setup_intent_id, e)
            return SetupIntentStatusResult(
                success=False,
                setup_intent_id=setup_intent_id,
                status="error",
                customer_id=None,
                payment_method_id=None,
                usage="",
                metadata={},
                error=f"Unexpected error: {e}",
            )

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
        """Charge a saved Stripe PaymentMethod for a PRAHO billing document.

        Stripe requires the Customer and PaymentMethod together with
        off_session and confirm enabled for a server-side renewal attempt.
        The stable idempotency key prevents duplicate remote intents if PRAHO
        retries after a timeout or before persisting the local row.
        """
        if document_type not in {"invoice", "proforma"}:
            return PaymentIntentResult(
                success=False,
                payment_intent_id="",
                client_secret=None,
                error=f"Unsupported billing document type: {document_type}",
            )
        try:
            payment_intent = self._stripe.PaymentIntent.create(
                amount=amount_cents,
                currency=currency.lower(),
                customer=customer_id,
                payment_method=payment_method_id,
                off_session=True,
                confirm=True,
                metadata={
                    **(metadata or {}),
                    f"praho_{document_type}_id": document_id,
                    "platform": "PRAHO",
                },
                statement_descriptor_suffix="PRAHO",
                idempotency_key=idempotency_key,
            )
            self.logger.info(
                "✅ Created off-session Stripe PaymentIntent %s for %s %s (%s %s)",
                payment_intent.id,
                document_type,
                document_id,
                amount_cents,
                currency,
            )
            return PaymentIntentResult(
                success=True,
                payment_intent_id=payment_intent.id,
                client_secret=payment_intent.client_secret,
                error=None,
            )
        except (
            self._stripe.error.APIConnectionError,
            self._stripe.error.APIError,
            self._stripe.error.RateLimitError,
        ) as e:
            self.logger.warning("⚠️ Transient off-session Stripe error for %s %s: %s", document_type, document_id, e)
            return PaymentIntentResult(
                success=False,
                payment_intent_id="",
                client_secret=None,
                error=str(e),
                retryable=True,
            )
        except self._stripe.error.StripeError as e:
            self.logger.warning("❌ Off-session Stripe payment failed for %s %s: %s", document_type, document_id, e)
            return PaymentIntentResult(success=False, payment_intent_id="", client_secret=None, error=str(e))
        except Exception as e:
            self.logger.error("🔥 Unexpected off-session payment error for %s %s: %s", document_type, document_id, e)
            return PaymentIntentResult(
                success=False,
                payment_intent_id="",
                client_secret=None,
                error=f"Unexpected error: {e}",
            )

    def refund_payment(
        self,
        gateway_txn_id: str,
        amount_cents: int | None = None,
        reason: str = "requested_by_customer",
    ) -> RefundResult:
        """
        Create a Stripe Refund for a PaymentIntent.

        Args:
            gateway_txn_id: Stripe PaymentIntent ID (pi_...)
            amount_cents: Partial refund amount (None = full refund)
            reason: Stripe reason code (requested_by_customer, duplicate, fraudulent)

        Returns:
            RefundResult with refund details
        """
        try:
            params: dict[str, Any] = {"payment_intent": gateway_txn_id, "reason": reason}
            if amount_cents is not None:
                params["amount"] = amount_cents

            refund = self._stripe.Refund.create(**params)

            self.logger.info(
                f"✅ Stripe refund {refund.id} for {gateway_txn_id}: {refund.amount} cents, status={refund.status}"
            )

            return RefundResult(
                success=refund.status in ("succeeded", "pending"),
                refund_id=refund.id,
                amount_refunded_cents=refund.amount,
                status=refund.status,
                error=None,
            )

        except self._stripe.error.StripeError as e:
            self.logger.error(f"🔥 Stripe refund failed for {gateway_txn_id}: {e}")
            return RefundResult(success=False, refund_id=None, amount_refunded_cents=0, status="error", error=str(e))
        except Exception as e:
            self.logger.error(f"🔥 Unexpected refund error for {gateway_txn_id}: {e}")
            return RefundResult(
                success=False, refund_id=None, amount_refunded_cents=0, status="error", error=f"Unexpected error: {e}"
            )


# ===============================================================================
# GATEWAY REGISTRATION
# ===============================================================================

# Register Stripe gateway with factory
PaymentGatewayFactory.register_gateway("stripe", StripeGateway)
