"""
Price Sealing Service for PRAHO Platform
Cryptographically seal prices to prevent manipulation during the order flow.
🔒 Security: Server-authoritative pricing with HMAC validation.
"""

import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import TYPE_CHECKING, Any, TypedDict

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from apps.products.models import ProductPrice

# Security constants
MIN_SECRET_LENGTH = 32  # Minimum characters for cryptographic security


class PriceData(TypedDict):
    """Structured price information for sealing"""

    product_price_id: uuid.UUID
    amount_cents: int
    setup_cents: int
    currency_code: str
    billing_period: str
    product_slug: str


# Security constants
PRICE_SEAL_TTL_SECONDS = 900  # 🔒 SECURITY: 15 minute window — allows browse→cart→checkout flow (#126)
HMAC_ALGORITHM = "sha256"

# Module-level flag to emit the dev-mode warning only once per process (B4/BUG-9)
_SEALING_SECRET_WARNING_ISSUED = False


class PriceSealingService:
    """
    🔒 Service for sealing and validating product prices with HMAC.
    Prevents price manipulation attacks by cryptographically binding prices.
    """

    @staticmethod
    def _get_secret_key() -> str:
        """🔒 SECURITY: Get portal-specific secret key for HMAC signing"""
        # 🔒 SECURITY: Use dedicated price sealing secret for multi-tenancy
        price_sealing_secret = getattr(settings, "PRICE_SEALING_SECRET", None)

        if not price_sealing_secret:
            # Check if we're in production (based on DEBUG setting)
            if not getattr(settings, "DEBUG", True):
                # Production mode - require dedicated secret
                raise ImproperlyConfigured(
                    "🚨 [Security] PRICE_SEALING_SECRET environment variable is required for production. "
                    "Generate a secure 64-character secret key using: "
                    "python manage.py generate_price_sealing_secret"
                )
            else:
                # Development mode - allow fallback with once-only warning
                global _SEALING_SECRET_WARNING_ISSUED  # noqa: PLW0603
                if not _SEALING_SECRET_WARNING_ISSUED:
                    logging.getLogger(__name__).warning(
                        "🚨 [Security] Using Django SECRET_KEY for price sealing in development. "
                        "Configure PRICE_SEALING_SECRET environment variable for production deployment."
                    )
                    _SEALING_SECRET_WARNING_ISSUED = True
                return str(settings.SECRET_KEY)  # noqa: SECRET_KEY — dev fallback when PRICE_SEALING_SECRET unset

        # Validate secret key length for security
        if len(price_sealing_secret) < MIN_SECRET_LENGTH:
            raise ValidationError(_("PRICE_SEALING_SECRET must be at least 32 characters long for security"))

        return str(price_sealing_secret)

    @staticmethod
    def seal_price(price_data: PriceData, client_ip: str, timestamp: float | None = None) -> str:
        """
        🔒 Create a sealed price token that cannot be tampered with.

        Args:
            product_price_id: UUID of the ProductPrice record
            amount_cents: Price amount in cents
            setup_cents: Setup fee in cents
            currency_code: Currency code (e.g., 'RON', 'EUR')
            billing_period: Billing period (e.g., 'monthly', 'annual')
            product_slug: Product slug for additional context
            client_ip: Client IP address for token binding
            timestamp: Optional timestamp (defaults to current time)

        Returns:
            Sealed price token string
        """
        if timestamp is None:
            timestamp = time.time()

        # 🔒 SECURITY: Create price payload with IP binding
        payload = {
            "product_price_id": str(price_data["product_price_id"]),
            "amount_cents": int(price_data["amount_cents"]),
            "setup_cents": int(price_data["setup_cents"]),
            "currency_code": price_data["currency_code"],
            "billing_period": price_data["billing_period"],
            "product_slug": price_data["product_slug"],
            "client_ip": client_ip,  # 🔒 SECURITY: IP address binding
            "timestamp": timestamp,
        }

        # Convert to canonical JSON (sorted keys for consistent signing)
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))

        # Create HMAC signature
        secret_key = PriceSealingService._get_secret_key()
        signature = hmac.new(secret_key.encode("utf-8"), canonical_json.encode("utf-8"), hashlib.sha256).hexdigest()

        # Combine payload and signature
        sealed_token = f"{canonical_json}.{signature}"

        return sealed_token

    @staticmethod
    def unseal_price(sealed_token: str) -> dict[str, Any]:
        """
        🔒 Validate and extract price data from a sealed token.

        Args:
            sealed_token: The sealed price token to validate

        Returns:
            Dictionary containing price data if valid

        Raises:
            ValidationError: If token is invalid, expired, or tampered with
        """
        try:
            # Split token into payload and signature
            if "." not in sealed_token:
                raise ValidationError(_("Invalid price token format"))

            payload_json, provided_signature = sealed_token.rsplit(".", 1)

            # Verify HMAC signature
            secret_key = PriceSealingService._get_secret_key()
            expected_signature = hmac.new(
                secret_key.encode("utf-8"), payload_json.encode("utf-8"), hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(expected_signature, provided_signature):
                raise ValidationError(_("Price token signature invalid - possible tampering detected"))

            # Parse price data
            price_data: dict[str, Any] = json.loads(payload_json)

            # Validate timestamp (prevent replay attacks)
            token_timestamp = float(price_data.get("timestamp", 0))
            current_timestamp = time.time()

            if current_timestamp - token_timestamp > PRICE_SEAL_TTL_SECONDS:
                raise ValidationError(_("Price token has expired - prices must be refreshed"))

            # Validate required fields
            required_fields = [
                "product_price_id",
                "amount_cents",
                "setup_cents",
                "currency_code",
                "billing_period",
                "product_slug",
                "client_ip",
            ]

            for field in required_fields:
                if field not in price_data:
                    raise ValidationError(_("Missing required field in price token: %(field)s") % {"field": field})

            # IP binding removed (#126): HMAC signature already prevents tampering,
            # and IP binding blocks mobile users behind rotating IPs and corporate proxies.

            return price_data

        except (json.JSONDecodeError, ValueError, TypeError) as e:
            raise ValidationError(_("Invalid price token format: %(error)s") % {"error": e}) from e

    @staticmethod
    def validate_price_against_database(
        unsealed_data: dict[str, Any], expected_product_price_id: uuid.UUID | None = None
    ) -> dict[str, Any]:
        """
        🔒 Validate that unsealed price data matches current database prices.
        This prevents stale/outdated prices from being used.

        Args:
            unsealed_data: Data extracted from unsealed token
            expected_product_price_id: Optional expected ProductPrice.id for additional validation

        Returns:
            Dictionary with validation results and current price data

        Raises:
            ValidationError: If prices don't match database or other validation fails
        """
        from apps.products.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            ProductPrice,  # Circular: cross-app  # Deferred: avoids circular import
        )

        try:
            product_price_id = uuid.UUID(unsealed_data["product_price_id"])

            # Fetch the ProductPrice record
            try:
                product_price = ProductPrice.objects.select_related("product", "currency").get(
                    id=product_price_id, is_active=True
                )
            except ProductPrice.DoesNotExist as e:
                raise ValidationError(_("Price no longer available - please refresh your cart")) from e

            # Optional: Validate expected ProductPrice ID matches
            if expected_product_price_id and product_price_id != expected_product_price_id:
                raise ValidationError(_("Price ID mismatch - possible tampering"))

            # Validate product is still active and public
            if not product_price.product.is_active or not product_price.product.is_public:
                raise ValidationError(_("Product no longer available"))

            # Get billing period from sealed token to calculate correct price
            billing_period = unsealed_data.get("billing_period", "monthly")

            # Get current effective prices (considering promotions and billing period)
            current_amount_cents = product_price.get_price_cents_for_period(billing_period)
            current_setup_cents = product_price.setup_cents

            # Compare sealed prices with current database prices
            sealed_amount_cents = int(unsealed_data["amount_cents"])
            sealed_setup_cents = int(unsealed_data["setup_cents"])

            price_changed = False
            if sealed_amount_cents != current_amount_cents:
                price_changed = True
            if sealed_setup_cents != current_setup_cents:
                price_changed = True

            # Validate other attributes match
            if unsealed_data["currency_code"] != product_price.currency.code:
                raise ValidationError(_("Currency mismatch - please refresh your cart"))

            # Note: billing_period validation removed - in simplified model, billing periods are calculated, not stored

            if unsealed_data["product_slug"] != product_price.product.slug:
                raise ValidationError(_("Product mismatch - please refresh your cart"))

            return {
                "is_valid": True,
                "price_changed": price_changed,
                "current_amount_cents": current_amount_cents,
                "current_setup_cents": current_setup_cents,
                "sealed_amount_cents": sealed_amount_cents,
                "sealed_setup_cents": sealed_setup_cents,
                "product_price": product_price,
                "product_price_id": product_price_id,
            }

        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(_("Price validation failed: %(error)s") % {"error": e}) from e


def create_sealed_price_for_product_price(
    product_price: "ProductPrice", client_ip: str, billing_period: str = "monthly"
) -> str:
    """
    🔒 Convenience function to create sealed price token from ProductPrice instance.
    Updated for simplified pricing model.

    Args:
        product_price: ProductPrice model instance
        client_ip: Client IP address for token binding
        billing_period: Billing period ('monthly', 'semiannual', 'annual')

    Returns:
        Sealed price token string
    """
    # Get the price for the specified billing period
    amount_cents = product_price.get_price_cents_for_period(billing_period)

    price_data = PriceData(
        product_price_id=product_price.id,
        amount_cents=amount_cents,
        setup_cents=product_price.setup_cents,
        currency_code=product_price.currency.code,
        billing_period=billing_period,
        product_slug=product_price.product.slug,
    )

    return PriceSealingService.seal_price(price_data=price_data, client_ip=client_ip)
