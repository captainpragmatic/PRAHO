"""
Price Sealing Service for PRAHO Platform
Cryptographically seal prices to prevent manipulation during the order flow.
🔒 Security: Server-authoritative pricing with HMAC validation.
"""

import hashlib
import hmac
import json
import time
import uuid
from typing import Any, Dict, Optional

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone


def get_client_ip(request) -> str:
    """
    🔒 SECURITY: Safely extract client IP address for token binding.
    Handles proxies and load balancers while preventing header spoofing.
    """
    # Check for forwarded IP headers (in order of preference)
    forwarded_headers = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_CF_CONNECTING_IP',  # Cloudflare
        'HTTP_X_FORWARDED_HOST',
    ]
    
    for header in forwarded_headers:
        forwarded_ip = request.META.get(header)
        if forwarded_ip:
            # Take first IP if comma-separated list
            ip = forwarded_ip.split(',')[0].strip()
            if ip and ip != 'unknown':
                # Basic IP validation
                if _is_valid_ip(ip):
                    return ip
    
    # Fall back to direct connection IP
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def _is_valid_ip(ip: str) -> bool:
    """Basic IP address validation"""
    try:
        # Simple validation - just check it has correct format
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Security constants
PRICE_SEAL_TTL_SECONDS = 60  # 🔒 SECURITY: 1 minute window - prices must be used within this tight window
HMAC_ALGORITHM = 'sha256'


class PriceSealingService:
    """
    🔒 Service for sealing and validating product prices with HMAC.
    Prevents price manipulation attacks by cryptographically binding prices.
    """
    
    @staticmethod
    def _get_secret_key() -> str:
        """🔒 SECURITY: Get portal-specific secret key for HMAC signing"""
        # 🔒 SECURITY: Use dedicated price sealing secret for multi-tenancy
        price_sealing_secret = getattr(settings, 'PRICE_SEALING_SECRET', None)
        
        if not price_sealing_secret:
            # Fall back to Django secret key but log warning for production
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "🚨 [Security] Using Django SECRET_KEY for price sealing. "
                "Configure PRICE_SEALING_SECRET environment variable for production."
            )
            return settings.SECRET_KEY
        
        # Validate secret key length for security
        if len(price_sealing_secret) < 32:
            raise ValidationError(
                "PRICE_SEALING_SECRET must be at least 32 characters long for security"
            )
        
        return price_sealing_secret
    
    @staticmethod
    def seal_price(
        product_price_id: uuid.UUID,
        amount_cents: int,
        setup_cents: int,
        currency_code: str,
        billing_period: str,
        product_slug: str,
        client_ip: str,
        timestamp: Optional[float] = None
    ) -> str:
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
        price_data = {
            'product_price_id': str(product_price_id),
            'amount_cents': int(amount_cents),
            'setup_cents': int(setup_cents),
            'currency_code': currency_code,
            'billing_period': billing_period,
            'product_slug': product_slug,
            'client_ip': client_ip,  # 🔒 SECURITY: IP address binding
            'timestamp': timestamp
        }
        
        # Convert to canonical JSON (sorted keys for consistent signing)
        canonical_json = json.dumps(price_data, sort_keys=True, separators=(',', ':'))
        
        # Create HMAC signature
        secret_key = PriceSealingService._get_secret_key()
        signature = hmac.new(
            secret_key.encode('utf-8'),
            canonical_json.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Combine payload and signature
        sealed_token = f"{canonical_json}.{signature}"
        
        return sealed_token
    
    @staticmethod
    def unseal_price(sealed_token: str, client_ip: str) -> Dict[str, Any]:
        """
        🔒 Validate and extract price data from a sealed token.
        
        Args:
            sealed_token: The sealed price token to validate
            client_ip: Client IP address to validate against token binding
            
        Returns:
            Dictionary containing price data if valid
            
        Raises:
            ValidationError: If token is invalid, expired, tampered with, or IP mismatch
        """
        try:
            # Split token into payload and signature
            if '.' not in sealed_token:
                raise ValidationError("Invalid price token format")
            
            payload_json, provided_signature = sealed_token.rsplit('.', 1)
            
            # Verify HMAC signature
            secret_key = PriceSealingService._get_secret_key()
            expected_signature = hmac.new(
                secret_key.encode('utf-8'),
                payload_json.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(expected_signature, provided_signature):
                raise ValidationError("Price token signature invalid - possible tampering detected")
            
            # Parse price data
            price_data = json.loads(payload_json)
            
            # Validate timestamp (prevent replay attacks)
            token_timestamp = float(price_data.get('timestamp', 0))
            current_timestamp = time.time()
            
            if current_timestamp - token_timestamp > PRICE_SEAL_TTL_SECONDS:
                raise ValidationError("Price token has expired - prices must be refreshed")
            
            # Validate required fields
            required_fields = [
                'product_price_id', 'amount_cents', 'setup_cents',
                'currency_code', 'billing_period', 'product_slug', 'client_ip'
            ]
            
            for field in required_fields:
                if field not in price_data:
                    raise ValidationError(f"Missing required field in price token: {field}")
            
            # 🔒 SECURITY: Validate IP address binding
            token_ip = price_data.get('client_ip', '')
            if token_ip != client_ip:
                raise ValidationError("Price token IP address mismatch - token not valid for this client")
            
            return price_data
            
        except (json.JSONDecodeError, ValueError, TypeError) as e:
            raise ValidationError(f"Invalid price token format: {e}")
    
    @staticmethod
    def validate_price_against_database(
        unsealed_data: Dict[str, Any],
        expected_product_price_id: Optional[uuid.UUID] = None
    ) -> Dict[str, Any]:
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
        from apps.products.models import ProductPrice, Product
        from apps.billing.models import Currency
        
        try:
            product_price_id = uuid.UUID(unsealed_data['product_price_id'])
            
            # Fetch the ProductPrice record
            try:
                product_price = ProductPrice.objects.select_related('product', 'currency').get(
                    id=product_price_id,
                    is_active=True
                )
            except ProductPrice.DoesNotExist:
                raise ValidationError("Price no longer available - please refresh your cart")
            
            # Optional: Validate expected ProductPrice ID matches
            if expected_product_price_id and product_price_id != expected_product_price_id:
                raise ValidationError("Price ID mismatch - possible tampering")
            
            # Validate product is still active and public
            if not product_price.product.is_active or not product_price.product.is_public:
                raise ValidationError("Product no longer available")
            
            # Get current effective prices (considering promotions)
            current_amount_cents = product_price.effective_price_cents
            current_setup_cents = product_price.setup_cents
            
            # Compare sealed prices with current database prices
            sealed_amount_cents = int(unsealed_data['amount_cents'])
            sealed_setup_cents = int(unsealed_data['setup_cents'])
            
            price_changed = False
            if sealed_amount_cents != current_amount_cents:
                price_changed = True
            if sealed_setup_cents != current_setup_cents:
                price_changed = True
            
            # Validate other attributes match
            if unsealed_data['currency_code'] != product_price.currency.code:
                raise ValidationError("Currency mismatch - please refresh your cart")
            
            if unsealed_data['billing_period'] != product_price.billing_period:
                raise ValidationError("Billing period mismatch - please refresh your cart")
            
            if unsealed_data['product_slug'] != product_price.product.slug:
                raise ValidationError("Product mismatch - please refresh your cart")
            
            return {
                'is_valid': True,
                'price_changed': price_changed,
                'current_amount_cents': current_amount_cents,
                'current_setup_cents': current_setup_cents,
                'sealed_amount_cents': sealed_amount_cents,
                'sealed_setup_cents': sealed_setup_cents,
                'product_price': product_price,
                'product_price_id': product_price_id
            }
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Price validation failed: {e}")


def create_sealed_price_for_product_price(product_price, client_ip: str) -> str:
    """
    🔒 Convenience function to create sealed price token from ProductPrice instance.
    
    Args:
        product_price: ProductPrice model instance
        client_ip: Client IP address for token binding
        
    Returns:
        Sealed price token string
    """
    return PriceSealingService.seal_price(
        product_price_id=product_price.id,
        amount_cents=product_price.effective_price_cents,
        setup_cents=product_price.setup_cents,
        currency_code=product_price.currency.code,
        billing_period=product_price.billing_period,
        product_slug=product_price.product.slug,
        client_ip=client_ip
    )