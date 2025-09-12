"""
Order Management Services for PRAHO Portal
Session-based cart management with platform API integration.
"""

import hashlib
import json
import logging
import uuid
from datetime import timedelta
from typing import Any, Dict, List, Optional

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIClient, PlatformAPIError
from .validators import OrderInputValidator

logger = logging.getLogger(__name__)


class CartRateLimiter:
    """🔒 Enhanced rate limiting for cart operations with per-IP sliding windows"""
    
    # Per-session limits (existing)
    OPERATIONS_LIMIT = 30  # operations per minute per session
    TIME_WINDOW = 60  # seconds
    
    # Per-IP limits (new - stricter)
    IP_OPERATIONS_LIMIT_MINUTE = 60  # operations per minute per IP
    IP_OPERATIONS_LIMIT_HOUR = 300   # operations per hour per IP  
    IP_TIME_WINDOW_MINUTE = 60       # 1 minute window
    IP_TIME_WINDOW_HOUR = 3600       # 1 hour window
    
    @staticmethod
    def check_rate_limit(session_key: str, client_ip: str = None) -> bool:
        """
        🔒 SECURITY: Check both session and IP-based rate limits
        
        Args:
            session_key: Django session key
            client_ip: Client IP address for broader abuse prevention
            
        Returns:
            True if within limits, False if rate limited
        """
        if not session_key:
            return True  # Allow if no session yet
        
        # Check per-session rate limit (existing logic)
        session_cache_key = f'cart_rate_limit:{session_key}'
        session_count = cache.get(session_cache_key, 0)
        
        if session_count >= CartRateLimiter.OPERATIONS_LIMIT:
            logger.warning(f"🚨 [Cart] Session rate limit exceeded for {session_key[:8]}...")
            return False
        
        # 🔒 SECURITY: Check per-IP rate limits (new)
        if client_ip:
            # IP hash for privacy
            import hashlib
            ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
            
            # Check per-minute IP limit
            ip_minute_key = f'cart_ip_minute:{ip_hash}'
            ip_minute_count = cache.get(ip_minute_key, 0)
            
            if ip_minute_count >= CartRateLimiter.IP_OPERATIONS_LIMIT_MINUTE:
                logger.warning(f"🚨 [Cart] IP rate limit (minute) exceeded for IP hash {ip_hash}")
                return False
            
            # Check per-hour IP limit  
            ip_hour_key = f'cart_ip_hour:{ip_hash}'
            ip_hour_count = cache.get(ip_hour_key, 0)
            
            if ip_hour_count >= CartRateLimiter.IP_OPERATIONS_LIMIT_HOUR:
                logger.warning(f"🚨 [Cart] IP rate limit (hour) exceeded for IP hash {ip_hash}")
                return False
        
        return True
    
    @staticmethod
    def record_operation(session_key: str, client_ip: str = None) -> None:
        """
        🔒 SECURITY: Record cart operation with both session and IP tracking
        
        Args:
            session_key: Django session key
            client_ip: Client IP address for broader tracking
        """
        if session_key:
            # Record session-based operation
            session_cache_key = f'cart_rate_limit:{session_key}'
            session_count = cache.get(session_cache_key, 0)
            cache.set(session_cache_key, session_count + 1, CartRateLimiter.TIME_WINDOW)
        
        # 🔒 SECURITY: Record IP-based operations
        if client_ip:
            import hashlib
            ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
            
            # Record per-minute IP operation
            ip_minute_key = f'cart_ip_minute:{ip_hash}'
            ip_minute_count = cache.get(ip_minute_key, 0)
            cache.set(ip_minute_key, ip_minute_count + 1, CartRateLimiter.IP_TIME_WINDOW_MINUTE)
            
            # Record per-hour IP operation
            ip_hour_key = f'cart_ip_hour:{ip_hash}'
            ip_hour_count = cache.get(ip_hour_key, 0)
            cache.set(ip_hour_key, ip_hour_count + 1, CartRateLimiter.IP_TIME_WINDOW_HOUR)
    
    @staticmethod
    def get_client_ip(request) -> str:
        """Extract client IP address safely"""
        # Check forwarded headers
        forwarded_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP', 
            'HTTP_CF_CONNECTING_IP',  # Cloudflare
        ]
        
        for header in forwarded_headers:
            forwarded_ip = request.META.get(header)
            if forwarded_ip:
                # Take first IP if comma-separated
                ip = forwarded_ip.split(',')[0].strip()
                if ip and ip != 'unknown':
                    return ip
        
        # Fall back to direct connection
        return request.META.get('REMOTE_ADDR', '0.0.0.0')


class GDPRCompliantCartSession:
    """
    Session-based cart that complies with GDPR and Romanian data protection laws.
    Minimal PII storage, automatic expiry, security-focused design.
    """
    
    SESSION_KEY = 'praho_portal_cart_v1'
    CART_EXPIRY_HOURS = 24
    
    def __init__(self, session):
        self.session = session
        self._load_cart()
    
    def _load_cart(self) -> None:
        """Load cart from session with validation and expiry check"""
        cart_data = self.session.get(self.SESSION_KEY, {})
        
        # Check for expired cart
        if cart_data.get('expires_at'):
            try:
                expires_at = timezone.datetime.fromisoformat(cart_data['expires_at'])
                if timezone.now() > expires_at:
                    logger.info("🕒 [Cart] Cart expired, clearing")
                    self.clear()
                    return
            except (ValueError, TypeError):
                # Invalid date format, clear cart
                self.clear()
                return
        
        # Initialize with defaults if empty
        self.cart = cart_data or self._create_empty_cart()
        
        # Ensure cart has required structure
        if 'items' not in self.cart:
            self.cart['items'] = []
        if 'currency' not in self.cart:
            self.cart['currency'] = 'RON'  # Romanian default
    
    def _create_empty_cart(self) -> Dict[str, Any]:
        """Create an empty cart with proper structure and versioning"""
        expires_at = timezone.now() + timedelta(hours=self.CART_EXPIRY_HOURS)
        
        cart = {
            'currency': 'RON',
            'items': [],
            'created_at': timezone.now().isoformat(),
            'updated_at': timezone.now().isoformat(),
            'expires_at': expires_at.isoformat(),
            'warnings': [],
            'meta': {
                'ip_hash': None,  # Only store hash, not actual IP
                'user_agent_hash': None,  # Hash for fraud detection only
            }
        }
        
        # 🔒 SECURITY: Add cart version for stale mutation detection
        cart['version'] = self._generate_cart_version(cart)
        
        return cart
    
    def _save_cart(self) -> None:
        """Save cart to session with updated timestamp and version"""
        self.cart['updated_at'] = timezone.now().isoformat()
        
        # 🔒 SECURITY: Update cart version to detect concurrent modifications
        self.cart['version'] = self._generate_cart_version(self.cart)
        
        self.session[self.SESSION_KEY] = self.cart
        self.session.modified = True
        
        logger.debug(f"💾 [Cart] Cart saved with {len(self.cart['items'])} items, version: {self.cart['version'][:8]}...")
    
    def add_item(self, product_slug: str, quantity: int, billing_period: str, 
                 domain_name: str = '', config: Optional[Dict[str, Any]] = None) -> None:
        """Add item to cart with comprehensive validation"""
        
        # Validate inputs
        product_slug = OrderInputValidator.validate_product_slug(product_slug)
        quantity = OrderInputValidator.validate_quantity(quantity)
        billing_period = OrderInputValidator.validate_billing_period(billing_period)
        domain_name = OrderInputValidator.validate_domain_name(domain_name)
        
        # Get product info from platform for validation
        try:
            platform_api = PlatformAPIClient()
            product_data = platform_api.get(f'/orders/products/{product_slug}/')
            
            if not product_data or not product_data.get('is_active'):
                raise ValidationError(_("Product is not available"))
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Cart] Failed to validate product {product_slug}: {e}")
            raise ValidationError(_("Error validating product"))
        
        # Validate domain requirement
        if product_data.get('requires_domain') and not domain_name:
            raise ValidationError(_("This product requires a domain name"))
        
        # Validate and sanitize config
        clean_config = OrderInputValidator.validate_config(
            config or {}, product_data.get('product_type', '')
        )
        
        # 🔒 SECURITY: Find and store sealed price token for selected billing period
        sealed_price_token = None
        selected_price_data = None
        
        for price_info in product_data.get('prices', []):
            if price_info.get('billing_period') == billing_period:
                sealed_price_token = price_info.get('sealed_price_token')
                selected_price_data = price_info
                break
        
        if not sealed_price_token:
            logger.warning(f"⚠️ [Cart] No sealed price token found for {product_slug} - {billing_period}")
        
        # Create cart item with sealed price token
        item = {
            'product_slug': product_slug,
            'product_id': product_data['id'],  # Store UUID for API calls
            'product_name': product_data['name'],  # Cache for display
            'product_type': product_data['product_type'],
            'quantity': quantity,
            'billing_period': billing_period,
            'domain_name': domain_name,
            'config': clean_config,
            'added_at': timezone.now().isoformat(),
            'requires_domain': product_data.get('requires_domain', False),
            'sealed_price_token': sealed_price_token,  # 🔒 SECURITY: Store sealed price token
            'cached_price_data': selected_price_data  # Cache for display (not used for calculations)
        }
        
        # Update or add item (same product + billing period = update quantity)
        existing_index = self._find_item_index(product_slug, billing_period)
        if existing_index >= 0:
            self.cart['items'][existing_index] = item
            logger.info(f"🔄 [Cart] Updated existing item: {product_slug}")
        else:
            self.cart['items'].append(item)
            logger.info(f"➕ [Cart] Added new item: {product_slug}")
        
        self._save_cart()
    
    def update_item_quantity(self, product_slug: str, billing_period: str, quantity: int) -> None:
        """Update quantity for existing cart item"""
        quantity = OrderInputValidator.validate_quantity(quantity)
        
        item_index = self._find_item_index(product_slug, billing_period)
        if item_index >= 0:
            self.cart['items'][item_index]['quantity'] = quantity
            self.cart['items'][item_index]['updated_at'] = timezone.now().isoformat()
            self._save_cart()
            logger.info(f"🔄 [Cart] Updated quantity for {product_slug}: {quantity}")
        else:
            raise ValidationError(_("Produsul nu a fost găsit în coș"))
    
    def remove_item(self, product_slug: str, billing_period: str) -> None:
        """Remove item from cart"""
        item_index = self._find_item_index(product_slug, billing_period)
        if item_index >= 0:
            removed_item = self.cart['items'].pop(item_index)
            self._save_cart()
            logger.info(f"🗑️ [Cart] Removed item: {removed_item['product_name']}")
        else:
            raise ValidationError(_("Produsul nu a fost găsit în coș"))
    
    def clear(self) -> None:
        """Clear entire cart"""
        old_item_count = len(self.cart.get('items', []))
        self.cart = self._create_empty_cart()
        self._save_cart()
        logger.info(f"🧹 [Cart] Cart cleared ({old_item_count} items removed)")
    
    def get_items(self) -> List[Dict[str, Any]]:
        """Get all cart items"""
        return self.cart.get('items', [])
    
    def get_item_count(self) -> int:
        """Get total number of items in cart"""
        return len(self.cart.get('items', []))
    
    def get_total_quantity(self) -> int:
        """Get total quantity of all items"""
        return sum(item['quantity'] for item in self.cart.get('items', []))
    
    def has_items(self) -> bool:
        """Check if cart has any items"""
        return self.get_item_count() > 0
    
    def _find_item_index(self, product_slug: str, billing_period: str) -> int:
        """Find index of item in cart by product and billing period"""
        for index, item in enumerate(self.cart.get('items', [])):
            if (item['product_slug'] == product_slug and 
                item['billing_period'] == billing_period):
                return index
        return -1
    
    def get_api_items(self) -> List[Dict[str, Any]]:
        """Get cart items formatted for platform API calls with sealed price tokens"""
        api_items = []
        for item in self.cart.get('items', []):
            api_item = {
                'product_id': item['product_id'],
                'quantity': item['quantity'],
                'billing_period': item['billing_period'],
                'config': item.get('config', {}),
                'domain_name': item.get('domain_name', '')
            }
            
            # 🔒 SECURITY: Include sealed price token if available
            sealed_token = item.get('sealed_price_token')
            if sealed_token:
                api_item['sealed_price_token'] = sealed_token
            
            api_items.append(api_item)
        
        return api_items
    
    def set_warnings(self, warnings: List[Dict[str, Any]]) -> None:
        """Set cart warnings (price changes, etc.)"""
        self.cart['warnings'] = warnings
        self._save_cart()
    
    def get_warnings(self) -> List[Dict[str, Any]]:
        """Get cart warnings"""
        return self.cart.get('warnings', [])
    
    def clear_warnings(self) -> None:
        """Clear all cart warnings"""
        self.cart['warnings'] = []
        self._save_cart()
    
    @property
    def currency(self) -> str:
        """Get cart currency"""
        return self.cart.get('currency', 'RON')
    
    @currency.setter
    def currency(self, new_currency: str) -> None:
        """Set cart currency (clears warnings as prices may change)"""
        if new_currency != self.cart.get('currency'):
            self.cart['currency'] = new_currency
            self.cart['warnings'] = []  # Clear warnings on currency change
            self._save_cart()
            logger.info(f"💱 [Cart] Currency changed to {new_currency}")
    
    def is_expired(self) -> bool:
        """Check if cart has expired"""
        expires_at = self.cart.get('expires_at')
        if not expires_at:
            return False
        
        try:
            expires_datetime = timezone.datetime.fromisoformat(expires_at)
            return timezone.now() > expires_datetime
        except (ValueError, TypeError):
            return True  # Invalid date = expired
    
    def extend_expiry(self) -> None:
        """Extend cart expiry by another 24 hours"""
        new_expiry = timezone.now() + timedelta(hours=self.CART_EXPIRY_HOURS)
        self.cart['expires_at'] = new_expiry.isoformat()
        self._save_cart()
        logger.debug("🕒 [Cart] Cart expiry extended")
    
    def _generate_cart_version(self, cart: Dict[str, Any]) -> str:
        """
        🔒 SECURITY: Generate cart version hash for mutation detection.
        Version changes when cart contents, quantities, or configuration changes.
        """
        # Create canonical representation of cart state
        version_data = {
            'items': [],
            'currency': cart.get('currency', 'RON'),
            'updated_at': cart.get('updated_at', '')
        }
        
        # Include essential item data that affects pricing/checkout
        for item in cart.get('items', []):
            item_fingerprint = {
                'product_slug': item.get('product_slug', ''),
                'quantity': item.get('quantity', 0),
                'billing_period': item.get('billing_period', ''),
                'domain_name': item.get('domain_name', ''),
                'config': item.get('config', {}),
                'sealed_price_token': item.get('sealed_price_token', '')  # Include for integrity
            }
            version_data['items'].append(item_fingerprint)
        
        # Sort items for consistent hashing
        version_data['items'].sort(key=lambda x: (x['product_slug'], x['billing_period']))
        
        # Generate SHA-256 hash
        canonical_json = json.dumps(version_data, sort_keys=True, separators=(',', ':'))
        version_hash = hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
        
        return version_hash
    
    def get_cart_version(self) -> str:
        """Get current cart version for ETag/version checks"""
        return self.cart.get('version', '')
    
    def validate_cart_version(self, expected_version: str) -> bool:
        """
        🔒 SECURITY: Validate cart version to detect stale mutations.
        
        Args:
            expected_version: Version from client (form, AJAX, etc.)
            
        Returns:
            True if version matches, False if cart was modified elsewhere
        """
        current_version = self.get_cart_version()
        
        if not expected_version or not current_version:
            # Missing version data - assume stale
            logger.warning("🔒 [Cart] Missing version data for validation")
            return False
        
        if expected_version != current_version:
            logger.warning(
                f"🔒 [Cart] Version mismatch detected - expected: {expected_version[:8]}..., "
                f"current: {current_version[:8]}..."
            )
            return False
        
        return True


class CartCalculationService:
    """Service for calculating cart totals via platform API"""
    
    @staticmethod
    def calculate_cart_totals(cart: GDPRCompliantCartSession, customer_id: str, user_id: int) -> Dict[str, Any]:
        """Calculate cart totals using platform API"""
        
        if not cart.has_items():
            return {
                'items': [],
                'subtotal_cents': 0,
                'tax_cents': 0,
                'total_cents': 0,
                'currency': cart.currency,
                'warnings': []
            }
        
        try:
            platform_api = PlatformAPIClient()
            
            # Prepare API payload - match pattern from working billing APIs
            payload = {
                'customer_id': customer_id,
                'action': 'calculate_cart_totals',
                'currency': cart.currency,
                'items': cart.get_api_items()
            }
            
            # Debug: Write payload to file for inspection
            import json
            debug_data = {
                'payload': payload,
                'user_id': user_id,
                'customer_id_type': type(customer_id).__name__,
                'user_id_type': type(user_id).__name__
            }
            with open('/tmp/cart_api_payload.json', 'w') as f:
                json.dump(debug_data, f, indent=2, default=str)
            logger.info(f"💾 [Cart] Saved debug data - customer_id: {customer_id} ({type(customer_id)}), user_id: {user_id} ({type(user_id)})")
            
            # Call platform calculation API
            result = platform_api.post('orders/calculate/', payload, user_id=user_id)
            
            # Update cart with any warnings
            if result.get('warnings'):
                cart.set_warnings(result['warnings'])
            
            logger.info(f"💰 [Cart] Calculated totals: {result.get('total_cents', 0)} cents")
            return result
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Cart] Calculation failed: {e}")
            logger.error(f"🔥 [Cart] PlatformAPIError details - status_code: {e.status_code}, response_data: {e.response_data}")
            raise ValidationError(_("Error calculating totals"))
        except Exception as e:
            logger.error(f"🔥 [Cart] Unexpected error: {e}")
            logger.error(f"🔥 [Cart] Exception type: {type(e)}")
            raise ValidationError(_("Error calculating totals"))


class OrderCreationService:
    """Service for creating orders from cart via platform API"""
    
    @staticmethod
    def preflight_order(cart: GDPRCompliantCartSession, customer_id: str, 
                       user_id: str, notes: str = '') -> Dict[str, Any]:
        """
        🔎 Preflight order validation before creation.
        Calls platform API to validate order without creating it.
        
        Returns:
            Dict with validation results, errors, and warnings
        """
        if not cart.has_items():
            return {
                'valid': False,
                'errors': [_("Cart is empty")],
                'warnings': []
            }
        
        # Validate notes
        try:
            notes = OrderInputValidator.validate_notes(notes)
        except ValidationError as e:
            return {
                'valid': False,
                'errors': [str(e)],
                'warnings': []
            }
        
        try:
            platform_api = PlatformAPIClient()
            
            # Prepare preflight payload (same as order creation)
            preflight_data = {
                'customer_id': customer_id,
                'items': cart.get_api_items(),
                'currency': cart.currency,
                'notes': notes,
                'source': 'portal_self_serve',
                'meta': {
                    'cart_created_at': cart.cart.get('created_at'),
                    'portal_version': 'v1'
                }
            }
            
            logger.info(f"🔎 [Orders] Running preflight validation for customer {customer_id}")
            
            # Debug: Write preflight payload to file for inspection
            debug_preflight = {
                'preflight_data': preflight_data,
                'customer_id': customer_id,
                'customer_id_type': type(customer_id).__name__
            }
            with open('/tmp/preflight_api_payload.json', 'w') as f:
                json.dump(debug_preflight, f, indent=2, default=str)
            logger.info(f"💾 [Preflight] Saved debug data - customer_id: {customer_id} ({type(customer_id)})")
            
            # Call preflight API endpoint with user_id for HMAC authentication
            result = platform_api.post('orders/preflight/', preflight_data, user_id=int(user_id))
            
            # Log the full API response for debugging
            logger.info(f"🔎 [Orders] Platform API preflight response: {result}")
            
            # Extract validation results
            is_valid = result.get('success', False)  # Platform API returns 'success', not 'valid'
            errors = result.get('errors', [])
            warnings = result.get('warnings', [])
            
            # Log detailed results
            if errors:
                logger.error(f"🔥 [Orders] Preflight validation errors: {errors}")
            if warnings:
                logger.warning(f"⚠️ [Orders] Preflight validation warnings: {warnings}")
            
            # Update cart warnings if any
            if warnings:
                cart.set_warnings(warnings)
            
            logger.info(f"🔎 [Orders] Preflight result: valid={is_valid}, errors={len(errors)}, warnings={len(warnings)}")
            
            return {
                'valid': is_valid,
                'errors': errors,
                'warnings': warnings,
                'preflight_data': result.get('preflight_data', {})
            }
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Orders] Preflight validation failed: {e}")
            return {
                'valid': False,
                'errors': [_("Error validating order")],
                'warnings': []
            }
    
    @staticmethod
    def create_draft_order(cart: GDPRCompliantCartSession, customer_id: str, user_id: str,
                          notes: str = '', auto_pending: bool = False) -> Dict[str, Any]:
        """Create draft order from cart items"""
        
        if not cart.has_items():
            raise ValidationError(_("Cart is empty"))
        
        # Validate notes
        notes = OrderInputValidator.validate_notes(notes)
        
        try:
            platform_api = PlatformAPIClient()
            
            # Prepare order data
            order_data = {
                'customer_id': customer_id,
                'items': cart.get_api_items(),
                'currency': cart.currency,
                'status': 'draft',
                'notes': notes,
                'source': 'portal_self_serve',
                'meta': {
                    'cart_created_at': cart.cart.get('created_at'),
                    'portal_version': 'v1'
                }
            }
            
            # 🔒 SECURITY: Generate idempotency key to prevent race conditions and duplicate orders
            import uuid
            idempotency_key = uuid.uuid4().hex  # Generate secure UUID-based key
            order_data['idempotency_key'] = idempotency_key
            
            # Add auto-pending flag if requested
            if auto_pending:
                order_data['auto_pending'] = True
            
            logger.info(f"🛡️ [Orders] Creating order with idempotency key: {idempotency_key[:8]}... (auto_pending={auto_pending})")
            
            # Create order via platform API with user_id for HMAC authentication
            result = platform_api.post('orders/create/', order_data, user_id=int(user_id))
            
            if result.get('error'):
                raise ValidationError(result['error'])
            
            # Clear cart after successful order creation
            cart.clear()
            
            logger.info(f"📦 [Orders] Draft order created: {result.get('order', {}).get('order_number')}")
            return result
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Orders] Order creation failed: {e}")
            raise ValidationError(_("Error creating order"))