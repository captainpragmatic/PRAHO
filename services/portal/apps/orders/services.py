"""
Order Management Services for PRAHO Portal
Session-based cart management with platform API integration.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Any, cast

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.api_client.services import PlatformAPIClient, PlatformAPIError

from .validators import MAX_CART_ITEMS, OrderInputValidator

logger = logging.getLogger(__name__)


class HMACPriceSealer:
    """
    🔒 HMAC-based price sealing to prevent client-side price tampering.
    Seals price data with HMAC signature, timestamp, nonce, and IP binding.
    """

    # Secret key for HMAC signing (in production, use settings.SECRET_KEY)
    @staticmethod
    def _get_secret_key() -> str:
        from django.conf import settings  # noqa: PLC0415

        secret_key = getattr(settings, "SECRET_KEY", None)
        if not secret_key:
            from django.core.exceptions import ImproperlyConfigured  # noqa: PLC0415

            raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set for price seal verification")
        return str(secret_key)

    @staticmethod
    def seal_price_data(price_data: dict[str, Any], client_ip: str = "127.0.0.1") -> dict[str, Any]:
        """
        🔒 SECURITY: Create HMAC-sealed price data with replay protection.

        Args:
            price_data: Dict with price information (price_cents, currency, etc.)
            client_ip: Client IP for binding seal to specific client

        Returns:
            Dict with sealed data including signature, timestamp, nonce, body_hash
        """
        import hmac  # noqa: PLC0415
        import time  # noqa: PLC0415
        import uuid  # noqa: PLC0415

        secret_key = HMACPriceSealer._get_secret_key()
        timestamp = int(time.time())
        nonce = uuid.uuid4().hex

        # Create canonical body representation
        canonical_body = json.dumps(price_data, sort_keys=True, separators=(",", ":"))
        body_hash = hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()

        # Create canonical data for signing
        canonical_data = f"{body_hash}:{timestamp}:{nonce}:{client_ip}"
        signature = hmac.new(secret_key.encode("utf-8"), canonical_data.encode("utf-8"), hashlib.sha256).hexdigest()

        return {
            "signature": signature,
            "body_hash": body_hash,
            "timestamp": timestamp,
            "nonce": nonce,
            "portal_id": "praho_portal_v1",
            "ip_hash": hashlib.sha256(client_ip.encode("utf-8")).hexdigest()[:16],
        }

    @staticmethod
    def verify_seal(  # noqa: PLR0911 - guard clauses keep security validation checks explicit and fail-fast
        sealed_data: dict[str, Any], price_data: dict[str, Any], client_ip: str = "127.0.0.1", max_age_seconds: int = 61
    ) -> bool:
        """
        🔒 SECURITY: Verify HMAC-sealed price data.

        Args:
            sealed_data: The sealed data dict from seal_price_data
            price_data: The price data to verify against
            client_ip: Client IP to verify binding
            max_age_seconds: Maximum age of seal in seconds

        Returns:
            True if seal is valid, False otherwise
        """
        import hmac as hmac_mod  # noqa: PLC0415
        import time  # noqa: PLC0415

        secret_key = HMACPriceSealer._get_secret_key()

        # Verify portal_id
        if sealed_data.get("portal_id") != "praho_portal_v1":
            logger.warning("🔒 [HMAC] Invalid portal_id")
            return False

        # Verify timestamp freshness
        timestamp = sealed_data.get("timestamp", 0)
        if abs(int(time.time()) - timestamp) > max_age_seconds:
            logger.warning("🔒 [HMAC] Stale timestamp")
            return False

        # Verify body hash
        canonical_body = json.dumps(price_data, sort_keys=True, separators=(",", ":"))
        expected_body_hash = hashlib.sha256(canonical_body.encode("utf-8")).hexdigest()
        if not hmac_mod.compare_digest(sealed_data.get("body_hash", ""), expected_body_hash):
            logger.warning("🔒 [HMAC] Body hash mismatch")
            return False

        # Verify IP binding
        expected_ip_hash = hashlib.sha256(client_ip.encode("utf-8")).hexdigest()[:16]
        if not hmac_mod.compare_digest(sealed_data.get("ip_hash", ""), expected_ip_hash):
            logger.warning("🔒 [HMAC] IP binding mismatch")
            return False

        # Verify signature
        nonce = sealed_data.get("nonce", "")
        canonical_data = f"{sealed_data['body_hash']}:{timestamp}:{nonce}:{client_ip}"
        expected_signature = hmac_mod.new(
            secret_key.encode("utf-8"), canonical_data.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        if not hmac_mod.compare_digest(sealed_data.get("signature", ""), expected_signature):
            logger.warning("🔒 [HMAC] Signature mismatch")
            return False

        # Check nonce for replay protection — atomic check-and-set prevents race condition
        nonce_cache_key = f"hmac_nonce:{nonce}"
        if not cache.add(nonce_cache_key, True, timeout=max_age_seconds * 2):
            logger.warning("🔒 [HMAC] Replay detected - nonce already used")
            return False

        return True

    @staticmethod
    def verify_seal_metadata(
        sealed_data: dict[str, Any],
        client_ip: str = "127.0.0.1",
        max_age_seconds: int = 61,
    ) -> bool:
        """
        Verify seal fields when original price payload is unavailable in the request.
        This validates portal_id, timestamp, nonce replay, IP binding, and signature
        over the provided body hash.
        """
        import hmac as hmac_mod  # noqa: PLC0415
        import time  # noqa: PLC0415

        secret_key = HMACPriceSealer._get_secret_key()
        if not isinstance(client_ip, str) or not client_ip:
            client_ip = "127.0.0.1"

        if sealed_data.get("portal_id") != "praho_portal_v1":
            return False

        try:
            timestamp = int(float(sealed_data.get("timestamp", 0)))
        except (TypeError, ValueError):
            return False

        if abs(int(time.time()) - timestamp) > max_age_seconds:
            return False

        expected_ip_hash = hashlib.sha256(client_ip.encode("utf-8")).hexdigest()[:16]
        if not hmac_mod.compare_digest(sealed_data.get("ip_hash", ""), expected_ip_hash):
            return False

        body_hash = str(sealed_data.get("body_hash", ""))
        nonce = str(sealed_data.get("nonce", ""))
        canonical_data = f"{body_hash}:{timestamp}:{nonce}:{client_ip}"
        expected_signature = hmac_mod.new(
            secret_key.encode("utf-8"), canonical_data.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        if not hmac_mod.compare_digest(str(sealed_data.get("signature", "")), expected_signature):
            return False

        nonce_cache_key = f"hmac_nonce:{nonce}"
        return cache.add(nonce_cache_key, True, timeout=max_age_seconds * 2)


class GDPRCompliantCartSession:
    """
    Session-based cart that complies with GDPR and Romanian data protection laws.
    Minimal PII storage, automatic expiry, security-focused design.
    """

    SESSION_KEY = "praho_portal_cart_v1"
    CART_EXPIRY_HOURS = 24

    def __init__(self, session: Any) -> None:
        self.session = session
        self._load_cart()

    def _load_cart(self) -> None:
        """Load cart from session with validation and expiry check"""
        cart_data = self.session.get(self.SESSION_KEY, {})
        self.cart = cart_data or self._create_empty_cart()

        # Check for expired cart
        if self.cart.get("expires_at"):
            try:
                expires_at = datetime.fromisoformat(self.cart["expires_at"])
                if timezone.now() > expires_at:
                    logger.info("🕒 [Cart] Cart expired, clearing")
                    self.cart = self._create_empty_cart()
                    self._save_cart()
                    return
            except (ValueError, TypeError):
                # Invalid date format, clear cart
                self.cart = self._create_empty_cart()
                self._save_cart()
                return

        # Ensure cart has required structure
        if "items" not in self.cart:
            self.cart["items"] = []
        if "currency" not in self.cart:
            self.cart["currency"] = "RON"  # Romanian default

    def _create_empty_cart(self) -> dict[str, Any]:
        """Create an empty cart with proper structure and versioning"""
        expires_at = timezone.now() + timedelta(hours=self.CART_EXPIRY_HOURS)

        cart = {
            "currency": "RON",
            "items": [],
            "created_at": timezone.now().isoformat(),
            "updated_at": timezone.now().isoformat(),
            "expires_at": expires_at.isoformat(),
            "warnings": [],
            "meta": {
                "ip_hash": None,  # Only store hash, not actual IP
                "user_agent_hash": None,  # Hash for fraud detection only
            },
        }

        # 🔒 SECURITY: Add cart version for stale mutation detection
        cart["version"] = self._generate_cart_version(cart)

        return cart

    def _save_cart(self) -> None:
        """Save cart to session with updated timestamp and version"""
        self.cart["updated_at"] = timezone.now().isoformat()

        # 🔒 SECURITY: Update cart version to detect concurrent modifications
        self.cart["version"] = self._generate_cart_version(self.cart)

        self.session[self.SESSION_KEY] = self.cart
        self.session.modified = True

        logger.debug(
            f"💾 [Cart] Cart saved with {len(self.cart['items'])} items, version: {self.cart['version'][:8]}..."
        )

    def add_item(
        self,
        product_slug: str,
        quantity: int,
        billing_period: str,
        domain_name: str = "",
        config: dict[str, Any] | None = None,
    ) -> None:
        """Add item to cart with comprehensive validation"""

        # Validate inputs
        product_slug = OrderInputValidator.validate_product_slug(product_slug)
        quantity = OrderInputValidator.validate_quantity(quantity)
        billing_period = OrderInputValidator.validate_billing_period(billing_period)
        domain_name = OrderInputValidator.validate_domain_name(domain_name)

        # Get product info from platform for validation.
        # When platform is temporarily unavailable, keep cart operations functional
        # and rely on server-authoritative checks during totals/order creation.
        try:
            platform_api = PlatformAPIClient()
            product_data = platform_api.get(f"/api/orders/products/{product_slug}/")

            if not product_data:
                raise ValidationError(_("Product is not available"))
            if product_data.get("is_active") is False:
                raise ValidationError(_("Product is not available"))

        except PlatformAPIError as e:
            if getattr(e, "is_rate_limited", False):
                raise  # Let view handle rate-limit UX
            logger.warning(f"⚠️ [Cart] Product lookup unavailable for {product_slug}: {e}")
            product_data = {
                "id": product_slug,
                "slug": product_slug,
                "name": product_slug.replace("-", " ").title(),
                "product_type": "",
                "requires_domain": True,  # Fail-safe: assume domain required during outage
                "is_active": True,
            }

        # Validate domain requirement
        if product_data.get("requires_domain") and not domain_name:
            raise ValidationError(_("This product requires a domain name"))

        # Validate and sanitize config
        clean_config = OrderInputValidator.validate_config(config or {}, product_data.get("product_type", ""))

        # Create minimal cart item (GDPR/business fields only).
        # NOTE: product_id (internal platform ID) is intentionally omitted;
        # product_slug is the stable public identifier used for all API calls.
        try:
            item = {
                "item_id": self._generate_item_id(product_slug, billing_period),
                "product_slug": product_slug,
                "product_name": product_data.get("name") or product_slug,
                "product_type": product_data.get("product_type", ""),
                "quantity": quantity,
                "billing_period": billing_period,
                "domain_name": domain_name,
                "config": clean_config,
                "added_at": timezone.now().isoformat(),
            }
            logger.debug(f"🔧 [Cart] Created item dict for {product_slug}")
        except Exception as e:
            logger.error(f"🔥 [Cart] Failed to create item dict for {product_slug}: {e}")
            logger.error(f"🔍 [Cart] Product data keys: {list(product_data.keys()) if product_data else 'None'}")
            raise

        # Update or add item (same product + billing period = update quantity)
        existing_index = self._find_item_index(product_slug, billing_period)
        if existing_index >= 0:
            self.cart["items"][existing_index] = item
            logger.info(f"🔄 [Cart] Updated existing item: {product_slug}")
        else:
            if len(self.cart["items"]) >= MAX_CART_ITEMS:
                raise ValidationError(_("Cart cannot contain more than %(max)s items") % {"max": MAX_CART_ITEMS})
            self.cart["items"].append(item)
            logger.info(f"➕ [Cart] Added new item: {product_slug}")  # noqa: RUF001

        self._save_cart()

    def update_item_quantity(self, product_slug: str, billing_period: str, quantity: int) -> None:
        """Update quantity for existing cart item"""
        quantity = OrderInputValidator.validate_quantity(quantity)

        item_index = self._find_item_index(product_slug, billing_period)
        if item_index >= 0:
            self.cart["items"][item_index]["quantity"] = quantity
            self.cart["items"][item_index]["updated_at"] = timezone.now().isoformat()
            self._save_cart()
            logger.info(f"🔄 [Cart] Updated quantity for {product_slug}: {quantity}")
        else:
            raise ValidationError(_("Product not found in cart"))

    def remove_item(self, product_slug: str, billing_period: str) -> None:
        """Remove item from cart"""
        item_index = self._find_item_index(product_slug, billing_period)
        if item_index >= 0:
            removed_item = self.cart["items"].pop(item_index)
            self._save_cart()
            logger.info(f"🗑️ [Cart] Removed item: {removed_item['product_name']}")
        else:
            raise ValidationError(_("Product not found in cart"))

    def clear(self) -> None:
        """Clear entire cart"""
        old_item_count = len(self.cart.get("items", []))
        self.cart = self._create_empty_cart()
        self._save_cart()
        logger.info(f"🧹 [Cart] Cart cleared ({old_item_count} items removed)")

    def get_items(self) -> list[dict[str, Any]]:
        """Get all cart items"""
        return cast(list[dict[str, Any]], self.cart.get("items", []))

    def get_item_count(self) -> int:
        """Get total number of items in cart"""
        return len(self.cart.get("items", []))

    def get_total_quantity(self) -> int:
        """Get total quantity of all items"""
        return sum(item["quantity"] for item in self.cart.get("items", []))

    def has_items(self) -> bool:
        """Check if cart has any items"""
        return self.get_item_count() > 0

    def _generate_item_id(self, product_slug: str, billing_period: str) -> str:
        """Generate deterministic item id for product/billing combination."""
        return hashlib.sha256(f"{product_slug}:{billing_period}".encode()).hexdigest()[:24]

    def _find_item_index(self, product_slug: str, billing_period: str) -> int:
        """Find index of item in cart by product and billing period"""
        for index, item in enumerate(self.cart.get("items", [])):
            if item["product_slug"] == product_slug and item["billing_period"] == billing_period:
                return index
        return -1

    def get_api_items(self) -> list[dict[str, Any]]:
        """Get cart items formatted for platform API calls with sealed price tokens"""
        api_items = []
        for item in self.cart.get("items", []):
            api_item: dict[str, Any] = {
                "product_slug": item.get("product_slug", ""),
                "quantity": item["quantity"],
                "billing_period": item["billing_period"],
                "config": item.get("config", {}),
                "domain_name": item.get("domain_name", ""),
            }

            # Include product_id only when present and non-empty
            product_id = item.get("product_id")
            if product_id:
                api_item["product_id"] = product_id

            # 🔒 SECURITY: Include sealed price token if available
            sealed_token = item.get("sealed_price_token")
            if sealed_token:
                api_item["sealed_price_token"] = sealed_token

            api_items.append(api_item)

        return api_items

    def set_warnings(self, warnings: list[dict[str, Any]]) -> None:
        """Set cart warnings (price changes, etc.)"""
        self.cart["warnings"] = warnings
        self._save_cart()

    def get_warnings(self) -> list[dict[str, Any]]:
        """Get cart warnings"""
        return cast(list[dict[str, Any]], self.cart.get("warnings", []))

    def clear_warnings(self) -> None:
        """Clear all cart warnings"""
        self.cart["warnings"] = []
        self._save_cart()

    @property
    def currency(self) -> str:
        """Get cart currency"""
        return cast(str, self.cart.get("currency", "RON"))

    @currency.setter
    def currency(self, new_currency: str) -> None:
        """Set cart currency (clears warnings as prices may change)"""
        if new_currency != self.cart.get("currency"):
            self.cart["currency"] = new_currency
            self.cart["warnings"] = []  # Clear warnings on currency change
            self._save_cart()
            logger.info(f"💱 [Cart] Currency changed to {new_currency}")

    def is_expired(self) -> bool:
        """Check if cart has expired"""
        expires_at = self.cart.get("expires_at")
        if not expires_at:
            return False

        try:
            expires_datetime = datetime.fromisoformat(expires_at)
            return timezone.now() > expires_datetime
        except (ValueError, TypeError):
            return True  # Invalid date = expired

    def extend_expiry(self) -> None:
        """Extend cart expiry by another 24 hours"""
        new_expiry = timezone.now() + timedelta(hours=self.CART_EXPIRY_HOURS)
        self.cart["expires_at"] = new_expiry.isoformat()
        self._save_cart()
        logger.debug("🕒 [Cart] Cart expiry extended")

    def _generate_cart_version(self, cart: dict[str, Any]) -> str:
        """
        🔒 SECURITY: Generate cart version hash for mutation detection.
        Version changes when cart contents, quantities, or configuration changes.
        """
        # Create canonical representation of cart state
        version_data = {"items": [], "currency": cart.get("currency", "RON")}

        # Include essential item data that affects pricing/checkout
        for item in cart.get("items", []):
            item_fingerprint = {
                "product_slug": item.get("product_slug", ""),
                "quantity": item.get("quantity", 0),
                "billing_period": item.get("billing_period", ""),
                "domain_name": item.get("domain_name", ""),
                "config": item.get("config", {}),
                "sealed_price_token": item.get("sealed_price_token", ""),  # Include for integrity
            }
            version_data["items"].append(item_fingerprint)

        # Sort items for consistent hashing
        version_data["items"].sort(key=lambda x: (x["product_slug"], x["billing_period"]))

        # Generate SHA-256 hash
        canonical_json = json.dumps(version_data, sort_keys=True, separators=(",", ":"))
        version_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        return version_hash

    def get_cart_version(self) -> str:
        """Get current cart version for ETag/version checks"""
        return cast(str, self.cart.get("version", ""))

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
    def calculate_cart_totals(cart: GDPRCompliantCartSession, customer_id: str, user_id: int) -> dict[str, Any]:
        """Calculate cart totals using platform API"""

        if not cart.has_items():
            return {
                "items": [],
                "subtotal_cents": 0,
                "tax_cents": 0,
                "total_cents": 0,
                "currency": cart.currency,
                "warnings": [],
            }

        try:
            platform_api = PlatformAPIClient()

            # Prepare API payload - match pattern from working billing APIs
            payload = {
                "action": "calculate_cart_totals",
                "customer_id": customer_id,
                "currency": cart.currency,
                "items": cart.get_api_items(),
            }

            # Debug logging (no file writing for security)
            logger.info(
                f"💾 [Cart] API payload - customer_id: {customer_id} ({type(customer_id)}), user_id: {user_id} ({type(user_id)}), items: {len(payload.get('items', []))}"
            )

            # Call platform calculation API
            result = platform_api.post("orders/calculate/", payload, user_id=user_id)

            # Update cart with any warnings
            if result.get("warnings"):
                cart.set_warnings(result["warnings"])

            logger.info(f"💰 [Cart] Calculated totals: {result.get('total_cents', 0)} cents")
            return result

        except PlatformAPIError as e:
            if getattr(e, "is_rate_limited", False):
                raise  # Let view handle rate-limit UX
            logger.error(f"🔥 [Cart] Calculation failed: {e}")
            logger.error(
                f"🔥 [Cart] PlatformAPIError details - status_code: {e.status_code}, response_data: {e.response_data}"
            )
            raise ValidationError(_("Error calculating totals")) from e
        except Exception as e:
            logger.error(f"🔥 [Cart] Unexpected error: {e}")
            logger.error(f"🔥 [Cart] Exception type: {type(e)}")
            raise ValidationError(_("Error calculating totals")) from e


class OrderCreationService:
    """Service for creating orders from cart via platform API"""

    @staticmethod
    def preflight_order(
        cart: GDPRCompliantCartSession,
        customer_id: str,
        user_id: str,
        notes: str = "",
        api_client_factory: type[PlatformAPIClient] | None = None,
    ) -> dict[str, Any]:
        """
        🔎 Preflight order validation before creation.
        Calls platform API to validate order without creating it.

        Returns:
            Dict with validation results, errors, and warnings
        """
        if not cart.has_items():
            return {"valid": False, "errors": [_("Cart is empty")], "warnings": []}

        # Validate notes
        try:
            notes = OrderInputValidator.validate_notes(notes)
        except ValidationError as e:
            return {"valid": False, "errors": [str(e)], "warnings": []}

        try:
            platform_api_class = api_client_factory or PlatformAPIClient
            platform_api = platform_api_class()

            # Prepare preflight payload (same as order creation)
            preflight_data = {
                "customer_id": customer_id,
                "items": cart.get_api_items(),
                "currency": cart.currency,
                "notes": notes,
                "meta": {"cart_created_at": cart.cart.get("created_at"), "portal_version": "v1"},
            }

            logger.info(f"🔎 [Orders] Running preflight validation for customer {customer_id}")

            # Debug: Write preflight payload to file for inspection
            # Debug logging (no file writing for security)
            items = preflight_data.get("items", [])
            item_count = len(items) if isinstance(items, list) else 0
            logger.info(
                f"💾 [Preflight] API payload - customer_id: {customer_id} ({type(customer_id)}), items: {item_count}"
            )

            # Call preflight API endpoint with user_id for HMAC authentication
            result = platform_api.post("orders/preflight/", preflight_data, user_id=int(user_id))

            # Log the full API response for debugging
            logger.info(f"🔎 [Orders] Platform API preflight response: {result}")

            # Extract validation results
            is_valid = result.get("success", False)  # Platform API returns 'success', not 'valid'
            errors = result.get("errors", [])
            warnings = result.get("warnings", [])

            # Log detailed results
            if errors:
                logger.error(f"🔥 [Orders] Preflight validation errors: {errors}")
            if warnings:
                logger.warning(f"⚠️ [Orders] Preflight validation warnings: {warnings}")

            # Update cart warnings if any
            if warnings:
                cart.set_warnings(warnings)

            logger.info(
                f"🔎 [Orders] Preflight result: valid={is_valid}, errors={len(errors)}, warnings={len(warnings)}"
            )

            return {
                "valid": is_valid,
                "errors": errors,
                "warnings": warnings,
                "preflight_data": result.get("preflight_data", {}),
            }

        except PlatformAPIError as e:
            if getattr(e, "is_rate_limited", False):
                raise  # Let view handle rate-limit UX
            logger.error(f"🔥 [Orders] Preflight validation failed: {e}")

            # Check if this is an API response with error details
            if hasattr(e, "response") and e.response:
                try:
                    # Try to parse JSON response for specific errors
                    if isinstance(e.response, dict):
                        api_errors = e.response.get("errors", [])
                        if api_errors:
                            return {"valid": False, "errors": api_errors, "warnings": []}
                except (AttributeError, TypeError, ValueError):
                    logger.debug("Could not parse structured preflight errors from platform response")

            # If we can't get specific errors, provide a more helpful generic message
            return {
                "valid": False,
                "errors": [
                    _("Unable to validate your order. Please ensure your company profile is complete with:"),
                    _("Company name and VAT number"),
                    _("Complete billing address"),
                    _("Contact email and phone number"),
                ],
                "warnings": [],
            }

    @staticmethod
    def create_draft_order(  # noqa: PLR0913
        cart: GDPRCompliantCartSession,
        customer_id: str,
        user_id: str,
        notes: str = "",
        auto_pending: bool = False,
        idempotency_key: str | None = None,
        api_client_factory: type[PlatformAPIClient] | None = None,
    ) -> dict[str, Any]:
        """Create draft order from cart items"""

        if not cart.has_items():
            raise ValidationError(_("Cart is empty"))

        # Validate notes
        notes = OrderInputValidator.validate_notes(notes)

        try:
            platform_api_class = api_client_factory or PlatformAPIClient
            platform_api = platform_api_class()

            # Prepare order data
            order_data: dict[str, Any] = {
                "customer_id": customer_id,
                "items": cart.get_api_items(),
                "currency": cart.currency,
                "notes": notes,
                "meta": {"cart_created_at": cart.cart.get("created_at"), "portal_version": "v1"},
            }

            # 🔒 SECURITY: Generate idempotency key to prevent race conditions and duplicate orders
            import uuid  # noqa: PLC0415

            effective_idempotency_key = idempotency_key or uuid.uuid4().hex
            order_data["idempotency_key"] = effective_idempotency_key

            # Add auto-pending flag if requested
            if auto_pending:
                order_data["auto_pending"] = True

            logger.info(
                f"🛡️ [Orders] Creating order with idempotency key: {effective_idempotency_key[:8]}... "
                f"(auto_pending={auto_pending})"
            )

            # Create order via platform API with user_id for HMAC authentication
            result = platform_api.post("orders/create/", order_data, user_id=int(user_id))

            if result.get("error"):
                raise ValidationError(result["error"])

            # Clear cart after successful order creation
            cart.clear()

            logger.info(f"📦 [Orders] Draft order created: {result.get('order', {}).get('order_number')}")
            return result

        except PlatformAPIError as e:
            if getattr(e, "is_rate_limited", False):
                raise  # Let view handle rate-limit UX
            logger.error(f"🔥 [Orders] Order creation failed: {e}")
            raise ValidationError(_("Error creating order")) from e
