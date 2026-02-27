"""
Order Preflight Validation Service

Performs blocking validations before promoting an order from draft → pending.
Validates customer profile completeness, VAT scenario/amounts, pricing snapshots,
product state, currency and totals consistency.
"""

from __future__ import annotations

import logging

from django.utils.translation import gettext_lazy as _

from .models import Order
from .vat_rules import CustomerVATInfo, OrderVATCalculator

logger = logging.getLogger(__name__)


class OrderPreflightValidationService:
    """Run comprehensive checks before an order becomes payable."""

    @staticmethod
    def validate(order: Order) -> tuple[list[str], list[str]]:  # noqa: C901, PLR0912
        """Return (errors, warnings) for the given order."""
        errors: list[str] = []
        warnings: list[str] = []

        # 1) Customer and billing snapshot completeness
        billing = order.billing_address or {}
        required_fields = [
            ("contact_name", _("Please provide a contact name for your order")),
            ("email", _("Please provide a contact email address")),  # Fixed: was "contact_email"
            ("address_line1", _("Please provide your street address")),  # Fixed: was "line1"
            ("city", _("Please provide your city")),
            ("county", _("Please provide your county/state")),
            ("postal_code", _("Please provide your postal/ZIP code")),
            ("country", _("Please provide your country")),
        ]
        for field, message in required_fields:
            field_value = str(billing.get(field, "")).strip()
            if not field_value:
                logger.warning(
                    f"🔎 [Validation] Missing field '{field}': '{field_value}' from billing data: {list(billing.keys())}"
                )
                errors.append(str(message))

        # Basic email presence - format validation is assumed upstream
        # VAT number presence for businesses (company name given)
        company_name = str(billing.get("company_name", "")).strip()
        vat_number = str(billing.get("vat_number", billing.get("vat_id", ""))).strip()
        is_business = bool(company_name)
        country = str(billing.get("country", "RO")).upper()

        if is_business and country == "RO" and not vat_number:
            warnings.append(str(_("Romanian business without VAT number - verify tax profile")))

        # 2) Pricing snapshots and product state per item
        for item in order.items.select_related("product"):
            # Non-negative prices
            if int(item.unit_price_cents) < 0 or int(item.setup_cents) < 0:
                errors.append(str(_("Item '{}': invalid pricing (negative values)").format(item.product_name)))

            # Product state
            product = item.product
            if product is None:
                errors.append(str(_("Item '{}': missing product reference").format(item.product_name)))  # type: ignore[unreachable]
            else:
                if not product.is_active:
                    warnings.append(str(_("Item '{}': product is inactive").format(item.product_name)))

                # Price availability in catalog for the order currency
                price = product.get_price_for_currency(order.currency.code)
                if price is None:
                    errors.append(
                        str(_("Item '{}': no current price for {}").format(item.product_name, order.currency.code))
                    )

                # Snapshot presence (optional warn for legacy)
                if not isinstance(item.config, dict) or not str(item.config.get("product_price_id", "")):
                    warnings.append(str(_("Item '{}': missing price snapshot metadata").format(item.product_name)))

        # 3) VAT and totals consistency - recompute
        try:
            # For preflight validation (temporary orders), use the provided subtotal
            # For real orders, recompute from items
            if hasattr(order, "_preflight_subtotal_cents"):
                subtotal_cents = order._preflight_subtotal_cents
            else:
                # Compute subtotal from items (unit * qty + setup)
                subtotal_cents = 0
                for item in order.items.all():
                    subtotal_cents += (int(item.unit_price_cents) * int(item.quantity)) + int(item.setup_cents)

            customer_vat_info: CustomerVATInfo = {
                "country": country,
                "is_business": is_business,
                "vat_number": vat_number or None,
                "customer_id": str(order.customer_id),
                "order_id": str(order.id),
            }
            vat_result = OrderVATCalculator.calculate_vat(
                subtotal_cents=subtotal_cents, customer_info=customer_vat_info
            )

            expected_tax_cents = int(vat_result.vat_cents)
            expected_total_cents = int(vat_result.total_cents)

            if int(order.tax_cents) != expected_tax_cents:
                errors.append(
                    str(
                        _("VAT mismatch: order={}¢ vs computed={}¢ ({})").format(
                            order.tax_cents, expected_tax_cents, vat_result.reasoning
                        )
                    )
                )
            if int(order.total_cents) != expected_total_cents:
                errors.append(
                    str(
                        _("Total mismatch: order={}¢ vs computed={}¢ (subtotal={}¢)").format(
                            order.total_cents, expected_total_cents, subtotal_cents
                        )
                    )
                )
        except Exception as exc:
            logger.exception("Order VAT validation failed: %s", exc)
            errors.append(str(_("Failed to validate VAT and totals")))

        # 4) Currency support
        if not order.currency_id:
            errors.append(str(_("Order currency not set")))

        return errors, warnings

    @staticmethod
    def assert_valid(order: Order, allow_warning_override: bool = True) -> None:
        """Raise ValueError on blocking validation failures. Warnings ignored by default."""
        errors, warnings = OrderPreflightValidationService.validate(order)
        if errors:
            raise ValueError("; ".join(errors))
        # optionally escalate warnings
        if warnings and not allow_warning_override:
            raise ValueError("; ".join(warnings))
