"""
Order Preflight Validation Service

Performs blocking validations before promoting an order from draft → pending.
Validates customer profile completeness, VAT scenario/amounts, pricing snapshots,
product state, currency and totals consistency.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Tuple

from django.utils.translation import gettext_lazy as _

from apps.products.models import Product
from .models import Order
from .vat_rules import OrderVATCalculator

logger = logging.getLogger(__name__)


class OrderPreflightValidationService:
    """Run comprehensive checks before an order becomes payable."""

    @staticmethod
    def validate(order: Order) -> Tuple[list[str], list[str]]:
        """Return (errors, warnings) for the given order."""
        errors: list[str] = []
        warnings: list[str] = []

        # 1) Customer and billing snapshot completeness
        billing = order.billing_address or {}
        required_fields = [
            ("contact_name", _("Contact name is required")),
            ("contact_email", _("Contact email is required")),
            ("line1", _("Billing address line1 is required")),
            ("city", _("Billing city is required")),
            ("county", _("Billing county is required")),
            ("postal_code", _("Billing postal code is required")),
            ("country", _("Billing country is required")),
        ]
        for field, message in required_fields:
            if not str(billing.get(field, "")).strip():
                errors.append(str(message))

        # Basic email presence – format validation is assumed upstream
        # VAT number presence for businesses (company name given)
        company_name = str(billing.get("company_name", "")).strip()
        vat_number = str(billing.get("vat_number", billing.get("vat_id", ""))).strip()
        is_business = bool(company_name)
        country = str(billing.get("country", "RO")).upper()

        if is_business and country == "RO" and not vat_number:
            warnings.append(str(_("Romanian business without VAT number – verify tax profile")))

        # 2) Pricing snapshots and product state per item
        for item in order.items.select_related("product"):
            # Billing period required
            if not item.billing_period:
                errors.append(_(f"Item '{item.product_name}': missing billing period"))

            # Non-negative prices
            if int(item.unit_price_cents) < 0 or int(item.setup_cents) < 0:
                errors.append(_(f"Item '{item.product_name}': invalid pricing (negative values)"))

            # Product state
            product = item.product
            if product is None:
                errors.append(_(f"Item '{item.product_name}': missing product reference"))
            else:
                if not product.is_active:
                    warnings.append(_(f"Item '{item.product_name}': product is inactive"))

                # Price availability in catalog for snapshot period/currency
                price = product.get_price_for_period(order.currency.code, item.billing_period)
                if price is None:
                    errors.append(
                        _(f"Item '{item.product_name}': no current price for {order.currency.code} / {item.billing_period}")
                    )

                # Snapshot presence (optional warn for legacy)
                if not isinstance(item.config, dict) or not str(item.config.get("product_price_id", "")):
                    warnings.append(_(f"Item '{item.product_name}': missing price snapshot metadata"))

        # 3) VAT and totals consistency – recompute
        try:
            # Compute subtotal from items (unit * qty + setup)
            subtotal_cents = 0
            for item in order.items.all():
                subtotal_cents += (int(item.unit_price_cents) * int(item.quantity)) + int(item.setup_cents)

            vat_result = OrderVATCalculator.calculate_vat(
                subtotal_cents=subtotal_cents,
                customer_country=country,
                is_business=is_business,
                vat_number=vat_number or None,
                customer_id=str(order.customer_id),
                order_id=str(order.id),
            )

            expected_tax_cents = int(vat_result.vat_cents)
            expected_total_cents = int(vat_result.total_cents)

            if int(order.tax_cents) != expected_tax_cents:
                errors.append(
                    _(f"VAT mismatch: order={order.tax_cents}¢ vs computed={expected_tax_cents}¢ ({vat_result.reasoning})")
                )
            if int(order.total_cents) != expected_total_cents:
                errors.append(
                    _(f"Total mismatch: order={order.total_cents}¢ vs computed={expected_total_cents}¢ (subtotal={subtotal_cents}¢)")
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

