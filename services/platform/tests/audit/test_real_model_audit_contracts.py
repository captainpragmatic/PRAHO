"""Persisted model contracts: mocks must not invent retired audit attributes."""

from decimal import Decimal

from django.test import TestCase

from apps.audit.models import AuditEvent
from apps.audit.services import DomainsAuditService, ProductsAuditService
from apps.billing.models import Currency
from apps.domains.models import Registrar
from apps.products.models import Product, ProductPrice
from apps.users.models import User


class RealPricingAuditTests(TestCase):
    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.product = Product.objects.create(name="Audit VPS", slug="audit-vps", product_type="vps")
        self.user = User.objects.create_user(email="audit-billing@example.test", password="test-password")

    def test_creation_signal_uses_monthly_price(self) -> None:
        with self.assertNoLogs("apps.products.signals", level="ERROR"):
            price = ProductPrice.objects.create(product=self.product, currency=self.currency, monthly_price_cents=2999)
        event = AuditEvent.objects.get(action="product_pricing_changed", object_id=str(price.pk))
        self.assertIn("RON 29.99 (monthly)", event.description)
        self.assertEqual(event.metadata["current_pricing"]["monthly_price_cents"], 2999)

    def test_free_to_paid_and_back_preserves_zero_and_impact(self) -> None:
        price = ProductPrice.objects.create(product=self.product, currency=self.currency, monthly_price_cents=0)
        for old, new in ((0, 2500), (2500, 0)):
            with self.subTest(old=old, new=new), self.assertNoLogs("apps.products.signals", level="ERROR"):
                price.monthly_price_cents = new
                price.save()
                event = AuditEvent.objects.filter(action="product_pricing_changed", object_id=str(price.pk)).latest(
                    "timestamp"
                )
                self.assertEqual(event.old_values["monthly_price_changed"], old)
                self.assertEqual(event.new_values["monthly_price_changed"], new)
                self.assertTrue(event.metadata["business_impact"]["significant_change"])
                self.assertEqual(event.metadata["business_impact"]["price_increased"], new > old)
                self.assertEqual(
                    event.metadata["changes"]["monthly_price_changed"]["percent_change"],
                    None if old == 0 else 100.0,
                )

    def test_promo_removal_preserves_null_and_explicit_actor(self) -> None:
        price = ProductPrice.objects.create(
            product=self.product, currency=self.currency, monthly_price_cents=1000, promo_price_cents=0
        )
        event = ProductsAuditService.log_product_pricing_changed(
            price,
            "price_updated",
            {"promotional_pricing_changed": {"from_cents": 0, "to_cents": None}},
            user=self.user,
        )
        event.refresh_from_db()
        self.assertEqual(event.user_id, self.user.pk)
        self.assertEqual(event.old_values, {"promotional_pricing_changed": 0})
        self.assertEqual(event.new_values, {"promotional_pricing_changed": None})

    def test_small_positive_price_change_preserves_threshold(self) -> None:
        price = ProductPrice.objects.create(product=self.product, currency=self.currency, monthly_price_cents=10000)
        count = AuditEvent.objects.filter(action="product_pricing_changed").count()
        price.monthly_price_cents = 10001
        price.save()
        self.assertEqual(AuditEvent.objects.filter(action="product_pricing_changed").count(), count)

    def test_setup_fee_can_be_changed_to_zero(self) -> None:
        price = ProductPrice.objects.create(
            product=self.product, currency=self.currency, monthly_price_cents=1000, setup_cents=500
        )
        price.setup_cents = 0
        price.annual_discount_percent = Decimal("0")
        price.save()
        event = AuditEvent.objects.filter(action="product_pricing_changed", object_id=str(price.pk)).latest("timestamp")
        self.assertEqual(event.new_values["setup_fee_changed"], 0)


class RealRegistrarAuditTests(TestCase):
    def test_registrar_fields_and_redaction(self) -> None:
        with self.assertNoLogs("apps.domains.signals", level="ERROR"):
            registrar = Registrar.objects.create(
                name="audit-registrar",
                display_name="Audit Registrar",
                status="disabled",
                api_endpoint="https://registrar.example.test/api",
                website_url="https://registrar.example.test",
            )
        for sensitive in (False, True):
            with self.subTest(sensitive=sensitive):
                event = DomainsAuditService.log_registrar_event(
                    "registrar_updated", registrar, security_sensitive=sensitive
                )
                event.refresh_from_db()
                self.assertEqual(event.metadata["api_url"], "[REDACTED]" if sensitive else registrar.api_endpoint)
                self.assertFalse(event.metadata["is_active"])
                self.assertEqual(event.metadata["supported_tlds"], [])
                self.assertNotIn("api_key", event.metadata)
