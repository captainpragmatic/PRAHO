"""Catalog writes survive optional audit failures."""

from apps.products.models import Product
from tests.common._signal_isolation import SignalIsolationTestCase


class ProductSignalIsolationTests(SignalIsolationTestCase):
    def test_product_creation_survives_failed_audit_write(self) -> None:
        product = self.run_effect(
            "apps.products.signals.ProductsAuditService.log_product_created",
            lambda: Product.objects.create(name="Isolation", slug="isolation", product_type="shared_hosting"),
        )
        self.assertTrue(Product.objects.filter(pk=product.pk).exists())

    def test_original_state_read_failure_preserves_product_update(self) -> None:
        product = Product.objects.create(name="Original", slug="original", product_type="shared_hosting")
        product.name = "Changed"
        self.run_effect(
            "apps.products.signals.Product.objects.get",
            lambda: product.save(update_fields=["name"]),
        )
        self.assertEqual(Product.objects.get(pk=product.pk).name, "Changed")
