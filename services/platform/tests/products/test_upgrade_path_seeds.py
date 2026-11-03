"""Development fixtures must not bypass the runtime graph or reset an operator's link."""

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.products.models import Product, ProductRelationship
from apps.users.models import User


class UpgradePathSeedTests(TestCase):
    def setUp(self) -> None:
        self.admin = User.objects.create_superuser(email="seed-catalog@example.com", password="fixture")
        self.basic = Product.objects.create(name="Basic", slug="web-hosting-basic", product_type="shared_hosting")
        self.premium = Product.objects.create(name="Premium", slug="web-hosting-premium", product_type="shared_hosting")
        self.products = {product.slug: product for product in (self.basic, self.premium)}
        for slug in ("domain-registration", "ssl-certificate", "email-hosting"):
            self.products[slug] = Product.objects.create(name=slug, slug=slug, product_type="shared_hosting")

    def seed(self) -> int:
        # Import the real standalone script after Django's app initialization.
        from scripts.setup_test_data import seed_product_relationships  # noqa: PLC0415

        return seed_product_relationships(self.products, self.admin)

    def test_seed_refuses_an_upgrade_opposite_to_an_existing_live_edge(self) -> None:
        ProductRelationship.objects.create(
            source_product=self.premium, target_product=self.basic, relationship_type="upgrades_to"
        )
        with self.assertRaisesMessage(ValidationError, "opposite direction"):
            self.seed()
        # This control proves the real fixture reached relationship creation.
        self.assertTrue(
            ProductRelationship.objects.filter(source_product=self.basic, relationship_type="requires").exists()
        )
        self.assertFalse(
            ProductRelationship.objects.filter(
                source_product=self.basic, target_product=self.premium, relationship_type="upgrades_to"
            ).exists()
        )

    def test_seed_rerun_preserves_existing_inactive_order_and_config(self) -> None:
        edge = ProductRelationship.objects.create(
            source_product=self.basic,
            target_product=self.premium,
            relationship_type="upgrades_to",
            is_active=False,
            sort_order=17,
            config={"reason": "Curated manually"},
        )
        self.seed()
        self.seed()
        edge.refresh_from_db()
        self.assertFalse(edge.is_active)
        self.assertEqual(edge.sort_order, 17)
        self.assertEqual(edge.config, {"reason": "Curated manually"})
        self.assertEqual(ProductRelationship.objects.filter(relationship_type="upgrades_to").count(), 1)
        self.assertTrue(ProductRelationship.objects.filter(relationship_type="cross_sell").exists())
