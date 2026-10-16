"""Create the product a customer orders a domain through; the TLD price list prices it."""

from typing import Any

from django.core.management.base import BaseCommand

from apps.products.models import Product


class Command(BaseCommand):
    help = "Ensure a domain product exists (idempotent, safe for every deploy)"

    def handle(self, *args: Any, **options: Any) -> None:
        product = Product.objects.filter(product_type="domain").order_by("created_at").first()
        if product is None:
            product = Product.objects.create(slug="domain", name="Domain name", product_type="domain")
        self.stdout.write(self.style.SUCCESS(f"Domain product: {product.slug}"))
