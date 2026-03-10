"""
ProductListSerializer and ProductDetailSerializer field coverage tests.

The `meta` field is a JSONField containing product features (e.g., disk space,
bandwidth) that the catalog template renders via `product.meta.features`.
Both list and detail serializers must include `meta`.

(H2 was originally a chaos-monkey finding to remove `meta` from the list
serializer, but the catalog template depends on it for feature display.)
"""

from __future__ import annotations

from typing import ClassVar

from django.test import SimpleTestCase

from apps.api.orders.serializers import ProductDetailSerializer, ProductListSerializer


class ProductListSerializerFieldsTest(SimpleTestCase):
    """ProductListSerializer must include all fields the catalog template needs."""

    REQUIRED_FIELDS: ClassVar[tuple[str, ...]] = (
        "id",
        "slug",
        "name",
        "short_description",
        "product_type",
        "product_type_display",
        "is_featured",
        "requires_domain",
        "is_active",
        "prices",
        "meta",
    )

    def test_all_required_catalog_fields_declared(self) -> None:
        """All fields needed by the catalog template must be declared."""
        serializer = ProductListSerializer()
        declared = set(serializer.fields.keys())
        for field_name in self.REQUIRED_FIELDS:
            self.assertIn(
                field_name,
                declared,
                msg=f"Required catalog field '{field_name}' missing from ProductListSerializer",
            )

    def test_meta_in_list_serializer(self) -> None:
        """meta must be in ProductListSerializer — catalog uses product.meta.features."""
        serializer = ProductListSerializer()
        self.assertIn("meta", serializer.fields)

    def test_meta_in_detail_serializer(self) -> None:
        """ProductDetailSerializer must also expose meta."""
        serializer = ProductDetailSerializer()
        self.assertIn("meta", serializer.fields)
