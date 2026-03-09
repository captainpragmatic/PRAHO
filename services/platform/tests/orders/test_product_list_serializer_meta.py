"""
ENH-4: ProductListSerializer must expose `meta` field for feature specs.

The portal product catalog needs feature specs (storage, bandwidth, email
accounts, databases) from product.meta to render feature lists on cards.
The `ProductListSerializer` previously omitted `meta`, which meant the portal
template's `product.meta.features` block was always skipped.

TDD — these tests must fail before the fix and pass after.
"""

from __future__ import annotations

from typing import ClassVar

from django.test import SimpleTestCase

from apps.api.orders.serializers import ProductListSerializer


class ProductListSerializerMetaFieldTest(SimpleTestCase):
    """
    ProductListSerializer must include `meta` in its serialised output
    so the portal catalog can render feature lists on product cards.
    """

    DECLARED_FIELDS: ClassVar[tuple[str, ...]] = (
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

    def test_meta_field_declared_in_serializer(self) -> None:
        """
        `meta` must be a declared field on ProductListSerializer so that
        product.meta.features is available in the portal catalog template.
        """
        serializer = ProductListSerializer()
        self.assertIn(
            "meta",
            serializer.fields,
            msg=(
                "ProductListSerializer does not expose 'meta'. "
                "Add 'meta' to the Meta.fields tuple so the portal can render "
                "product feature lists on catalog cards."
            ),
        )

    def test_all_required_catalog_fields_declared(self) -> None:
        """All fields needed by the catalog template must be declared."""
        serializer = ProductListSerializer()
        declared = set(serializer.fields.keys())
        for field_name in self.DECLARED_FIELDS:
            self.assertIn(
                field_name,
                declared,
                msg=f"Required catalog field '{field_name}' missing from ProductListSerializer",
            )
