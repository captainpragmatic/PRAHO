"""Tests for CartItemInputSerializer product identifier contract."""

import uuid
from typing import ClassVar

from django.test import SimpleTestCase

from apps.api.orders.serializers import CartItemInputSerializer


class CartItemInputSerializerTestCase(SimpleTestCase):
    """Validates that CartItemInputSerializer accepts slug-only, uuid-only, and rejects missing identifiers."""

    BASE_DATA: ClassVar[dict[str, object]] = {
        "quantity": 1,
        "billing_period": "monthly",
    }

    def test_accepts_slug_only(self) -> None:
        data = {**self.BASE_DATA, "product_slug": "shared-hosting-basic"}
        serializer = CartItemInputSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["product_slug"], "shared-hosting-basic")

    def test_accepts_uuid_only(self) -> None:
        pid = str(uuid.uuid4())
        data = {**self.BASE_DATA, "product_id": pid}
        serializer = CartItemInputSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(str(serializer.validated_data["product_id"]), pid)

    def test_accepts_both_identifiers(self) -> None:
        pid = str(uuid.uuid4())
        data = {**self.BASE_DATA, "product_id": pid, "product_slug": "shared-hosting-basic"}
        serializer = CartItemInputSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_rejects_when_both_identifiers_missing(self) -> None:
        serializer = CartItemInputSerializer(data=self.BASE_DATA)
        self.assertFalse(serializer.is_valid())
        self.assertIn("non_field_errors", serializer.errors)

    def test_rejects_blank_slug_without_product_id(self) -> None:
        data = {**self.BASE_DATA, "product_slug": "   "}
        serializer = CartItemInputSerializer(data=data)
        self.assertFalse(serializer.is_valid())

    def test_rejects_invalid_uuid_product_id(self) -> None:
        data = {**self.BASE_DATA, "product_id": "not-a-uuid"}
        serializer = CartItemInputSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn("product_id", serializer.errors)

    def test_rejects_empty_string_product_id(self) -> None:
        data = {**self.BASE_DATA, "product_id": ""}
        serializer = CartItemInputSerializer(data=data)
        self.assertFalse(serializer.is_valid())
