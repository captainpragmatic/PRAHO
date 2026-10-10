"""The Stripe-config call carries the signed-in user, so Platform limits it per customer (ADR-0030)."""

from __future__ import annotations

import io
import json
from typing import cast
from unittest.mock import patch

from django.test import SimpleTestCase
from requests import Response

from apps.billing.services import GiftCardPurchaseService


class StripeConfigIdentityTests(SimpleTestCase):
    def test_the_signed_body_names_the_user(self) -> None:
        sent: list[dict[str, object]] = []

        def platform(**kwargs: object) -> Response:
            sent.append(json.loads(cast(bytes, kwargs["data"])))
            response = Response()
            response.status_code = 200
            response.headers["Content-Type"] = "application/json"
            response.raw = io.BytesIO(
                json.dumps({"success": True, "config": {"publishable_key": "pk_test_1"}}).encode()
            )
            return response

        with patch("apps.api_client.services.portal_request", side_effect=platform):
            key = GiftCardPurchaseService(customer_id=42, user_id=7).stripe_public_key()
        self.assertEqual(key, "pk_test_1")
        self.assertEqual([body.get("user_id") for body in sent], [7])
