"""A webhook secret no key can decrypt is a configuration error, not a bad signature (#751 follow-up, M12).

A stored secret written under a superseded format (or a keyring that lacks its key) raised during
verification, which the broad handler turned into "Invalid webhook signature" (400): the sender was told
its request was forged, and the operator was told nothing. It now answers 503 with a generic body and a
CRITICAL log, so the sender retries and the configuration gets fixed. There is no fallback to the
environment's secret: an unreadable configured secret is a fault to fix, not a reason to verify against
something else.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from apps.common.encryption import DecryptionError
from apps.settings.services import SettingsService

_get_setting = SettingsService.get_setting


def _unreadable_webhook_secret(key: str, *args: Any, **kwargs: Any) -> Any:
    if key == "integrations.stripe_webhook_secret":
        raise DecryptionError("Persistent secret requires context-bound v2 ciphertext; replace the stored secret")
    return _get_setting(key, *args, **kwargs)


class UnreadableWebhookSecretTests(TestCase):
    def test_an_unreadable_secret_answers_503_and_says_why_in_the_log(self) -> None:
        body = json.dumps({"id": "evt_secret", "type": "payment_intent.succeeded", "data": {"object": {}}})

        with (
            patch.object(SettingsService, "get_setting", side_effect=_unreadable_webhook_secret),
            self.assertLogs("apps.integrations", level="CRITICAL") as logs,
        ):
            response = self.client.post(
                reverse("integrations:stripe_webhook"), data=body, content_type="application/json",
                HTTP_STRIPE_SIGNATURE="t=1,v1=0000",
            )

        self.assertEqual(response.status_code, 503, "the sender retries once the configuration is fixed")
        self.assertNotIn("signature", response.content.decode().lower(), "it is not a forged request")
        self.assertIn("webhook secret", " ".join(logs.output).lower())
