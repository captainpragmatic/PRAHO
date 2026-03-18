"""Tests for DomainRegistrarGateway.verify_webhook_signature (issue #92).

Verifies HMAC-SHA256 signature checking with timing-safe comparison,
fail-closed behavior on missing/bad inputs, and DecryptionError handling.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from django.test import TestCase

from apps.domains.models import Registrar
from apps.domains.services import DomainRegistrarGateway


class WebhookSignatureVerificationTests(TestCase):
    """Core HMAC-SHA256 verification tests for registrar webhooks."""

    WEBHOOK_SECRET = "whsec_test_secret_abc123"

    def setUp(self) -> None:
        self.registrar = Registrar.objects.create(
            name="test-registrar",
            display_name="Test Registrar",
            website_url="https://example.com",
            api_endpoint="https://api.example.com",
            status="active",
        )
        # Store encrypted webhook secret
        self.registrar.set_encrypted_credentials(webhook_secret=self.WEBHOOK_SECRET)
        self.registrar.save()

        self.payload = json.dumps({"event_type": "domain.registered", "domain_name": "example.com"})

    def _sign(self, payload: str, secret: str | None = None) -> str:
        """Generate a valid sha256=<hex> signature for a payload."""
        key = (secret or self.WEBHOOK_SECRET).encode("utf-8")
        digest = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def test_valid_signature_accepted(self) -> None:
        signature = self._sign(self.payload)
        result = DomainRegistrarGateway.verify_webhook_signature(
            self.registrar, self.payload, signature
        )
        self.assertTrue(result)

    def test_invalid_signature_rejected(self) -> None:
        result = DomainRegistrarGateway.verify_webhook_signature(
            self.registrar, self.payload, "sha256=deadbeef1234567890"
        )
        self.assertFalse(result)

    def test_wrong_secret_rejected(self) -> None:
        bad_sig = self._sign(self.payload, secret="wrong_secret")
        result = DomainRegistrarGateway.verify_webhook_signature(
            self.registrar, self.payload, bad_sig
        )
        self.assertFalse(result)

    def test_tampered_payload_rejected(self) -> None:
        signature = self._sign(self.payload)
        tampered = self.payload.replace("example.com", "evil.com")
        result = DomainRegistrarGateway.verify_webhook_signature(
            self.registrar, tampered, signature
        )
        self.assertFalse(result)

    def test_empty_signature_rejected(self) -> None:
        result = DomainRegistrarGateway.verify_webhook_signature(
            self.registrar, self.payload, ""
        )
        self.assertFalse(result)

    def test_missing_webhook_secret_rejected(self) -> None:
        registrar_no_secret = Registrar.objects.create(
            name="no-secret-registrar",
            display_name="No Secret",
            website_url="https://example.com",
            api_endpoint="https://api.example.com",
            status="active",
        )
        result = DomainRegistrarGateway.verify_webhook_signature(
            registrar_no_secret, self.payload, "sha256=anything"
        )
        self.assertFalse(result)

    def test_decryption_error_rejected(self) -> None:
        # Simulate corrupted encrypted secret
        self.registrar.webhook_secret = "aes:corrupted_data_not_valid_base64url"
        self.registrar.save()

        result = DomainRegistrarGateway.verify_webhook_signature(
            self.registrar, self.payload, "sha256=anything"
        )
        self.assertFalse(result)

    def test_empty_decrypted_secret_rejected(self) -> None:
        """Unencrypted empty/whitespace value stored in DB should be rejected."""
        # Store a raw (unencrypted) whitespace value — decrypt_value returns it as-is
        self.registrar.webhook_secret = "   "
        self.registrar.save()

        result = DomainRegistrarGateway.verify_webhook_signature(
            self.registrar, self.payload, "sha256=anything"
        )
        self.assertFalse(result)

    def test_signature_without_prefix_rejected(self) -> None:
        """Signatures must include the 'sha256=' prefix."""
        raw_hex = self._sign(self.payload).removeprefix("sha256=")
        result = DomainRegistrarGateway.verify_webhook_signature(
            self.registrar, self.payload, raw_hex
        )
        self.assertFalse(result)


class WebhookViewSignatureIntegrationTests(TestCase):
    """Integration tests for RegistrarWebhookView signature enforcement via RequestFactory."""

    WEBHOOK_SECRET = "whsec_integration_test_456"

    def setUp(self) -> None:
        from django.test import RequestFactory  # noqa: PLC0415

        self.factory = RequestFactory()
        self.registrar = Registrar.objects.create(
            name="integration-registrar",
            display_name="Integration Registrar",
            website_url="https://example.com",
            api_endpoint="https://api.example.com",
            status="active",
        )
        self.registrar.set_encrypted_credentials(webhook_secret=self.WEBHOOK_SECRET)
        self.registrar.save()

        self.payload = json.dumps({
            "event_type": "domain.registered",
            "domain_name": "test-integration.com",
        })

    def _sign(self, payload: str) -> str:
        key = self.WEBHOOK_SECRET.encode("utf-8")
        digest = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def _post_webhook(self, payload: str, **extra_headers: str) -> Any:
        from apps.domains.webhooks import RegistrarWebhookView  # noqa: PLC0415

        request = self.factory.post(
            f"/webhooks/{self.registrar.name}/",
            data=payload,
            content_type="application/json",
            **extra_headers,
        )
        view = RegistrarWebhookView.as_view()
        return view(request, registrar_slug=self.registrar.name)

    def test_webhook_view_rejects_no_signature(self) -> None:
        response = self._post_webhook(self.payload)
        self.assertEqual(response.status_code, 403)

    def test_webhook_view_rejects_bad_signature(self) -> None:
        response = self._post_webhook(
            self.payload,
            HTTP_X_HUB_SIGNATURE_256="sha256=invalid",
        )
        self.assertEqual(response.status_code, 403)

    def test_webhook_view_accepts_valid_signature(self) -> None:
        signature = self._sign(self.payload)
        response = self._post_webhook(
            self.payload,
            HTTP_X_HUB_SIGNATURE_256=signature,
        )
        # Signature passes; domain doesn't exist → 400 (processing error, not auth error)
        self.assertEqual(response.status_code, 400)

    def test_webhook_view_accepts_valid_signature_via_x_signature_header(self) -> None:
        """X-Signature header is the fallback when X-Hub-Signature-256 is absent."""
        signature = self._sign(self.payload)
        response = self._post_webhook(
            self.payload,
            HTTP_X_SIGNATURE=signature,
        )
        # Signature passes via fallback header; domain doesn't exist → 400
        self.assertEqual(response.status_code, 400)
