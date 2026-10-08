"""Manual deployment tokens must remain bound to their OAuth client identity."""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import AuthenticationError, EFacturaClient, EFacturaConfig, TokenResponse
from apps.billing.efactura.service import EFacturaService
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


@override_settings(
    EFACTURA_ENVIRONMENT="test",
    EFACTURA_CLIENT_ID="client-a",
    EFACTURA_CLIENT_SECRET="secret-a",
    EFACTURA_COMPANY_CUI="12345678",
    EFACTURA_ACCESS_TOKEN="manual-client-a-token",
    CACHES={
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "efactura-manual-token-identity",
        }
    },
)
class ManualTokenIdentityTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        SystemSetting.objects.filter(key__startswith="efactura.").delete()
        self.authorizations: list[str] = []

    def _write(self, key: str, value: str) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), str(result))

    def _transport(self, method: str, url: str, **kwargs: object) -> requests.Response:
        self.assertEqual(method, "POST")
        headers = cast(dict[str, str], kwargs["headers"])
        self.authorizations.append(headers["Authorization"])
        response = requests.Response()
        if url == "https://logincert.anaf.ro/anaf-oauth2/v1/token":
            response.status_code = 401
            response._content = b'{"error":"invalid_grant"}'
        else:
            self.assertEqual(url, "https://api.anaf.ro/test/FCTEL/rest/upload")
            response.status_code = 200
            response._content = b'<header ExecutionStatus="0" index_incarcare="MANUAL-IDENTITY"/>'
        return response

    @staticmethod
    def _attempt_upload(client: EFacturaClient) -> AuthenticationError | None:
        try:
            client.upload_invoice("<Invoice/>")
        except AuthenticationError as exc:
            return exc
        return None

    def test_stored_credential_rotation_cannot_dispatch_the_deployment_manual_token(self) -> None:
        service = EFacturaService()
        with patch("apps.billing.efactura.client.safe_request", side_effect=self._transport):
            self.assertTrue(service.client.upload_invoice("<Invoice/>").success)
            self.assertEqual(self.authorizations, ["Bearer manual-client-a-token"])
            service.client._cache_token(
                TokenResponse(
                    access_token="cached-client-a-token",
                    token_type="Bearer",
                    expires_in=3600,
                    expires_at=timezone.now() + timedelta(hours=1),
                )
            )

            self._write("efactura.oauth.client_id", "client-b")
            self._write("efactura.oauth.client_secret", "secret-b")
            rotated = service._client_for_environment("test")
            self.assertEqual((rotated.config.client_id, rotated.config.client_secret), ("client-b", "secret-b"))
            error = self._attempt_upload(rotated)
            self.assertEqual(self.authorizations, ["Bearer manual-client-a-token"])
            self.assertIsInstance(error, AuthenticationError)

            rotated._cache_token(
                TokenResponse(
                    access_token="cached-client-b-token",
                    token_type="Bearer",
                    expires_in=3600,
                    expires_at=timezone.now() + timedelta(hours=1),
                )
            )
            self.assertTrue(rotated.upload_invoice("<Invoice/>").success)
            self.assertEqual(self.authorizations, ["Bearer manual-client-a-token", "Bearer cached-client-b-token"])

            self._write("efactura.oauth.client_id", "")
            self._write("efactura.oauth.client_secret", "")
            cache.delete(service.client.token_cache_key)
            restored = service._client_for_environment("test")
            restored._token = None
            restored._token_cache_key = None
            self.assertTrue(restored.upload_invoice("<Invoice/>").success)
            self.assertEqual(
                self.authorizations,
                ["Bearer manual-client-a-token", "Bearer cached-client-b-token", "Bearer manual-client-a-token"],
            )

    def test_explicit_client_cannot_use_a_mismatched_or_unbound_manual_token(self) -> None:
        for owner in ("client-a", ""):
            with self.subTest(deployment_client_id=owner), override_settings(EFACTURA_CLIENT_ID=owner):
                self.authorizations.clear()
                client = EFacturaClient(EFacturaConfig("client-b", "secret-b", "12345678"))
                with patch("apps.billing.efactura.client.safe_request", side_effect=self._transport):
                    error = self._attempt_upload(client)
                self.assertEqual(self.authorizations, [])
                self.assertIsInstance(error, AuthenticationError)

    def test_failed_refresh_cannot_fall_back_to_another_clients_manual_token(self) -> None:
        client = EFacturaClient(EFacturaConfig("client-b", "secret-b", "12345678"))
        client._cache_token(
            TokenResponse(
                access_token="expired-client-b-token",
                token_type="Bearer",
                expires_in=3600,
                refresh_token="refresh-client-b",
                expires_at=timezone.now() - timedelta(minutes=1),
            )
        )
        with patch("apps.billing.efactura.client.safe_request", side_effect=self._transport):
            error = self._attempt_upload(client)
        basic_b = base64.b64encode(b"client-b:secret-b").decode("ascii")
        self.assertEqual(self.authorizations, [f"Basic {basic_b}"])
        self.assertIsInstance(error, AuthenticationError)
