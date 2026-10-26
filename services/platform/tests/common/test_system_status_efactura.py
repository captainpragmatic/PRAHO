"""Status probes may read an existing ANAF token, never renew one or submit data."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.utils import timezone

from apps.billing.efactura.client import (
    AuthenticationError,
    EFacturaClient,
    EFacturaConfig,
    LocalQuotaError,
    TokenResponse,
)
from apps.common.system_status import StatusLevel, _check_efactura
from apps.common.system_status_probes import ProbeBudget, ProbeCode
from config.settings.test import LOCMEM_TEST_CACHE


@override_settings(CACHES=LOCMEM_TEST_CACHE, EFACTURA_ACCESS_TOKEN="", EFACTURA_CLIENT_ID="runtime-client")
class EFacturaProbeTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.config = EFacturaConfig("runtime-client", "secret", "123456")
        self.client = EFacturaClient(self.config)

    def _token(self, *, expired: bool = False) -> TokenResponse:
        return TokenResponse(
            "existing-access",
            "Bearer",
            3600,
            "private-refresh",
            expires_at=timezone.now() + timedelta(hours=-1 if expired else 1),
        )

    @patch.object(EFacturaClient, "refresh_token")
    @patch.object(EFacturaClient, "_reserve_request_quota")
    def test_existing_token_and_quota_used_for_one_day_page_one(self, quota: Mock, refresh: Mock) -> None:
        token = self._token()
        cache.set(self.client.token_cache_key, token.__dict__)
        request = self.client.prepare_status_probe("654321")
        self.assertIn("/test/FCTEL/rest/listaMesajePaginatieFactura", request["url"])
        self.assertEqual(request["headers"]["Authorization"], "Bearer existing-access")
        self.assertEqual(request["params"]["cif"], "654321")
        self.assertEqual(request["params"]["pagina"], 1)
        self.assertEqual(request["params"]["endTime"] - request["params"]["startTime"], 86400000)
        quota.assert_called_once_with(request["url"], request["params"])
        self.assertEqual(cache.get(self.client.token_cache_key), token.__dict__)
        refresh.assert_not_called()

    @patch.object(EFacturaClient, "refresh_token")
    @patch.object(EFacturaClient, "_reserve_request_quota")
    def test_expired_token_is_not_refreshed(self, quota: Mock, refresh: Mock) -> None:
        token = self._token(expired=True)
        cache.set(self.client.token_cache_key, token.__dict__)
        with self.assertRaises(AuthenticationError):
            self.client.prepare_status_probe("654321")
        refresh.assert_not_called()
        quota.assert_not_called()
        self.assertEqual(cache.get(self.client.token_cache_key), token.__dict__)

    @override_settings(EFACTURA_ACCESS_TOKEN="manual-token")
    @patch("apps.billing.efactura.client.efactura_environment", return_value=SimpleNamespace(value="test"))
    @patch.object(EFacturaClient, "_reserve_request_quota")
    def test_manual_token_requires_matching_environment_and_client(self, _quota: Mock, _environment: Mock) -> None:
        self.assertEqual(self.client.prepare_status_probe("654321")["headers"]["Authorization"], "Bearer manual-token")
        self.client.config.client_id = "different-client"
        with self.assertRaises(AuthenticationError):
            self.client.prepare_status_probe("654321")

    @patch.object(EFacturaClient, "refresh_token")
    def test_normal_client_still_refreshes_expired_token(self, refresh: Mock) -> None:
        cache.set(self.client.token_cache_key, self._token(expired=True).__dict__)
        refresh.return_value = self._token()
        self.assertEqual(self.client._get_access_token(), "existing-access")
        refresh.assert_called_once_with("private-refresh")

    @patch("apps.common.system_status.operator_is_romanian", return_value=True)
    @patch("apps.billing.efactura.settings.efactura_enabled", return_value=True)
    @patch.object(EFacturaConfig, "from_settings")
    @patch("apps.billing.efactura.xml_builder.get_supplier_info", return_value=SimpleNamespace(numeric_tax_id="654321"))
    @patch.object(ProbeBudget, "run", return_value=ProbeCode.OK)
    @patch.object(EFacturaClient, "_reserve_request_quota")
    def test_status_uses_actual_issuer_and_existing_token(
        self, quota: Mock, probe: Mock, _supplier: Mock, config: Mock, _enabled: Mock, _country: Mock
    ) -> None:
        config.return_value = self.config
        cache.set(self.client.token_cache_key, self._token().__dict__)
        result = _check_efactura()
        self.assertEqual(result.level, StatusLevel.GREEN)
        self.assertEqual(probe.call_args.args[1]["params"]["cif"], "654321")
        quota.side_effect = LocalQuotaError("exhausted", timezone.now())
        result = _check_efactura()
        self.assertEqual(result.message, "Local quota reached")
        self.assertEqual(probe.call_count, 1)
