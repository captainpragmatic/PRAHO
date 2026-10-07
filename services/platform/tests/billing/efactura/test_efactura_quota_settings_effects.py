"""Effect tests for staff-configured ANAF request quotas."""

from collections.abc import Mapping
from typing import cast
from unittest.mock import patch
from urllib.parse import urlsplit

import requests
from django.core.cache import cache
from django.test import TestCase, override_settings
from freezegun import freeze_time

from apps.billing.efactura.client import EFacturaClient, EFacturaConfig, RateLimitError
from apps.billing.efactura.quota import ANAFQuotaTracker, QuotaEndpoint
from apps.common.counters import Counter
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


@freeze_time("2026-10-07 09:00:00+00:00")
@override_settings(EFACTURA_ENVIRONMENT="test", EFACTURA_ACCESS_TOKEN="quota-test-token")
class EFacturaQuotaSettingsEffectsTests(TestCase):
    client: EFacturaClient
    requests_seen: list[tuple[str, dict[str, object]]]
    response_codes: list[int]

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        SystemSetting.objects.filter(key__startswith="efactura.").delete()
        Counter.objects.filter(key__startswith=ANAFQuotaTracker.CACHE_PREFIX).delete()
        self.requests_seen = []
        self.response_codes = []
        self.client = self._client("12345678")
        self._write("efactura.rate_limit.global_per_minute", 0)
        transport = patch("apps.billing.efactura.client.safe_request", side_effect=self._transport)
        transport.start()
        self.addCleanup(transport.stop)

    @staticmethod
    def _client(cui: str) -> EFacturaClient:
        return EFacturaClient(
            EFacturaConfig(
                client_id="quota-client",
                client_secret="quota-secret",
                company_cui=cui,
                max_retries=2,
                retry_delay=0,
            )
        )

    def _write(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), str(result))

    def _transport(self, method: str, url: str, **kwargs: object) -> requests.Response:
        self.assertEqual(method, "GET")
        self.assertEqual(kwargs["headers"], self.client._default_headers | {"Authorization": "Bearer quota-test-token"})
        path = urlsplit(url).path.rsplit("/", 1)[-1]
        params = dict(cast(Mapping[str, object], kwargs["params"]))
        self.requests_seen.append((path, params))
        response = requests.Response()
        response.status_code = self.response_codes.pop(0) if self.response_codes else 200
        response.headers["Retry-After"] = "0"
        if path == "descarcare":
            response._content = b"PK-quota-response"
        elif path == "stareMesaj":
            response._content = b'{"stare":"ok","id_descarcare":"result-1"}'
        else:
            self.assertIn(path, ("listaMesajeFactura", "listaMesajePaginatieFactura"))
            response._content = b'{"mesaje":[{"id":"result-1"}]}'
        return response

    def test_download_quota_refuses_only_the_exhausted_message_and_can_be_changed(self) -> None:
        self._write("efactura.rate_limit.download_per_message_day", 1)
        self.assertEqual(self.client.download_response("download-a"), b"PK-quota-response")
        before = self.requests_seen.copy()
        with self.assertRaises(RateLimitError):
            self.client.download_response("download-a")
        self.assertEqual(self.requests_seen, before)
        self.assertEqual(ANAFQuotaTracker().get_current_usage(QuotaEndpoint.DOWNLOAD, "12345678", "download-a"), 1)
        self.assertEqual(self.client.download_response("download-b"), b"PK-quota-response")

        self._write("efactura.rate_limit.download_per_message_day", 2)
        self.assertEqual(self.client.download_response("download-a"), b"PK-quota-response")
        self._write("efactura.rate_limit.download_per_message_day", 0)
        self.assertEqual(self.client.download_response("download-a"), b"PK-quota-response")
        self.assertEqual(ANAFQuotaTracker().get_current_usage(QuotaEndpoint.DOWNLOAD, "12345678", "download-a"), 3)

    def test_global_quota_is_shared_across_endpoints_and_companies_and_can_be_changed(self) -> None:
        self._write("efactura.rate_limit.global_per_minute", 1)
        self.assertEqual(self.client.download_response("download-a"), b"PK-quota-response")
        other_client = self._client("87654321")
        before = self.requests_seen.copy()
        with self.assertRaises(RateLimitError):
            other_client.get_upload_status("upload-b")
        self.assertEqual(self.requests_seen, before)

        refused = self.client._post_upload("/upload", {"cif": "12345678"}, "<Invoice/>")
        self.assertFalse(refused.success)
        self.assertTrue(refused.outcome_is_known)
        self.assertEqual(self.requests_seen, before)

        self._write("efactura.rate_limit.global_per_minute", 2)
        self.assertTrue(other_client.get_upload_status("upload-b").is_accepted)
        self._write("efactura.rate_limit.global_per_minute", 0)
        self.assertEqual(self.client.download_response("download-a"), b"PK-quota-response")
        self.assertEqual(
            ANAFQuotaTracker().get_current_usage(QuotaEndpoint.STATUS, "87654321", "upload-b"),
            1,
        )

    def test_paginated_list_quota_is_per_company_across_pages_and_can_be_changed(self) -> None:
        self._write("efactura.rate_limit.list_paginated_per_day", 1)
        messages = self.client.list_messages_paginated(1000, 2000, page=1, cif="87654321")
        self.assertEqual([message.message_id for message in messages], ["result-1"])
        before = self.requests_seen.copy()
        with self.assertRaises(RateLimitError):
            self.client.list_messages_paginated(1000, 2000, page=2, cif="87654321")
        self.assertEqual(self.requests_seen, before)
        self.assertEqual(ANAFQuotaTracker().get_current_usage(QuotaEndpoint.LIST_PAGINATED, "87654321"), 1)
        messages = self.client.list_messages_paginated(1000, 2000, page=2, cif="12345678")
        self.assertEqual([message.message_id for message in messages], ["result-1"])

        self._write("efactura.rate_limit.list_paginated_per_day", 2)
        messages = self.client.list_messages_paginated(1000, 2000, page=2, cif="87654321")
        self.assertEqual([message.message_id for message in messages], ["result-1"])
        self.assertEqual(
            self.requests_seen[-1],
            ("listaMesajePaginatieFactura", {"startTime": 1000, "endTime": 2000, "pagina": 2, "cif": "87654321"}),
        )
        self._write("efactura.rate_limit.list_paginated_per_day", 0)
        messages = self.client.list_messages_paginated(1000, 2000, page=3, cif="87654321")
        self.assertEqual([message.message_id for message in messages], ["result-1"])

    def test_simple_list_quota_is_per_company_across_filters_and_can_be_changed(self) -> None:
        self._write("efactura.rate_limit.list_simple_per_day", 1)
        messages = self.client.list_messages(days=10, cif="87654321", filter_type="E")
        self.assertEqual([message.message_id for message in messages], ["result-1"])
        before = self.requests_seen.copy()
        with self.assertRaises(RateLimitError):
            self.client.list_messages(days=20, cif="87654321", filter_type="T")
        self.assertEqual(self.requests_seen, before)
        self.assertEqual(ANAFQuotaTracker().get_current_usage(QuotaEndpoint.LIST_SIMPLE, "87654321"), 1)
        messages = self.client.list_messages(cif="12345678")
        self.assertEqual([message.message_id for message in messages], ["result-1"])

        self._write("efactura.rate_limit.list_simple_per_day", 2)
        messages = self.client.list_messages(days=20, cif="87654321", filter_type="T")
        self.assertEqual([message.message_id for message in messages], ["result-1"])
        self.assertEqual(
            self.requests_seen[-1],
            ("listaMesajeFactura", {"zile": 20, "cif": "87654321", "filtru": "T"}),
        )
        self._write("efactura.rate_limit.list_simple_per_day", 0)
        messages = self.client.list_messages(cif="87654321")
        self.assertEqual([message.message_id for message in messages], ["result-1"])

    def test_status_quota_refuses_only_the_exhausted_message_and_can_be_changed(self) -> None:
        self._write("efactura.rate_limit.status_per_message_day", 1)
        self.assertTrue(self.client.get_upload_status("upload-a").is_accepted)
        before = self.requests_seen.copy()
        with self.assertRaises(RateLimitError):
            self.client.get_upload_status("upload-a")
        self.assertEqual(self.requests_seen, before)
        self.assertEqual(ANAFQuotaTracker().get_current_usage(QuotaEndpoint.STATUS, "12345678", "upload-a"), 1)
        self.assertTrue(self.client.get_upload_status("upload-b").is_accepted)

        self._write("efactura.rate_limit.status_per_message_day", 2)
        self.assertTrue(self.client.get_upload_status("upload-a").is_accepted)
        self._write("efactura.rate_limit.status_per_message_day", 0)
        self.assertTrue(self.client.get_upload_status("upload-a").is_accepted)
        self.assertEqual(ANAFQuotaTracker().get_current_usage(QuotaEndpoint.STATUS, "12345678", "upload-a"), 3)

    def test_global_quota_counts_each_http_retry_attempt(self) -> None:
        self._write("efactura.rate_limit.global_per_minute", 1)
        self.response_codes = [429, 200]
        with self.assertRaises(RateLimitError):
            self.client.get_upload_status("upload-retry")
        self.assertEqual(self.requests_seen, [("stareMesaj", {"id_incarcare": "upload-retry"})])
        self.assertEqual(ANAFQuotaTracker().get_current_usage(QuotaEndpoint.STATUS, "12345678", "upload-retry"), 1)
