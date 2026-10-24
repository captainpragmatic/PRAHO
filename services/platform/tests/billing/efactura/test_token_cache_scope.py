"""The e-Factura token cache holds a row id, scoped and checked, never the bearer token (#751 follow-up, M24).

TokenStorageService cached the decrypted access token in the shared cache (the database cache in production)
for five minutes, keyed by CUI alone: a production and a test token for one company shared a key, a token
replaced or deactivated in the database kept being served from the cache, and its five minutes ran past the
token's own expiry. Storing a token for one environment also deactivated the other environment's tokens.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.billing.efactura.settings import EFacturaEnvironment
from apps.billing.efactura.token_storage import OAuthToken, TokenStorageService
from config.settings.test import LOCMEM_TEST_CACHE

CUI = "12345678"


def _service(environment: EFacturaEnvironment) -> TokenStorageService:
    return TokenStorageService(settings=SimpleNamespace(company_cui=CUI, environment=environment))


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class TokenCacheScopeTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def _cache_holds(self, text: str) -> bool:
        """Whether any stored entry contains `text`, read from LocMemCache's own store of pickled values."""
        store: dict[str, bytes] = getattr(cache, "_cache")  # noqa: B009  # The backend's private store
        return any(text.encode() in raw for raw in store.values())

    def test_the_cache_never_holds_the_access_token(self) -> None:
        service = _service(EFacturaEnvironment.PRODUCTION)
        service.store_token(access_token="bearer-secret-value", expires_in=3600)
        self.assertEqual(service.get_access_token(), "bearer-secret-value")
        self.assertFalse(self._cache_holds("bearer-secret-value"))

    def test_a_token_for_one_environment_is_not_served_to_the_other(self) -> None:
        _service(EFacturaEnvironment.PRODUCTION).store_token(access_token="production-token", expires_in=3600)
        self.assertIsNone(_service(EFacturaEnvironment.TEST).get_access_token())

    def test_storing_for_one_environment_keeps_the_others_token_active(self) -> None:
        _service(EFacturaEnvironment.TEST).store_token(access_token="test-token", expires_in=3600)
        _service(EFacturaEnvironment.PRODUCTION).store_token(access_token="production-token", expires_in=3600)
        self.assertEqual(_service(EFacturaEnvironment.TEST).get_access_token(), "test-token")
        self.assertTrue(OAuthToken.objects.filter(environment="test", is_active=True).exists())

    def test_a_token_replaced_in_the_database_is_not_served_from_the_cache(self) -> None:
        service = _service(EFacturaEnvironment.PRODUCTION)
        service.store_token(access_token="old-token", expires_in=3600)
        self.assertEqual(service.get_access_token(), "old-token")
        OAuthToken.store_token(cui=CUI, access_token="new-token", expires_in=3600, environment="production")
        self.assertEqual(service.get_access_token(), "new-token")

    def test_a_deactivated_token_is_not_served_from_the_cache(self) -> None:
        service = _service(EFacturaEnvironment.PRODUCTION)
        service.store_token(access_token="old-token", expires_in=3600)
        self.assertEqual(service.get_access_token(), "old-token")
        OAuthToken.objects.filter(cui=CUI).update(is_active=False)
        self.assertIsNone(service.get_access_token())

    def test_the_cache_entry_never_outlives_the_token(self) -> None:
        service = _service(EFacturaEnvironment.PRODUCTION)
        OAuthToken.store_token(cui=CUI, access_token="short-token", expires_in=60, environment="production")
        cache.clear()
        with patch("apps.billing.efactura.token_storage.cache.set", wraps=cache.set) as cache_set:
            self.assertEqual(service.get_access_token(), "short-token")
        timeouts = [call.kwargs.get("timeout", call.args[2] if len(call.args) > 2 else None) for call in cache_set.call_args_list]
        self.assertTrue(timeouts)
        self.assertTrue(all(timeout is not None and timeout <= 60 for timeout in timeouts), timeouts)
