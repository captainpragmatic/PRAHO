"""Production settings must not silently select an unsupported Redis cache (#558).

ADR-0020 runs every cache and counter on the database store and ships no Redis client.
The old ``REDIS_URL`` branch built a Django ``RedisCache`` with django-redis-only OPTIONS,
so setting the variable produced a configuration that could not work. The variable is
now refused loudly at import instead of being half-honoured.
"""

from __future__ import annotations

import importlib
import os
import sys
from types import ModuleType
from unittest.mock import patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from tests.settings.test_logging_configuration import _PROD_ENV

_PROD = "config.settings.prod"


def _import_prod(redis_url: str | None) -> ModuleType:
    """Execute prod settings afresh under a production-like environment."""
    previous = sys.modules.pop(_PROD, None)
    try:
        with (
            patch.dict(os.environ, _PROD_ENV),
            patch("config.settings.base.validate_production_secret_key"),
        ):
            os.environ.pop("REDIS_URL", None)
            if redis_url is not None:
                os.environ["REDIS_URL"] = redis_url
            return importlib.import_module(_PROD)
    finally:
        sys.modules.pop(_PROD, None)
        if previous is not None:
            sys.modules[_PROD] = previous


class ProdCacheBackendTests(SimpleTestCase):
    def test_redis_url_is_refused(self) -> None:
        with self.assertRaisesMessage(ImproperlyConfigured, "REDIS_URL"):
            _import_prod("redis://cache:6379/0")

    def test_empty_redis_url_counts_as_unset(self) -> None:
        # Compose ``${REDIS_URL:-}`` forwards an empty string; that must not abort startup.
        prod = _import_prod("")
        self.assertEqual(prod.CACHES["default"]["BACKEND"], "django.core.cache.backends.db.DatabaseCache")

    def test_database_cache_with_production_tuning(self) -> None:
        prod = _import_prod(None)
        self.assertEqual(set(prod.CACHES), {"default"})
        default = prod.CACHES["default"]
        self.assertEqual(default["BACKEND"], "django.core.cache.backends.db.DatabaseCache")
        self.assertEqual(default["OPTIONS"], {"MAX_ENTRIES": 50000, "CULL_FREQUENCY": 4})
        self.assertEqual(default["TIMEOUT"], 3600)
        self.assertFalse(hasattr(prod, "SESSION_CACHE_ALIAS"))
