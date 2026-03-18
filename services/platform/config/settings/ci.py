"""
CI settings for PRAHO Platform — production-parity testing.

Inherits test optimizations (fast hasher, minimal middleware, etc.)
but uses PostgreSQL + DatabaseCache to match production.

Used by: platform.yml (master), full-test.yml, nightly.yml
"""

from __future__ import annotations

import os

from .test import *  # noqa: F403

# ===============================================================================
# DATABASE — PostgreSQL (production parity)
# ===============================================================================
# Overrides test.py's SQLite in-memory with real PostgreSQL.
# Performance flags disable fsync/WAL for speed — data durability is irrelevant in CI.

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "test_db"),
        "USER": os.environ.get("DB_USER", "test"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "test"),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
        "OPTIONS": {
            # synchronous_commit=off is session-level (safe to set per-connection).
            # fsync/full_page_writes are server-level — set via POSTGRES_INITDB_ARGS in CI.
            "options": "-c synchronous_commit=off",
        },
        "TEST": {
            "NAME": "test_db",
            "SERIALIZE": False,
        },
    }
}

# ===============================================================================
# RE-ENABLE MIGRATIONS
# ===============================================================================
# test.py sets MIGRATION_MODULES to DisableMigrations for SQLite speed.
# CI needs real migrations to validate:
#   - Partial UniqueConstraints (condition=)
#   - GIN/BRIN indexes
#   - Table partitioning
#   - PostgreSQL-specific RunSQL in migrations
if "MIGRATION_MODULES" in dir():
    del MIGRATION_MODULES  # noqa: F821

# ===============================================================================
# CACHE — DatabaseCache (production parity)
# ===============================================================================
# Production uses DatabaseCache; test.py uses DummyCache.
# CI validates cache serialization, rate limiting, and deduplication logic.

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "django_cache_table",
        "KEY_PREFIX": "pragmatichost_ci",
        "OPTIONS": {
            "MAX_ENTRIES": 1000,
        },
    }
}
