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
        # Connect to the admin DB; Django's test runner creates test_<NAME> automatically.
        "NAME": os.environ.get("DB_NAME", "postgres"),
        "USER": os.environ.get("DB_USER", "test"),
        "PASSWORD": os.environ.get("DB_PASSWORD", "test"),
        "HOST": os.environ.get("DB_HOST", "localhost"),
        "PORT": os.environ.get("DB_PORT", "5432"),
        "OPTIONS": {
            # synchronous_commit=off is session-level (safe to set per-connection).
            # fsync/full_page_writes are server-level — set via POSTGRES_INITDB_ARGS in CI.
            "options": "-c synchronous_commit=off",
        },
        "CONN_MAX_AGE": 0,  # Close connection after each request (CI — no pooling needed)
        "TEST": {
            "SERIALIZE": False,
        },
    }
}

# ===============================================================================
# RE-ENABLE MIGRATIONS
# ===============================================================================
# test.py uses DisableMigrations (syncdb from models) for SQLite speed.
# PostgreSQL CI needs real migrations to create named indexes, partial
# constraints, and RunSQL operations that syncdb skips.
if "MIGRATION_MODULES" in dir():
    del MIGRATION_MODULES  # noqa: F821

# ===============================================================================
# CACHE — LocMemCache (functional cache, no table required)
# ===============================================================================
# Production uses DatabaseCache; test.py uses DummyCache (no-op).
# CI uses LocMemCache to validate cache serialization, rate limiting, and
# deduplication logic without requiring createcachetable (which can't run
# inside Django's test runner before tests start).

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "ci-cache",
        "KEY_PREFIX": "pragmatichost_ci",
        "OPTIONS": {
            "MAX_ENTRIES": 1000,
        },
    }
}
