"""Atomic counters and expiring claims shared by both services.

Counter keys and claim keys must use separate namespaces. A NULL value denotes
a counter. Claims use count=1 with the owner's token while pending, and count=0
with the result after completion. Completed claims remain reserved until expiry.
All operations use the write database, including reads, to avoid replica lag.
Operations participate in the caller's transaction and roll back with it.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
from collections.abc import Iterable
from secrets import randbelow
from typing import overload

from django.apps import AppConfig
from django.core.checks import Error, Tags, register
from django.db import connections, models, router
from django.db.backends.base.base import BaseDatabaseWrapper
from django.utils.translation import gettext as _

MAX_KEY_LENGTH = 200
MAX_VALUE_LENGTH = 255
CULL_CHANCE = 200
CULL_BATCH_SIZE = 500
# An expired row is already invisible to every read; the grace only keeps a delete from racing a
# concurrent upsert of the same key, so it stays short and bounds how long dead keys occupy the table.
CULL_GRACE_SECONDS = 60
MIN_SQLITE_VERSION = (3, 35, 0)


class Counter(models.Model):
    """Infrastructure counters and token-owned claims; never business records."""

    key = models.CharField(max_length=MAX_KEY_LENGTH, unique=True)
    count = models.PositiveIntegerField()
    expires_at = models.BigIntegerField(db_index=True)
    value = models.CharField(max_length=MAX_VALUE_LENGTH, null=True)  # noqa: DJ001 -- NULL distinguishes counters.

    class Meta:
        db_table = "common_counters"


def _key(key: str) -> str:
    if len(key) > MAX_KEY_LENGTH or not key.isprintable():
        return "h:" + hashlib.sha256(key.encode("utf-8", errors="surrogatepass")).hexdigest()
    return key


def _write_connection() -> BaseDatabaseWrapper:
    return connections[router.db_for_write(Counter)]


def _cull(connection: BaseDatabaseWrapper, now: int) -> int:
    """Delete at most one batch, preserving expired rows within the grace period; return the rows removed."""
    with connection.cursor() as cursor:
        cursor.execute(
            "DELETE FROM common_counters WHERE id IN ("
            "SELECT id FROM common_counters WHERE expires_at < %s "
            "ORDER BY expires_at, id LIMIT %s) AND expires_at < %s",
            [now - CULL_GRACE_SECONDS, CULL_BATCH_SIZE, now - CULL_GRACE_SECONDS],
        )
        return int(cursor.rowcount)


def cull_expired(*, batches: int = 1) -> int:
    """Sweep expired rows past the grace period in bounded batches; return the rows removed.

    Writes already cull one batch at random, which keeps a busy table small; this
    scheduled sweep covers a table that has gone quiet with expired rows left behind.
    """
    connection = _write_connection()
    now = int(time.time())
    deleted = 0
    for _batch in range(max(1, batches)):
        removed = _cull(connection, now)
        deleted += removed
        if removed < CULL_BATCH_SIZE:
            break
    return deleted


def increment(key: str, window_seconds: int, *, delta: int = 1) -> int:
    """Return this hit's count, preserving the first hit's expiry until reset."""
    now = int(time.time())
    connection = _write_connection()
    if randbelow(CULL_CHANCE) == 0:
        _cull(connection, now)
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO common_counters (key, count, expires_at) VALUES (%s, %s, %s) "
            "ON CONFLICT (key) DO UPDATE SET "
            "count = CASE WHEN common_counters.expires_at > %s "
            "THEN common_counters.count + excluded.count ELSE excluded.count END, "
            "expires_at = CASE WHEN common_counters.expires_at > %s "
            "THEN common_counters.expires_at ELSE excluded.expires_at END "
            "RETURNING count",
            [_key(key), delta, now + window_seconds, now, now],
        )
        return int(cursor.fetchone()[0])


def peek(key: str) -> int:
    """Return zero for a missing or expired counter."""
    with _write_connection().cursor() as cursor:
        cursor.execute(
            "SELECT count FROM common_counters WHERE key = %s AND expires_at > %s",
            [_key(key), int(time.time())],
        )
        row = cursor.fetchone()
    return int(row[0]) if row is not None else 0


def reset(key: str) -> None:
    """Delete a counter or explicitly invalidate a claim."""
    with _write_connection().cursor() as cursor:
        cursor.execute("DELETE FROM common_counters WHERE key = %s", [_key(key)])


@overload
def release(key: str) -> None: ...


@overload
def release(key: str, token: str) -> bool: ...


def release(key: str, token: str | None = None) -> bool | None:
    """Decrement a counter, or delete a live pending claim owned by token.

    Tokenless release cannot change claims. Completed results are retained until
    expiry or explicit reset; they cannot be released as failed attempts.
    """
    with _write_connection().cursor() as cursor:
        if token is not None:
            cursor.execute(
                "DELETE FROM common_counters WHERE key = %s AND value = %s AND count = 1 AND expires_at > %s",
                [_key(key), token, int(time.time())],
            )
            return bool(cursor.rowcount == 1)
        cursor.execute(
            "UPDATE common_counters SET count = CASE WHEN count > 0 THEN count - 1 ELSE 0 END "
            "WHERE key = %s AND value IS NULL AND expires_at > %s",
            [_key(key), int(time.time())],
        )
    return None


def claim(key: str, ttl_seconds: int, token: str) -> bool:
    """Acquire a fresh or expired claim without changing a live owner's lease."""
    if len(token) > MAX_VALUE_LENGTH:
        raise ValueError(_("Claim tokens must contain at most 255 characters."))
    now = int(time.time())
    connection = _write_connection()
    # Claims cull too: request nonces claim a row per request, so expired rows must not depend
    # on rate-limit increments (which can be switched off) to be cleared.
    if randbelow(CULL_CHANCE) == 0:
        _cull(connection, now)
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO common_counters (key, count, expires_at, value) VALUES (%s, 1, %s, %s) "
            "ON CONFLICT (key) DO UPDATE SET "
            "count = excluded.count, expires_at = excluded.expires_at, value = excluded.value "
            "WHERE common_counters.expires_at <= %s RETURNING count",
            [_key(key), now + ttl_seconds, token, now],
        )
        return cursor.fetchone() is not None


def complete(key: str, token: str, result: str, *, retain_seconds: int = 0) -> bool:
    """Publish a result once, only for the owner of a live pending claim.

    The result stays readable until the claim's expiry, extended to at least
    retain_seconds from now; retention never shortens the lease it replaces.
    """
    if len(result) > MAX_VALUE_LENGTH:
        raise ValueError(_("Claim results must contain at most 255 characters."))
    now = int(time.time())
    with _write_connection().cursor() as cursor:
        cursor.execute(
            "UPDATE common_counters SET count = 0, value = %s, "
            "expires_at = CASE WHEN expires_at > %s THEN expires_at ELSE %s END "
            "WHERE key = %s AND value = %s AND count = 1 AND expires_at > %s",
            [result, now + retain_seconds, now + retain_seconds, _key(key), token, now],
        )
        return bool(cursor.rowcount == 1)


def lookup(key: str) -> str | None:
    """Return a completed result, or None for missing, expired or pending claims."""
    with _write_connection().cursor() as cursor:
        cursor.execute(
            "SELECT value FROM common_counters WHERE key = %s AND count = 0 AND value IS NOT NULL AND expires_at > %s",
            [_key(key), int(time.time())],
        )
        row = cursor.fetchone()
    return str(row[0]) if row is not None else None


@register(Tags.database)
def check_counter_database(app_configs: Iterable[AppConfig] | None, **kwargs: object) -> list[Error]:
    """Require SQLite RETURNING support without querying unmigrated tables."""
    connection = _write_connection()
    if connection.vendor == "sqlite" and sqlite3.dbapi2.sqlite_version_info < MIN_SQLITE_VERSION:
        return [
            Error(
                _("The counter store requires SQLite 3.35 or newer."),
                hint=_("Upgrade the SQLite library used by Python."),
                obj=connection.alias,
                id="common.E001",
            )
        ]
    return []
