"""Portal sessions that merge concurrent writes instead of overwriting them (ADR-0055).

Django's database backend saves the whole session dict. Two requests of one customer that load
the same session and both save it race: the later save writes back the earlier one's stale view,
undoing its changes (a cart edit, a company switch). Threaded workers make that likely.

This store remembers the session exactly as it loaded it (the stored text and a deep copy of the
decoded dict). On save it applies only what this request changed onto the latest stored row, with
a compare-and-swap on the stored text: ``UPDATE ... WHERE session_key = ? AND session_data = ?``.
Without contention that is the only query. When another request saved in between, the latest row
is re-read and the same changes are applied to it again.

Rules:

- A key, or a key group below, is last-writer-wins when two requests both change it. Groups move
  together, so a mixed company id/name/role can never be stored. A list or dict is one value,
  except the record maps below, which merge entry by entry.
- A row that is gone (logout, flush, revocation) is never recreated: the save raises UpdateError,
  which the session middleware turns into SessionInterrupted. Only a confirmed missing row does;
  a database error propagates as itself.
- Rotating the key of a session that was authenticated when loaded deletes exactly the row it
  read first. If a concurrent logout deleted it, rotation is refused rather than minting a new
  authenticated session.

The class keeps Django's name, ``SessionStore``: Django imports ``engine.SessionStore``, and the
signing salt is derived from the class name, so existing sessions keep decoding.
"""

from __future__ import annotations

import copy
import logging
import random
import time
from typing import Any

from asgiref.sync import sync_to_async
from django.contrib.sessions.backends import db
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.db import router
from django.utils import timezone

logger = logging.getLogger(__name__)

# Keys that are only meaningful together. If a request changed any of them, the whole group is
# stored as that request saw it.
KEY_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({"selected_customer_id", "selected_customer_name", "selected_customer_role", "active_customer_id"}),
    frozenset(
        {"validated_at", "next_validate_at", "membership_hash", "user_memberships", "user_memberships_fetched_at"}
    ),
    frozenset({"user_id", "email", "customer_id", "session_auth_hash", "authenticated_at", "session_created_at"}),
    frozenset({"account_health_data", "account_health_fetched_at"}),
)

# Dict-valued keys holding independent records (one per purchase in progress). Two tabs adding
# different records must both keep theirs, so these merge per record.
RECORD_MAPS = frozenset({"order_checkout_attempts", "gift_purchase_forms"})

MAX_MERGE_ATTEMPTS = 25
# Between attempts, a short random wait growing with the attempt, so requests that collided do not
# collide again in lockstep. The worst case is well under a second.
MERGE_BACKOFF_SECONDS = 0.002

_MISSING = object()

# One change to apply onto the latest stored dict: (operation, key, entry, value).
Change = tuple[str, str, Any, Any]


def _record_changes(key: str, before: dict[str, Any], after: dict[str, Any]) -> list[Change]:
    """Per-record changes to a record map, so concurrent requests keep each other's records."""
    changes: list[Change] = []
    for entry in after.keys() | before.keys():
        if entry not in after:
            changes.append(("delete_entry", key, entry, None))
        elif before.get(entry, _MISSING) != after[entry]:
            changes.append(("set_entry", key, entry, copy.deepcopy(after[entry])))
    return changes


def _changes(baseline: dict[str, Any], mine: dict[str, Any]) -> list[Change]:
    """What this request changed compared with what it loaded."""
    changes: list[Change] = []
    touched: set[str] = set()
    for key in mine.keys() | baseline.keys():
        before, after = baseline.get(key, _MISSING), mine.get(key, _MISSING)
        if before == after:
            continue
        touched.add(key)
        if key in RECORD_MAPS and isinstance(before, dict) and isinstance(after, dict):
            changes.extend(_record_changes(key, before, after))
        elif after is _MISSING:
            changes.append(("delete", key, None, None))
        else:
            changes.append(("set", key, None, copy.deepcopy(after)))
    for group in KEY_GROUPS:
        if not group & touched:
            continue
        for key in group - touched:  # the group's other keys, as this request saw them
            if key in mine:
                changes.append(("set", key, None, copy.deepcopy(mine[key])))
            else:
                changes.append(("delete", key, None, None))
    return changes


def _apply(changes: list[Change], latest: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(latest)
    for operation, key, entry, value in changes:
        if operation == "set":
            merged[key] = value
        elif operation == "delete":
            merged.pop(key, None)
        else:
            records = merged.get(key)
            records = dict(records) if isinstance(records, dict) else {}
            if operation == "set_entry":
                records[entry] = value
            else:
                records.pop(entry, None)
            merged[key] = records
    return merged


def _back_off(attempt: int) -> None:
    time.sleep(random.uniform(0, MERGE_BACKOFF_SECONDS * (attempt + 1)))  # noqa: S311  # jitter, not security


class SessionStore(db.SessionStore):
    """Database sessions whose saves merge with concurrent saves; see the module docstring."""

    def __init__(self, session_key: str | None = None) -> None:
        super().__init__(session_key)
        self._baseline: dict[str, Any] | None = None  # the dict as loaded or last written
        self._baseline_text: str | None = None  # its stored text, the compare-and-swap token
        self._pending: tuple[dict[str, Any], str] | None = None

    # ---- loading -------------------------------------------------------------------------------

    def load(self) -> dict[str, Any]:
        stored = self.model.objects.filter(session_key=self.session_key, expire_date__gt=timezone.now()).first()
        if stored is None:
            self._session_key = None  # as Django does for a missing or expired session
            self._forget_baseline()
            return {}
        data: dict[str, Any] = self.decode(stored.session_data)
        self._baseline, self._baseline_text = copy.deepcopy(data), stored.session_data
        return data

    async def aload(self) -> dict[str, Any]:
        return await sync_to_async(self.load)()

    def _forget_baseline(self) -> None:
        self._baseline = self._baseline_text = None

    def _publish(self, data: dict[str, Any], text: str) -> None:
        """Only an acknowledged write becomes the new baseline."""
        self._baseline, self._baseline_text = copy.deepcopy(data), text

    # ---- writing -------------------------------------------------------------------------------

    def create_model_instance(self, data: dict[str, Any]) -> Any:
        instance = super().create_model_instance(data)
        self._pending = (data, instance.session_data)  # published only once the insert succeeds
        return instance

    def save(self, must_create: bool = False) -> None:
        if must_create or self.session_key is None:
            super().save(must_create=must_create)  # an insert; Django's own path
            if self._pending is not None:
                self._publish(*self._pending)
                self._pending = None
            return
        self._merge_and_save()

    async def asave(self, must_create: bool = False) -> None:
        await sync_to_async(self.save)(must_create)

    def _stored_text(self, using: str) -> str | None:
        text: str | None = (
            self.model.objects.using(using)
            .filter(session_key=self.session_key)
            .values_list("session_data", flat=True)
            .first()
        )
        return text

    def _merge_and_save(self) -> None:
        mine = dict(self.items())  # loads the session if this request never read it
        using = router.db_for_write(self.model)
        # Without a baseline (cleared before it was ever loaded) this request's view replaces the
        # stored one, as Django's own save would; it still never inserts.
        changes = _changes(self._baseline, mine) if self._baseline is not None else None
        expected_text = self._baseline_text
        latest = copy.deepcopy(self._baseline) if self._baseline is not None else None
        for _attempt in range(MAX_MERGE_ATTEMPTS):
            if expected_text is None or latest is None:
                expected_text = self._stored_text(using)
                if expected_text is None:
                    raise UpdateError  # the row is gone; never recreate it
                latest = self.decode(expected_text)
            merged = _apply(changes, latest) if changes is not None else copy.deepcopy(mine)
            text = self.encode(merged)
            expire_date = self.get_expiry_date(expiry=merged.get("_session_expiry"))
            updated = (
                self.model.objects.using(using)
                .filter(session_key=self.session_key, session_data=expected_text)
                .update(session_data=text, expire_date=expire_date)
            )
            if updated:
                self._session_cache = merged
                self._publish(merged, text)
                return
            expected_text = latest = None  # another request saved first: merge onto its row
            _back_off(_attempt)
        logger.warning("⚠️ [Session] Gave up merging a session save after %d attempts", MAX_MERGE_ATTEMPTS)
        raise UpdateError

    # ---- rotation and removal ------------------------------------------------------------------

    def cycle_key(self) -> None:
        old_key, baseline = self.session_key, self._baseline
        if old_key is None or baseline is None or baseline.get("user_id") is None:
            super().cycle_key()  # not authenticated when loaded: rotate exactly as Django does
            return
        mine = dict(self.items())
        changes = _changes(baseline, mine)
        expected_text: str | None = self._baseline_text
        latest: dict[str, Any] | None = copy.deepcopy(baseline)
        merged: dict[str, Any] = {}
        using = router.db_for_write(self.model)
        for _attempt in range(MAX_MERGE_ATTEMPTS):
            if expected_text is None or latest is None:
                expected_text = self._stored_text(using)
                if expected_text is None:
                    # A concurrent logout or revocation deleted the session: never mint a new one.
                    raise SessionInterrupted("The session ended while its key was being rotated.")
                latest = self.decode(expected_text)
            merged = _apply(changes, latest)
            deleted, _ = (
                self.model.objects.using(using).filter(session_key=old_key, session_data=expected_text).delete()
            )
            if deleted:
                break
            expected_text = latest = None
            _back_off(_attempt)
        else:
            raise SessionInterrupted("The session kept changing while its key was being rotated.")
        self._session_cache = merged
        self._forget_baseline()
        self.create()  # inserts the merged data under a new key, and publishes it as the baseline
        self._session_cache = merged

    async def acycle_key(self) -> None:
        await sync_to_async(self.cycle_key)()

    def flush(self) -> None:
        super().flush()
        self._forget_baseline()

    async def aflush(self) -> None:
        await sync_to_async(self.flush)()
