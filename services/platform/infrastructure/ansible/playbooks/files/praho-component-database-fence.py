#!/usr/bin/env python3
"""Durably fence only qualified website SQL principals; retained services stay independent."""

# ruff: noqa: S608 -- Literal native SQL with strictly validated user/host/numeric identities, never a shell.

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType
from typing import Any

MAX_PRINCIPALS = 1000
MAX_CONNECTION_ID = 2**31 - 1
MAX_SESSION_PASSES = 3


def _module(filename: str, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native component database qualification is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mysql = _module("praho-component-mysql.py", "component_sql_qualification")
journals = _module("praho-component-journal.py", "component_database_receipts")


def _authority(databases: list[dict[str, Any]], *, include_locks: bool) -> str:
    result = []
    for database in databases:
        principals = [
            {key: value for key, value in principal.items() if include_locks or key != "locked"}
            for principal in database["principals"]
        ]
        result.append({**{key: value for key, value in database.items() if key != "bytes"}, "principals": principals})
    return json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False)


class DatabaseFence:
    def __init__(  # noqa: PLR0913 -- independent reviewed scope, durable identity and native SQL boundary
        self,
        domain_id: str,
        operation_id: str,
        reviewed: list[dict[str, Any]],
        native_owned: tuple[str, ...],
        *,
        state_dir: Path = Path("/var/lib/praho/component-database-fences"),
        boot_id: str | None = None,
        execute: Any = None,
    ) -> None:
        self.execute = execute if execute is not None else mysql.native_sql
        self.reviewed = json.loads(json.dumps(reviewed, allow_nan=False))
        if not isinstance(self.reviewed, list) or len(self.reviewed) > mysql.MAX_DATABASES:
            raise ValueError("Reviewed database scope is unrecognized")
        self.selected = tuple(database["name"] for database in self.reviewed)
        mysql._names(self.selected, native_owned)
        self.native_owned = native_owned
        self.principals: dict[tuple[str, str], dict[str, Any]] = {}
        for database in self.reviewed:
            if database.get("isolated") is not True or not database.get("principals"):
                raise ValueError("Only isolated, qualified database principals may be fenced")
            for principal in database["principals"]:
                if (
                    mysql.USER.fullmatch(principal["user"]) is None
                    or mysql.HOST.fullmatch(principal["host"]) is None
                    or type(principal["locked"]) is not bool
                    or any(
                        re.fullmatch(r"[0-9a-f]{64}", principal[key]) is None
                        for key in ("auth_digest", "grants_digest")
                    )
                ):
                    raise ValueError("Reviewed database principal is unrecognized")
                key = principal["user"], principal["host"]
                if key in self.principals and self.principals[key] != principal:
                    raise ValueError("Reviewed database principal has conflicting authority")
                self.principals[key] = principal
        if len(self.principals) > MAX_PRINCIPALS:
            raise ValueError("Reviewed database principal count exceeds its bound")
        self.authority = _authority(self.reviewed, include_locks=False)
        digest = hashlib.sha256(_authority(self.reviewed, include_locks=True).encode()).hexdigest()
        self.journal = journals.ComponentJournal(
            state_dir,
            domain_id,
            {
                "operation_id": operation_id,
                "scope_digest": digest,
                "boot_id": boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            },
        )

    def _current(self) -> dict[tuple[str, str], dict[str, Any]]:
        facts = mysql.inspect_databases(self.selected, self.native_owned, execute=self.execute)
        if facts["preparation"] or _authority(facts["databases"], include_locks=False) != self.authority:
            raise ValueError(
                "Native database identities, grants or retained dependencies changed; inspect before proceeding"
            )
        return {
            (principal["user"], principal["host"]): principal
            for database in facts["databases"]
            for principal in database["principals"]
        }

    def _sessions(self) -> list[tuple[int, str]]:
        if not self.principals:
            return []
        users = sorted({user for user, _host in self.principals})
        scope = ",".join("'" + user + "'" for user in users)
        rows = self.execute(
            "SELECT ID, USER FROM information_schema.PROCESSLIST " + f"WHERE USER IN ({scope}) ORDER BY ID"
        )
        if len(rows) > mysql.MAX_SQL_ROWS or any(
            len(row) != mysql.NATIVE_PRINCIPAL_COLUMNS
            or not row[0].isdecimal()
            or not 0 < int(row[0]) <= MAX_CONNECTION_ID
            or row[1] not in users
            for row in rows
        ):
            raise ValueError("Native database session inventory is incomplete or requires preparation")
        if len({row[0] for row in rows}) != len(rows):
            raise ValueError("Native database session identity is duplicated")
        return [(int(identifier), user) for identifier, user in rows]

    def _close_sessions(self) -> None:
        for _attempt in range(MAX_SESSION_PASSES):
            self._current()  # Including every host account: processlist does not identify the grant Host.
            sessions = self._sessions()
            if not sessions:
                return
            for identifier, user in sessions:
                current = self.execute(f"SELECT USER FROM information_schema.PROCESSLIST WHERE ID = {identifier}")
                if not current:
                    continue
                if current != [(user,)]:
                    raise ValueError("A database connection changed identity; refusing to kill an unrelated session")
                self.execute(f"KILL CONNECTION {identifier}")
        if self._sessions():
            raise ValueError("Selected website database sessions have not independently closed")

    def _held(self) -> None:
        if any(not principal["locked"] for principal in self._current().values()) or self._sessions():
            raise ValueError("Selected database principals and existing sessions are not fully fenced")

    def _owned_receipt(self, state: dict[str, Any]) -> None:
        self.journal.assert_owned(state)
        if state.get("phase") not in {"applying", "held", "released"} or not isinstance(state.get("principals"), list):
            raise ValueError("Native database ownership receipt is unrecognized")
        seen: set[tuple[str, str]] = set()
        for principal in state["principals"]:
            if not isinstance(principal, dict) or set(principal) != {"user", "host", "phase"}:
                raise ValueError("Native database principal receipt is incomplete")
            key = principal["user"], principal["host"]
            expected = self.principals.get(key)
            if expected is None or key in seen:
                raise ValueError("Native database receipt includes an unexpected or duplicated principal")
            allowed = (
                {"original_locked"}
                if expected["locked"]
                else {"unlocked", "lock_intent", "held", "unlock_intent", "released"}
            )
            if principal["phase"] not in allowed:
                raise ValueError("Native database receipt disagrees with the original principal lock")
            if state["phase"] in {"held", "released"} and principal["phase"] not in {state["phase"], "original_locked"}:
                raise ValueError("Native database receipt has incomplete principal outcomes")
            seen.add(key)
        if seen != self.principals.keys():
            raise ValueError("Native database receipt is missing a selected principal")

    def _lock(self, state: dict[str, Any], principal: dict[str, Any]) -> None:
        key = principal["user"], principal["host"]
        locked = self._current()[key]["locked"]
        if principal["phase"] in {"held", "original_locked"}:
            if not locked:
                raise ValueError("An owned native database lock was unexpectedly removed")
            return
        if principal["phase"] not in {"unlocked", "lock_intent"}:
            raise ValueError("Database lock receipt is unrecognized")
        if locked:
            raise ValueError("Native lock has no confirmed ownership receipt; operator inspection is required")
        principal["phase"] = "lock_intent"
        self.journal.write(state)
        self.execute(f"ALTER USER '{key[0]}'@'{key[1]}' ACCOUNT LOCK")
        if not self._current()[key]["locked"]:
            raise ValueError("Native database principal did not become locked")
        principal["phase"] = "held"
        self.journal.write(state)

    def apply(self) -> None:
        with self.journal.locked():
            state = self.journal.read()
            if state is not None and state.get("operation_id") != self.journal.identity["operation_id"]:
                if state.get("phase") != "released":
                    raise ValueError("Another operation still owns this native database fence")
                state = None
            if state is None:
                current = self._current()
                if any(current[key]["locked"] != principal["locked"] for key, principal in self.principals.items()):
                    raise ValueError("Native principal lock state changed after inspection")
                state = self.journal.create(
                    {
                        "phase": "applying",
                        "principals": [
                            {
                                "user": user,
                                "host": host,
                                "phase": "original_locked" if principal["locked"] else "unlocked",
                            }
                            for (user, host), principal in sorted(self.principals.items())
                        ],
                    }
                )
            self._owned_receipt(state)
            if state["phase"] == "held":
                self._held()
                return
            if state["phase"] != "applying":
                raise ValueError("This database fence cannot be automatically reapplied after compensation")
            for principal in state["principals"]:
                self._lock(state, principal)
            self._close_sessions()
            self._held()
            state["phase"] = "held"
            self.journal.write(state)

    def verify(self) -> None:
        with self.journal.locked():
            state = self.journal.read()
            if state is None:
                raise ValueError("Native database fence has no durable receipt")
            self._owned_receipt(state)
            if state["phase"] != "held":
                raise ValueError("Native database fence is not completely held")
            self._held()

    def release(self) -> None:
        with self.journal.locked():
            state = self.journal.read()
            if state is None:
                raise ValueError("Native database fence has no durable ownership receipt")
            self._owned_receipt(state)
            if state["phase"] == "released":
                return
            for principal in state["principals"]:
                key = principal["user"], principal["host"]
                locked = self._current()[key]["locked"]
                phase = principal["phase"]
                if phase == "original_locked":
                    if not locked:
                        raise ValueError("The original native lock state changed; inspect before compensation")
                    continue
                if phase in {"lock_intent", "unlock_intent", "unlocked", "released"}:
                    if locked:
                        raise ValueError(
                            "Native lock has an uncertain ownership receipt; operator inspection is required"
                        )
                elif phase == "held":
                    if locked:
                        principal["phase"] = "unlock_intent"
                        self.journal.write(state)
                        self.execute(f"ALTER USER '{key[0]}'@'{key[1]}' ACCOUNT UNLOCK")
                        if self._current()[key]["locked"]:
                            raise ValueError("Native database principal unlock is unconfirmed")
                else:
                    raise ValueError("Native database ownership receipt is unrecognized")
                principal["phase"] = "released"
                self.journal.write(state)
            state["phase"] = "released"
            self.journal.write(state)
