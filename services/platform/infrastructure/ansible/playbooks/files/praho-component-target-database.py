#!/usr/bin/env python3
"""Restore exact private application SQL identities behind an independently held target."""

# ruff: noqa: S608 -- local SQL uses stdin and strictly validated identities, hashes and parsed privilege tokens.

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path
from typing import Any


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native target SQL restoration support is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mysql = _module("praho-component-mysql.py", "component_target_database_sql")
archives = _module("praho-component-archive.py", "component_target_database_credentials")
journals = _module("praho-component-journal.py", "component_target_database_receipts")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _credential_digest(auth: tuple[str, ...]) -> str:
    return _digest([auth[0], auth[1], auth[3]])


class TargetDatabase:
    def __init__(  # noqa: PLR0913 -- exact scope, private evidence, confirmed fresh native namespace and durable operation.
        self,
        manifest: dict[str, Any],
        private_principals: list[dict[str, Any]],
        native_owner_hosts: tuple[str, ...],
        domain_id: str,
        operation_id: str,
        scope_digest: str,
        *,
        state_dir: Path,
        boot_id: str | None = None,
        execute: Any = None,
    ) -> None:
        archives._private_principals(manifest, private_principals)
        self.execute = execute if execute is not None else mysql.native_sql
        self.owner = manifest["source"]["owner"]
        if mysql.USER.fullmatch(self.owner) is None or len(set(native_owner_hosts)) != len(native_owner_hosts):
            raise ValueError("Fresh native target SQL namespace is unqualified")
        if any(mysql.HOST.fullmatch(host) is None for host in native_owner_hosts):
            raise ValueError("Fresh native target SQL host identity is unqualified")
        self.selected = tuple(row["name"] for row in manifest["databases"])
        mysql._names(self.selected, self.selected)
        self.principals = {
            (row["user"], row["host"]): row for database in manifest["databases"] for row in database["principals"]
        }
        self.private = {(row["user"], row["host"]): row for row in private_principals}
        self.grants = {
            key: mysql.selected_schema_grants(row["grants"], *key, self.selected) for key, row in self.private.items()
        }
        self.native_accounts = {(self.owner, host) for host in native_owner_hosts}
        self.accounts = self.native_accounts | self.principals.keys()
        self.users = sorted({self.owner, *(user for user, _host in self.accounts)})
        self.journal = journals.ComponentJournal(
            state_dir,
            domain_id,
            {
                "operation_id": operation_id,
                "scope_digest": _digest([scope_digest, manifest, sorted(self.native_accounts)]),
                "boot_id": boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            },
        )

    def _namespace(self) -> set[tuple[str, str]]:
        mysql._is_mariadb(self.execute)
        scope = ",".join("'" + user + "'" for user in self.users)
        # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — Approved manifest/private principals qualify USER/HOST; native mysql CLI, not SQLAlchemy.
        rows = self.execute(f"SELECT User, Host FROM mysql.user WHERE User IN ({scope}) ORDER BY User, Host")
        if any(
            len(row) != mysql.NATIVE_PRINCIPAL_COLUMNS
            or row[0] not in self.users
            or mysql.HOST.fullmatch(row[1]) is None
            for row in rows
        ):
            raise ValueError("Target SQL namespace is unreadable")
        if len(rows) != len(set(rows)):
            raise ValueError("Target SQL namespace is duplicated")
        return set(rows)

    def _authentication(self, key: tuple[str, str]) -> tuple[str, ...]:
        return mysql._authentication(self.execute, *key, mysql._is_mariadb(self.execute))

    def _state(self) -> dict[str, Any]:
        state = self.journal.read()
        if state is None:
            raise ValueError("Target SQL credentials have no durable ownership receipt")
        self.journal.assert_owned(state)
        if state.get("policy") != "component-target-sql-v1" or state.get("phase") not in {
            "applying",
            "held",
            "activating",
            "active",
            "policy_changing",
            "removing",
            "removed",
        }:
            raise ValueError("Target SQL ownership receipt is unrecognized")
        return state

    def _verify(
        self, state: dict[str, Any], *, active: bool, native_activation: bool = False, check_locks: bool = True
    ) -> None:
        if self._namespace() != self.accounts:
            raise ValueError("Owned target SQL namespace changed")
        for key in sorted(self.accounts):
            auth = self._authentication(key)
            expected_lock = (
                self.principals[key]["locked"]
                if active and state.get("enabled") is True and key in self.principals
                else True
            )
            if auth[2] not in {"true", "false", "1", "0", "Y", "N"} or (
                check_locks and (auth[2] in {"true", "1", "Y"}) != expected_lock
            ):
                raise ValueError("Target SQL lock state changed")
            actual = mysql._grants(self.execute, *key)
            if key in self.principals:
                if mysql.selected_schema_grants(actual, *key, self.selected) != self.grants[key]:
                    raise ValueError("Target SQL selected schema grants changed")
                expected = self.private[key]
                if not (native_activation and key[0] == self.owner) and (auth[0], auth[1], auth[3]) != (
                    expected["plugin"],
                    expected["authentication_string"],
                    expected["alternatives"],
                ):
                    raise ValueError("Target SQL authentication changed")
            else:
                usage = (
                    r"GRANT USAGE ON \*\.\* TO `"
                    + re.escape(key[0])
                    + r"`@`"
                    + re.escape(key[1])
                    + r"`(?: IDENTIFIED BY PASSWORD '[^'\r\n]*')?(?: WITH MAX_USER_CONNECTIONS [0-9]+)?"
                )
                if len(actual) != 1 or re.fullmatch(usage, actual[0]) is None:
                    raise ValueError("Unused native owner acquired unselected SQL grants")
                if not native_activation and _credential_digest(auth) != state["unused_auth"]["@".join(key)]:
                    raise ValueError("Unused native owner SQL authentication changed")

    def _configure(self, key: tuple[str, str], *, create: bool) -> None:
        identity = "'" + key[0] + "'@'" + key[1] + "'"
        if create:
            # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — Identity belongs to validated manifest/native USER/HOST; native mysql DDL.
            self.execute(f"CREATE USER {identity} ACCOUNT LOCK")
        else:
            # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — Identity belongs to validated manifest/native USER/HOST; native mysql DDL.
            self.execute(f"ALTER USER {identity} ACCOUNT LOCK")
        # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — Identity belongs to validated manifest/native USER/HOST; native mysql DDL.
        self.execute(f"REVOKE ALL PRIVILEGES, GRANT OPTION FROM {identity}")
        if key in self.private:
            row = self.private[key]
            if mysql._is_mariadb(self.execute):
                clause = "IDENTIFIED VIA mysql_native_password USING '" + row["authentication_string"] + "'"
            else:
                clause = "IDENTIFIED WITH mysql_native_password AS '" + row["authentication_string"] + "'"
            # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — Private principal parser allows only *[A-F0-9]{40} and fixed plugin syntax.
            self.execute(f"ALTER USER {identity} {clause} ACCOUNT LOCK")
            for privileges, database, grant_option in self.grants[key]:
                # nosemgrep: sqlalchemy-execute-raw-query — selected_schema_grants parses allowed privilege tokens; exact_schema quotes the reviewed schema.
                self.execute(
                    f"GRANT {privileges} ON {mysql.exact_schema(database)}.* TO {identity}"
                    + (" WITH GRANT OPTION" if grant_option else "")
                )

    def _fingerprints(self, accounts: set[tuple[str, str]]) -> list[dict[str, str]]:
        return [
            {
                "user": key[0],
                "host": key[1],
                "authentication_digest": _digest(self._authentication(key)),
                "grants_digest": _digest(mysql._grants(self.execute, *key)),
            }
            for key in sorted(accounts)
        ]

    def apply(self) -> None:
        with self.journal.locked():
            state = self.journal.read()
            if state is not None:
                state = self._state()
                if state["phase"] != "held":
                    raise ValueError("Target SQL restoration was interrupted; inspect before replay or adoption")
                self._verify(state, active=False)
                return
            if self._namespace() != self.native_accounts:
                raise ValueError("Fresh target SQL namespace changed before restoration; never adopt it")
            state = self.journal.create({"policy": "component-target-sql-v1", "phase": "applying"})
            for key in sorted(self.accounts):
                self._configure(key, create=key not in self.native_accounts)
            state["unused_auth"] = {
                "@".join(key): _credential_digest(self._authentication(key))
                for key in sorted(self.accounts - self.principals.keys())
            }
            self._verify(state, active=False)
            state["owned_accounts"] = self._fingerprints(self.accounts)
            state["phase"] = "held"
            self.journal.write(state)

    def verify(self, *, active: bool = False) -> None:
        with self.journal.locked():
            state = self._state()
            if state["phase"] != ("active" if active else "held"):
                raise ValueError("Target SQL restoration is not in the required phase")
            self._verify(state, active=active)

    def activate(self, *, enabled: bool = True) -> None:
        """Called only after native enable, while independent HTTP/cron/Unix holds remain in force."""
        with self.journal.locked():
            if type(enabled) is not bool:
                raise ValueError("Target SQL activation policy must be explicit")
            state = self._state()
            if state["phase"] == "active":
                if state.get("enabled") is not enabled:
                    raise ValueError("Completed target SQL activation policy changed")
                self._verify(state, active=True)
                return
            if state["phase"] != "held":
                raise ValueError("Target SQL activation was interrupted; preserve all ingress holds")
            self._verify(state, active=False, native_activation=True)
            state["phase"] = "activating"
            state["enabled"] = enabled
            self.journal.write(state)
            for key in sorted(self.accounts):
                self._configure(key, create=False)
            state["unused_auth"] = {
                "@".join(key): _credential_digest(self._authentication(key))
                for key in sorted(self.accounts - self.principals.keys())
            }
            for key, principal in sorted(self.principals.items()):
                if enabled and not principal["locked"]:
                    # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — Identity belongs to validated manifest USER/HOST; native mysql DDL.
                    self.execute(f"ALTER USER '{key[0]}'@'{key[1]}' ACCOUNT UNLOCK")
            self._verify(state, active=True)
            state["owned_accounts"] = self._fingerprints(self.accounts)
            state["phase"] = "active"
            self.journal.write(state)

    def reconcile_policy(self, *, enabled: bool) -> None:
        """Converge current lock policy without restoring old credentials, grants or schedules."""
        with self.journal.locked():
            state = self._state()
            if type(enabled) is not bool or state["phase"] not in {"active", "policy_changing"}:
                raise ValueError("Current SQL policy requires a completed, owned target activation")
            if state["phase"] == "policy_changing" and state.get("policy_enabled") is not enabled:
                raise ValueError("Reconcile the uncertain SQL policy before accepting another decision")
            self._verify(state, active=True, check_locks=False)
            state.update(phase="policy_changing", policy_enabled=enabled)
            self.journal.write(state)
            for user, host in sorted(self.accounts):
                principal = self.principals.get((user, host))
                unlock = enabled and principal is not None and not principal["locked"]
                # nosemgrep: sqlalchemy-execute-raw-query — Validated manifest/native USER/HOST and a fixed LOCK/UNLOCK choice; native mysql DDL.
                self.execute(f"ALTER USER '{user}'@'{host}' ACCOUNT " + ("UNLOCK" if unlock else "LOCK"))
            state["enabled"] = enabled
            self._verify(state, active=True)
            state["owned_accounts"] = self._fingerprints(self.accounts)
            state["phase"] = "active"
            self.journal.write(state)

    def retire(self) -> None:
        """Native domain/schema absence precedes exact-account cleanup; completed replays never adopt names."""
        with self.journal.locked():
            state = self._state()
            domain = Path("/etc/webmin/virtual-server/domains") / self.journal.identity["domain_id"]
            if domain.exists() or domain.is_symlink():
                raise ValueError("The native target domain still exists; SQL cleanup is not authorized")
            schemas = sorted({self.owner, *self.selected})
            scope = ",".join("'" + name + "'" for name in schemas)
            # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — Owner matches mysql.USER and selected schemas pass mysql._names; native mysql CLI.
            if self.execute(
                f"SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ({scope}) ORDER BY SCHEMA_NAME"
            ):
                raise ValueError("Native target schemas are not independently absent before SQL cleanup")
            remaining = self._namespace()
            if state["phase"] == "removed":
                if remaining:
                    raise ValueError("The retired SQL namespace has been reused; never delete its new occupant")
                return
            if state["phase"] not in {"held", "active"}:
                raise ValueError("Target SQL cleanup is unprepared or interrupted; inspect before replaying")
            if not remaining <= self.accounts:
                raise ValueError("A foreign target SQL host namespace exists; cleanup needs review")
            expected = {(row["user"], row["host"]): row for row in state.get("owned_accounts", [])}
            if expected.keys() != self.accounts or any(
                row != expected[(row["user"], row["host"])] for row in self._fingerprints(remaining)
            ):
                raise ValueError("The remaining SQL account identity changed; never delete it by username alone")
            state["phase"] = "removing"
            self.journal.write(state)
            for user, host in sorted(remaining):
                # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — _namespace validates Host and owned account fingerprints bind the exact validated username.
                self.execute(f"DROP USER '{user}'@'{host}'")
            if self._namespace():
                raise ValueError("Target SQL cleanup did not prove exact account absence")
            state["phase"] = "removed"
            self.journal.write(state)
