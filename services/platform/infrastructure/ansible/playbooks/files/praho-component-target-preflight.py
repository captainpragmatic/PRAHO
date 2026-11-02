#!/usr/bin/env python3
"""Prove target identities absent before native creation can delete or reuse SQL accounts."""

# ruff: noqa: S608 -- Local native CLI accepts SQL on stdin; every interpolated identity is strictly validated.

from __future__ import annotations

import grp
import importlib.util
import pwd
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

RESERVED_USERS = frozenset({"root", "mysql", "mariadb.sys", "mysql.sys", "mysql.session", "debian-sys-maint"})


def _mysql() -> Any:
    spec = importlib.util.spec_from_file_location(
        "component_target_preflight_sql", Path(__file__).with_name("praho-component-mysql.py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("Native target SQL identity inspection is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mysql = _mysql()


def preflight_target(
    manifest: dict[str, Any],
    *,
    execute: Any = mysql.native_sql,
    lookup_user: Callable[[str], object] = pwd.getpwnam,
    lookup_group: Callable[[str], object] = grp.getgrnam,
) -> dict[str, Any]:
    """Read only, including every grant Host for all selected usernames and the native owner.

    The qualified default native template also creates its owner's default database;
    its absence must be proven even when the application selects a different schema.
    """
    owner = manifest["source"]["owner"]
    if not isinstance(owner, str) or re.fullmatch(r"[A-Za-z0-9_]{3,32}", owner) is None or owner in RESERVED_USERS:
        raise ValueError("Prepare a qualified non-system native owner before creating the target")
    for lookup in (lookup_user, lookup_group):
        try:
            lookup(owner)
        except KeyError:
            continue
        raise ValueError("The destination Unix user or group already exists; never adopt it through a native restore")
    databases = tuple(row["name"] for row in manifest["databases"])
    mysql._names(databases, databases)
    users = sorted({owner, *(principal["user"] for row in manifest["databases"] for principal in row["principals"])})
    if any(mysql.USER.fullmatch(user) is None or user in RESERVED_USERS for user in users):
        raise ValueError("Selected target SQL accounts include an unsupported or system identity")
    mysql._is_mariadb(execute)  # Requires complete direct DBA visibility, never a partial inventory.
    selected_users = ",".join("'" + user + "'" for user in users)
    accounts = execute(f"SELECT User, Host FROM mysql.user WHERE User IN ({selected_users}) ORDER BY User, Host")
    if accounts:
        raise ValueError(
            "An application or native-owner SQL username exists on the target; all host accounts require review"
        )
    schemas = sorted({owner, *databases})
    selected_schemas = ",".join("'" + name + "'" for name in schemas)
    if execute(
        "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA "
        + f"WHERE SCHEMA_NAME IN ({selected_schemas}) ORDER BY SCHEMA_NAME"
    ):
        raise ValueError("A selected or native-default schema already exists on the target; never overwrite it")
    return {"owner": owner, "sql_users": users, "schemas": schemas}
