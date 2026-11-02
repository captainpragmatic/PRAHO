#!/usr/bin/env python3
"""Read exact private component restoration evidence before any target callback."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import tarfile
from pathlib import Path
from typing import Any
from uuid import UUID

PRIVATE_MEMBER_MODE = 0o600


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Component target archive inspection is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


archives = _module("praho-component-archive.py", "component_target_archive_format")
source = _module("praho-component-native-source.py", "component_target_source_authority")
files = _module("praho-component-file-restore.py", "component_target_file_evidence")


def read_component_archive(
    path: Path, checksum: str, operation_id: str, expected_manifest: dict[str, Any]
) -> dict[str, Any]:
    """Return sensitive evidence only to the native target coordinator; never emit it to the controller."""
    if (
        str(UUID(operation_id)) != operation_id
        or path.name != "migration_" + operation_id + ".tar.gz"
        or re.fullmatch(r"[0-9a-f]{64}", checksum) is None
    ):
        raise ValueError("An exact component archive UUID and checksum are required")
    archives._private_file(path)
    with path.open("rb") as incoming:
        if hashlib.file_digest(incoming, "sha256").hexdigest() != checksum:
            raise ValueError("The selected target archive changed after source publication")
    domain = expected_manifest["source"]["domain"]
    names = {domain + "_" + name for name in archives.NATIVE_COMPONENTS}
    databases = {row["name"] for row in expected_manifest["databases"]}
    names.update(domain + "_mysql_" + name for name in databases)
    if databases:
        names.add(domain + "_mysql")
    private_name = domain + "_virtualmin_components"
    names.add(private_name)
    seen, private = set(), None
    with tarfile.open(path, "r|gz") as bundle:
        for count, member in enumerate(bundle):
            if (
                count >= archives.MAX_OUTER_ENTRIES
                or member.name not in names
                or member.name in seen
                or not member.isfile()
                or member.uid != 0
                or member.gid != 0
                or member.mode != PRIVATE_MEMBER_MODE
            ):
                raise ValueError("The target archive contains foreign, duplicated or unsafe native members")
            seen.add(member.name)
            if member.name == private_name:
                if member.size > archives.MAX_PRIVATE_BYTES:
                    raise ValueError("Private component restoration evidence exceeds its bound")
                incoming = bundle.extractfile(member)
                if incoming is None:
                    raise ValueError("Private component restoration evidence is unreadable")
                private = json.loads(incoming.read(archives.MAX_PRIVATE_BYTES + 1))
    required = {domain + "_" + name for name in ("virtualmin", "unix", "web", "logrotate", "virtualmin_components")}
    required.update(domain + "_mysql_" + name for name in databases)
    if databases:
        required.add(domain + "_mysql")
    if not required <= seen or len(seen & {domain + "_dir.tar", domain + "_dir.tar.gz"}) != 1:
        raise ValueError("The selected target archive lacks required native restoration components")
    if (
        not isinstance(private, dict)
        or set(private) != {"schema", "operation_id", "manifest", "source_uid", "source_gid", "files", "principals"}
        or type(private["schema"]) is not int
        or private["schema"] != 1
        or private["operation_id"] != operation_id
        or source.authority_digest(private["manifest"]) != source.authority_digest(expected_manifest)
        or type(private["source_uid"]) is not int
        or private["source_uid"] <= 0
        or type(private["source_gid"]) is not int
        or private["source_gid"] <= 0
    ):
        raise ValueError("Private restoration evidence belongs to another component authority or native owner")
    archives._private_principals(private["manifest"], private["principals"])
    files._records(private, Path(expected_manifest["source"]["home"]))
    return private
