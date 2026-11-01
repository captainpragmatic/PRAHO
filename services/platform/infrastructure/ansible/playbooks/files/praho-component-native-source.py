#!/usr/bin/env python3
"""Bind the source coordinator to exact native website, schedule, SQL and path holds."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native component source operation is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inspection = _module("praho-component-inspect.py", "component_source_inspection")
coordinator = _module("praho-component-source.py", "component_source_coordinator")
web = _module("praho-component-web-fence.py", "component_source_web")
cron = _module("praho-component-cron-fence.py", "component_source_cron")
database = _module("praho-component-database-fence.py", "component_source_database")
paths = _module("praho-component-fence.py", "component_source_paths")


def authority_digest(manifest: dict[str, Any]) -> str:
    """Same consent fields as Platform; current data bytes are captured after fencing."""
    scope = json.loads(json.dumps(manifest, allow_nan=False))
    scope["paths"] = [
        {key: value for key, value in row.items() if key not in {"bytes", "tree_digest"}} for row in scope["paths"]
    ]
    scope["databases"] = [{key: value for key, value in row.items() if key != "bytes"} for row in scope["databases"]]
    return hashlib.sha256(
        json.dumps(scope, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


class NativeSource:
    def __init__(self, request: dict[str, Any], operation_id: str, authority: str) -> None:
        self.request = json.loads(json.dumps(request, allow_nan=False))
        self.operation, self.authority = operation_id, authority
        self.coordinator = coordinator.SourceCoordinator(
            request["domain_id"],
            operation_id,
            authority,
            preflight=self.preflight,
            build=self.build,
            retained=self.retained,
        )

    def preflight(self) -> dict[str, Any]:
        manifest = inspection.inspect_source(self.request)
        if manifest["preparation"] or authority_digest(manifest) != self.authority:
            raise ValueError("Source components or retained dependencies changed; obtain a new operator preview")
        if any(writer["kind"] not in {"php_fpm_pool", "cron_entry"} for writer in manifest["writers"]):
            raise ValueError("Classify every source application writer before component migration")
        if any(not row["isolated"] or not row["principals"] for row in manifest["databases"]):
            raise ValueError("Selected database principals must be isolated from retained services")
        native = inspection._native_domain(self.request)
        original = inspection._read(Path("/etc/apache2/sites-available") / (native["dom"] + ".conf"))
        records = inspection._dns(native["dom"], local=native.get("dns") == "1")
        if inspection._digest({"web": original, "dns": records}) != manifest["routing"]["digest"]:
            raise ValueError("Source frontend or routing changed during its final inspection")
        return {
            "manifest": manifest,
            "native_owned": native.get("db_mysql", "").split(),
            "uid": int(native["uid"]),
            "gid": int(native["gid"]),
            "web_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "retained_digest": manifest["retained"]["digest"],
        }

    def retained(self, context: dict[str, Any]) -> str:
        manifest = context["manifest"]
        if authority_digest(manifest) != self.authority:
            raise ValueError("Durable source context belongs to another component authority")
        native = inspection._native_domain(self.request)
        if context.get("uid") != int(native["uid"]) or context.get("gid", int(native["gid"])) != int(native["gid"]):
            raise ValueError("The committed source Unix owner or group identity changed")
        _versions, preparation = inspection._callbacks()
        records = inspection._dns(native["dom"], local=native.get("dns") == "1")
        digest = inspection.retained_evidence(native, records, preparation)
        for writer in manifest["writers"]:
            if writer["kind"] == "php_fpm_pool":
                pools = list(Path("/etc/php").glob("*/fpm/pool.d/" + native["id"] + ".conf"))
                if (
                    len(pools) != 1
                    or hashlib.sha256(inspection._read(pools[0]).encode()).hexdigest() != writer["digest"]
                ):
                    raise ValueError("The independently classified source PHP pool changed")
        if preparation:
            raise ValueError("Retained services or native callbacks need preparation before proceeding")
        return digest

    def build(self, context: dict[str, Any]) -> dict[str, Any]:
        manifest = context["manifest"]
        source = manifest["source"]
        domain_id, operation = source["domain_id"], self.operation
        digests = {row["tree_digest"] for row in manifest["paths"]}
        if len(digests) != 1:
            raise ValueError("Selected paths do not share one independently qualified inode closure")
        return {
            "web": web.WebIngressFence(
                domain_id,
                operation,
                source["domain"],
                tuple(manifest["routing"]["website_names"]),
                context["web_sha256"],
            ),
            "cron": cron.CronFileFence(
                domain_id,
                operation,
                source["owner"],
                tuple(writer["digest"] for writer in manifest["writers"] if writer["kind"] == "cron_entry"),
            ),
            "database": database.DatabaseFence(
                domain_id,
                operation,
                manifest["databases"],
                tuple(context["native_owned"]),
            ),
            "paths": paths.PathFence(
                Path(source["home"]),
                tuple(row["relative"] for row in manifest["paths"]),
                domain_id,
                context["uid"],
                operation,
                next(iter(digests)),
            ),
        }
