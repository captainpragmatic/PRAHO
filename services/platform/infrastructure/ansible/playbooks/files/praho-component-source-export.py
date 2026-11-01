#!/usr/bin/env python3
"""Publish one private selected native archive while every source hold remains proven."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path("/var/lib/praho-transfer/components")


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native component export helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


archives = _module("praho-component-archive.py", "component_source_archive")
databases = _module("praho-component-database-export.py", "component_source_sql_export")
capacity = _module("praho-component-capacity.py", "component_source_output_capacity")


def _run(
    arguments: list[str],
    *,
    data: dict[str, Any] | None = None,
    file_limit: int | None = None,
    workspace_limit: int | None = None,
    paths: tuple[Path, ...] = (),
) -> None:
    if file_limit is not None:
        capacity.run_limited(
            arguments,
            paths=paths,
            file_limit=file_limit,
            workspace_limit=workspace_limit,
            data=json.dumps(data) if data is not None else None,
        )
        return
    result = subprocess.run(  # noqa: S603 -- fixed native backup/capture commands, no shell; secrets only on stdin
        arguments,
        input=json.dumps(data) if data is not None else None,
        capture_output=True,
        text=True,
        timeout=1800,
        check=False,
    )
    if result.returncode:
        raise ValueError("Native component export did not complete; preserve its private artifacts for inspection")


def _digest(path: Path) -> str:
    archives._private_file(path)
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(archives.COPY_BYTES), b""):
            result.update(block)
    return result.hexdigest()


def export_source(source: Any) -> dict[str, Any]:
    """A lost backup/dump/publication response parks; a durable ready receipt is reusable."""
    coordinator = source.coordinator
    with coordinator.journal.locked():
        state = coordinator._state()
        if state["phase"] != "held":
            raise ValueError("Only a fully held source may export its selected website")
        coordinator._verify(state)
        directory = ROOT / source.operation
        output = directory / ("migration_" + source.operation + ".tar.gz")
        previous = state.get("export")
        if previous is not None:
            if (
                previous.get("phase") != "ready"
                or previous.get("path") != str(output)
                or _digest(output) != previous.get("sha256")
                or output.stat().st_size != previous.get("bytes")
            ):
                raise ValueError("Source export is incomplete or changed; inspect before retrying")
            return {key: value for key, value in previous.items() if key != "phase"}
        if ROOT.resolve() != ROOT:
            raise ValueError("Component staging traverses an unqualified symlink")
        ROOT.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = ROOT.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Component exports require private root-owned staging")
        if directory.exists() or directory.is_symlink():
            raise ValueError("Unreceipted component staging exists; inspect before proceeding")
        inspector = _module("praho-component-inspect.py", "component_export_final_inspection")
        inspector.capacity.require_capacity(state["context"]["manifest"], ROOT, inspector.native_temporary_directory())
        state["export"] = {"phase": "started", "path": str(output)}
        coordinator.journal.write(state)
        directory.mkdir(mode=0o700)
        context = state["context"]
        manifest = json.loads(json.dumps(context["manifest"], allow_nan=False))
        native_temp = inspector.native_temporary_directory()
        raw_limit, sql_limit = capacity.native_archive_budget(manifest), capacity.sql_dump_budget(manifest)
        state["export"]["budgets"] = {
            "native_file_bytes": raw_limit,
            "sql_dump_bytes": sql_limit,
            "retained_reserve_bytes": capacity.RETAINED_RESERVE_BYTES,
        }
        coordinator.journal.write(state)
        native = source.request
        steps = coordinator._steps(state)
        _run(
            ["/usr/bin/perl", str(Path(__file__).with_name("praho-recovery-credentials.pl"))],
            data={
                "action": "capture-owner",
                "domain": native["domain"],
                "owner": native["owner"],
                "domain_id": native["domain_id"],
                "archive": output.name,
                "require_fenced": False,
            },
        )
        raw = directory / "native.tar.gz"
        arguments = [
            "/usr/sbin/virtualmin",
            "backup-domain",
            "--domain",
            native["domain"],
            "--dest",
            str(raw),
            "--no-differential",
            "--compression",
            "gzip",
            "--option",
            "dir",
            "dirnologs",
            "1",
        ]
        for path in manifest["paths"]:
            arguments.extend(["--include", path["relative"]])
        for feature in ("virtualmin", "unix", "dir", "web", "ssl", "logrotate"):
            arguments.extend(["--feature", feature])
        _run(arguments, file_limit=raw_limit, workspace_limit=4 * raw_limit, paths=(directory, native_temp))
        coordinator._verify(state)
        selected = databases.export_databases(
            steps["database"], directory, budget=capacity.OutputBudget(sql_limit, (directory,))
        )
        fields = inspector._native_domain(native)
        manifest["paths"], scope = inspector._path_facts(
            Path(manifest["source"]["home"]),
            [{"relative": row["relative"], "purpose": row["purpose"]} for row in manifest["paths"]],
        )
        result = json.loads(
            capacity.run_limited(
                [sys.executable, str(Path(__file__)), "--sanitize"],
                paths=(directory,),
                file_limit=raw_limit + sql_limit + archives.MAX_PRIVATE_BYTES,
                workspace_limit=2 * (raw_limit + sql_limit + archives.MAX_PRIVATE_BYTES),
                data=json.dumps(
                    {
                        "raw": str(raw),
                        "output": str(output),
                        "manifest": manifest,
                        "operation_id": source.operation,
                        "source_uid": context["uid"],
                        "source_gid": int(fields["gid"]),
                        "selected_cron": steps["cron"].selected_cron(),
                        "database_dumps": {name: str(path) for name, path in selected["dumps"].items()},
                        "private_principals": selected["principals"],
                        "expected_entries": scope["entries"],
                    }
                ),
            )
        )
        coordinator._verify(state)
        state["export"] = {"phase": "ready", "path": str(output), **result}
        coordinator.journal.write(state)
        return {"path": str(output), **result}


if __name__ == "__main__":
    if sys.argv[1:] != ["--sanitize"]:
        raise ValueError("Only the isolated selected source sanitizer may run directly")
    selected = json.load(sys.stdin)
    selected["raw"], selected["output"] = Path(selected["raw"]), Path(selected["output"])
    selected["database_dumps"] = {name: Path(path) for name, path in selected["database_dumps"].items()}
    selected["selected_cron"], selected["expected_entries"] = (
        tuple(selected["selected_cron"]),
        tuple(selected["expected_entries"]),
    )
    print(json.dumps(archives.sanitize_component_archive(**selected)))
