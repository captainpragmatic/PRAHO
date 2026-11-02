#!/usr/bin/env python3
"""Committed component source retirement; retained source services remain independent."""

# ruff: noqa: S608 -- SQL identifiers are the existing strictly qualified fence scope, never shell text.

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

ORDER = ("web", "database", "paths", "files", "cron", "ingress", "export")
MAX_NATIVE_RESULT = 16 * 1024


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native source retirement support is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = _module("praho-component-native-source.py", "component_retirement_native_source")
files = _module("praho-component-file-retire.py", "component_retirement_files")
exports = _module("praho-component-source-export.py", "component_retirement_exports")


def _retained(source: Any, context: dict[str, Any]) -> str:
    """Baseline CURRENT retained state, normalizing only authorized selected-component changes."""
    inspection = native.inspection
    manifest = context["manifest"]
    if native.authority_digest(manifest) != source.authority:
        raise ValueError("The source retirement context changed its approved authority")
    identity = manifest["source"]
    domain = inspection._fields(Path("/etc/webmin/virtual-server/domains") / identity["domain_id"])
    if (
        any(
            domain.get(key) != identity[reviewed]
            for key, reviewed in (("id", "domain_id"), ("dom", "domain"), ("user", "owner"), ("home", "home"))
        )
        or domain.get("parent")
        or domain.get("alias")
        or any(domain.get(key) != "1" for key in ("unix", "dir"))
    ):
        raise ValueError("The retained native source domain identity or standalone Unix owner changed")
    owner = inspection.pwd.getpwnam(identity["owner"])
    if (
        owner.pw_dir != identity["home"]
        or owner.pw_uid != context["uid"]
        or owner.pw_gid != context.get("gid", int(domain["gid"]))
    ):
        raise ValueError("The retained source Unix account identity changed")
    if int(domain["uid"]) != context["uid"] or int(domain["gid"]) != context.get("gid", int(domain["gid"])):
        raise ValueError("The retained Unix owner identity changed")
    _versions, preparation = inspection._callbacks()
    mail = inspection._mail_dependencies(domain, preparation)
    if preparation:
        raise ValueError("Retained mail dependencies or native callbacks require qualification before cleanup")
    records = inspection._dns(domain["dom"], local=domain.get("dns") == "1")
    allowed = {row["name"] for row in manifest["databases"]}

    def normalized(row: dict[str, str]) -> dict[str, str]:
        return {
            key: value
            for key, value in row.items()
            if key not in {"web", "ssl", "db_mysql", "mysql"} and not key.startswith("lastsave")
        }

    related = inspection._related_domains(domain["user"])
    owner_domains = []
    for row in related:
        complete = inspection._fields(Path("/etc/webmin/virtual-server/domains") / row["id"])
        owner_domains.append(normalized(complete) if row["id"] == domain["id"] else complete)
    ssl = {key: value for key, value in domain.items() if key.startswith(("ssl_", "letsencrypt_"))}
    certificates = {}
    for key in ("ssl_cert", "ssl_key", "ssl_chain", "ssl_combined", "ssl_everything"):
        if domain.get(key):
            certificates[key] = hashlib.sha256(inspection._read(Path(domain[key])).encode()).hexdigest()
    return inspection._digest(
        {
            "domain": normalized(domain),
            "retained_databases": sorted(set(domain.get("db_mysql", "").split()) - allowed),
            "unix_authentication": hashlib.sha256(
                inspection._command(["/usr/bin/getent", "shadow", domain["user"]]).encode()
            ).hexdigest(),
            "owner_cron": inspection._owner_cron(domain["user"], []),
            "owner_domains": owner_domains,
            "dns": {
                key: value for key, value in records.items() if key not in {"apex_a", "apex_aaaa", "www_a", "www_aaaa"}
            },
            "mail": mail,
            "ssl": ssl,
            "certificates": certificates,
        }
    )


def _native(action: str, source: Any, context: dict[str, Any]) -> dict[str, Any]:
    manifest = context["manifest"]
    identity = manifest["source"]
    pools = []
    if action in {"inspect", "retire"}:
        candidates = sorted(Path("/etc/php").glob("*/fpm/pool.d/" + identity["domain_id"] + ".conf"))
        writers = [row for row in manifest["writers"] if row["kind"] == "php_fpm_pool"]
        if len(candidates) != len(writers) or len(candidates) > 1:
            raise ValueError("The original source PHP pool scope changed")
        for path, writer in zip(candidates, writers, strict=True):
            digest = hashlib.sha256(native.inspection._read(path).encode()).hexdigest()
            if digest != writer["digest"]:
                raise ValueError("The original source PHP pool changed")
            pools.append({"path": str(path), "sha256": digest})
    request = {
        "action": action,
        **{key: identity[key] for key in ("domain_id", "domain", "owner", "home")},
        "uid": context["uid"],
        "web_sha256": context["web_sha256"],
        "pool_digests": pools,
        "selected_databases": [row["name"] for row in manifest["databases"]],
    }
    result = subprocess.run(  # noqa: S603 -- fixed protected native helper; bounded identities on stdin only.
        ["/usr/bin/perl", str(Path(__file__).with_suffix(".pl"))],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if result.returncode or len(result.stdout.encode()) > MAX_NATIVE_RESULT:
        raise RuntimeError("Source native retirement step is uncertain: " + result.stderr[-2000:])
    response = json.loads(result.stdout)
    if (
        not isinstance(response, dict)
        or set(response) != {"domain_id", "web_sha256", "php_units"}
        or response["domain_id"] != identity["domain_id"]
        or not isinstance(response["web_sha256"], str)
        or re.fullmatch(r"(?:[0-9a-f]{64})?", response["web_sha256"]) is None
        or not isinstance(response["php_units"], list)
        or any(
            not isinstance(unit, str) or re.fullmatch(r"php[0-9]+(?:\.[0-9]+)?-fpm", unit) is None
            for unit in response["php_units"]
        )
        or len(set(response["php_units"])) != len(response["php_units"])
    ):
        raise ValueError("The native source retirement receipt is unrecognized")
    return response


def _verify_web(source: Any, context: dict[str, Any]) -> str:
    return str(_native("verify", source, context)["web_sha256"])


def _retire_web(source: Any, context: dict[str, Any], web: Any) -> str:
    with web.bindings.transaction():
        response = _native("retire", source, context)
        for unit in response["php_units"]:
            # No restart fallback: unrelated website requests must finish on their
            # existing workers while the selected pool retires gracefully.
            native.inspection._command(["/usr/bin/systemctl", "reload", unit])
            native.inspection._command(["/usr/bin/systemctl", "is-active", unit])
        web.bindings.refresh()
        web.bindings.reload()
    current = _verify_web(source, context)
    if current != response["web_sha256"]:
        raise ValueError("The retired native website changed before its cleanup receipt")
    return current


def _sql_absent(fence: Any) -> None:
    if fence.selected:
        names = ",".join("'" + name + "'" for name in fence.selected)
        # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — DatabaseFence validates selected schema names with mysql._names; native mysql CLI.
        if fence.execute(
            f"SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ({names}) ORDER BY SCHEMA_NAME"
        ):
            raise ValueError("A retired selected source schema is present or reused")
    if fence.principals:
        scope = " OR ".join(f"(User = '{user}' AND Host = '{host}')" for user, host in sorted(fence.principals))
        # nosemgrep: sqlalchemy-execute-raw-query — DatabaseFence USER/HOST fullmatches qualify every literal; native mysql CLI.
        if fence.execute("SELECT User, Host FROM mysql.user WHERE " + scope + " ORDER BY User, Host"):
            raise ValueError("A retired selected source principal is present or reused")


def _retire_database(source: Any, context: dict[str, Any], fence: Any) -> None:
    with fence.journal.locked():
        state = fence.journal.read()
        if state is None:
            raise ValueError("Selected source SQL has no owned fence receipt")
        fence.journal.assert_owned(state)
        if state.get("phase") == "retired":
            _sql_absent(fence)
            return
        fence._owned_receipt(state)
        if state["phase"] != "held":
            raise ValueError("Selected source SQL retirement was interrupted; inspect before replay")
        fence._held()
        state["phase"] = "retiring"
        fence.journal.write(state)
        for name in fence.selected:
            # nosemgrep: sqlalchemy-execute-raw-query — DatabaseFence mysql._names excludes quotes/backticks; owned held receipt precedes DROP.
            fence.execute("DROP DATABASE `" + name + "`")
        for user, host in sorted(fence.principals):
            # nosemgrep: formatted-sql-query, sqlalchemy-execute-raw-query — DatabaseFence USER/HOST fullmatches and exact owned held receipt precede DROP.
            fence.execute(f"DROP USER '{user}'@'{host}'")
        _sql_absent(fence)
        if fence.selected:
            _native("sql_metadata", source, context)
        state["phase"] = "retired"
        fence.journal.write(state)


def _retire_export(source: Any, state: dict[str, Any], *, owner_uid: int = 0) -> None:
    exported = state.get("export")
    if not isinstance(exported, dict) or exported.get("phase") != "ready":
        raise ValueError("The committed source has no exact ready export ownership receipt")
    directory = exports.ROOT / source.operation
    output = directory / ("migration_" + source.operation + ".tar.gz")
    native_artifacts = {"native.tar.gz", "native.tar.gz.dom", "native.tar.gz.info"}
    expected = {
        *native_artifacts,
        output.name,
        *(
            "migration_" + source.operation + ".db_" + row["name"] + ".sql"
            for row in state["context"]["manifest"]["databases"]
        ),
    }
    if exported.get("path") != str(output) or exports._digest(output) != exported.get("sha256"):
        raise ValueError("The exact selected source export changed before private staging retirement")
    # A ready export names this newly created root-private operation directory.
    # Unknown files, symlinks, external hardlinks or non-private ownership park
    # cleanup; this is never a recursive deletion of a mutable customer path.
    with files._opened(files._private_directory(directory, owner_uid)) as descriptor:
        if set(os.listdir(descriptor)) != expected:
            raise ValueError("Unapproved source export staging entries require manual review")
        for name in expected:
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            forbidden_mode = 0o022 if name in native_artifacts else 0o077
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != owner_uid
                or info.st_mode & forbidden_mode
                or info.st_nlink != 1
            ):
                raise ValueError("Source export staging is not exact private operation-owned data")
        for name in sorted(expected):
            os.unlink(name, dir_fd=descriptor)
        os.fsync(descriptor)
    # Keep the private empty UUID directory as an anti-replay tombstone.


def _verify_empty_export(source: Any) -> None:
    directory = exports.ROOT / source.operation
    if not directory.is_dir() or directory.is_symlink() or directory.resolve() != directory:
        raise ValueError("The retired private source export tombstone changed")
    with files._opened(files._private_directory(directory, 0)) as descriptor:
        if os.listdir(descriptor):
            raise ValueError("The retired private source export namespace was reused")


class SourceRetirement:
    def __init__(self, source: Any) -> None:
        self.source, self.coordinator = source, source.coordinator

    def _step(self, name: str, state: dict[str, Any], steps: dict[str, Any]) -> None:
        context, retirement = state["context"], state["retirement"]
        if name == "web":
            retirement["web_sha256"] = _retire_web(self.source, context, steps["web"])
        elif name == "database":
            _retire_database(self.source, context, steps["database"])
        elif name == "paths":
            steps["paths"].release()
        elif name == "files":
            files.retire(retirement["file_capture"])
        elif name == "cron":
            steps["cron"].retire()
        elif name == "ingress":
            current = _verify_web(self.source, context)
            if current != retirement["web_sha256"]:
                raise ValueError("The retired source website changed before ingress retirement")
            steps["web"].retire_after_web_absence(current)
        else:
            _retire_export(self.source, state)

    def retire(self) -> dict[str, str]:
        with self.coordinator.journal.locked():
            state = self.coordinator._state()
            context = state["context"]
            steps = self.source.build(context)
            if state["phase"] == "committed":
                for name in native.coordinator.ORDER:
                    steps[name].verify()
                _native("inspect", self.source, context)
                captured = files.capture(
                    Path(context["manifest"]["source"]["home"]),
                    tuple(row["relative"] for row in context["manifest"]["paths"]),
                    self.source.request["domain_id"],
                    self.source.operation,
                    self.source.authority,
                )
                state["retirement"] = {
                    "retained_digest": _retained(self.source, context),
                    "file_capture": captured,
                    "completed": [],
                    "pending": None,
                }
                state["phase"] = "retiring"
                self.coordinator.journal.write(state)
            elif state["phase"] == "retired":
                retirement = state.get("retirement")
                if (
                    not isinstance(retirement, dict)
                    or retirement.get("pending") is not None
                    or retirement.get("completed") != list(ORDER)
                ):
                    raise ValueError("The completed source retirement has no exact final receipts")
                current = _verify_web(self.source, context)
                _sql_absent(steps["database"])
                files.retire(retirement["file_capture"])
                steps["cron"].retire()
                steps["web"].retire_after_web_absence(current)
                _verify_empty_export(self.source)
                return {
                    "phase": "retired",
                    "operation_id": self.source.operation,
                    "source_domain_id": self.source.request["domain_id"],
                }
            elif state["phase"] != "retiring":
                raise ValueError("Only the exact committed source may retire selected components")
            retirement = state.get("retirement")
            if (
                not isinstance(retirement, dict)
                or retirement.get("pending") is not None
                or retirement.get("completed") != list(ORDER[: len(retirement.get("completed", []))])
            ):
                raise ValueError("Source retirement was interrupted or is uncertain; inspect its exact receipts")
            for name in ORDER[len(retirement["completed"]) :]:
                if _retained(self.source, context) != retirement["retained_digest"]:
                    raise ValueError("Retained source services changed during component retirement")
                retirement["pending"] = name
                self.coordinator.journal.write(state)
                self._step(name, state, steps)
                if _retained(self.source, context) != retirement["retained_digest"]:
                    raise ValueError("Retained source services changed during component retirement")
                retirement["completed"].append(name)
                retirement["pending"] = None
                self.coordinator.journal.write(state)
            state["phase"] = "retired"
            self.coordinator.journal.write(state)
            return {
                "phase": "retired",
                "operation_id": self.source.operation,
                "source_domain_id": self.source.request["domain_id"],
            }


def retire_source(request: dict[str, Any], operation_id: str, authority: str) -> dict[str, str]:
    return SourceRetirement(native.NativeSource(request, operation_id, authority)).retire()


def cleanup_released_export(request: dict[str, Any], operation_id: str, authority: str) -> dict[str, str]:
    """Retire only ready private export artifacts after exact source compensation."""
    source = native.NativeSource(request, operation_id, authority)
    with source.coordinator.journal.locked():
        state = source.coordinator._state()
        if state["phase"] != "released":
            raise ValueError("Private rollback export cleanup requires exact released source ownership")
        directory = exports.ROOT / source.operation
        previous = state.get("export_retirement")
        if previous == "retired":
            if state.get("export") is not None:
                _verify_empty_export(source)
            elif directory.exists() or directory.is_symlink():
                raise ValueError("The retired rollback export namespace was reused")
        elif previous is not None:
            raise ValueError("Rollback export cleanup was interrupted; inspect its private artifacts")
        elif state.get("export") is None:
            if directory.exists() or directory.is_symlink():
                raise ValueError("Unreceipted source export staging requires manual review")
            state["export_retirement"] = "retired"
            source.coordinator.journal.write(state)
        else:
            exported = state["export"]
            if not isinstance(exported, dict) or exported.get("phase") != "ready":
                raise ValueError("Incomplete native export needs manual artifact review")
            state["export_retirement"] = "retiring"
            source.coordinator.journal.write(state)
            _retire_export(source, state)
            state["export_retirement"] = "retired"
            source.coordinator.journal.write(state)
        return {
            "phase": "released_export_retired",
            "operation_id": operation_id,
            "source_domain_id": request["domain_id"],
        }
