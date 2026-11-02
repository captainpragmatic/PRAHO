#!/usr/bin/env python3
"""Publish only approved native website components; private credentials stay inside the archive."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import posixpath
import re
import shlex
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

MAX_ENTRIES = 200000
MAX_METADATA_BYTES = 64 * 1024
MAX_PRIVATE_BYTES = 64 * 1024 * 1024
MAX_OUTER_ENTRIES = 1000
MAX_ROOTS = 100
COPY_BYTES = 1024 * 1024
SAFE_LOGROTATE = (
    b'"/var/log/praho-component-native-placeholder" {\n'
    b"    weekly\n    missingok\n    rotate 8\n    compress\n    delaycompress\n    notifempty\n}\n"
)
WEB_FEATURES = frozenset({"unix", "dir", "web", "ssl", "logrotate", "mysql"})
OTHER_FEATURES = frozenset(
    {
        "mail",
        "dns",
        "webmin",
        "ftp",
        "spam",
        "virus",
        "status",
        "postgres",
        "virtualmin-awstats",
        "virtualmin-mailman",
        "virtualmin-dav",
        "virtualmin-sqlite",
    }
)
RESERVED_ROOTS = frozenset({"mail", "maildir", "homes", "domains", "logs", "etc", "tmp", "cgi-bin"})
NATIVE_COMPONENTS = frozenset(
    {
        "virtualmin",
        "unix",
        "web",
        "web_pool",
        "ssl",
        "ssl_cert",
        "ssl_key",
        "ssl_ca",
        "logrotate",
        "dir.tar",
        "dir.tar.gz",
    }
)
NATIVE_OMITTED = frozenset(
    {
        "unix_url",
        "web_alog",
        "web_elog",
        "virtualmin_admins",
        "virtualmin_users",
        "virtualmin_plan",
        "virtualmin_template",
        "virtualmin_scripts",
        "virtualmin_aliases",
        "virtualmin_ssl_cert",
        "virtualmin_ssl_key",
        "virtualmin_ssl_ca",
    }
)


def _relative(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    name = name.rstrip("/")
    path = PurePosixPath(name)
    if not name or path.is_absolute() or ".." in path.parts or str(path) != name or "\x00" in name:
        raise ValueError("Native component archive has an unsafe path")
    return name


def _scope(relative: str, roots: tuple[str, ...]) -> bool:
    return any(relative == root or relative.startswith(root + "/") for root in roots)


def _read_small(path: Path, limit: int = MAX_METADATA_BYTES) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit or b"\0" in value:
        raise ValueError("Native component metadata exceeds its bound or contains unsupported data")
    return value


def _private_file(path: Path, *, raw_native: bool = False) -> None:
    info = path.lstat()
    permissions = 0o022 if raw_native else 0o077
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & permissions
        or info.st_nlink != 1
    ):
        raise ValueError("Component archive inputs must be private owned regular files")


def _unpack_native(raw: Path, directory: Path, domain: str) -> dict[str, Path]:
    result, seen = {}, set()
    with tarfile.open(raw, "r|*") as bundle:
        for count, member in enumerate(bundle):
            if count >= MAX_OUTER_ENTRIES:
                raise ValueError("Native backup has too many outer members")
            if member.isdir() and member.name in {".", "./"}:
                continue
            name = _relative(member.name)
            if "/" in name or not name.startswith(domain + "_") or not member.isfile() or name in seen:
                raise ValueError("Native backup has unexpected, duplicated or non-regular component members")
            seen.add(name)
            kind = name.removeprefix(domain + "_")
            if kind in NATIVE_OMITTED:
                continue
            if kind not in NATIVE_COMPONENTS:
                raise ValueError("Native backup contains an unqualified service callback member")
            if kind not in {"dir.tar", "dir.tar.gz"} and member.size > MAX_METADATA_BYTES:
                raise ValueError("Native website metadata exceeds its qualification limit")
            path = directory / name
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("Native backup member is unreadable")
            with path.open("xb") as destination:
                os.fchmod(destination.fileno(), 0o600)
                shutil.copyfileobj(source, destination, COPY_BYTES)
            result[name] = path
    return result


def _file_record(entry: tarfile.TarInfo, manifest: dict[str, Any], uid: int, gid: int) -> dict[str, Any]:
    relative = _relative(entry.name)
    if entry.uid not in {0, uid} or entry.gid not in {0, gid} or entry.mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError("Prepare foreign ownership or privileged website files before component migration")
    kind = (
        "file"
        if entry.isfile()
        else "directory"
        if entry.isdir()
        else "symlink"
        if entry.issym()
        else "hardlink"
        if entry.islnk()
        else "unknown"
    )
    if kind == "unknown":
        raise ValueError("Selected website archive contains a socket, pipe or device")
    target = ""
    if kind == "symlink":
        link = PurePosixPath(entry.linkname)
        if link.is_absolute():
            try:
                target = link.relative_to(manifest["source"]["home"]).as_posix()
            except ValueError as error:
                raise ValueError("Selected website link escapes into retained source data") from error
        else:
            target = posixpath.normpath(str(PurePosixPath(relative).parent / link))
    elif kind == "hardlink":
        target = _relative(entry.linkname)
    roots = tuple(item["relative"] for item in manifest["paths"])
    if not _scope(relative, roots) or (target and not _scope(_relative(target), roots)):
        raise ValueError("Selected website archive or link escapes its approved roots")
    return {
        "relative": relative,
        "uid": entry.uid,
        "gid": entry.gid,
        "mode": entry.mode & 0o1777,
        "kind": kind,
        "target": target,
    }


def _assert_links(records: list[dict[str, Any]]) -> None:
    entries = {row["relative"]: row for row in records}
    for row in records:
        if row["target"] and row["target"] not in entries:
            raise ValueError("Selected website archive has an absent link target")
        if row["kind"] == "hardlink" and entries[row["target"]]["kind"] != "file":
            raise ValueError("Selected website hardlink needs an independently qualified regular target")
        if any(
            str(parent) in entries and entries[str(parent)]["kind"] != "directory"
            for parent in PurePosixPath(row["relative"]).parents
        ):
            raise ValueError("Selected website archive traverses a link or non-directory parent")


def _files(
    path: Path, manifest: dict[str, Any], uid: int, gid: int, expected_entries: tuple[str, ...]
) -> list[dict[str, Any]]:
    roots = tuple(item["relative"] for item in manifest["paths"])
    records, seen = [], set()
    total = 0
    with tarfile.open(path, "r|*") as bundle:
        for count, entry in enumerate(bundle):
            if count >= MAX_ENTRIES:
                raise ValueError("Selected website exceeds its archive member limit")
            relative = _relative(entry.name)
            if relative in seen:
                raise ValueError("Native directory backup contains duplicated or unselected website data")
            if entry.isfile():
                total += entry.size
            records.append(_file_record(entry, manifest, uid, gid))
            seen.add(relative)
    if total != sum(item["bytes"] for item in manifest["paths"]):
        raise ValueError("Selected archive bytes differ from the source fence snapshot")
    if (
        not expected_entries
        or len(expected_entries) > MAX_ENTRIES
        or len(set(expected_entries)) != len(expected_entries)
        or any(not _scope(_relative(name), roots) for name in expected_entries)
        or seen != set(expected_entries)
    ):
        raise ValueError("Selected archive entries differ from the held filesystem closure")
    _assert_links(records)
    if not records or any(not any(_scope(row["relative"], (root,)) for row in records) for root in roots):
        raise ValueError("Selected website archive is missing an approved root")
    return records


def _metadata(raw: bytes, manifest: dict[str, Any]) -> bytes:
    fields: dict[str, str] = {}
    for line in raw.decode().splitlines():
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z0-9_-]+", key) or key in fields:
            raise ValueError("Native domain metadata is incomplete or duplicated")
        fields[key] = value
    source = manifest["source"]
    if any(
        fields.get(native) != source[reviewed]
        for native, reviewed in (("dom", "domain"), ("user", "owner"), ("id", "domain_id"))
    ):
        raise ValueError("Native backup metadata belongs to another source domain or owner")
    if any(fields.get(name) != "1" for name in ("unix", "dir", "web")):
        raise ValueError("Native backup does not contain an independent website owner and application")
    for feature in OTHER_FEATURES:
        fields[feature] = "0"
    spec = importlib.util.spec_from_file_location(
        "component_archive_native_sql", Path(__file__).with_name("praho-component-mysql.py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("Selected native owner credential qualification is unavailable")
    mysql = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mysql)
    owner_password = mysql.native_owner_password(fields, manifest["databases"])
    # Native domain settings can identify retained SQL/mail/DNS provisioning
    # services or install this certificate on unrelated node services. Export
    # only the separately hash-qualified selected MySQL owner's credential.
    omitted = {"smtp_cloud", "dns_cloud_import", "dns_remote", "ssl_everything", "default_cert_owner"}
    fields = {
        key: value
        for key, value in fields.items()
        if not any(engine in key.lower() for engine in ("mysql", "postgres")) and key not in omitted
    }
    fields["postgres"] = "0"
    fields["pass"] = ""
    fields["mysql"] = "1" if manifest["databases"] else "0"
    fields["db_mysql"] = " ".join(database["name"] for database in manifest["databases"])
    if owner_password is not None:
        fields["mysql_pass"] = owner_password
    fields["backup_excludes"], fields["backup_db_excludes"] = "", ""
    return ("\n".join(key + "=" + fields[key] for key in sorted(fields)) + "\n").encode()


def privileged_web_preparation(web: str) -> list[str]:
    """Imported native configuration cannot introduce root programs or inherited macros on the destination."""
    reasons = []
    programs = {
        "rewritemap",
        "action",
        "extfilterdefine",
        "loadmodule",
        "loadfile",
        "sslpassphrasedialog",
        "define",
        "undefine",
    }
    for line in web.splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        directive = words[0].lower()
        executable = directive in programs or directive.startswith(("perl", "python", "lua"))
        piped_log = (
            directive in {"errorlog", "customlog", "transferlog"} and len(words) > 1 and words[1].startswith("|")
        )
        if executable or piped_log:
            reasons.append(
                "Prepare supported website logging and module directives before migration (" + directive + ")."
            )
    return reasons


def _web_config(path: Path, domain: str, names: set[str]) -> None:
    config = _read_small(path).decode()
    if privileged_web_preparation(config):
        raise ValueError("Prepare qualified website directives before copying native Apache callbacks")
    declared = re.findall(r"^\s*ServerName\s+(\S+)\s*$", config, re.MULTILINE | re.IGNORECASE)
    aliases = re.findall(r"^\s*ServerAlias\s+(.+)$", config, re.MULTILINE | re.IGNORECASE)
    if not declared or set(declared) != {domain} or any(name not in names for line in aliases for name in line.split()):
        raise ValueError("Separate retained mail, webmail and admin aliases before exporting website routing")


def _add_bytes(bundle: tarfile.TarFile, name: str, value: bytes) -> None:
    entry = tarfile.TarInfo(name)
    entry.mode, entry.size = 0o600, len(value)
    bundle.addfile(entry, io.BytesIO(value))


def _add_file(bundle: tarfile.TarFile, path: Path, name: str) -> None:
    entry = bundle.gettarinfo(str(path), arcname=name)
    entry.uid = entry.gid = 0
    entry.uname = entry.gname = "root"
    entry.mode = 0o600
    with path.open("rb") as stream:
        bundle.addfile(entry, stream)


def _private_principals(manifest: dict[str, Any], principals: list[dict[str, Any]]) -> None:
    expected = {}
    for database in manifest["databases"]:
        for principal in database["principals"]:
            identity = principal["user"], principal["host"]
            if identity in expected and principal != expected[identity]:
                raise ValueError("Reviewed database authentication evidence is inconsistent")
            expected[identity] = principal
    seen = set()
    for principal in principals:
        if not isinstance(principal, dict) or set(principal) != {
            "user",
            "host",
            "plugin",
            "authentication_string",
            "alternatives",
            "grants",
        }:
            raise ValueError("Private database login evidence is incomplete")
        identity = principal["user"], principal["host"]
        if identity not in expected or identity in seen:
            raise ValueError("Private database login does not belong to the exact approved principals")
        auth = [principal["plugin"], principal["authentication_string"], principal["alternatives"]]
        if (
            auth[0] != "mysql_native_password"
            or re.fullmatch(r"\*[A-F0-9]{40}", auth[1]) is None
            or auth[2] not in {"[]", "[{}]"}
        ):
            raise ValueError("Prepare qualified native database password authentication before exporting")
        grants = principal["grants"]
        if (
            not isinstance(grants, list)
            or not grants
            or not all(isinstance(grant, str) and "\n" not in grant and "\0" not in grant for grant in grants)
        ):
            raise ValueError("Private native database grants are incomplete")
        auth_digest = hashlib.sha256(json.dumps(auth, separators=(",", ":")).encode()).hexdigest()
        grants_digest = hashlib.sha256(json.dumps(sorted(grants), separators=(",", ":")).encode()).hexdigest()
        if (auth_digest, grants_digest) != (expected[identity]["auth_digest"], expected[identity]["grants_digest"]):
            raise ValueError("Private database credentials or grants changed after component review")
        seen.add(identity)
    if seen != expected.keys():
        raise ValueError("A selected database principal has no private restoration evidence")


def _staging(raw: Path, output: Path, operation_id: str, source_uid: int, source_gid: int) -> None:
    if str(UUID(operation_id)) != operation_id or output.name != f"migration_{operation_id}.tar.gz":
        raise ValueError("A component archive must belong to its exact migration UUID")
    if type(source_uid) is not int or type(source_gid) is not int or min(source_uid, source_gid) <= 0:
        raise ValueError("Component archive needs a non-root native owner and group")
    parent = output.parent.lstat()
    if (
        output.parent.resolve() != output.parent
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or parent.st_mode & 0o077
    ):
        raise ValueError("Component archive staging must be a private owned directory")
    _private_file(raw, raw_native=True)
    if raw.parent != output.parent:
        raise ValueError("The native archive must share this operation's private staging directory")
    if output.exists() or output.is_symlink():
        raise ValueError("A component archive already occupies this migration identity")


def _selection(manifest: dict[str, Any], selected_cron: tuple[str, ...], database_dumps: dict[str, Path]) -> str:
    domain = manifest["source"]["domain"]
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", domain) is None:
        raise ValueError("A native website domain is required")
    roots = tuple(_relative(item["relative"]) for item in manifest["paths"])
    if (
        not roots
        or len(roots) > MAX_ROOTS
        or any(
            PurePosixPath(root).parts[0].lower() in RESERVED_ROOTS
            or any(part.startswith(".") for part in PurePosixPath(root).parts)
            for root in roots
        )
    ):
        raise ValueError("Select bounded website roots independently of retained source data")
    cron_digests = {row["digest"] for row in manifest["writers"] if row["kind"] == "cron_entry"}
    if (
        len(set(selected_cron)) != len(selected_cron)
        or any("\n" in line or "\r" in line or "\0" in line for line in selected_cron)
        or {hashlib.sha256(line.encode()).hexdigest() for line in selected_cron} != cron_digests
    ):
        raise ValueError("Only exactly reviewed website jobs may enter the destination crontab")
    selected_databases = {database["name"] for database in manifest["databases"]}
    if set(database_dumps) != selected_databases or any(
        re.fullmatch(r"[A-Za-z0-9_]{1,64}", name) is None for name in selected_databases
    ):
        raise ValueError("Native SQL exports must contain exactly the selected databases")
    for dump in database_dumps.values():
        _private_file(dump)
    return domain


def _publish(staged: Path, output: Path) -> None:
    os.link(staged, output)  # Never replace another operation's already-published file.
    staged.unlink()
    descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_bundle(  # noqa: PLR0913 -- independently validated native payloads and exact selected components
    staged: Path,
    members: dict[str, Path],
    selected: set[str],
    prefix: str,
    manifest: dict[str, Any],
    selected_cron: tuple[str, ...],
    encoded: bytes,
    database_dumps: dict[str, Path],
) -> None:
    with staged.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        with tarfile.open(fileobj=stream, mode="w:gz") as bundle:
            for name in sorted(selected):
                _add_file(bundle, members[name], name)
            _add_bytes(bundle, prefix + "virtualmin", _metadata(_read_small(members[prefix + "virtualmin"]), manifest))
            # Existing-domain restore keeps the destination log patterns and
            # regenerates its own postrotate callback. Never import source root
            # hooks, includes, alternate paths or command blocks.
            _add_bytes(bundle, prefix + "logrotate", SAFE_LOGROTATE)
            _add_bytes(bundle, prefix + "unix", ("\n".join(selected_cron) + ("\n" if selected_cron else "")).encode())
            _add_bytes(bundle, prefix + "virtualmin_components", encoded)
            if database_dumps:
                mysql_metadata = "".join(
                    f"charset_{row['name']}={row['charset']}\ncollate_{row['name']}={row['collation']}\n"
                    for row in manifest["databases"]
                )
                _add_bytes(bundle, prefix + "mysql", mysql_metadata.encode())
            for name, dump in sorted(database_dumps.items()):
                _add_file(bundle, dump, prefix + "mysql_" + name)
        stream.flush()
        os.fsync(stream.fileno())


def sanitize_component_archive(  # noqa: PLR0913 -- exact reviewed scope and private, independent native exports
    raw: Path,
    output: Path,
    *,
    manifest: dict[str, Any],
    operation_id: str,
    source_uid: int,
    source_gid: int,
    selected_cron: tuple[str, ...],
    database_dumps: dict[str, Path],
    private_principals: list[dict[str, Any]],
    expected_entries: tuple[str, ...],
) -> dict[str, Any]:
    _staging(raw, output, operation_id, source_uid, source_gid)
    domain = _selection(manifest, selected_cron, database_dumps)
    _private_principals(manifest, private_principals)
    with tempfile.TemporaryDirectory(prefix=".component-", dir=output.parent) as temporary:
        directory = Path(temporary)
        members = _unpack_native(raw, directory, domain)
        prefix = domain + "_"
        required = {prefix + name for name in ("virtualmin", "unix", "web", "logrotate")}
        directory_members = [name for name in members if name in {prefix + "dir.tar", prefix + "dir.tar.gz"}]
        if not required <= members.keys() or len(directory_members) != 1:
            raise ValueError("Native component archive lacks its required website metadata or selected files")
        records = _files(members[directory_members[0]], manifest, source_uid, source_gid, expected_entries)
        names = set(manifest["routing"]["website_names"])
        if not names <= {domain, "www." + domain}:
            raise ValueError("Retained service hostnames cannot move with website routing")
        _web_config(members[prefix + "web"], domain, names)
        if prefix + "ssl" in members:
            _web_config(members[prefix + "ssl"], domain, names)
        private = {
            "schema": 1,
            "operation_id": operation_id,
            "manifest": manifest,
            "source_uid": source_uid,
            "source_gid": source_gid,
            "files": records,
            "principals": private_principals,
        }
        encoded = json.dumps(private, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(encoded) > MAX_PRIVATE_BYTES:
            raise ValueError("Component archive private restoration metadata exceeds its bound")
        selected = {
            directory_members[0],
            *(
                prefix + name
                for name in ("web", "web_pool", "ssl", "ssl_cert", "ssl_key", "ssl_ca")
                if prefix + name in members
            ),
        }
        staged = directory / "ready.tar.gz"
        _write_bundle(staged, members, selected, prefix, manifest, selected_cron, encoded, database_dumps)
        _publish(staged, output)
    digest = hashlib.sha256()
    with output.open("rb") as stream:
        for block in iter(lambda: stream.read(COPY_BYTES), b""):
            digest.update(block)
    return {
        "sha256": digest.hexdigest(),
        "bytes": output.stat().st_size,
        "files": len(records),
        "databases": sorted(database_dumps),
    }
