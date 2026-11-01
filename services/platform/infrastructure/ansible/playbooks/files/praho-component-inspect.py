#!/usr/bin/env python3
"""Read-only native component evidence with actionable preparation for retained services."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pwd
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from uuid import UUID

LIMIT = 256 * 1024
MAX_CALLBACK_BYTES = 4 * 1024 * 1024
MAX_DOMAINS = 10000
MX_FIELDS = 2
PATH_ALIAS_FIELDS = 3
QUALIFIED_CALLBACKS = {
    "feature-dns.pl": "059e88a9d2ec9b4e62c49ba285b2956759be1b19c1429aad102364e986547892",
    "backup-domain.pl": "e5c4f9b8a4e583dad6f09051057320a528f8dbdc1c73ba82745f52d5a508ac42",
    "restore-domain.pl": "eba2b7b0421c6937ee62812ac2988ec640eec0d861005de626f964d545fb3ccd",
    "backups-lib.pl": "71cd564a93338f5190e61df2bc844cf690c7c0fba07a2f80388c28ce4b8d88a5",
    "feature-dir.pl": "38d5432c1b209fe15e42b441d711a0ab57ec883a9e276b613b0fa3143f250dd3",
    "feature-unix.pl": "4df3f8ad78975f22629dfe4976006de78e8219f3814ea7313b1ad158ee842861",
    "feature-mysql.pl": "313b33927811b090e206c0a68fa7bc400bc02eeb5d8bed9b6bc18b3858b25134",
    "feature-web.pl": "81d1c63a04be5d7ea734a318bc5fe2eea91948c8763f3c310291ee17f3ad26f2",
    "feature-ssl.pl": "4dd253f9bbec29b7a0fd7c78b8c542429d6bc211edb50b346482a261d8546fb0",
    "feature-logrotate.pl": "ab55bd1526ab0ff97f5c831dbe32c1b897e1490918dab37601fafbf300df5189",
}
DOMAIN_FIELDS = (
    "id",
    "dom",
    "user",
    "home",
    "uid",
    "gid",
    "parent",
    "alias",
    "mail",
    "dns",
    "unix",
    "web",
    "ssl",
    "db_mysql",
    "disabled",
)
MAX_NATIVE_TEMP_PATH_LENGTH = 1024
NATIVE_DEFAULT_TEMP = "/tmp/.webmin"  # noqa: S108 -- pinned Webmin's private native workspace; read-only capacity discovery


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native component inspection is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


paths = _module("praho-component-paths.py", "component_inspection_paths")
mysql = _module("praho-component-mysql.py", "component_inspection_sql")
cron = _module("praho-component-cron-fence.py", "component_inspection_cron")
capacity = _module("praho-component-capacity.py", "component_inspection_capacity")
defaults = _module("praho-component-default.py", "component_inspection_default")
archives = _module("praho-component-archive.py", "component_inspection_native_config")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _command(arguments: list[str]) -> str:
    result = subprocess.run(  # noqa: S603 -- literal read-only native commands and qualified identities
        arguments,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode or len(result.stdout.encode()) > LIMIT:
        raise ValueError("Native component evidence is unreadable or exceeds its qualification bound")
    return result.stdout


def _read(path: Path, limit: int = LIMIT) -> str:
    if path.resolve() != path:
        raise ValueError("Native component metadata traverses an unqualified symlink")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("Native component metadata must be an owned, protected regular file")
    with path.open() as stream:
        content = stream.read(limit + 1)
    if len(content.encode()) > limit or "\0" in content:
        raise ValueError("Native component metadata exceeds its qualification bound")
    return content


def _fields(path: Path) -> dict[str, str]:
    result = {}
    for line in _read(path).splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in result:
            raise ValueError("Native component metadata is incomplete or duplicated")
        result[key] = value
    return result


def native_temporary_directory() -> Path:
    """The pinned native backup callback uses Webmin's module-specific/global temporary directory."""
    selected: dict[str, str] = {}
    for line in _read(Path("/etc/webmin/config")).splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"tempdir_virtual-server", "tempdir"}:
            if key in selected or len(value) > MAX_NATIVE_TEMP_PATH_LENGTH:
                raise ValueError("Qualify the native temporary directory before exporting selected components")
            selected[key] = value
    return Path(selected.get("tempdir_virtual-server") or selected.get("tempdir") or NATIVE_DEFAULT_TEMP)


def routing_preparation(domain: str, web: str, records: dict[str, list[str]]) -> list[str]:
    preparation = []
    website = {domain, "www." + domain}
    declared = re.findall(r"^\s*ServerName\s+(\S+)\s*$", web, re.MULTILINE | re.IGNORECASE)
    aliases = re.findall(r"^\s*ServerAlias\s+(.+)$", web, re.MULTILINE | re.IGNORECASE)
    if (
        not declared
        or set(declared) != {domain}
        or any(name not in website for line in aliases for name in line.split())
    ):
        preparation.append(
            "Separate retained mail, webmail and administration HTTP names from the selected website vhosts."
        )
    exchanges = [line.split()[-1].rstrip(".").lower() for line in records["mx"] if line.split()]
    if not exchanges or any(name in website for name in exchanges):
        preparation.append("Publish independent explicit MX names before moving the website apex or www address.")
    if any(name.rstrip(".").lower() in website for name in records["mx_cname"]):
        preparation.append(
            "Replace the retained mail exchange alias to the website with an independent source address."
        )
    if not records["mx_addresses"] or records.get("mx_unresolved"):
        preparation.append("Resolve every retained mail exchange independently before changing website routing.")
    for text in records["txt"]:
        normalized = text.replace('" "', "").strip('"')
        if not normalized.lower().startswith("v=spf1 "):
            continue
        for raw in normalized.split()[1:]:
            mechanism = raw.lstrip("+-~?").lower()
            implicit = mechanism == "a" or mechanism.startswith(("a/", "a//"))
            bound = any(
                mechanism.split("/", 1)[0] in {"a:" + name, "include:" + name, "redirect=" + name} for name in website
            )
            if implicit or bound:
                preparation.append(
                    "Replace SPF authorization through the moving website apex with explicit retained mail authorization."
                )
    return sorted(set(preparation))


def web_path_preparation(web: str, home: str, selected: list[dict[str, str]]) -> list[str]:
    """Native web callbacks must not reactivate unselected CGI/files or an unclassified backend."""
    roots = [Path(home) / row["relative"] for row in selected]
    preparation = archives.privileged_web_preparation(web)
    document_roots = []
    for line in web.splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        directive = words[0].lower()
        if (
            directive == "proxypass"
            and len(words) == PATH_ALIAS_FIELDS
            and words[1].startswith("/")
            and words[2] == "!"
        ):
            continue  # Native ACME exclusion: no backend or additional application path is introduced.
        if directive in {
            "scriptalias",
            "scriptaliasmatch",
            "aliasmatch",
            "proxypass",
            "proxypassmatch",
            "include",
            "includeoptional",
        }:
            preparation.append(
                "Prepare independent supported website paths/backends before copying native Apache callbacks ("
                + directive
                + ")."
            )
        elif directive in {"documentroot", "alias"}:
            expected = 2 if directive == "documentroot" else PATH_ALIAS_FIELDS
            if len(words) != expected:
                raise ValueError("Native website path directives require explicit qualification")
            path = Path(words[-1])
            if directive == "documentroot":
                document_roots.append(path)
            if (
                not path.is_absolute()
                or ".." in path.parts
                or not any(path == root or root in path.parents for root in roots)
            ):
                preparation.append(
                    "Include every website document/alias root in selected application paths; retained paths must stay separate."
                )
    if not document_roots:
        preparation.append("Qualify the native website's exact selected document root before migration.")
    return sorted(set(preparation))


def _dns(domain: str, *, local: bool) -> dict[str, list[str]]:
    def query(name: str, kind: str) -> list[str]:
        arguments = ["/usr/bin/dig", "+time=3", "+tries=1", "+short"]
        if local:
            arguments.append("@127.0.0.1")
        return _command([*arguments, name, kind]).splitlines()

    mx = query(domain, "MX")
    records = {
        "mx": mx,
        "txt": query(domain, "TXT"),
        "mx_cname": [],
        "mx_addresses": [],
        "mx_unresolved": [],
        "apex_a": query(domain, "A"),
        "apex_aaaa": query(domain, "AAAA"),
        "www_a": query("www." + domain, "A"),
        "www_aaaa": query("www." + domain, "AAAA"),
    }
    for row in mx:
        fields = row.split()
        if (
            len(fields) != MX_FIELDS
            or not fields[0].isdecimal()
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", fields[1]) is None
        ):
            raise ValueError("Native mail exchange records require inspection before migration")
        name = fields[1].rstrip(".")
        records["mx_cname"].extend(query(name, "CNAME"))
        addresses = [*query(name, "A"), *query(name, "AAAA")]
        records["mx_addresses"].extend(addresses)
        if not addresses:
            records["mx_unresolved"].append(name)
    return records


def _native_domain(request: dict[str, Any]) -> dict[str, str]:
    if (
        re.fullmatch(r"[0-9]{1,30}", request["domain_id"]) is None
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", request["owner"]) is None
    ):
        raise ValueError("An exact native domain and Unix owner are required")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", request["domain"]) is None:
        raise ValueError("An exact native website name is required")
    native = _fields(Path("/etc/webmin/virtual-server/domains") / request["domain_id"])
    if any(
        native.get(key) != request[reviewed]
        for key, reviewed in (("id", "domain_id"), ("dom", "domain"), ("user", "owner"))
    ):
        raise ValueError("Native source domain identity changed")
    if native.get("parent") or native.get("alias") or any(native.get(key) != "1" for key in ("unix", "dir", "web")):
        raise ValueError("Prepare a standalone native website and independent owner before component migration")
    owner = pwd.getpwnam(request["owner"])
    if min(owner.pw_uid, owner.pw_gid) <= 0:
        raise ValueError("A component website requires a non-root native Unix owner and group")
    if (
        native["home"] != "/home/" + owner.pw_name
        or owner.pw_dir != native["home"]
        or (str(owner.pw_uid), str(owner.pw_gid)) != (native["uid"], native["gid"])
    ):
        raise ValueError("Native website Unix ownership or home is inconsistent")
    return native


def _callbacks() -> tuple[dict[str, str], list[str]]:
    module = Path("/usr/share/webmin/virtual-server")
    versions = {
        "webmin": _read(Path("/usr/share/webmin/version")).strip(),
        "virtualmin": _fields(module / "module.info")["version"],
    }
    hashes = {
        name: hashlib.sha256(_read(module / name, MAX_CALLBACK_BYTES).encode()).hexdigest()
        for name in QUALIFIED_CALLBACKS
    }
    preparation = []
    if versions != {"webmin": "2.670", "virtualmin": "8.3.0"} or hashes != QUALIFIED_CALLBACKS:
        preparation.append(
            "Qualify the installed native backup and restore callbacks before migrating website components."
        )
    return versions, preparation


def _path_facts(home: Path, selected: list[dict[str, str]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    scope = paths.scan_paths(home, tuple(row["relative"] for row in selected))
    seen, sizes = set(), {row["relative"]: 0 for row in selected}
    for relative in scope["files"]:
        info = (home / relative).lstat()
        identity = info.st_dev, info.st_ino
        if stat.S_ISREG(info.st_mode) and identity not in seen:
            root = next(root for root in sizes if relative == root or relative.startswith(root + "/"))
            sizes[root] += info.st_size
            seen.add(identity)
    facts = []
    for row in selected:
        info = (home / row["relative"]).lstat()
        facts.append(
            {
                **row,
                "device": info.st_dev,
                "inode": info.st_ino,
                "bytes": sizes[row["relative"]],
                "tree_digest": scope["tree_digest"],
            }
        )  # One qualified inode closure covers cross-root hardlinks.
    return facts, scope


def _writers(native: dict[str, str], scope: dict[str, Any], preparation: list[str]) -> list[dict[str, str]]:
    pool = list(Path("/etc/php").glob("*/fpm/pool.d/" + native["id"] + ".conf"))
    writers = []
    if len(pool) != 1 or native.get("php_mode") != "fpm":
        preparation.append(
            "Prepare a dedicated native PHP-FPM pool; shared or unclassified application services need review."
        )
    else:
        writers.append(
            {
                "kind": "php_fpm_pool",
                "identity": native["id"],
                "digest": hashlib.sha256(_read(pool[0]).encode()).hexdigest(),
            }
        )
    for writer in paths.path_writers(scope["inodes"], native["id"], int(native["uid"])):
        if writer["kind"] != "php_fpm_pool":
            preparation.append(
                "Stop or separately classify an active process holding selected application files before migration."
            )
            writers.append({"kind": "unknown", "identity": "process-" + str(writer["pid"]), "digest": _digest(writer)})
    try:
        paths.qualify_mounts(Path(native["home"]), tuple(row["relative"] for row in scope["selection"]))
    except (ValueError, OSError) as error:
        preparation.append("Prepare independent website mount namespaces: " + str(error))
    path = Path("/etc/cron.d") / ("praho-component-" + native["id"])
    if path.exists() or path.is_symlink():
        jobs = cron.selected_jobs(_read(path), native["user"])
        for job in jobs:
            digest = hashlib.sha256(job.encode()).hexdigest()
            writers.append({"kind": "cron_entry", "identity": "cron-" + digest[:16], "digest": digest})
    return writers


def _owner_cron(owner: str, preparation: list[str]) -> str:
    result = subprocess.run(  # noqa: S603 -- strictly qualified native owner; read-only crontab inventory
        ["/usr/bin/crontab", "-u", owner, "-l"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        env={**os.environ, "LC_ALL": "C"},
    )
    if result.returncode == 1 and not result.stdout and "no crontab for" in result.stderr.lower():
        return _digest("")
    if result.returncode or len(result.stdout.encode()) > cron.MAX_CRON_BYTES:
        raise ValueError("The native owner schedule is unreadable or exceeds its qualification bound")
    jobs = [line for line in result.stdout.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if any(not re.match(r"\s*[A-Za-z_][A-Za-z0-9_]*\s*=", line) for line in jobs):
        preparation.append(
            "Classify shared owner cron jobs and prepare selected website jobs in the independent website schedule; retained owner jobs must remain separate."
        )
    return _digest(result.stdout)


def _related_domains(owner: str) -> list[dict[str, str]]:
    result = []
    for count, path in enumerate(sorted(Path("/etc/webmin/virtual-server/domains").iterdir())):
        if count >= MAX_DOMAINS or not path.name.isdecimal():
            raise ValueError("Native retained-domain inventory is unclassified or exceeds its bound")
        fields = _fields(path)
        if fields.get("user") == owner:
            result.append({key: fields.get(key, "") for key in DOMAIN_FIELDS})
    return result


def shared_website_preparation(native: dict[str, str]) -> list[str]:
    for other in _related_domains(native["user"]):
        if other["id"] == native["id"] or other.get("web") != "1":
            continue
        # A platform account-name child can be excluded only after its owned
        # native parent, disabled state, TLS/config receipts and actual404 prove
        # it cannot execute this application's files or use its database login.
        if re.fullmatch(r"[a-f0-9]{8}\.[A-Za-z0-9.-]+", other["dom"]):
            try:
                neutral = _module("praho-account-name-neutral.py", "component_retained_neutral_alias")
                neutral.NeutralGuard().verify(other["dom"], native["user"], native["dom"], native["id"], other["dom"])
                continue
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        return [
            "Prepare independently classified websites and aliases for other native domains sharing this Unix owner; "
            "a partial file/database hold must not interrupt an unselected application."
        ]
    return []


def retained_path_preparation(native: dict[str, str], selected: list[dict[str, str]]) -> list[str]:
    if native.get("mail") != "1":
        return []
    preparation = []
    roots = [(Path(native["home"]) / row["relative"]).resolve() for row in selected]
    if any(
        native.get(key) and any(Path(native[key]).resolve().is_relative_to(root) for root in roots)
        for key in ("ssl_cert", "ssl_key", "ssl_chain", "ssl_combined", "ssl_everything")
    ):
        preparation.append(
            "Move retained mail TLS certificates and keys outside the selected website paths before migration."
        )
    if (
        native.get("letsencrypt_renew") == "1"
        and any(native.get(key) for key in ("letsencrypt_last", "letsencrypt_last_success", "letsencrypt_last_id"))
        and native.get("dns") != "1"
    ):
        preparation.append(
            "Prepare independent DNS-based or external retained mail certificate renewal before retiring its HTTP website."
        )
    return sorted(set(preparation))


def _mail_dependencies(native: dict[str, str], preparation: list[str]) -> dict[str, str]:
    if native.get("mail") != "1":
        return {}
    postfix = _command(["/usr/sbin/postconf", "-n"])
    dovecot = _command(["/usr/bin/doveconf", "-n"])
    if re.search(r"(?:mysql|pgsql|sqlite|proxy:mysql):", postfix, re.IGNORECASE) or re.search(
        r"\bdriver\s*=\s*(?:sql|ldap)\b", dovecot, re.IGNORECASE
    ):
        preparation.append(
            "Qualify and separate retained mail authentication/database dependencies before migrating selected website databases."
        )
    return {"postfix": _digest(postfix), "dovecot": _digest(dovecot)}


def retained_evidence(native: dict[str, str], records: dict[str, list[str]], preparation: list[str]) -> str:
    """Read only state that component holds are never authorized to change."""
    return _digest(
        {
            "domain": {key: native.get(key, "") for key in DOMAIN_FIELDS},
            "unix_authentication": hashlib.sha256(
                _command(["/usr/bin/getent", "shadow", native["user"]]).encode()
            ).hexdigest(),
            "dns": {
                key: value for key, value in records.items() if key not in {"apex_a", "apex_aaaa", "www_a", "www_aaaa"}
            },
            "owner_domains": _related_domains(native["user"]),
            "owner_cron": _owner_cron(native["user"], preparation),
            "mail_dependencies": _mail_dependencies(native, preparation),
        }
    )


def inspect_source(request: dict[str, Any]) -> dict[str, Any]:
    if (
        str(UUID(request["server_uuid"])) != request["server_uuid"]
        or re.fullmatch(r"[0-9a-f]{64}", request["connection_identity"]) is None
    ):
        raise ValueError("Exact enrolled source connection identity is required")
    native = _native_domain(request)
    versions, preparation = _callbacks()
    preparation.extend(defaults.qualify_default())
    preparation.extend(shared_website_preparation(native))
    selected = request["paths"]
    if not isinstance(selected, list) or any(
        set(row) != {"relative", "purpose"} or row["purpose"] not in {"application", "configuration", "uploads"}
        for row in selected
    ):
        raise ValueError("Select exact application, configuration and upload roots")
    facts, scope = _path_facts(Path(native["home"]), selected)
    scope["selection"] = selected
    writers = _writers(native, scope, preparation)
    selected_databases = tuple(request["databases"])
    native_owned = tuple(native.get("db_mysql", "").split())
    databases = mysql.inspect_databases(selected_databases, native_owned)
    preparation.extend(databases["preparation"])
    try:
        capacity.require_capacity(
            {"paths": facts, "databases": databases["databases"]},
            Path("/var/lib/praho-transfer/components"),
            native_temporary_directory(),
        )
    except ValueError as error:
        preparation.append(str(error))
    try:
        mysql.native_owner_password(native, databases["databases"])
    except ValueError as error:
        preparation.append(str(error))
    web = _read(Path("/etc/apache2/sites-available") / (native["dom"] + ".conf"))
    preparation.extend(web_path_preparation(web, native["home"], selected))
    preparation.extend(retained_path_preparation(native, selected))
    records = _dns(native["dom"], local=native.get("dns") == "1")
    preparation.extend(routing_preparation(native["dom"], web, records))
    retained = retained_evidence(native, records, preparation)
    return {
        "schema": 1,
        "source": {
            "server_uuid": request["server_uuid"],
            "connection_identity": request["connection_identity"],
            "domain_id": native["id"],
            "domain": native["dom"],
            "owner": native["user"],
            "home": native["home"],
            **versions,
        },
        "paths": facts,
        "databases": databases["databases"],
        "writers": writers,
        "routing": {
            "website_names": [native["dom"], "www." + native["dom"]],
            "digest": _digest({"web": web, "dns": records}),
        },
        "retained": {
            "services": [
                "authentication",
                *(name for name in ("mail", "dns") if native.get(name) == "1"),
                *(["mysql"] if set(native_owned) - set(selected_databases) else []),
            ],
            "database_names": sorted(set(native_owned) - set(selected_databases)),
            "digest": retained,
        },
        "preparation": sorted(set(preparation)),
    }


if __name__ == "__main__":
    request = sys.stdin.read(LIMIT + 1)
    if len(request.encode()) > LIMIT:
        raise ValueError("Component selection exceeds its inspection bound")
    print(json.dumps(inspect_source(json.loads(request)), sort_keys=True, separators=(",", ":")))
