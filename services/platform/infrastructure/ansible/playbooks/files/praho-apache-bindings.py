#!/usr/bin/env python3
# PRAHO managed Apache bindings v1
"""Literal Apache address groups shared by root neutral guards and migration bridges.

Definitions are stable in individual guards: refreshing this separately owned file
does not invalidate another name's config digest. Interface addresses are probe
destinations, never an excuse to create a new Apache group over wildcard sites.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import shlex
import stat
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

HEADER = b"# PRAHO managed Apache bindings v1\n"
PORTS = ("80", "443")
SS_LOCAL_ADDRESS_COLUMN = 3
SERVER_NAME_WORDS = 2


def command(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30).stdout  # noqa: S603


def address(value: str) -> str:
    if value == "*":
        return value
    if "%" in value:
        raise ValueError("Scoped Apache bindings are unsupported")
    return str(ipaddress.ip_address(value))


def endpoint(value: str, port: str) -> str:
    return f"[{value}]:{port}" if ":" in value else f"{value}:{port}"


def parse_bindings(value: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for token in value.split():
        match = re.fullmatch(r"(?:\[([^\]]+)\]|([^:\s]+)):(80|443)", token)
        if not match:
            raise ValueError("Unsupported non-literal Apache binding")
        result.setdefault(match[3], []).append(address(match[1] or match[2]))
    if not result:
        raise ValueError("Apache virtual host has no literal bindings")
    return {port: sorted(set(values)) for port, values in result.items()}


class ApacheBindings:
    parse = staticmethod(parse_bindings)
    endpoint = staticmethod(endpoint)

    def __init__(self, root: Path = Path("/"), *, execute: Callable[[list[str]], str] = command, owner_uid: int = 0):
        self.root, self.execute, self.owner_uid = root, execute, owner_uid
        self.state = root / "var/lib/praho/apache-bindings"
        self.conf, self.sites = root / "etc/apache2/conf-enabled", root / "etc/apache2/sites-enabled"
        self.configuration = self.conf / "praho-00-neutral-bindings.conf"
        self.metadata = self.state / "state.json"
        self.pending = self.state / "pending.json"
        self.in_transaction = False

    def directory(self, path: Path, *, private: bool = False) -> None:
        if path != self.root:
            self.directory(path.parent)
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o700 if private else 0o755)
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_mode & (0o077 if private else 0o022)
        ):
            raise ValueError("Apache binding directory is not safely owned")

    def read(self, path: Path, mode: int) -> bytes:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_mode & (0o077 if not mode & 0o077 else 0o022)
        ):
            raise ValueError("Apache binding file is not safely owned")
        return path.read_bytes()

    def write(self, path: Path, content: bytes, mode: int) -> None:
        if path.exists() or path.is_symlink():
            self.read(path, mode)
        fd, temporary = tempfile.mkstemp(dir=path.parent, prefix="." + path.name)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def install(self) -> None:
        self.directory(self.state, private=True)
        library = self.state / "library.py"
        if (
            library.exists()
            and b"# PRAHO managed Apache bindings v1\n" not in self.read(library, 0o600).splitlines(keepends=True)[:2]
        ):
            raise ValueError("Apache binding library is not managed")
        self.write(library, Path(__file__).read_bytes(), 0o700)

    @contextmanager
    def transaction(self, extra_paths: dict[Path, int] | None = None) -> Iterator[None]:
        self.directory(self.state, private=True)
        descriptor = os.open(self.state / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a+") as lock:
            self.read(self.state / ".lock", 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if self.pending.exists():
                self.restore(json.loads(self.read(self.pending, 0o600)))
                self.reload()
                self.clear_pending()
            paths = {self.configuration: 0o644, self.metadata: 0o600, **(extra_paths or {})}
            snapshot = [
                {
                    "path": str(path),
                    "mode": mode,
                    "value": self.read(path, mode).hex() if path.exists() or path.is_symlink() else None,
                }
                for path, mode in paths.items()
            ]
            # Durable rollback journal: a killed dispatcher cannot silently adopt
            # a config that has not passed configtest and the consumer's probes.
            self.write(self.pending, json.dumps(snapshot).encode(), 0o600)
            self.in_transaction = True
            completed = False
            try:
                yield
                completed = True
            finally:
                try:
                    if not completed and any(
                        (Path(item["path"]).read_bytes().hex() if Path(item["path"]).exists() else None)
                        != item["value"]
                        for item in snapshot
                    ):
                        self.restore(snapshot)
                        self.reload()
                    self.clear_pending()
                finally:
                    self.in_transaction = False

    def clear_pending(self) -> None:
        self.pending.unlink()
        descriptor = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def restore(self, snapshot: list[dict[str, Any]]) -> None:
        for item in snapshot:
            path = Path(item["path"])
            if path not in {self.configuration, self.metadata} and not (
                self.root in path.parents and (self.conf in path.parents or self.root / "var/lib/praho" in path.parents)
            ):
                raise ValueError("Apache rollback journal has an unexpected path")
            if item["value"] is None:
                if path.exists() or path.is_symlink():
                    self.read(path, item["mode"])
                    path.unlink()
            else:
                self.write(path, bytes.fromhex(item["value"]), item["mode"])

    def observed(self) -> dict[str, list[str]]:
        groups = {port: {"*"} for port in PORTS}
        for directory in (self.conf, self.sites):
            for path in sorted(directory.glob("*.conf")):
                if path.name == "praho-default-site.conf" or path.name.startswith(
                    ("praho-neutral-", "praho-00-neutral-")
                ):
                    continue
                # Native sites are commonly root-owned symlinks into sites-available.
                target = path.resolve(strict=True)
                text = self.read(target, 0o644).decode()
                for value in re.findall(r"^\s*<VirtualHost\s+([^>]+)>", text, re.I | re.M):
                    for port, values in parse_bindings(value).items():
                        groups[port].update(values)
        return {port: sorted(values) for port, values in groups.items()}

    def render(self, groups: dict[str, list[str]]) -> bytes:
        text = HEADER.decode()
        for port, token in (("80", "HTTP"), ("443", "HTTPS")):
            values = " ".join(endpoint(value, port) for value in groups[port])
            text += f'Define PRAHO_NEUTRAL_{token}_BINDINGS "{values}"\n'
        common = (
            "ServerName praho-default.invalid\nDocumentRoot /var/www/praho-default\n"
            'ErrorDocument 404 "Not Found"\n'
            "<Directory /var/www/praho-default>\nAllowOverride None\nRequire all granted\n</Directory>\n"
        )
        return (
            text
            + "<VirtualHost ${PRAHO_NEUTRAL_HTTP_BINDINGS}>\n"
            + common
            + "RedirectMatch 404 ^/(?!\\.well-known/acme-challenge/[A-Za-z0-9_-]+$)\n</VirtualHost>\n"
            "<VirtualHost ${PRAHO_NEUTRAL_HTTPS_BINDINGS}>\n" + common + "RedirectMatch 404 ^\nSSLEngine on\n"
            "SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem\n"
            "SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key\n</VirtualHost>\n"
        ).encode()

    def current(self) -> dict[str, list[str]]:
        if self.pending.exists() and not self.in_transaction:
            raise ValueError("Apache binding refresh is incomplete")
        value = json.loads(self.read(self.metadata, 0o600))
        if value.get("version") != 1 or hashlib.sha256(self.read(self.configuration, 0o644)).hexdigest() != value.get(
            "sha256"
        ):
            raise ValueError("Apache binding config digest changed")
        groups = value["groups"]
        for port in PORTS:
            if parse_bindings(" ".join(endpoint(item, port) for item in groups[port])) != {port: groups[port]}:
                raise ValueError("Apache binding snapshot changed")
        return groups

    def refresh(self) -> bool:
        self.directory(self.conf)
        if self.metadata.exists():
            # During our transaction pending exists, but digest ownership still
            # has to hold before refreshing the separately owned definitions.
            state = json.loads(self.read(self.metadata, 0o600))
            if hashlib.sha256(self.read(self.configuration, 0o644)).hexdigest() != state.get("sha256"):
                raise ValueError("Apache binding config digest changed")
        elif self.configuration.exists() or self.configuration.is_symlink():
            raise ValueError("Apache binding config has no managed ownership record")
        groups = self.observed()
        body = self.render(groups)
        changed = not self.configuration.exists() or self.read(self.configuration, 0o644) != body
        self.write(self.configuration, body, 0o644)
        self.write(
            self.metadata,
            json.dumps(
                {"version": 1, "groups": groups, "sha256": hashlib.sha256(body).hexdigest()}, sort_keys=True
            ).encode(),
            0o600,
        )
        return changed

    def reload(self) -> None:
        self.execute(["apache2ctl", "configtest"])
        self.execute(["apache2ctl", "graceful"])

    def local_addresses(self) -> list[str]:
        records = json.loads(self.execute(["ip", "-j", "address", "show"]))
        return list(
            dict.fromkeys(
                str(ipaddress.ip_address(item["local"]))
                for record in records
                for item in record.get("addr_info", [])
                if "%" not in item.get("local", "") and not ipaddress.ip_address(item["local"]).is_link_local
            )
        )

    def probe_addresses(self, bindings: dict[str, list[str]], port: str) -> list[str]:
        values = bindings.get(port, [])
        return list(
            dict.fromkeys(
                [
                    *(self.listening_addresses(port) if "*" in values else []),
                    *(value for value in values if value != "*"),
                ]
            )
        )

    def listening_addresses(self, port: str) -> list[str]:
        listeners = []
        for family, option in ((4, "-4"), (6, "-6")):
            for line in self.execute(["ss", "-H", "-lnt", option]).splitlines():
                words = line.split()
                if len(words) <= SS_LOCAL_ADDRESS_COLUMN:
                    continue
                host, _, service = words[SS_LOCAL_ADDRESS_COLUMN].rpartition(":")
                host = host.strip("[]")
                if service == port and (host == "*" or ipaddress.ip_address(host).version == family):
                    listeners.append((host, family))
        return [
            value
            for value in self.local_addresses()
            if any(
                ipaddress.ip_address(value).version == family and listener in {value, "*", "0.0.0.0", "::"}
                for listener, family in listeners
            )
        ]

    def http_backend(self, bindings: list[str], all_groups: dict[str, list[str]]) -> str:
        local = self.listening_addresses("80")
        candidates = [value for value in bindings if value != "*" and value in local]
        if "*" in bindings:
            candidates.extend(value for value in local if value not in all_groups["80"])
        if not candidates:
            raise ValueError("The target HTTP binding has no safe local address")
        return candidates[0]

    def native_endpoints(self, name: str) -> dict[str, list[str]]:
        """Read the actual native groups without creating state or changing Apache."""
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", name):
            raise ValueError("Invalid native binding name")
        groups: dict[str, set[str]] = {}
        for path in sorted(self.sites.glob("*.conf")):
            for raw, body in re.findall(
                r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>",
                self.read(path.resolve(strict=True), 0o644).decode(),
                re.S | re.I,
            ):
                names = [
                    parts[1]
                    for line in body.splitlines()
                    if (parts := shlex.split(line, comments=True))
                    and parts[0].lower() == "servername"
                    and len(parts) == SERVER_NAME_WORDS
                ]
                if len(names) != 1 or names[0].lower() != name.lower():
                    continue
                for port, values in parse_bindings(raw).items():
                    groups.setdefault(port, set()).update(values)
        endpoints = {port: self.probe_addresses({port: sorted(values)}, port) for port, values in groups.items()}
        if "80" not in endpoints or not all(endpoints.values()):
            raise ValueError("The native HTTP binding surface cannot be proved")
        return endpoints


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Apache binding library requires root")
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["install", "addresses", "endpoints"], nargs="?", default="install")
    parser.add_argument("--name")
    arguments = parser.parse_args()
    policy = ApacheBindings()
    if arguments.action == "install":
        policy.install()
    else:
        endpoints = policy.native_endpoints(arguments.name or "")
        if arguments.action == "addresses":
            print("\n".join(dict.fromkeys(value for addresses in endpoints.values() for value in addresses)))
        else:
            print("\n".join(port + "\t" + value for port, addresses in endpoints.items() for value in addresses))
