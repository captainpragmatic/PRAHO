#!/usr/bin/env python3
# PRAHO managed account-name neutral helper v1
"""Root-owned account-name vhosts. Native credentials/private TLS never leave the node.

Receipt config_sha256 = SHA256(zone config bytes + NUL + named config bytes), with
empty named bytes before native creation and after retirement. Certificate digests
are SHA256 of the DER leaf, not private material. A read-only verify command is
also used by write barriers; namespace fallback alone is never per-child proof.
"""

from __future__ import annotations

import _ssl
import argparse
import base64
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
import re
import shlex
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

MANAGED = "# PRAHO account-name neutral v1\n"
BODY = b"Not Found"
MAX_STATE_BYTES = 16384
MAX_DNS_LENGTH = 253
HTTPS_PORT = 443
NOT_FOUND = 404


def command(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True, input="", timeout=30).stdout  # noqa: S603


def dns_name(value: str) -> str:
    if (
        value != value.lower()
        or len(value) > MAX_DNS_LENGTH
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value)
    ):
        raise ValueError("Invalid neutral DNS name")
    return value


def validate(zone: str, name: str, owner: str, identity: str | None = None, *, allow_empty_owner: bool = False) -> None:
    dns_name(zone)
    dns_name(name)
    if not re.fullmatch(r"[a-z0-9]{8}\." + re.escape(zone), name):
        raise ValueError("The provider name is not a direct opaque child of its zone")
    if not (allow_empty_owner and owner == "") and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", owner):
        raise ValueError("Invalid neutral owner")
    if identity is not None and str(UUID(identity)) != identity:
        raise ValueError("Invalid neutral identity")


def leaf_fingerprint(certificate: bytes) -> str:
    match = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", certificate, re.S)
    if match is None or b"PRIVATE KEY" in certificate:
        raise ValueError("Invalid public neutral certificate bundle")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(match[0].decode("ascii"))).hexdigest()


def probe_response(  # noqa: PLR0913  # One TLS identity and its actual HTTP/HTTPS probe destinations.
    *, name: str, host: str, certificate: Path, certificate_sha256: str, named: bool, addresses: dict[str, list[str]]
) -> None:
    """Both hops are local; TLS always verifies its anchor and exact leaf, plus DNS for named guards."""
    for port, address in ((int(port), address) for port, values in addresses.items() for address in values):
        connection = http.client.HTTPConnection(address, port, timeout=8)
        try:
            if port == HTTPS_PORT:
                context = ssl.create_default_context()
                context.load_verify_locations(cafile=str(certificate))
                # Unclaimed names deliberately use the node's pinned snakeoil fallback.
                # They have no advertised certificate readiness; named guards always check DNS.
                context.check_hostname = named
                with socket.create_connection((address, port), timeout=8) as raw:
                    connection.sock = context.wrap_socket(raw, server_hostname=name)
                actual = connection.sock.getpeercert(binary_form=True)
                if actual is None or hashlib.sha256(actual).hexdigest() != certificate_sha256:
                    raise ValueError("The neutral TLS leaf pin changed")
            connection.request("GET", "/__praho_neutral_probe__", headers={"Host": host, "Connection": "close"})
            response = connection.getresponse()
            body = response.read(129)
            if (
                response.status != NOT_FOUND
                or body != BODY
                or response.getheader("Set-Cookie")
                or response.getheader("Location")
            ):
                raise ValueError("The neutral response is not an exact fixed 404")
        finally:
            connection.close()


class NeutralGuard:
    def __init__(
        self,
        root: Path = Path("/"),
        *,
        execute: Callable[[list[str]], str] = command,
        probe: Callable[..., None] = probe_response,
    ) -> None:
        self.root = root
        self.state = root / "var/lib/praho/account-name-neutral"
        self.conf = root / "etc/apache2/conf-enabled"
        self.sites = root / "etc/apache2/sites-enabled"
        self.native_domains = root / "etc/webmin/virtual-server/domains"
        self.webroot = root / "var/www/praho-account-name-neutral"
        self.snakeoil_certificate = root / "etc/ssl/certs/ssl-cert-snakeoil.pem"
        self.snakeoil_key = root / "etc/ssl/private/ssl-cert-snakeoil.key"
        self.owner_uid = 0
        self.execute = execute
        self.probe = probe
        self.binding_policy = None

    def bindings(self) -> Any:
        if self.binding_policy is None:
            library = Path(__file__).with_name("praho-apache-bindings.py")
            if not library.exists():
                library = self.root / "var/lib/praho/apache-bindings/library.py"
                self.directory(library.parent, create=False)
                self.regular(library, private=True)
            spec = importlib.util.spec_from_file_location("praho_apache_bindings", library)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.binding_policy = module.ApacheBindings(self.root, execute=self.execute, owner_uid=self.owner_uid)
        return self.binding_policy

    def native_bindings(self, name: str) -> dict[str, list[str]]:
        result: dict[str, set[str]] = {"80": set(), "443": set()}
        policy = self.bindings()
        for path in sorted(self.sites.glob("*.conf")):
            for ports, body in re.findall(
                r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>", self.regular(path, follow=True).decode(), re.S | re.I
            ):
                names = re.findall(r"^\s*ServerName\s+(\S+)\s*$", body, re.I | re.M)
                if names != [name]:
                    continue
                parsed = policy.parse(ports)
                for port, values in parsed.items():
                    result[port].update(values)
        if not all(result.values()):
            raise ValueError("The native name has no complete literal HTTP/TLS bindings")
        return {port: sorted(values) for port, values in result.items()}

    @contextmanager
    def configuration_transaction(self, zone: str, name: str) -> Iterator[None]:
        paths = {
            self.config_path("zone", zone): 0o644,
            self.config_path("name", name): 0o644,
            self.state / "names" / name / "state.json": 0o600,
        }
        self.pending_prunes = []
        try:
            with self.bindings().transaction(paths):
                yield
            # Old keys are collected only after config/state/probes have committed;
            # rollback must always retain every key referenced by the old config.
            for directory, keep in self.pending_prunes:
                self._prune_versions(directory, keep)
        finally:
            self.pending_prunes = None

    def directory(self, path: Path, *, private: bool = True, create: bool = True) -> None:
        ancestor = path.parent
        while ancestor != self.root and self.root in ancestor.parents:
            if ancestor.exists() or ancestor.is_symlink():
                info = ancestor.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o022:
                    raise ValueError("The neutral directory has an unsafe ancestor")
            ancestor = ancestor.parent
        if not path.exists() and not path.is_symlink():
            if not create:
                raise ValueError("The private neutral directory is absent")
            if not path.parent.exists():
                self.directory(path.parent, private=False)
            path.mkdir(mode=0o700 if private else 0o755)
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_mode & (0o077 if private else 0o022)
        ):
            raise ValueError("The neutral directory is unsafe or a symlink")

    def regular(self, path: Path, *, private: bool = False, follow: bool = False) -> bytes:
        info = path.stat() if follow else path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != self.owner_uid
            or info.st_mode & (0o077 if private else 0o022)
        ):
            raise ValueError(
                "The neutral file is not privately owned" if private else "The neutral file is not root-owned"
            )
        return path.read_bytes()

    @contextmanager
    def locked(self, *, create: bool = True) -> Iterator[None]:
        self.directory(self.state, create=create)
        lock_path = self.state / ".lock"
        flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0)
        descriptor = os.open(lock_path, flags, 0o600)
        with os.fdopen(descriptor, "a+") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o077:
                raise ValueError("The neutral lock is not private owned state")
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            yield

    def write(self, path: Path, value: bytes, *, mode: int = 0o600) -> bool:
        if path.exists() or path.is_symlink():
            previous = self.regular(path, private=not mode & 0o077)
            if previous == value:
                return False
        descriptor, scratch = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(scratch, path)
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            Path(scratch).unlink(missing_ok=True)
        return True

    def json_write(self, path: Path, value: dict[str, Any]) -> None:
        self.write(path, json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    def json_read(self, path: Path) -> dict[str, Any]:
        value = self.regular(path, private=True)
        if len(value) > MAX_STATE_BYTES:
            raise ValueError("The neutral state is too large")
        result = json.loads(value)
        if not isinstance(result, dict) or result.get("version") != 1 or type(result["version"]) is not int:
            raise ValueError("The neutral state version is invalid")
        return result

    def install_helper(self) -> None:
        target = self.state / "helper.py"
        if target.exists() and not self.regular(target).startswith(
            b"#!/usr/bin/env python3\n# PRAHO managed account-name neutral helper v1\n"
        ):
            raise ValueError("The fixed neutral helper is not managed state")
        self.write(target, Path(__file__).read_bytes(), mode=0o700)

    def config_path(self, kind: str, value: str) -> Path:
        order = "10-name" if kind == "name" else "20-zone"
        return self.conf / f"praho-neutral-{order}-{hashlib.sha256(value.encode()).hexdigest()}.conf"

    def render(self, kind: str, zone: str, name: str, certificate: Path, key: Path) -> bytes:
        value = name if kind == "name" else zone
        token = f"PRAHO_NEUTRAL_{kind.upper()}_{hashlib.sha256(value.encode()).hexdigest()}"
        head = f"{MANAGED}# kind={kind} zone={zone} name={name if kind == 'name' else '-'}\n"
        define = f"Define {token} {value}\nDefine {token}_ALIASES *.{value}\n"
        common = (
            f"    ServerName ${{{token}}}\n    ServerAlias ${{{token}_ALIASES}}\n"
            f"    DocumentRoot {self.webroot}\n    RewriteEngine Off\n    RewriteOptions IgnoreInherit\n"
            '    Redirect 404 /\n    ErrorDocument 404 "Not Found"\n    ErrorDocument 503 "Not Found"\n'
            f"    <Directory {self.webroot}>\n        AllowOverride None\n        Require all denied\n    </Directory>\n"
        )
        return (
            head + define + f"<VirtualHost ${{PRAHO_NEUTRAL_HTTP_BINDINGS}}>\n{common}</VirtualHost>\n"
            f"<VirtualHost ${{PRAHO_NEUTRAL_HTTPS_BINDINGS}}>\n{common}    SSLEngine on\n    SSLCertificateFile {certificate}\n"
            f"    SSLCertificateKeyFile {key}\n</VirtualHost>\n"
        ).encode()

    def managed_config(self, path: Path, value: bytes) -> bool:
        if path.exists() or path.is_symlink():
            previous = self.regular(path)
            binding = value.splitlines()[:2]
            if previous.splitlines()[:2] != binding:
                raise ValueError("The neutral config is not managed by this binding")
        return self.write(path, value, mode=0o644)

    def native(self, name: str, owner: str) -> dict[str, str] | None:
        names = self.execute(["virtualmin", "list-domains", "--name-only"]).splitlines()
        if name not in names:
            return None
        actual_owner = self.execute(["virtualmin", "list-domains", "--domain", name, "--user-only"]).strip()
        domain_id = self.execute(["virtualmin", "list-domains", "--domain", name, "--id-only"]).strip()
        if actual_owner != owner or not domain_id.isdigit():
            raise ValueError("The native provider name has a different owner or identity")
        values = self.domain_fields(domain_id)
        parent_id = values.get("parent", "")
        if values.get("dom") != name or values.get("user") != owner or not parent_id.isdigit():
            raise ValueError("The native provider name is not an owned child")
        parent = self.domain_fields(parent_id)
        if parent.get("user") != owner or parent.get("parent") or not parent.get("dom"):
            raise ValueError("The native provider name has a different parent")
        return {"native_domain_id": domain_id, "native_parent_id": parent_id, "native_parent_domain": parent["dom"]}

    def domain_fields(self, identity: str) -> dict[str, str]:
        contents = self.regular(self.native_domains / identity).decode()
        return {
            key: value
            for line in contents.splitlines()
            if "=" in line
            for key, value in [line.split("=", 1)]
            if key in {"dom", "user", "parent"}
        }

    def tls_identity(
        self, certificate: Path, key: Path, name: str, *, allow_expired: bool = False, private: bool = False
    ) -> tuple[str, bool]:
        """Expiry is classified only after ownership, DNS, notBefore and keypair checks."""
        bundle = self.regular(certificate, private=private, follow=not private)
        self.regular(key, private=private, follow=not private)
        info = _ssl._test_decode_cert(str(certificate))
        names = [value for kind, value in info.get("subjectAltName", ()) if kind == "DNS"]
        if not names:
            names = [value for group in info["subject"] for kind, value in group if kind == "commonName"]
        if not any(
            value.lower() == name or (value.startswith("*.") and value[2:].lower() == name.split(".", 1)[1])
            for value in names
        ):
            raise ValueError("The neutral certificate does not cover the provider name")
        if ssl.cert_time_to_seconds(info["notBefore"]) > time.time():
            raise ValueError("The neutral certificate is not yet valid")
        public = self.execute(["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"])
        if public != self.execute(["openssl", "pkey", "-in", str(key), "-pubout"]):
            raise ValueError("The neutral certificate and private key differ")
        expired = time.time() >= ssl.cert_time_to_seconds(info["notAfter"])
        if expired and not allow_expired:
            raise ValueError("The neutral certificate is expired")
        return leaf_fingerprint(bundle), expired

    def native_tls(self, name: str, *, allow_expired: bool = False) -> tuple[bytes, bytes, str, bool]:
        for path in sorted(self.sites.glob("*.conf")):
            contents = self.regular(path, follow=True).decode()
            for ports, body in re.findall(r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>", contents, re.S | re.I):
                if not any(port.endswith(":443") for port in ports.split()):
                    continue
                directives: dict[str, list[str]] = {}
                for line in body.splitlines():
                    parts = shlex.split(line, comments=True)
                    if parts:
                        directives.setdefault(parts[0].lower(), []).extend(parts[1:])
                if directives.get("servername") != [name]:
                    continue
                certificate = Path(directives["sslcertificatefile"][0])
                key = Path(directives["sslcertificatekeyfile"][0])
                bundle = self.regular(certificate, follow=True)
                for chain in directives.get("sslcertificatechainfile", []):
                    if Path(chain) != certificate:
                        bundle += self.regular(Path(chain), follow=True)
                private_key = self.regular(key, follow=True)
                fingerprint, expired = self.tls_identity(certificate, key, name, allow_expired=allow_expired)
                if leaf_fingerprint(bundle) != fingerprint:
                    raise ValueError("The native certificate changed while it was captured")
                return bundle, private_key, fingerprint, expired
        raise ValueError("The native provider name has no discoverable TLS vhost")

    def zone(self, zone: str, name: str) -> tuple[Path, bool]:
        self.directory(self.conf, private=False, create=False)
        self.directory(self.webroot, private=False)
        default = self.regular(self.conf / "praho-default-site.conf")
        if b"ServerName praho-default.invalid" not in default:
            raise ValueError("The neutral default site must be installed first")
        self.regular(self.snakeoil_certificate, follow=True)
        self.regular(self.snakeoil_key, follow=True)
        path = self.config_path("zone", zone)
        changed = self.bindings().refresh()
        return path, self.managed_config(
            path, self.render("zone", zone, name, self.snakeoil_certificate, self.snakeoil_key)
        ) or changed

    def name_directory(self, name: str, *, create: bool = True) -> Path:
        self.directory(self.state / "names", create=create)
        directory = self.state / "names" / name
        self.directory(directory, create=create)
        return directory

    def owned_manifest(self, directory: Path, zone: str, name: str, owner: str) -> dict[str, Any] | None:
        path = directory / "state.json"
        if not path.exists() and not path.is_symlink():
            return None
        value = self.json_read(path)
        if any(value.get(key) != expected for key, expected in {"zone": zone, "name": name, "owner": owner}.items()):
            raise ValueError("The neutral state belongs to a different owner or name")
        return value

    def reload(self) -> None:
        self.execute(["apache2ctl", "configtest"])
        self.execute(["apache2ctl", "graceful"])

    def prove(self, name: str, certificate: Path, fingerprint: str, *, named: bool, host: str | None = None) -> None:
        policy = self.bindings()
        groups = policy.current()
        # The native child may have been deleted already. Its original literal
        # destinations remain part of retirement proof even after group refresh.
        state = self.state / "names" / name / "state.json"
        if state.exists():
            previous = self.json_read(state).get("native_bindings", {})
            groups = {port: sorted(set(groups[port]) | set(previous.get(port, []))) for port in ("80", "443")}
        addresses = {port: policy.probe_addresses(groups, port) for port in ("80", "443")}
        if not all(addresses.values()):
            raise ValueError("The neutral guard has no real binding probe destinations")
        hosts = [host] if host is not None else [name, "webmail." + name, "admin." + name, "probe.sub." + name]
        for requested in hosts:
            self.probe(
                name=name,
                host=requested,
                certificate=certificate,
                certificate_sha256=fingerprint,
                named=named,
                addresses=addresses,
            )

    def receipt(self, identity: str, action: str, zone: str, name: str, certificate: str = "") -> dict[str, Any]:
        zone_bytes = self.regular(self.config_path("zone", zone))
        named_path = self.config_path("name", name)
        named_bytes = self.regular(named_path) if named_path.exists() else b""
        result = {
            "version": 1,
            "identity": identity,
            "action": action,
            "zone": zone,
            "name": name,
            "neutral": True,
            "config_sha256": hashlib.sha256(zone_bytes + b"\0" + named_bytes).hexdigest(),
        }
        if certificate:
            result["certificate_sha256"] = certificate
        return result

    def prune_versions(self, directory: Path, keep: Path | None = None) -> None:
        if getattr(self, "pending_prunes", None) is not None:
            self.pending_prunes.append((directory, keep))
            return
        self._prune_versions(directory, keep)

    def _prune_versions(self, directory: Path, keep: Path | None = None) -> None:
        versions = directory / "versions"
        if not versions.exists():
            return
        self.directory(versions, create=False)
        candidates = list(versions.iterdir())
        for candidate in candidates:
            self.directory(candidate, create=False)
            if not re.fullmatch(r"[0-9a-f]{64}", candidate.name):
                raise ValueError("The private neutral TLS directory contains unowned state")
            if candidate == keep:
                continue
            for path in candidate.iterdir():
                if path.name not in {"chain.pem", "key.pem"}:
                    raise ValueError("The private neutral TLS directory contains unowned state")
                self.regular(path, private=True)
        for candidate in candidates:
            if candidate == keep:
                continue
            for path in candidate.iterdir():
                path.unlink()
            candidate.rmdir()

    def ensure(self, identity: str, zone: str, name: str, owner: str) -> dict[str, Any]:
        return self.install(identity, zone, name, owner, action="ensure")

    def prepare(self, identity: str, zone: str, name: str, owner: str) -> dict[str, Any]:
        """Prove privacy before a certificate install; this receipt never claims certificate readiness."""
        return self.install(identity, zone, name, owner, action="prepare")

    def install(self, identity: str, zone: str, name: str, owner: str, *, action: str) -> dict[str, Any]:
        validate(zone, name, owner, identity)
        with self.locked(), self.configuration_transaction(zone, name):
            self.install_helper()
            zone_path, changed = self.zone(zone, name)
            native = self.native(name, owner)
            directory = self.name_directory(name)
            previous = self.owned_manifest(directory, zone, name, owner)
            if native is None:
                if self.config_path("name", name).exists() or (previous and previous.get("phase") == "ready"):
                    raise ValueError("An absent native name still has a named guard; retire it first")
                if changed:
                    self.reload()
                self.prove(
                    name,
                    self.snakeoil_certificate,
                    leaf_fingerprint(self.regular(self.snakeoil_certificate, follow=True)),
                    named=False,
                )
                return self.receipt(identity, action, zone, name)
            bundle, key, fingerprint, expired = self.native_tls(name, allow_expired=action == "prepare")
            if expired:
                return self.prepare_expired(
                    identity, zone, name, owner, native, previous, directory, zone_path, changed
                )
            versions = directory / "versions"
            self.directory(versions)
            version = versions / hashlib.sha256(bundle).hexdigest()
            self.directory(version)
            self.write(version / "chain.pem", bundle)
            self.write(version / "key.pem", key)
            # Validate the captured pair before making Apache reference it; a
            # concurrent native rotation must not publish mismatched PEM files.
            copied, _expired = self.tls_identity(version / "chain.pem", version / "key.pem", name, private=True)
            if copied != fingerprint:
                raise ValueError("The copied neutral certificate changed")
            named_path = self.config_path("name", name)
            changed = (
                self.managed_config(
                    named_path, self.render("name", zone, name, version / "chain.pem", version / "key.pem")
                )
                or changed
            )
            if changed:
                self.reload()
            self.prove(name, version / "chain.pem", fingerprint, named=True)
            value = {
                **self.named_state("ready", zone, name, owner, native, zone_path, named_path),
                "certificate_sha256": fingerprint,
            }
            self.json_write(directory / "state.json", value)
            self.prune_versions(directory, version)
            return self.receipt(identity, action, zone, name, fingerprint if action == "ensure" else "")

    def named_state(  # noqa: PLR0913  # One immutable owner/native binding and its installed config paths.
        self, phase: str, zone: str, name: str, owner: str, native: dict[str, str], zone_path: Path, named_path: Path
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "phase": phase,
            "zone": zone,
            "name": name,
            "owner": owner,
            **native,
            "native_bindings": self.native_bindings(name),
            "zone_config_path": str(zone_path),
            "zone_config_sha256": hashlib.sha256(zone_path.read_bytes()).hexdigest(),
            "named_config_path": str(named_path),
            "named_config_sha256": hashlib.sha256(named_path.read_bytes()).hexdigest(),
        }

    def existing_tls(self, previous: dict[str, Any], directory: Path, name: str) -> tuple[Path, str, bool]:
        values: dict[str, str] = {}
        for line in self.regular(Path(previous["named_config_path"])).decode().splitlines():
            parts = shlex.split(line, comments=True)
            if parts and parts[0].lower() in {"sslcertificatefile", "sslcertificatekeyfile"}:
                directive, value = parts
                values[directive.lower()] = value
        certificate = Path(values["sslcertificatefile"])
        key = Path(values["sslcertificatekeyfile"])
        versions = directory / "versions"
        if (
            certificate.name != "chain.pem"
            or key != certificate.with_name("key.pem")
            or certificate.parent.parent != versions
            or not re.fullmatch(r"[0-9a-f]{64}", certificate.parent.name)
        ):
            raise ValueError("The existing neutral TLS paths are not owned")
        self.directory(versions, create=False)
        self.directory(certificate.parent, create=False)
        fingerprint, expired = self.tls_identity(certificate, key, name, allow_expired=True, private=True)
        if fingerprint != previous.get("certificate_sha256"):
            raise ValueError("The existing neutral certificate fingerprint changed")
        return certificate, fingerprint, expired

    def prepare_expired(  # noqa: PLR0913  # A locked expiry repair uses the already-validated owner/native/config scope.
        self,
        identity: str,
        zone: str,
        name: str,
        owner: str,
        native: dict[str, str],
        previous: dict[str, Any] | None,
        directory: Path,
        zone_path: Path,
        changed: bool,
    ) -> dict[str, Any]:
        if previous and previous.get("phase") in {"ready", "bootstrap"}:
            self.verify_configs(previous, zone, name)
            if any(previous.get(key) != value for key, value in native.items()):
                raise ValueError("The prepared neutral native identity changed")
            if previous["phase"] == "ready":
                certificate, fingerprint, expired = self.existing_tls(previous, directory, name)
                if not expired:
                    if changed:
                        self.reload()
                    self.prove(name, certificate, fingerprint, named=True)
                    return self.receipt(identity, "prepare", zone, name)
        elif previous and previous.get("phase") != "retired":
            raise ValueError("The existing neutral preparation state is unknown")
        elif previous is None and (directory / "versions").exists():
            raise ValueError("The existing neutral TLS versions have no owned binding")
        named_path = self.config_path("name", name)
        changed = (
            self.managed_config(
                named_path, self.render("name", zone, name, self.snakeoil_certificate, self.snakeoil_key)
            )
            or changed
        )
        if changed:
            self.reload()
        self.prove(
            name,
            self.snakeoil_certificate,
            leaf_fingerprint(self.regular(self.snakeoil_certificate, follow=True)),
            named=False,
        )
        self.json_write(
            directory / "state.json", self.named_state("bootstrap", zone, name, owner, native, zone_path, named_path)
        )
        return self.receipt(identity, "prepare", zone, name)

    def retire(self, identity: str, zone: str, name: str, owner: str) -> dict[str, Any]:
        validate(zone, name, owner, identity, allow_empty_owner=True)
        with self.locked(), self.configuration_transaction(zone, name):
            self.install_helper()
            # An orphaned row has no trustworthy username. Check absence before
            # deriving any owner from our private ready binding.
            if name in self.execute(["virtualmin", "list-domains", "--name-only"]).splitlines():
                raise ValueError("The native provider child still exists")
            _zone_path, changed = self.zone(zone, name)
            directory = self.name_directory(name)
            named_path = self.config_path("name", name)
            metadata_path = directory / "state.json"
            previous = self.json_read(metadata_path) if metadata_path.exists() or metadata_path.is_symlink() else None
            effective_owner = owner or (previous.get("owner", "") if previous else "")
            validate(zone, name, effective_owner, allow_empty_owner=not previous or previous.get("phase") == "retired")
            self.owned_manifest(directory, zone, name, effective_owner)
            if previous and previous.get("phase") in {"ready", "bootstrap"}:
                self.verify_configs(previous, zone, name, allow_missing_name=True)
                # Replay after unlink must still retire the in-memory vhost
                # before removing its private key and certificate.
                changed = True
            elif previous and previous.get("phase") != "retired":
                raise ValueError("The neutral retirement state is not ready")
            if not owner and previous is None and (named_path.exists() or (directory / "versions").exists()):
                raise ValueError("The orphan neutral state has no owned binding")
            if named_path.exists() or named_path.is_symlink():
                if previous and previous.get("phase") == "retired":
                    raise ValueError("A retired neutral name has an unexpected config")
                value = self.regular(named_path)
                expected = f"{MANAGED}# kind=name zone={zone} name={name}\n".encode()
                if not value.startswith(expected):
                    raise ValueError("The named guard is not managed state")
                named_path.unlink()
                changed = True
            if changed:
                self.reload()
            self.prove(
                name,
                self.snakeoil_certificate,
                leaf_fingerprint(self.regular(self.snakeoil_certificate, follow=True)),
                named=False,
            )
            self.prune_versions(directory)
            self.json_write(
                directory / "state.json",
                {"version": 1, "phase": "retired", "zone": zone, "name": name, "owner": effective_owner},
            )
            return self.receipt(identity, "retire", zone, name)

    def verify_configs(self, value: dict[str, Any], zone: str, name: str, *, allow_missing_name: bool = False) -> None:
        for kind, key in (("zone", "zone"), ("name", "named")):
            path = self.config_path(kind, zone if kind == "zone" else name)
            if value.get(f"{key}_config_path") != str(path):
                raise ValueError("The neutral config binding changed")
            if kind == "name" and allow_missing_name and not path.exists() and not path.is_symlink():
                continue
            if hashlib.sha256(self.regular(path)).hexdigest() != value.get(f"{key}_config_sha256"):
                raise ValueError("The neutral config digest changed")

    def verify(self, name: str, owner: str, parent: str, parent_id: str, host: str) -> None:
        dns_name(name)
        dns_name(parent)
        match = re.fullmatch(r"([A-Za-z0-9.-]+?)\.?(?::[0-9]{1,5})?", host)
        requested = match[1].lower() if match else ""
        if requested != name and not requested.endswith("." + name):
            raise ValueError("The requested host is outside this provider name's scope")
        with self.locked(create=False):
            directory = self.name_directory(name, create=False)
            value = self.json_read(directory / "state.json")
            zone = value.get("zone", "")
            validate(zone, name, owner)
            self.owned_manifest(directory, zone, name, owner)
            if value.get("phase") != "ready":
                raise ValueError("The provider child has no ready named guard")
            native = self.native(name, owner)
            if native is None or any(value.get(key) != actual for key, actual in native.items()):
                raise ValueError("The named guard native child identity changed")
            if value.get("native_bindings") != self.native_bindings(name):
                raise ValueError("The named guard native Apache binding changed")
            if native["native_parent_domain"] != parent or native["native_parent_id"] != parent_id:
                raise ValueError("The named guard native parent changed")
            if name not in self.execute(["virtualmin", "list-domains", "--disabled", "--name-only"]).splitlines():
                raise ValueError("The provider child is not native-disabled")
            self.verify_configs(value, zone, name)
            fingerprint = value.get("certificate_sha256", "")
            if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                raise ValueError("The neutral certificate proof is invalid")
            versions = directory / "versions"
            self.directory(versions, create=False)
            candidates = []
            for path in versions.iterdir():
                self.directory(path, create=False)
                if not re.fullmatch(r"[0-9a-f]{64}", path.name):
                    raise ValueError("The private neutral TLS directory contains unowned state")
                self.regular(path / "key.pem", private=True)
                candidates.append(path / "chain.pem")
            certificate = next(
                (path for path in candidates if leaf_fingerprint(self.regular(path, private=True)) == fingerprint), None
            )
            if certificate is None:
                raise ValueError("The neutral certificate proof is absent")
            self.prove(name, certificate, fingerprint, named=True, host=host)


def main() -> None:
    if os.geteuid() != 0:
        raise ValueError("The neutral helper requires root")
    os.umask(0o077)
    guard = NeutralGuard()
    if len(os.sys.argv) > 1:
        parser = argparse.ArgumentParser()
        parser.add_argument("action", choices=["verify"])
        for field in ("name", "owner", "parent", "parent-id", "host"):
            parser.add_argument("--" + field, required=True)
        args = parser.parse_args()
        guard.verify(args.name, args.owner, args.parent, args.parent_id, args.host)
        print("neutral")
        return
    action = os.environ["PRAHO_NEUTRAL_ACTION"]
    if action not in {"ensure", "prepare", "retire"}:
        raise ValueError("Invalid neutral action")
    value = getattr(guard, action)(
        os.environ["PRAHO_NEUTRAL_IDENTITY"],
        os.environ["PRAHO_NEUTRAL_ZONE"],
        os.environ["PRAHO_NEUTRAL_NAME"],
        os.environ["PRAHO_NEUTRAL_OWNER"],
    )
    print("NEUTRAL_RESULT=" + base64.b64encode(json.dumps(value, sort_keys=True).encode()).decode())


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, http.client.HTTPException) as error:
        print("NEUTRAL_REFUSED=" + (str(error) if isinstance(error, ValueError) else "node_operation_failed"))
        raise SystemExit(1) from None
