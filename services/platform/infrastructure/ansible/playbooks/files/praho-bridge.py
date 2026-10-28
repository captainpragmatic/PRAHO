#!/usr/bin/env python3
"""Migration-owned Apache bridges. Called as root by Ansible; never copies private keys off-node.

All node-wide hosts/config changes hold one lock. HTTP is carried inside TLS to a migration-owned
synthetic name on the target's existing 443, then local HTTP. HTTPS reaches the real customer vhost.
"""

from __future__ import annotations

import _ssl
import base64
import errno
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import shlex
import ssl
import stat
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any, cast
from uuid import UUID

HTTPS_PORT = 443
HTTP_PORT = 80
MAX_HOSTNAME_LENGTH = 253
NEUTRAL_BODY = "Not Found"


def command(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60).stdout  # noqa: S603


def hostname(value: str) -> str:
    value = value.lower()
    if len(value) > MAX_HOSTNAME_LENGTH or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise ValueError("Invalid bridge hostname")
    return value


class NodeBridge:
    def __init__(self, root: Path = Path("/"), *, execute: Callable[[list[str]], str] = command) -> None:
        self.root = root
        self.state = root / "var/lib/praho/bridges"
        self.barrier_state = root / "var/lib/praho/migration"
        self.owner_uid = 0
        self.conf = root / "etc/apache2/conf-enabled"
        self.sites = root / "etc/apache2/sites-enabled"
        self.probes = root / "var/www/praho-bridge-probes"
        self.ca = root / "etc/ssl/certs/ca-certificates.crt"
        self.hosts = root / "etc/hosts"
        self.credential_helper = root / "var/lib/praho/recovery/credentials.pl"
        self.execute = execute
        self.minimum_certificate_lifetime = 48 * 3600
        self.binding_policy = None

    def bindings(self) -> Any:
        if self.binding_policy is None:
            library = Path(__file__).with_name("praho-apache-bindings.py")
            if not library.exists():
                library = self.root / "var/lib/praho/apache-bindings/library.py"
                for path in (library.parent, library):
                    info = path.lstat()
                    if (
                        info.st_uid != self.owner_uid
                        or info.st_mode & 0o077
                        or (
                            not stat.S_ISDIR(info.st_mode) if path == library.parent else not stat.S_ISREG(info.st_mode)
                        )
                    ):
                        raise ValueError("The shared Apache binding library is not private owned state")
            spec = importlib.util.spec_from_file_location("praho_apache_bindings", library)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.binding_policy = module.ApacheBindings(self.root, execute=self.execute, owner_uid=self.owner_uid)
        return self.binding_policy

    @contextmanager
    def configuration_locked(self, identity: str) -> Iterator[None]:
        with self.locked():
            directory = self.directory(identity)
            paths = {self.conf / f"praho-{prefix}-{identity}.conf": 0o644 for prefix in ("origin", "migration")}
            paths.update(
                {
                    directory / name: 0o600
                    for name in (
                        "source.json",
                        "origin.json",
                        "origin-target.json",
                        "source-removed",
                        "origin-removed",
                        "origin-ca.pem",
                        "upstream-ca.pem",
                    )
                }
            )
            self.after_config_commit = []
            try:
                with self.bindings().transaction(paths):
                    yield
                for operation in self.after_config_commit:
                    operation()
            finally:
                self.after_config_commit = None

    def remove_after_config_commit(self, path: Path) -> None:
        self.after_config_commit.append(lambda: path.unlink(missing_ok=True))

    def target_http_bindings(self, domain: str) -> list[str]:
        result = set()
        for site in sorted(self.sites.glob("*.conf")):
            for ports, body in re.findall(r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>", site.read_text(), re.S | re.I):
                names = re.findall(r"^\s*ServerName\s+(\S+)\s*$", body, re.I | re.M)
                if names == [domain]:
                    result.update(self.bindings().parse(ports).get("80", []))
        if not result:
            raise ValueError("The current target HTTP vhost bindings could not be identified")
        return sorted(result)

    @contextmanager
    def locked(self) -> Iterator[None]:
        self.state.mkdir(parents=True, mode=0o700, exist_ok=True)
        with (self.state / ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def directory(self, identity: str) -> Path:
        if str(UUID(identity)) != identity:
            raise ValueError("Invalid bridge identity")
        path = self.state / identity
        path.mkdir(mode=0o700, exist_ok=True)
        return path

    @staticmethod
    def write(path: Path, body: str | bytes, mode: int = 0o600, *, durable: bool = False) -> None:
        path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        fd, scratch = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(body.encode() if isinstance(body, str) else body)
                if durable:
                    stream.flush()
                    os.fsync(stream.fileno())
            os.replace(scratch, path)
            if durable:
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            Path(scratch).unlink(missing_ok=True)

    def reload(self) -> None:
        self.execute(["apache2ctl", "configtest"])
        self.execute(["apache2ctl", "graceful"])

    def require_neutral_default(self) -> None:
        default = self.conf / "praho-default-site.conf"
        if not default.is_file() or "ServerName praho-default.invalid" not in default.read_text():
            raise ValueError("The node needs PRAHO's neutral default site before a bridge can be prepared")
        if self.bindings().refresh():
            self.reload()
        policy = self.bindings()
        groups = policy.current()
        probes = [
            (scheme, port, address)
            for scheme, port in (("http", HTTP_PORT), ("https", HTTPS_PORT))
            for address in policy.probe_addresses(groups, str(port))
        ]
        if not probes:
            raise ValueError("The neutral default has no local binding destinations")
        for scheme, port, address in probes:
            argv = [
                "curl",
                "--silent",
                "--show-error",
                "--noproxy",
                "*",
                "--connect-timeout",
                "2",
                "--max-time",
                "5",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--header",
                "Host: praho-unclaimed.invalid",
            ]
            if port == HTTPS_PORT:
                argv.append("--insecure")  # The neutral default deliberately uses the node's self-signed snakeoil cert.
            argv.append(f"{scheme}://{policy.endpoint(address, str(port))}/")
            if self.execute(argv).strip() != "404":
                raise ValueError("The node's neutral default site does not answer unknown hosts with 404")

    @staticmethod
    def origin_hostname(identity: str) -> str:
        return f"bridge-{UUID(identity).hex}.invalid"

    def pin_origin(self, identity: str, target: str | None) -> None:
        """Change only this UUID-tagged .invalid mapping; called under the node lock."""
        origin = self.origin_hostname(identity)
        tag = f"praho-bridge:{identity}"
        original = self.hosts.read_text() if self.hosts.exists() else ""
        kept = []
        for line in original.splitlines(keepends=True):
            addresses, _, comment = line.partition("#")
            if comment.strip() == tag:
                continue
            if target is not None and origin in [name.lower() for name in addresses.split()[1:]]:
                raise ValueError("An unowned hosts entry already maps this synthetic origin")
            kept.append(line)
        text = "".join(kept)
        if target is not None:
            if text and not text.endswith("\n"):
                text += "\n"
            text += f"{ipaddress.IPv4Address(target)} {origin} # {tag}\n"
        mode = (self.hosts.stat().st_mode & 0o777) if self.hosts.exists() else 0o644
        try:
            self.write(self.hosts, text, mode)
        except OSError as error:
            if error.errno != errno.EBUSY:
                raise
            # Docker bind-mounts /etc/hosts. Preserve its inode and all unrelated mappings.
            with self.hosts.open("r+") as stream:
                stream.write(text)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())

    def prepare(self, identity: str, domain: str, account_name: str, target: str, source: str) -> dict[str, Any]:
        with self.configuration_locked(identity):
            directory = self.directory(identity)
            if (directory / "source-removed").exists():
                raise ValueError("The source bridge was removed")
            self.require_neutral_default()
            self.execute(["apache2ctl", "configtest"])
            expected = {
                "domain": hostname(domain),
                "target": str(ipaddress.IPv4Address(target)),
                "source": str(ipaddress.IPv4Address(source)),
            }
            account_name = hostname(account_name) if account_name else ""
            kept = directory / "source.json"
            if kept.exists():
                return self.resume_preparation(kept, identity, account_name, expected)
            wanted = {expected["domain"]}
            if account_name:
                wanted.add(hostname(account_name))
            vhosts: list[dict[str, Any]] = []
            for site in sorted(self.sites.glob("*.conf")):
                for ports, body in re.findall(
                    r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>", site.read_text(), re.S | re.I
                ):
                    directives: dict[str, list[str]] = {}
                    for line in body.splitlines():
                        words = shlex.split(line, comments=True)
                        if words:
                            directives.setdefault(words[0].lower(), []).extend(words[1:])
                    name = (directives.get("servername") or [""])[0].lower()
                    if name not in wanted:
                        continue
                    groups = self.bindings().parse(ports)
                    if len(groups) != 1:
                        raise ValueError("The native bridge vhost mixes HTTP and HTTPS bindings")
                    port = int(next(iter(groups)))
                    names = list(dict.fromkeys(hostname(item) for item in [name, *directives.get("serveralias", [])]))
                    item: dict[str, Any] = {
                        "name": name,
                        "names": names,
                        "port": port,
                        "neutral": bool(account_name and name == account_name),
                        "bindings": groups[str(port)],
                    }
                    if port == HTTPS_PORT:
                        self.keep_certificate(directory, item, directives, len(vhosts))
                    else:
                        item["verify_names"] = names
                    vhosts.append(item)
            if not any(item["name"] == expected["domain"] and item["port"] == HTTP_PORT for item in vhosts):
                raise ValueError("The customer HTTP vhost could not be identified")
            manifest = self.bound_manifest(
                {
                    **expected,
                    "identity": identity,
                    "origin": self.origin_hostname(identity),
                    "account_name": account_name,
                    "vhosts": vhosts,
                },
                identity,
            )
            self.pin_origin(identity, expected["target"])
            self.write(kept, json.dumps(manifest))
            return manifest

    def resume_preparation(
        self, kept: Path, identity: str, account_name: str, expected: dict[str, str]
    ) -> dict[str, Any]:
        manifest = json.loads(kept.read_text())
        if any(manifest.get(key) != value for key, value in expected.items()):
            raise ValueError("Bridge identity belongs to a different account or target")
        if "account_name" not in manifest and (self.conf / f"praho-migration-{identity}.conf").exists():
            raise ValueError("An installed legacy bridge needs explicit retirement before its policy can change")
        manifest = self.bound_manifest(manifest, identity, account_name=account_name, allow_legacy=True)
        self.recheck_frontend_lifetimes(manifest)
        self.pin_origin(identity, manifest["target"])
        self.write(kept, json.dumps(manifest))
        return manifest

    def bound_manifest(
        self,
        manifest: dict[str, Any],
        identity: str,
        *,
        account_name: str | None = None,
        allow_legacy: bool = False,
    ) -> dict[str, Any]:
        """Bind the neutral policy to a captured primary name; downstream steps never infer it."""
        legacy = "account_name" not in manifest
        if legacy and (not allow_legacy or account_name is None):
            raise ValueError("The bridge manifest has no bound account-name policy; prepare it again")
        captured = manifest.get("account_name", account_name)
        captured = hostname(captured) if captured else ""
        if account_name is not None and captured != account_name:
            raise ValueError("The bridge manifest belongs to another account name")
        domain = hostname(manifest["domain"])
        if (
            captured == domain
            or manifest["identity"] != identity
            or manifest["origin"] != self.origin_hostname(identity)
        ):
            raise ValueError("The bridge manifest belongs to another account or migration")
        vhosts = []
        for original in manifest["vhosts"]:
            item = dict(original)
            port = str(item["port"])
            if not item.get("bindings") or port not in {"80", "443"}:
                raise ValueError("The bridge manifest has no captured literal source bindings; prepare a fresh bridge")
            normalized = self.bindings().parse(
                " ".join(self.bindings().endpoint(value, port) for value in item["bindings"])
            )
            if normalized != {port: item["bindings"]}:
                raise ValueError("The bridge source binding snapshot changed")
            name = hostname(item["name"])
            neutral = bool(captured and name == captured)
            if name not in {domain, captured} or (not legacy and item.get("neutral") is not neutral):
                raise ValueError("The bridge manifest has an inconsistent account-name policy")
            names = [hostname(value) for value in item["names"]]
            if name not in names or (domain if neutral else captured) in names:
                raise ValueError("The bridge manifest mixes customer and neutral account names")
            vhosts.append({**item, "neutral": neutral})
        if captured and {item["port"] for item in vhosts if item["name"] == captured} != {HTTP_PORT, HTTPS_PORT}:
            raise ValueError("The bridge manifest is missing the account-name HTTP or HTTPS vhost")
        return {**manifest, "account_name": captured, "vhosts": vhosts}

    def keep_certificate(
        self, directory: Path, item: dict[str, Any], directives: dict[str, list[str]], index: int
    ) -> None:
        cert_path = Path(directives["sslcertificatefile"][0])
        certificate = cert_path.read_text()
        chain = directives.get("sslcertificatechainfile")
        if chain:
            certificate += Path(chain[0]).read_text()
        if "PRIVATE KEY" in certificate:
            raise ValueError("The public certificate bundle contains a private key")
        item["certificate"] = str(directory / f"source-{index}-chain.pem")
        item["key"] = str(directory / f"source-{index}-key.pem")
        self.write(Path(item["certificate"]), certificate)
        self.write(Path(item["key"]), Path(directives["sslcertificatekeyfile"][0]).read_bytes())
        decoded = self.certificate_metadata(cert_path)
        patterns = [entry[1].lower() for entry in decoded.get("subjectAltName", ()) if entry[0] == "DNS"]
        if not patterns:
            patterns = [value.lower() for group in decoded["subject"] for key, value in group if key == "commonName"]
        item["verify_names"] = [
            value
            for value in item["names"]
            if any(
                value == pattern or (pattern.startswith("*.") and value.split(".", 1)[-1] == pattern[2:])
                for pattern in patterns
            )
        ]
        if item["name"] not in item["verify_names"]:
            raise ValueError("The customer's certificate does not cover its hostname")
        item["public_certificate"] = certificate

    def certificate_metadata(self, certificate: Path) -> dict[str, Any]:
        decode: Callable[[str], dict[str, Any]] = cast(Any, _ssl)._test_decode_cert
        decoded = decode(str(certificate))
        if ssl.cert_time_to_seconds(decoded["notAfter"]) < time.time() + self.minimum_certificate_lifetime:
            raise ValueError("The frontend certificate expires before the bridge window ends; renew it before moving")
        return decoded

    def recheck_frontend_lifetimes(self, manifest: dict[str, Any]) -> None:
        for item in manifest["vhosts"]:
            if item["port"] == HTTPS_PORT:
                self.certificate_metadata(Path(item["certificate"]))

    def install_origin(self, identity: str, manifest: dict[str, Any]) -> str:
        with self.configuration_locked(identity):
            directory = self.directory(identity)
            if (directory / "origin-removed").exists():
                raise ValueError("The target origin was removed")
            manifest = self.bound_manifest(manifest, identity)
            self.require_neutral_default()
            target_bindings = self.target_http_bindings(manifest["domain"])
            backend = self.bindings().http_backend(target_bindings, self.bindings().current())
            target_record = directory / "origin-target.json"
            target_mapping = {"domain": manifest["domain"], "bindings": target_bindings, "backend": backend}
            if target_record.exists() and json.loads(target_record.read_text()) != target_mapping:
                raise ValueError("The target origin HTTP binding changed")
            self.write(target_record, json.dumps(target_mapping))
            if manifest["identity"] != identity:
                raise ValueError("Origin belongs to a different migration")
            source = str(ipaddress.IPv4Address(manifest["source"]))
            names = sorted(
                {hostname(name) for item in manifest["vhosts"] if not item["neutral"] for name in item["names"]}
            )
            origin = self.origin_hostname(identity)
            if manifest["origin"] != origin:
                raise ValueError("The synthetic origin belongs to another migration")
            certificate, key = directory / "origin.pem", directory / "origin-key.pem"
            if not certificate.exists():
                self.execute(
                    [
                        "openssl",
                        "req",
                        "-x509",
                        "-newkey",
                        "rsa:2048",
                        "-nodes",
                        "-days",
                        "365",
                        "-subj",
                        f"/CN={origin}",
                        "-addext",
                        f"subjectAltName=DNS:{origin}",
                        "-keyout",
                        str(key),
                        "-out",
                        str(certificate),
                    ]
                )
                key.chmod(0o600)
                certificate.chmod(0o600)
            origin_record = directory / "origin.json"
            if origin_record.exists():
                previous = self.bound_manifest(
                    json.loads(origin_record.read_text()),
                    identity,
                    account_name=manifest["account_name"],
                    allow_legacy=True,
                )
                if previous != manifest:
                    raise ValueError("Origin belongs to a different account or source")
            self.write(origin_record, json.dumps(manifest))
            self.conf.mkdir(parents=True, exist_ok=True)
            self.probes.mkdir(parents=True, mode=0o755, exist_ok=True)
            self.write(self.probes / identity, identity, 0o644)
            probe = f"/.__praho_bridge_{identity}"
            text = (
                f"Alias {probe} {self.probes / identity}\n"
                f"<Location {probe}>\nSetHandler default-handler\nRequire ip {source} 127.0.0.1\n</Location>\n"
                f"<VirtualHost {' '.join(self.bindings().endpoint(value, '443') for value in self.bindings().current()['443'])}>\nServerName {origin}\n"
                f"SSLEngine on\nSSLCertificateFile {certificate}\nSSLCertificateKeyFile {key}\n"
                f"ProxyRequests Off\nProxyPreserveHost On\nProxyAddHeaders Off\n"
                f"<Location />\n<RequireAll>\nRequire ip {source}\n"
                f"Require expr \"req('X-Praho-Original-Host') =~ m#^(?:{'|'.join(re.escape(name) for name in names)})(?::[0-9]{{1,5}})?$#i\"\n"
                "</RequireAll>\n</Location>\n"
                'RequestHeader set Host "expr=%{req:X-Praho-Original-Host}"\n'
                "RequestHeader unset X-Praho-Original-Host\n"
                f"ProxyPass {probe} !\nAlias {probe} {self.probes / identity}\n"
                f"ProxyPass / http://{self.bindings().endpoint(backend, '80')}/ retry=0 connectiontimeout=5 timeout=60\n"
                f"ProxyPassReverse / http://{self.bindings().endpoint(backend, '80')}/\n</VirtualHost>\n"
            )
            self.write(self.conf / f"praho-origin-{identity}.conf", text, 0o644)
            self.bindings().refresh()
            self.reload()
            return certificate.read_text()

    def install_source(self, identity: str, origin_certificate: str) -> None:
        with self.configuration_locked(identity):
            directory = self.directory(identity)
            if (directory / "source-removed").exists():
                raise ValueError("The source bridge was removed")
            manifest = self.bound_manifest(json.loads((directory / "source.json").read_text()), identity)
            ssl.PEM_cert_to_DER_cert(origin_certificate)
            self.write(directory / "origin-ca.pem", origin_certificate)
            self.keep_upstream_trust(directory, manifest)
            self.pin_origin(identity, manifest["target"])
            blocks = []
            for index, item in enumerate(manifest["vhosts"]):
                port = int(item["port"])
                upstream = manifest["target"] if port == HTTPS_PORT else manifest["origin"]
                ca = directory / ("upstream-ca.pem" if port == HTTPS_PORT else "origin-ca.pem")
                # Virtualmin deletes the first literal ServerName/ServerAlias match across all
                # Apache configs. Keep its original vhost discoverable when deleting the domain:
                # Apache expands these migration-owned Defines, Webmin's parser keeps them literal.
                variables = [
                    f"PRAHO_BRIDGE_{UUID(identity).hex}_{index}_{number}" for number in range(len(item["names"]))
                ]
                body = [
                    *(f"Define {variable} {name}" for variable, name in zip(variables, item["names"], strict=True)),
                    f"<VirtualHost {' '.join(self.bindings().endpoint(value, str(port)) for value in item['bindings'])}>",
                    f"ServerName ${{{variables[0]}}}",
                ]
                if len(item["names"]) > 1:
                    body.append("ServerAlias " + " ".join(f"${{{variable}}}" for variable in variables[1:]))
                if port == HTTPS_PORT:
                    body.extend(
                        [
                            "SSLEngine on",
                            f"SSLCertificateFile {item['certificate']}",
                            f"SSLCertificateKeyFile {item['key']}",
                        ]
                    )
                if item["neutral"]:
                    self.probes.mkdir(parents=True, mode=0o755, exist_ok=True)
                    body.extend(
                        [
                            f"DocumentRoot {self.probes}",
                            "RewriteEngine Off",
                            "Redirect 404 /",
                            f'ErrorDocument 404 "{NEUTRAL_BODY}"',
                            f"<Directory {self.probes}>",
                            "AllowOverride None",
                            "Require all denied",
                            "</Directory>",
                            "</VirtualHost>",
                        ]
                    )
                    blocks.append("\n".join(body))
                    continue
                body.extend(
                    [
                        "ProxyRequests Off",
                        f"ProxyPreserveHost {'On' if port == HTTPS_PORT else 'Off'}",
                        "ProxyAddHeaders Off",
                        "SSLProxyEngine On",
                        f'Header always set X-Praho-Bridge "{identity}"',
                        "SSLProxyVerify require",
                        "SSLProxyVerifyDepth 5",
                        "SSLProxyCheckPeerName On",
                        "SSLProxyCheckPeerExpire On",
                        f"SSLProxyCACertificateFile {ca}",
                        *(['RequestHeader set X-Praho-Original-Host "expr=%{req:Host}"'] if port == HTTP_PORT else []),
                        f"ProxyPass / https://{upstream}:443/ retry=0 connectiontimeout=5 timeout=60",
                        f"ProxyPassReverse / https://{upstream}:443/",
                        "</VirtualHost>",
                    ]
                )
                blocks.append("\n".join(body))
            self.write(self.conf / f"praho-migration-{identity}.conf", "\n".join(blocks) + "\n", 0o644)
            self.bindings().refresh()
            self.reload()

    def verify_origin(self, identity: str, certificate: str) -> None:
        with self.locked():
            directory = self.directory(identity)
            manifest = self.bound_manifest(json.loads((directory / "source.json").read_text()), identity)
            ssl.PEM_cert_to_DER_cert(certificate)
            self.write(directory / "origin-ca.pem", certificate)
            self.check_origin(identity, directory, manifest)
            self.keep_upstream_trust(directory, manifest)
            for item in manifest["vhosts"]:
                if item["neutral"]:
                    for name in item["verify_names"]:
                        self.verify_neutral(name, int(item["port"]), manifest["target"], directory, identity)
                    continue
                if item["port"] != HTTPS_PORT:
                    continue
                for name in item["verify_names"]:
                    argv = [
                        "curl",
                        "--silent",
                        "--show-error",
                        "--noproxy",
                        "*",
                        "--connect-timeout",
                        "5",
                        "--max-time",
                        "30",
                        "--resolve",
                        f"{name}:443:{manifest['target']}",
                        "--cacert",
                        str(directory / "upstream-ca.pem"),
                        "--output",
                        "/dev/null",
                        "--write-out",
                        "%{http_code}",
                        f"https://{name}/.__praho_bridge_{identity}",
                    ]
                    # Target remains disabled before commit. Any real HTTP response proves its
                    # authenticated TLS route; curl still rejects transport/certificate failures.
                    if not re.fullmatch(r"[2-5][0-9]{2}", self.execute(argv).strip()):
                        raise ValueError(f"The target HTTPS route could not be verified for {name}")

    def keep_upstream_trust(self, directory: Path, manifest: dict[str, Any]) -> None:
        trust = (self.ca.read_text() if self.ca.exists() else "") + "".join(
            item.get("public_certificate", "") for item in manifest["vhosts"]
        )
        self.write(directory / "upstream-ca.pem", trust)

    def check_origin(self, identity: str, directory: Path, manifest: dict[str, Any]) -> None:
        names = sorted({name for item in manifest["vhosts"] if not item["neutral"] for name in item["names"]})
        for name in names:
            direct = [
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--noproxy",
                "*",
                "--connect-timeout",
                "5",
                "--max-time",
                "30",
                "--resolve",
                f"{manifest['origin']}:443:{manifest['target']}",
                "--cacert",
                str(directory / "origin-ca.pem"),
                "--header",
                f"X-Praho-Original-Host: {name}",
                f"https://{manifest['origin']}/.__praho_bridge_{identity}",
            ]
            if self.execute(direct).strip() != identity:
                raise ValueError(f"The target origin returned another migration's identity for {name}")

    def verify_neutral(self, name: str, port: int, target: str, directory: Path, identity: str) -> None:
        argv = [
            "curl",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--connect-timeout",
            "5",
            "--max-time",
            "30",
            "--resolve",
            f"{name}:{port}:{target}",
            "--output",
            "-",
            "--write-out",
            "\n%{http_code}",
        ]
        if port == HTTPS_PORT:
            argv.extend(["--cacert", str(directory / "upstream-ca.pem")])
        argv.append(f"{'https' if port == HTTPS_PORT else 'http'}://{name}/.__praho_bridge_{identity}")
        if self.execute(argv) != f"{NEUTRAL_BODY}\n404":
            raise ValueError(f"The account-name route is not neutral for {name}:{port}")

    def verify(self, identity: str) -> None:
        with self.locked():
            directory = self.directory(identity)
            manifest = self.bound_manifest(json.loads((directory / "source.json").read_text()), identity)
            self.check_origin(identity, directory, manifest)
            for item in manifest["vhosts"]:
                port = int(item["port"])
                addresses = self.bindings().probe_addresses({str(port): item["bindings"]}, str(port))
                if not addresses:
                    raise ValueError("The source bridge has no binding probe destinations")
                for name, address in ((name, address) for name in item["verify_names"] for address in addresses):
                    resolved = f"[{address}]" if ":" in address else address
                    if item["neutral"]:
                        self.verify_neutral(name, port, resolved, directory, identity)
                        continue
                    argv = [
                        "curl",
                        "--silent",
                        "--show-error",
                        "--fail",
                        "--noproxy",
                        "*",
                        "--connect-timeout",
                        "5",
                        "--max-time",
                        "30",
                        "--dump-header",
                        "-",
                        "--output",
                        "/dev/null",
                        "--resolve",
                        f"{name}:{port}:{resolved}",
                    ]
                    if port == HTTPS_PORT:
                        argv.extend(["--cacert", str(directory / "upstream-ca.pem")])
                    argv.append(f"{'https' if port == HTTPS_PORT else 'http'}://{name}/.__praho_bridge_{identity}")
                    headers = self.execute(argv).splitlines()
                    if not any(line.lower() == f"x-praho-bridge: {identity}" for line in headers):
                        raise ValueError(f"The source did not serve this migration's bridge identity for {name}:{port}")

    def source_record_for_cleanup(self, domain: str, record: str) -> Path:
        domain = hostname(domain)
        names = [
            hostname(name.strip())
            for name in self.execute(["virtualmin", "list-domains", "--name-only"]).splitlines()
            if name.strip()
        ]
        if domain in names:
            raise ValueError("The source domain still exists; its original cron must be kept")
        path = Path(record)
        if path.parent != self.barrier_state or not re.fullmatch(
            r"migration-[0-9]{1,30}\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.crontab", path.name
        ):
            raise ValueError("The original source cron path is outside the migration record directory")
        if path.parent.is_symlink():
            raise ValueError("The original source cron directory is not owned storage")
        try:
            info = path.lstat()
        except FileNotFoundError:
            # A previous teardown may have already removed its cron. Still retire this approved
            # original token, so an upgrade/retry does not leave late record/apply RPCs usable.
            return path
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid or path.parent.is_symlink():
            raise ValueError("The original source cron is not an owned regular file")
        return path

    def remove_source(self, identity: str, *, domain: str = "", cleanup_source_record: str = "") -> None:
        with self.configuration_locked(identity):
            record = self.source_record_for_cleanup(domain, cleanup_source_record) if cleanup_source_record else None
            if record is not None:
                record.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                prefix, saved = record.stem.split(".", 1)
                self.write(record.with_name(f"{prefix}.cancelled.{saved}"), b"", durable=True)
            self.write(self.directory(identity) / "source-removed", "removed\n", durable=True)
            (self.conf / f"praho-migration-{identity}.conf").unlink(missing_ok=True)
            self.bindings().refresh()
            self.reload()
            self.after_config_commit.append(lambda: self.pin_origin(identity, None))
            directory = self.directory(identity)
            for pattern in ("source-*-*.pem", "upstream-ca.pem", "origin-ca.pem", "source.json"):
                for path in directory.glob(pattern):
                    self.remove_after_config_commit(path)
            if record is not None:
                self.remove_after_config_commit(record)

    def remove_origin(self, identity: str) -> None:
        with self.configuration_locked(identity):
            directory = self.directory(identity)
            self.write(directory / "origin-removed", "removed\n", durable=True)
            record = directory / "origin.json"
            (self.conf / f"praho-origin-{identity}.conf").unlink(missing_ok=True)
            self.bindings().refresh()
            self.reload()
            self.remove_after_config_commit(record)
            self.remove_after_config_commit(directory / "origin-target.json")
            self.remove_after_config_commit(self.probes / identity)
            for name in ("origin.pem", "origin-key.pem"):
                self.remove_after_config_commit(directory / name)
            self.after_config_commit.append(lambda: self.retire_activation_directory(directory))

    def retire_activation_directory(self, directory: Path) -> None:
        """Called under the node lock; never changes a customer domain or its live runtime state."""
        self.write(directory / "activation-retired", "retired\n", durable=True)
        marker = directory / "activation.json"
        activation = json.loads(marker.read_text()) if marker.exists() else {}
        if activation.get("phase") != "completed":
            self.write(marker, json.dumps({**activation, "phase": "removed"}), durable=True)
        for name in ("activation.crontab", "activation.incoming", "activation.policy.crontab"):
            (directory / name).unlink(missing_ok=True)

    def retire_activation_data(self, identity: str) -> None:
        with self.locked():
            self.retire_activation_directory(self.directory(identity))

    @staticmethod
    def active_cron_digest(text: str) -> str:
        active = "".join(
            line + "\n" for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
        )
        return hashlib.sha256(active.encode()).hexdigest()

    def sql(self, statement: str) -> str:
        return self.execute(["mysql", "-N", "-B", "-e", statement])

    def restore_accounts(self, record: dict[str, Any]) -> None:
        for account in record["accounts"]:
            user, host = account["user"], account["host"]
            if not re.fullmatch(r"[A-Za-z0-9._@-]{1,80}", user) or not re.fullmatch(r"[A-Za-z0-9.%_:-]{1,255}", host):
                raise ValueError("Invalid database account in the barrier record")
            mode = "LOCK" if account["locked"] else "UNLOCK"
            self.sql(f"ALTER USER '{user}'@'{host}' ACCOUNT {mode}")

    def verify_accounts(self, record: dict[str, Any], *, verify_auth: bool = True) -> None:
        for account in record["accounts"]:
            user, host = account["user"], account["host"]
            predicate = f"User = '{user}' AND Host = '{host}'"
            locked = self.sql(
                "SELECT IFNULL(JSON_VALUE(Priv, '$.account_locked'), 'false') "  # noqa: S608  # Identifiers validated by restore_accounts before this read.
                f"FROM mysql.global_priv WHERE {predicate}"
            ).strip() in {"true", "1"}
            if locked != account["locked"]:
                raise ValueError("A target database account has another lock state")
            plugin = self.sql(
                "SELECT IFNULL(JSON_VALUE(Priv, '$.plugin'), '') "  # noqa: S608  # Validated identifiers.
                f"FROM mysql.global_priv WHERE {predicate}"
            ).strip()
            auth = self.sql(
                "SELECT IFNULL(JSON_VALUE(Priv, '$.authentication_string'), '') "  # noqa: S608  # Validated identifiers.
                f"FROM mysql.global_priv WHERE {predicate}"
            )
            grants = self.sql(f"SHOW GRANTS FOR '{user}'@'{host}'")
            cleaned = [
                re.sub(
                    r" IDENTIFIED VIA [^ ]+( USING '[^']*')?", "", re.sub(r" IDENTIFIED BY PASSWORD '[^']*'", "", line)
                )
                for line in grants.splitlines()
            ]
            grants_sha = hashlib.sha256("\n".join(sorted(cleaned)).encode()).hexdigest()
            actual = (plugin, hashlib.sha256(auth.encode()).hexdigest(), grants_sha)
            expected = (account["plugin"], account["auth_sha"], account["grants_sha"])
            differences = [
                name
                for name, got, wanted in zip(("plugin", "authentication", "grants"), actual, expected, strict=True)
                if got != wanted and (verify_auth or name != "authentication")
            ]
            if differences:
                raise ValueError(
                    "The target database identity differs from the original record: " + ", ".join(differences)
                )

    def target_binding(self, domain: str, owner: str, record: dict[str, Any]) -> dict[str, str]:
        domain = hostname(domain)
        if self.execute(["virtualmin", "list-domains", "--domain", domain, "--user-only"]).strip() != owner:
            raise ValueError("The target domain has a different owner")
        target_id = self.execute(["virtualmin", "list-domains", "--domain", domain, "--id-only"]).strip()
        if not target_id.isdigit():
            raise ValueError("The target domain id could not be read")
        if not record["enabled"] or record["enabled"][0]["name"] != domain:
            raise ValueError("The original barrier record belongs to another domain")
        return {
            "domain": domain,
            "owner": owner,
            "target_domain_id": target_id,
            "record_sha": hashlib.sha256(
                json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }

    def original_cron(self, path: Path, record: dict[str, Any]) -> str:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o077:
            raise ValueError("The staged original cron is not an owned private regular file")
        original = path.read_text()
        # The source barrier hashes shell command substitution, which strips final newlines.
        if (hashlib.sha256(original.encode().rstrip(b"\n")).hexdigest(), self.active_cron_digest(original)) != (
            record["crontab_sha"],
            record["active_sha"],
        ):
            raise ValueError("The transported cron does not match the original barrier record")
        return original

    def stage_activation(self, identity: str, domain: str, owner: str, record: dict[str, Any]) -> None:
        """Keep the verified original cron and actual target id before the ownership commit."""
        with self.locked():
            directory = self.directory(identity)
            incoming = directory / "activation.incoming"
            try:
                if (directory / "origin-removed").exists() or (directory / "activation-retired").exists():
                    raise ValueError("The target activation was removed")
                binding = self.target_binding(domain, owner, record)
                marker = directory / "activation.json"
                if marker.exists():
                    previous = json.loads(marker.read_text())
                    if any(previous.get(key) != value for key, value in binding.items()):
                        raise ValueError("The activation record belongs to a different target domain or barrier")
                    if previous.get("phase") == "completed":
                        return
                    if previous.get("phase") != "staged":
                        raise ValueError(
                            "An interrupted activation needs review before its original state can be applied"
                        )
                original = self.original_cron(incoming, record)
                self.write(directory / "activation.crontab", original, durable=True)
                self.write(marker, json.dumps({**binding, "phase": "staged"}), durable=True)
            finally:
                incoming.unlink(missing_ok=True)

    def activate_target(
        self,
        identity: str,
        domain: str,
        owner: str,
        record: dict[str, Any],
        *,
        enabled: bool | None = None,
    ) -> None:
        """Apply once on the target; replay may never overwrite state after writes were admitted."""
        with self.locked():
            binding = self.target_binding(domain, owner, record)
            directory = self.directory(identity)
            marker = directory / "activation.json"
            if not marker.exists():
                raise ValueError("The original activation record was not staged before commit")
            previous = json.loads(marker.read_text())
            if any(previous.get(key) != value for key, value in binding.items()):
                raise ValueError("The activation record belongs to a different target domain or barrier")
            kept = directory / "activation.crontab"
            if previous.get("phase") == "completed":
                kept.unlink(missing_ok=True)
                return
            if previous.get("phase") != "staged" or (directory / "origin-removed").exists():
                raise ValueError(
                    "An interrupted or removed activation needs review; target state will not be overwritten"
                )
            self.original_cron(kept, record)
            self.write(marker, json.dumps({**binding, "phase": "applying"}), durable=True)
            self.restore_target_runtime(domain, owner, record, kept, enabled=enabled)
            policy_record = {
                "enabled": record["enabled"],
                "accounts": [
                    {key: account[key] for key in ("user", "host", "locked")} for account in record["accounts"]
                ],
                "databases": record["databases"],
                "ids": {
                    item["name"]: self.execute(
                        ["virtualmin", "list-domains", "--domain", item["name"], "--id-only"]
                    ).strip()
                    for item in record["enabled"]
                },
            }
            self.write(
                marker, json.dumps({**binding, "phase": "completed", "policy_record": policy_record}), durable=True
            )
            kept.unlink(missing_ok=True)

    def restore_target_runtime(  # noqa: C901, PLR0912, PLR0915  # One locked native activation with ordered verification.
        self,
        domain: str,
        owner: str,
        record: dict[str, Any],
        kept: Path,
        *,
        enabled: bool | None = None,
    ) -> None:
        """The caller holds the node lock and has persisted the applying marker."""
        desired = record["enabled"][0]["enabled"] if enabled is None else enabled
        if type(desired) is not bool:
            raise ValueError("Current enabled policy must be boolean")
        effective = json.loads(json.dumps(record))
        for index, item in enumerate(effective["enabled"]):
            item["enabled"] = desired if index == 0 else item["enabled"] and desired
        for account in effective["accounts"]:
            account["locked"] = account["locked"] or not desired
        record = effective
        self.restore_accounts(record)
        for item in record["enabled"]:
            name = hostname(item["name"])
            if self.execute(["virtualmin", "list-domains", "--domain", name, "--user-only"]).strip() != owner:
                raise ValueError("A target child belongs to a different owner")
            disabled = set(self.execute(["virtualmin", "list-domains", "--disabled", "--name-only"]).splitlines())
            if (name not in disabled) != item["enabled"]:
                action = "enable-domain" if item["enabled"] else "disable-domain"
                # This record restores each child separately. Cascading a parent enable
                # would briefly expose a child that must remain disabled, including a
                # provider-name child created after the pair hold captured its surfaces.
                params = [] if item["enabled"] else ["--subservers"]
                self.execute(["virtualmin", action, "--domain", name, *params])
        if record["has_crontab"]:
            if desired:
                self.execute(["crontab", "-u", owner, str(kept)])
            else:
                paused = kept.with_name("activation.policy.crontab")
                content = self.suspended_cron(kept.read_text())
                self.write(paused, content)
                try:
                    self.execute(["crontab", "-u", owner, str(paused)])
                finally:
                    paused.unlink(missing_ok=True)
        else:
            with suppress(subprocess.CalledProcessError):
                self.execute(["crontab", "-u", owner, "-r"])
        if not desired:
            # Held Unix activation already completed, but this bridge marker is
            # still applying. Use that completed identity to close every native
            # policy surface without replaying its archived credential fields.
            self.policy_native(
                self._activation_identity(kept),
                domain,
                owner,
                self.execute(["virtualmin", "list-domains", "--domain", domain, "--id-only"]).strip(),
                False,
                scope="recovery",
            )
        self.verify_accounts(record, verify_auth=desired)
        disabled = set(self.execute(["virtualmin", "list-domains", "--disabled", "--name-only"]).splitlines())
        if any((item["name"] not in disabled) != item["enabled"] for item in record["enabled"]):
            raise ValueError("The target's enabled states do not match the original barrier record")
        try:
            cron = self.execute(["crontab", "-u", owner, "-l"])
        except subprocess.CalledProcessError:
            if record["has_crontab"]:
                raise
            cron = ""
        else:
            if not record["has_crontab"]:
                raise ValueError("The target still has a crontab that was originally absent")
        expected_active = (
            record["active_sha"] if desired else self.active_cron_digest(self.suspended_cron(kept.read_text()))
        )
        if self.active_cron_digest(cron) != expected_active:
            raise ValueError("The target cron differs from the original barrier record")
        if record["databases"]:
            self.probe_target_write(domain, record)

    @staticmethod
    def _activation_identity(kept: Path) -> str:
        return str(UUID(kept.parent.name))

    @staticmethod
    def suspended_cron(content: str) -> str:
        result = []
        for line in content.splitlines(keepends=True):
            stripped = line.lstrip()
            if not stripped.strip() or stripped.startswith("#") or re.match(r"[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
                result.append(line)
            else:
                ending = "\n" if line.endswith("\n") else ""
                job = line.rstrip("\r\n")
                suffix = "" if re.search(r"#\s+VIRTUALMIN\s+DISABLE", job) else " # VIRTUALMIN DISABLE"
                result.append("# " + job + suffix + ending)
        return "".join(result)

    def policy_native(  # noqa: PLR0913  # Public immutable target identity plus current policy and activation scope.
        self,
        identity: str,
        domain: str,
        owner: str,
        domain_id: str,
        enabled: bool,
        *,
        scope: str = "bridge",
    ) -> dict[str, Any]:
        info = self.credential_helper.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid or info.st_mode & 0o077:
            raise ValueError("The native current-policy helper is not private owned code")
        request = {
            "action": "reconcile-policy",
            "operation_id": identity,
            "activation_scope": scope,
            "domain": domain,
            "owner": owner,
            "domain_id": domain_id,
            "enabled": enabled,
        }
        output = subprocess.run(  # noqa: S603  # Fixed helper; public identity JSON only on stdin.
            ["/usr/bin/perl", str(self.credential_helper)],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            check=True,
            timeout=120,
        ).stdout
        matches = re.findall(r"PRAHO_POLICY_RESULT=([A-Za-z0-9+/=]+)", output)
        proof = json.loads(base64.b64decode(matches[0], validate=True)) if len(matches) == 1 else None
        if (
            not isinstance(proof, dict)
            or type(proof.get("enabled")) is not bool
            or proof
            != {
                "domain_id": domain_id,
                "owner": owner,
                "enabled": enabled,
            }
        ):
            raise ValueError("The native current-policy proof does not match the target")
        return proof

    def reconcile_policy(  # noqa: C901, PLR0912, PLR0915  # One locked policy transition preserves customer state across native callbacks.
        self,
        identity: str,
        domain: str,
        owner: str,
        domain_id: str,
        enabled: bool,
    ) -> dict[str, Any]:
        """Current policy is independent of the immutable original cron/credential replay."""
        if type(enabled) is not bool:
            raise ValueError("Current enabled policy must be boolean")
        with self.locked():
            directory = self.directory(identity)
            marker = directory / "activation.json"
            if not marker.exists() or (directory / "origin-removed").exists():
                raise ValueError("Current policy requires completed target activation")
            previous = json.loads(marker.read_text())
            if previous.get("phase") != "completed":
                raise ValueError("Current policy requires completed target activation")
            expected = {"domain": hostname(domain), "owner": owner, "target_domain_id": domain_id}
            if any(previous.get(key) != value for key, value in expected.items()):
                raise ValueError("Current policy target identity changed")
            if (
                self.execute(["virtualmin", "list-domains", "--domain", domain, "--user-only"]).strip() != owner
                or self.execute(["virtualmin", "list-domains", "--domain", domain, "--id-only"]).strip() != domain_id
            ):
                raise ValueError("Current policy target identity changed")
            disabled = set(self.execute(["virtualmin", "list-domains", "--disabled", "--name-only"]).splitlines())
            policy_file = directory / "policy.json"
            current_policy = json.loads(policy_file.read_text()) if policy_file.exists() else {}
            if enabled and domain not in disabled and current_policy.get("enabled", True):
                return {"domain_id": domain_id, "owner": owner, "enabled": True}
            record = previous.get("policy_record")
            if not isinstance(record, dict):
                raise ValueError("Completed activation lacks retained current-policy scope")
            resume = current_policy.get("resume") or record
            if not enabled and domain not in disabled:
                resume = json.loads(json.dumps(record))
                for item in resume["enabled"]:
                    item["enabled"] = item["name"] not in disabled
                for account in resume["accounts"]:
                    user, host = account["user"], account["host"]
                    if not re.fullmatch(r"[A-Za-z0-9._@-]{1,80}", user) or not re.fullmatch(
                        r"[A-Za-z0-9.%_:-]{1,255}", host
                    ):
                        raise ValueError("Invalid current-policy database scope")
                    account["locked"] = self.sql(
                        "SELECT IFNULL(JSON_VALUE(Priv, '$.account_locked'), 'false') "  # noqa: S608  # Both scope identifiers validated above.
                        f"FROM mysql.global_priv WHERE User = '{user}' AND Host = '{host}'"
                    ).strip() in {"true", "1"}
            # Save resume state BEFORE forcing native suspension; a retry must
            # never mistake our own lock states for the customer's prior state.
            self.write(policy_file, json.dumps({"enabled": False, "resume": resume}), durable=True)
            proof = self.policy_native(identity, domain, owner, domain_id, enabled)
            latest_disabled = set(
                self.execute(["virtualmin", "list-domains", "--disabled", "--name-only"]).splitlines()
            )
            for item in resume["enabled"][1:]:
                name = hostname(item["name"])
                if (
                    self.execute(["virtualmin", "list-domains", "--domain", name, "--user-only"]).strip() != owner
                    or self.execute(["virtualmin", "list-domains", "--domain", name, "--id-only"]).strip()
                    != record["ids"][name]
                ):
                    raise ValueError("Current policy child identity changed")
                desired = bool(item["enabled"] and enabled)
                if (name not in latest_disabled) != desired:
                    self.execute(["virtualmin", "enable-domain" if desired else "disable-domain", "--domain", name])
            accounts = json.loads(json.dumps(resume["accounts"]))
            if not enabled:
                for account in accounts:
                    account["locked"] = True
            self.restore_accounts({"accounts": accounts})
            final_disabled = set(self.execute(["virtualmin", "list-domains", "--disabled", "--name-only"]).splitlines())
            for item in resume["enabled"]:
                desired = enabled if item["name"] == domain else bool(item["enabled"] and enabled)
                if (item["name"] not in final_disabled) != desired:
                    raise ValueError("The target's current enabled policy did not converge")
            for account in accounts:
                user, host = account["user"], account["host"]
                actual = self.sql(
                    "SELECT IFNULL(JSON_VALUE(Priv, '$.account_locked'), 'false') "  # noqa: S608  # Scope validated by restore_accounts above.
                    f"FROM mysql.global_priv WHERE User = '{user}' AND Host = '{host}'"
                ).strip() in {"true", "1"}
                if actual != account["locked"]:
                    raise ValueError("The target's current database lock policy did not converge")
            self.write(policy_file, json.dumps({"enabled": enabled, "resume": resume}), durable=True)
            return proof

    def probe_target_write(self, domain: str, record: dict[str, Any]) -> None:
        listing = self.execute(["virtualmin", "list-domains", "--domain", domain, "--multiline"])
        attributes = dict(re.findall(r"^\s*(Username for mysql|Password for mysql): (.*)$", listing, re.M))
        user = attributes.get("Username for mysql", "")
        if not re.fullmatch(r"[A-Za-z0-9._@-]{1,80}", user):
            raise ValueError("The target database owner could not be read")
        enabled = next(item["enabled"] for item in record["enabled"] if item["name"] == domain)
        table = "praho_activation_" + secrets.token_hex(8)
        sql = (
            f"CREATE TABLE {table} (x INT); INSERT INTO {table} VALUES (1); DROP TABLE {table}"  # noqa: S608  # Locally generated hexadecimal identifier.
            if enabled
            else "SELECT 1"
        )
        outcome = subprocess.run(  # noqa: S603  # Fixed executable/argv, validated identifiers; password only in env.
            [
                "/usr/bin/mysql",
                "--connect-timeout=5",
                "-u",
                user,
                "-h",
                "localhost",
                "-N",
                "-B",
                record["databases"][0],
                "-e",
                sql,
            ],
            env={**os.environ, "MYSQL_PWD": attributes.get("Password for mysql", "")},
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if (outcome.returncode == 0) != enabled:
            raise ValueError("The target owner's write/login probe does not match its intended enabled state")


def main() -> None:  # noqa: C901, PLR0912  # Explicit allowlisted node-operation dispatch.
    node = NodeBridge()
    node.minimum_certificate_lifetime = int(os.environ.get("PRAHO_BRIDGE_CERT_MIN_SECONDS", str(48 * 3600)))
    identity = os.environ["PRAHO_BRIDGE_ID"]
    action = os.environ["PRAHO_BRIDGE_ACTION"]
    enabled_value = os.environ.get("PRAHO_BRIDGE_ENABLED", "")
    if enabled_value not in {"", "0", "1"}:
        raise ValueError("Current enabled policy must be boolean")
    enabled = None if enabled_value == "" else enabled_value == "1"
    payload: Any = ""
    if action == "prepare":
        payload = node.prepare(
            identity,
            os.environ["PRAHO_BRIDGE_DOMAIN"],
            os.environ.get("PRAHO_ACCOUNT_NAME", ""),
            os.environ["PRAHO_BRIDGE_TARGET"],
            os.environ["PRAHO_BRIDGE_SOURCE"],
        )
    elif action == "origin_install":
        payload = node.install_origin(identity, json.loads(os.environ["PRAHO_BRIDGE_MANIFEST"]))
    elif action == "origin_verify":
        node.verify_origin(identity, os.environ["PRAHO_BRIDGE_ORIGIN_CERTIFICATE"])
    elif action == "install":
        node.install_source(identity, os.environ["PRAHO_BRIDGE_ORIGIN_CERTIFICATE"])
        node.verify(identity)
    elif action == "verify":
        node.verify(identity)
    elif action == "remove":
        node.remove_source(
            identity,
            domain=os.environ["PRAHO_BRIDGE_DOMAIN"],
            cleanup_source_record=os.environ.get("PRAHO_CLEANUP_SOURCE_RECORD", ""),
        )
    elif action == "origin_remove":
        node.remove_origin(identity)
    elif action == "fetch_crontab":
        pass  # Ansible fetch transferred it directly to the private controller spool, never stdout.
    elif action == "stage_activation":
        node.stage_activation(
            identity,
            os.environ["PRAHO_BRIDGE_DOMAIN"],
            os.environ["PRAHO_BRIDGE_OWNER"],
            json.loads(os.environ["PRAHO_BARRIER_RECORD"]),
        )
    elif action == "retire_activation":
        node.retire_activation_data(identity)
    elif action == "activate":
        node.activate_target(
            identity,
            os.environ["PRAHO_BRIDGE_DOMAIN"],
            os.environ["PRAHO_BRIDGE_OWNER"],
            json.loads(os.environ["PRAHO_BARRIER_RECORD"]),
            enabled=enabled,
        )
    elif action == "reconcile_policy":
        if enabled is None:
            raise ValueError("Current enabled policy is required")
        payload = node.reconcile_policy(
            identity,
            os.environ["PRAHO_BRIDGE_DOMAIN"],
            os.environ["PRAHO_BRIDGE_OWNER"],
            os.environ["PRAHO_BRIDGE_DOMAIN_ID"],
            enabled,
        )
    else:
        raise ValueError("Invalid bridge action")
    print(
        "BRIDGE_RESULT="
        + base64.b64encode(json.dumps({"identity": identity, "action": action, "payload": payload}).encode()).decode()
    )


if __name__ == "__main__":
    main()
