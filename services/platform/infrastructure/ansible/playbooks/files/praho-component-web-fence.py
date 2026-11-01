#!/usr/bin/env python3
"""Own a separate maintenance vhost; native backups and retained services stay unchanged."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

MAX_WEB_BYTES = 256 * 1024
POLICY = "component-web-ingress-v2"


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("Native website ingress fencing is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


journals = _module("praho-component-journal.py", "component_web_receipts")
apache = _module("praho-apache-bindings.py", "component_web_bindings")


def command(arguments: list[str]) -> str:
    result = subprocess.run(  # noqa: S603 -- fixed native probes and configuration commands, never a shell
        arguments,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    if len(result.stdout.encode()) > MAX_WEB_BYTES:
        raise ValueError("Native website ingress proof exceeds its bound")
    return result.stdout


class WebIngressFence:
    def __init__(  # noqa: PLR0913 -- native identity, exact frontend scope, consent and independent OS boundaries
        self,
        domain_id: str,
        operation_id: str,
        domain: str,
        names: tuple[str, ...],
        original_sha256: str,
        *,
        root: Path = Path("/"),
        state_dir: Path | None = None,
        boot_id: str | None = None,
        execute: Callable[[list[str]], str] = command,
    ) -> None:
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", domain) is None
            or re.fullmatch(r"[0-9a-f]{64}", original_sha256) is None
        ):
            raise ValueError("Exact website identity and original native configuration digest are required")
        if domain not in names or len(set(names)) != len(names) or not set(names) <= {domain, "www." + domain}:
            raise ValueError("An ingress hold may cover only the reviewed website apex and www names")
        self.root, self.domain_id, self.operation, self.domain = root, domain_id, operation_id, domain
        self.names, self.original_sha256, self.execute = names, original_sha256, execute
        digest = hashlib.sha256(
            json.dumps([POLICY, domain, sorted(names), original_sha256], separators=(",", ":")).encode()
        ).hexdigest()
        directory = state_dir or root / "var/lib/praho/component-web-fences"
        self.journal = journals.ComponentJournal(
            directory,
            domain_id,
            {
                "operation_id": operation_id,
                "scope_digest": digest,
                "boot_id": boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            },
        )
        self.certificates = directory / (domain_id + "." + operation_id)
        self.path = root / "etc/apache2/conf-enabled" / ("praho-z-component-" + domain_id + ".conf")
        self.native = root / "etc/apache2/sites-available" / (domain + ".conf")
        self.bindings = apache.ApacheBindings(root, execute=execute, owner_uid=os.geteuid())

    def _original(self, expected_sha256: str | None = None) -> str:
        metadata = self.root / "etc/webmin/virtual-server/domains" / self.domain_id
        fields = dict(
            line.split("=", 1) for line in self.bindings.read(metadata, 0o644).decode().splitlines() if "=" in line
        )
        if fields.get("id") != self.domain_id or fields.get("dom") != self.domain or fields.get("web") != "1":
            raise ValueError("The native website identity changed before its ingress hold")
        if self.native.resolve() != self.native:
            raise ValueError("Native website configuration traverses a symlink")
        content = self.bindings.read(self.native, 0o644)
        if len(content) > MAX_WEB_BYTES or hashlib.sha256(content).hexdigest() != (
            expected_sha256 or self.original_sha256
        ):
            raise ValueError("Native website configuration changed after component inspection")
        return content.decode()

    def _copy_certificate(self, source: str, name: str) -> tuple[str, dict[str, str]]:
        path = Path(source)
        if not path.is_absolute():
            raise ValueError("Prepare absolute native frontend certificate paths before component fencing")
        if self.root != Path("/"):
            path = self.root / path.relative_to("/")
        with path.open("rb") as stream:
            content = stream.read(MAX_WEB_BYTES + 1)
        if len(content) > MAX_WEB_BYTES:
            raise ValueError("The native frontend certificate exceeds its bound")
        destination = self.certificates / name
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return str(destination), {"name": name, "sha256": hashlib.sha256(content).hexdigest()}

    def _render(self, original: str) -> tuple[str, dict[str, list[str]], list[dict[str, str]]]:
        blocks, groups, certificates = [], {}, []
        for index, (ports, body) in enumerate(
            re.findall(r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost>", original, re.S | re.I)
        ):
            directives: dict[str, list[str]] = {}
            for line in body.splitlines():
                words = shlex.split(line, comments=True)
                if words:
                    directives.setdefault(words[0].lower(), []).extend(words[1:])
            if directives.get("servername") != [self.domain]:
                continue
            current = self.bindings.parse(ports)
            if len(current) != 1 or any(port in groups for port in current):
                raise ValueError("Prepare one independent native vhost per website protocol before fencing")
            groups.update(current)
            # Apache expands these names, whereas Virtualmin's native parser sees
            # variables and continues to the customer's literal native vhost.
            # Literal names here make backup_web/backup_ssl export this hold.
            names = [self.domain, *(name for name in self.names if name != self.domain)]
            prefix = "PRAHO_COMPONENT_" + self.operation.replace("-", "") + "_" + str(index)
            variables = [prefix + "_" + str(number) for number in range(len(names))]
            lines = [
                *(f"Define {variable} {name}" for variable, name in zip(variables, names, strict=True)),
                f"<VirtualHost {ports}>",
                "  ServerName ${" + variables[0] + "}",
            ]
            if len(variables) > 1:
                lines.append("  ServerAlias " + " ".join("${" + variable + "}" for variable in variables[1:]))
            if "443" in current:
                lines.append("  SSLEngine on")
                for directive in ("SSLCertificateFile", "SSLCertificateKeyFile", "SSLCertificateChainFile"):
                    values = directives.get(directive.lower(), [])
                    if not values and directive == "SSLCertificateChainFile":
                        continue
                    if len(values) != 1:
                        raise ValueError("The native HTTPS website has unqualified frontend certificate metadata")
                    path, receipt = self._copy_certificate(values[0], f"tls-{index}-{directive}.pem")
                    certificates.append(receipt)
                    lines.append("  " + directive + ' "' + path + '"')
            lines.extend(
                [
                    '  Header always set X-PRAHO-Component-Hold "' + self.operation + '"',
                    '  ErrorDocument 503 "Website migration in progress"',
                    '  RedirectMatch 503 "^/"',
                    "</VirtualHost>",
                ]
            )
            blocks.append("\n".join(lines))
        if "80" not in groups:
            raise ValueError("The original website has no qualified HTTP ingress")
        return (
            "# PRAHO component website hold " + self.operation + "\n" + "\n".join(blocks) + "\n",
            groups,
            certificates,
        )

    def _state(self) -> dict[str, Any]:
        state = self.journal.read()
        if state is None:
            raise ValueError("Website ingress has no durable ownership receipt")
        self.journal.assert_owned(state)
        if state.get("policy") != POLICY or state.get("phase") not in {
            "applying",
            "held",
            "releasing",
            "released",
            "retiring",
            "retired",
        }:
            raise ValueError("Website ingress ownership receipt is unrecognized")
        return state

    def _owned(self, state: dict[str, Any]) -> None:
        if hashlib.sha256(self.bindings.read(self.path, 0o644)).hexdigest() != state["fenced_sha256"]:
            raise ValueError("Website ingress belongs to a changed or foreign configuration")
        self._owned_certificates(state)

    def _owned_certificates(self, state: dict[str, Any]) -> None:
        expected = {certificate["name"] for certificate in state["certificates"]}
        if {path.name for path in self.certificates.iterdir()} != expected:
            raise ValueError("The private component ingress certificate directory changed")
        for certificate in state["certificates"]:
            path = self.certificates / certificate["name"]
            if (
                path.parent != self.certificates
                or hashlib.sha256(self.bindings.read(path, 0o600)).hexdigest() != certificate["sha256"]
            ):
                raise ValueError("The private component ingress certificate receipt changed")

    def _prove(self, state: dict[str, Any]) -> None:
        self._original()
        self._owned(state)
        for port in state["bindings"]:
            addresses = self.bindings.probe_addresses(state["bindings"], port)
            if not addresses:
                raise ValueError("The held website has no independently probed local listener")
            for address in addresses:
                for name in self.names:
                    resolved = "[" + address + "]" if ":" in address else address
                    arguments = [
                        "curl",
                        "--silent",
                        "--show-error",
                        "--noproxy",
                        "*",
                        "--connect-timeout",
                        "3",
                        "--max-time",
                        "10",
                        "--dump-header",
                        "-",
                        "--output",
                        "/dev/null",
                        "--resolve",
                        f"{name}:{port}:{resolved}",
                    ]
                    if port == "443":
                        arguments.append(
                            "--insecure"
                        )  # Local UUID/status proof; the original native frontend owns TLS.
                    arguments.append(("https" if port == "443" else "http") + "://" + name + "/")
                    response = self.execute(arguments)
                    if (
                        re.search(r"^HTTP/\S+ 503(?:\s|$)", response, re.MULTILINE) is None
                        or ("x-praho-component-hold: " + self.operation) not in response.lower()
                    ):
                        raise ValueError(
                            "The current native website does not independently serve this operation's maintenance hold"
                        )
        self._original()

    def apply(self) -> None:
        with self.journal.locked():
            state = self.journal.read()
            if state is not None and state.get("operation_id") != self.operation:
                if state.get("phase") != "released":
                    raise ValueError("Another operation owns the native website ingress")
                state = None
            if state is None:
                original = self._original()
                if self.path.exists() or self.path.is_symlink() or self.certificates.exists():
                    raise ValueError("Native website ingress has unreceipted state; inspect before proceeding")
                self.certificates.mkdir(mode=0o700)
                body, bindings, certificates = self._render(original)
                state = self.journal.create(
                    {
                        "policy": POLICY,
                        "phase": "applying",
                        "body": body,
                        "bindings": bindings,
                        "certificates": certificates,
                        "fenced_sha256": hashlib.sha256(body.encode()).hexdigest(),
                    }
                )
            state = self._state()
            if state["phase"] == "held":
                self._prove(state)
                return
            if state["phase"] != "applying":
                raise ValueError("A released ingress hold cannot be reapplied with the same operation")
            self._original()
            with self.bindings.transaction({self.path: 0o644}):
                if self.path.exists() or self.path.is_symlink():
                    self._owned(state)
                else:
                    self.bindings.write(self.path, state["body"].encode(), 0o644)
                self.bindings.reload()
                self._prove(state)
            state["phase"] = "held"
            self.journal.write(state)

    def verify(self) -> None:
        with self.journal.locked():
            state = self._state()
            if state["phase"] != "held" or self.bindings.pending.exists():
                raise ValueError("Website ingress or its shared Apache transaction is unresolved")
            self._prove(state)

    def release(self) -> None:
        self._release(None)

    def release_after_native_change(self, current_native_sha256: str) -> None:
        """Forward activation, never source compensation: bind the exact authorized native callback result."""
        if re.fullmatch(r"[0-9a-f]{64}", current_native_sha256) is None:
            raise ValueError("Forward release needs an exact native configuration digest")
        self._release(current_native_sha256)

    def _release(self, current_native_sha256: str | None) -> None:
        with self.journal.locked():
            state = self._state()
            if state.get("forward_native_sha256") not in {None, current_native_sha256}:
                raise ValueError("Forward ingress release belongs to a different native configuration")
            if state["phase"] == "released":
                return
            if state["phase"] not in {"applying", "held", "releasing"}:
                raise ValueError("Website ingress needs inspection before compensation")
            self._original(current_native_sha256)
            if self.path.exists() or self.path.is_symlink():
                self._owned(state)
            state["phase"] = "releasing"
            if current_native_sha256 is not None:
                state["forward_native_sha256"] = current_native_sha256
            self.journal.write(state)
            with self.bindings.transaction({self.path: 0o644}):
                if self.path.exists() or self.path.is_symlink():
                    self._owned(state)
                    self.path.unlink()
                self.bindings.reload()
            state["phase"] = "released"
            self.journal.write(state)

    def retire_after_domain_absence(self) -> None:
        """Keep the independent guard through native deletion, then remove only its receipted artifacts."""
        with self.journal.locked():
            state = self._state()
            metadata = self.root / "etc/webmin/virtual-server/domains" / self.domain_id
            if any(path.exists() or path.is_symlink() for path in (metadata, self.native)):
                raise ValueError("Native target domain and website must be absent before ingress retirement")
            if state["phase"] == "retired":
                if self.path.exists() or self.path.is_symlink() or self.certificates.exists():
                    raise ValueError("Retired component ingress names were reused; never delete a new occupant")
                return
            if state["phase"] not in {"held", "released"}:
                raise ValueError("Component ingress retirement was interrupted; inspect before replaying")
            if state["phase"] == "held":
                self._owned(state)
            elif self.path.exists() or self.path.is_symlink():
                raise ValueError("A released component ingress path has a foreign occupant")
            self._owned_certificates(state)
            state["phase"] = "retiring"
            self.journal.write(state)
            with self.bindings.transaction({self.path: 0o644}):
                if self.path.exists() or self.path.is_symlink():
                    self._owned(state)
                    self.path.unlink()
                self.bindings.reload()
            for certificate in state["certificates"]:
                (self.certificates / certificate["name"]).unlink()
            self.certificates.rmdir()
            state["phase"] = "retired"
            self.journal.write(state)

    def retire_after_web_absence(self, current_native_sha256: str) -> None:
        """Retire source ingress while retaining the exact native mail/DNS/Unix domain."""
        with self.journal.locked():
            state = self._state()
            metadata = self.root / "etc/webmin/virtual-server/domains" / self.domain_id
            fields = dict(
                line.split("=", 1) for line in self.bindings.read(metadata, 0o600).decode().splitlines() if "=" in line
            )
            if (
                fields.get("id") != self.domain_id
                or fields.get("dom") != self.domain
                or fields.get("web") != "0"
                or fields.get("ssl") != "0"
            ):
                raise ValueError("The retained native source domain has no proven website retirement")
            if self.native.exists() or self.native.is_symlink():
                original = self.bindings.read(self.native, 0o644)
                if hashlib.sha256(original).hexdigest() != current_native_sha256 or re.search(
                    rb"^\s*<VirtualHost\b", original, re.MULTILINE | re.IGNORECASE
                ):
                    raise ValueError("The retired native source website changed or still has vhosts")
            elif current_native_sha256:
                raise ValueError("The receipted native source website file changed")
            if list((self.root / "etc/php").glob("*/fpm/pool.d/" + self.domain_id + ".conf")):
                raise ValueError("The source PHP pool still exists after website retirement")
            if state["phase"] == "retired":
                if self.path.exists() or self.path.is_symlink() or self.certificates.exists():
                    raise ValueError("The retired source ingress namespace was reused")
                return
            if state["phase"] != "held":
                raise ValueError("Source ingress retirement was interrupted; inspect before replay")
            self._owned(state)
            state["phase"] = "retiring"
            self.journal.write(state)
            with self.bindings.transaction({self.path: 0o644}):
                self._owned(state)
                self.path.unlink()
                self.bindings.reload()
            for certificate in state["certificates"]:
                (self.certificates / certificate["name"]).unlink()
            self.certificates.rmdir()
            state["phase"] = "retired"
            self.journal.write(state)
