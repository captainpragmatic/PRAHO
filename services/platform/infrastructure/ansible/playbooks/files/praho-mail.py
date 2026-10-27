#!/usr/bin/env python3
"""Versioned native mail capability and public observations; no customer opt-in action."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import smtplib
import socket
import ssl
import stat
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO
from uuid import UUID

PROFILES = {
    ("debian", "12"): ("debian12-dovecot23", "2.3.", "3.7."),
    ("ubuntu", "26.04"): ("ubuntu2604-dovecot24", "2.4.", "3.10."),
}
PUBLIC_PORTS = frozenset({25, 465, 993, 995})
ALL_MAIL_PORTS = frozenset({25, 110, 143, 465, 587, 993, 995})
MAX_USERS = 1000
MAX_ALIASES = 2000
MAX_NATIVE_BYTES = 256 * 1024
MIN_UID = 1000
MAX_HOSTNAME_LENGTH = 253
MAX_HOSTNAME_LABEL = 63
MAX_DOMAINS = 5000
MAX_RESERVED_ZONES = 64
MIN_SS_FIELDS = 4


class MailError(Exception):
    """Only fixed, nonsecret machine codes may cross the node boundary."""


def operation_lock(root: Path = Path("/")) -> TextIO:
    """Keep the global node lock outside Debian's customer-writable /run/lock."""
    directory = root / "run/praho-mail"
    descriptor = None
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise MailError("mail_operation_busy")
        descriptor = os.open(
            directory / "operation.lock", os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise MailError("mail_operation_busy")
        stream = os.fdopen(descriptor, "a", encoding="utf-8")
        descriptor = None
        return stream
    except OSError as error:
        raise MailError("mail_operation_busy") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def command(argv: list[str], *, stdin: str | None = None, timeout: int = 30) -> str:
    try:
        result = subprocess.run(  # noqa: S603
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none"},
        )
    except (subprocess.SubprocessError, OSError) as error:
        raise MailError("mail_native_inspection_failed") from error
    if len(result.stdout) > MAX_NATIVE_BYTES:
        raise MailError("mail_native_inspection_failed")
    return result.stdout


def hostname(value: str) -> str:
    if len(value) > MAX_HOSTNAME_LENGTH or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise MailError("mail_node_identity_mismatch")
    if any(
        not label or len(label) > MAX_HOSTNAME_LABEL or label.startswith("-") or label.endswith("-")
        for label in value.split(".")
    ):
        raise MailError("mail_node_identity_mismatch")
    return value


def tls_observations(name: str) -> list[dict[str, str]]:
    """Connect only to loopback; the account name is SNI/verification input, never a DNS destination."""
    name = hostname(name)
    context = ssl.create_default_context()
    result = []

    class LoopbackSMTP(smtplib.SMTP):
        def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
            return socket.create_connection(("127.0.0.1", port), timeout=timeout)

    for service, port in (("imap", 993), ("pop3", 995), ("submission", 465), ("smtp", 25)):
        try:
            if service == "smtp":
                client = LoopbackSMTP(name, port, timeout=3)
                try:
                    client.ehlo()
                    client.starttls(context=context)
                    client.ehlo()
                    if client.has_extn("auth"):
                        raise ValueError("public SMTP authentication must be disabled")
                    wire = client.sock.getpeercert(binary_form=True)
                    certificate = client.sock.getpeercert()
                finally:
                    client.close()
            else:
                with (
                    socket.create_connection(("127.0.0.1", port), timeout=3) as connection,
                    context.wrap_socket(connection, server_hostname=name) as secured,
                ):
                    wire = secured.getpeercert(binary_form=True)
                    certificate = secured.getpeercert()
            if wire and certificate:
                expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), UTC)
                result.append(
                    {
                        "service": service,
                        "hostname": name,
                        "sha256": hashlib.sha256(wire).hexdigest(),
                        "not_after": expiry.isoformat(),
                    }
                )
        except (OSError, ssl.SSLError, smtplib.SMTPException, KeyError, ValueError):
            # Missing/wrong/untrusted TLS is an absent proof, never a bypass or a guessed certificate.
            continue
    return result


class MailNode:
    def __init__(
        self,
        root: Path = Path("/"),
        *,
        execute: Callable[..., str] = command,
        probe: Callable[[str], list[dict[str, str]]] = tls_observations,
    ) -> None:
        self.root = root
        self.state = self.path("/var/lib/praho/mail")
        self.execute = execute
        self.probe = probe
        self.native_helper = Path(__file__).with_name("praho-mail-native.pl")

    def setup_driver(self) -> Any:
        # This sibling is a fixed, privately staged repository helper, never caller-supplied code.
        spec = importlib.util.spec_from_file_location(
            "praho_mail_setup", Path(__file__).with_name("praho_mail_setup.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.MailSetup(self, MailError)

    def reconcile_submitters(self, expected: str, zones: list[str]) -> dict[str, Any]:
        self.profile(expected)
        driver = self.setup_driver()
        marker = driver.marker(expected)
        if marker is None:
            return {
                "node_hostname": expected,
                "profile": self.profile_id,
                "configured": False,
                "default_mail_off": self.native("inventory").get("mail_default_off") is True,
                "maps_sha256": "",
            }
        if not driver.security(expected):
            raise MailError("mail_setup_review_required")
        if not zones or len(zones) > MAX_RESERVED_ZONES or len(set(zones)) != len(zones):
            raise MailError("mail_native_inspection_failed")
        zones = [hostname(zone) for zone in zones]
        result = self.native("reconcile_submitters", node=expected, reserved_zones=json.dumps(zones))
        digest = result.get("maps_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise MailError("mail_native_inspection_failed")
        return {
            "node_hostname": expected,
            "profile": self.profile_id,
            "configured": True,
            "default_mail_off": True,
            "maps_sha256": digest,
        }

    def reserved_zones(self) -> list[str]:
        zones = json.loads(os.environ.get("PRAHO_MAIL_RESERVED_ZONES", "[]"))
        if not isinstance(zones, list) or not zones or len(zones) > MAX_RESERVED_ZONES or len(set(zones)) != len(zones):
            raise MailError("mail_native_inspection_failed")
        normalized = [hostname(zone) for zone in zones]
        if hostname(os.environ.get("PRAHO_MAIL_ACCOUNT_ZONE", "")) not in normalized:
            raise MailError("mail_native_inspection_failed")
        return normalized

    def setup(self, expected: str) -> dict[str, Any]:
        return self.setup_driver().run(expected)

    def reconcile_node_certificate(self, expected: str, identity: str) -> dict[str, Any]:
        return self.setup_driver().reconcile_certificate(expected, identity)

    def path(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    def profile_settings(self) -> tuple[str, str, str]:
        try:
            values = dict(
                line.split("=", 1) for line in self.path("/etc/os-release").read_text().splitlines() if "=" in line
            )
            identity = (values.get("ID", "").strip('"'), values.get("VERSION_ID", "").strip('"'))
            return PROFILES[identity]
        except (OSError, KeyError) as error:
            raise MailError("mail_profile_unsupported") from error

    @property
    def profile_id(self) -> str:
        return self.profile_settings()[0]

    def profile(self, expected: str) -> str:
        expected = hostname(expected)
        _identifier, dovecot_prefix, postfix_prefix = self.profile_settings()
        try:
            module = self.path("/usr/share/webmin/virtual-server/module.info").read_text()
        except OSError as error:
            raise MailError("mail_profile_unsupported") from error
        if not re.search(r"(?m)^version=8\.3(?:\.\d+)?$", module):
            raise MailError("mail_profile_unsupported")
        if self.execute(["hostname", "-f"]).strip().lower() != expected:
            raise MailError("mail_node_identity_mismatch")
        if self.path("/usr/sbin/dovecot").exists() and not self.execute(["dovecot", "--version"]).strip().startswith(
            dovecot_prefix
        ):
            raise MailError("mail_profile_unsupported")
        if self.path("/usr/sbin/postfix").exists() and not self.execute(
            ["postconf", "-h", "mail_version"]
        ).strip().startswith(postfix_prefix):
            raise MailError("mail_profile_unsupported")
        return expected

    def native(self, action: str, **values: str) -> dict[str, Any]:
        output = self.execute(
            ["perl", str(self.native_helper)], stdin=json.dumps({"action": action, **values}), timeout=30
        )
        try:
            if len(output) > MAX_NATIVE_BYTES:
                raise ValueError("oversized native receipt")
            result = json.loads(output)
            if not isinstance(result, dict) or result.get("error"):
                raise ValueError("native inspection refused")
        except (ValueError, TypeError) as error:
            raise MailError("mail_native_inspection_failed") from error
        return result

    def preflight_setup(self, expected: str) -> dict[str, Any]:
        self.profile(expected)
        inventory = self.native("inventory")
        domains = inventory.get("domains")
        if not isinstance(domains, list) or len(domains) > MAX_DOMAINS:
            raise MailError("mail_native_inspection_failed")
        if any(not isinstance(domain, dict) or domain.get("mail_enabled") is not False for domain in domains):
            raise MailError("mail_unmanaged_mta")
        marker = self.state / "node.json"
        if (
            any(self.path("/usr/sbin/" + program).exists() for program in ("postfix", "dovecot"))
            and not marker.is_file()
        ):
            raise MailError("mail_unmanaged_mta")
        self.check_procmail()
        self.check_exim_spool()
        if self.path("/usr/sbin/exim4").exists():
            self.check_exim_configuration(expected)
            try:
                queue = self.execute(["exim4", "-bpc"]).strip()
            except Exception as error:
                raise MailError("mail_queue_uncertain") from error
            if queue != "0":
                raise MailError("mail_queue_uncertain")
            mta = "exim4"
        else:
            mta = "postfix" if self.path("/usr/sbin/postfix").exists() else "none"
            if mta == "none" and self.path("/usr/sbin/sendmail").exists():
                raise MailError("mail_unmanaged_mta")
        return {"mta": mta, "mail_default_off": inventory.get("mail_default_off") is True}

    def active_configuration(self, name: str) -> list[str]:
        file = self.path(name)
        if not file.exists() and not file.is_symlink():
            return []
        metadata = file.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
            or metadata.st_size > MAX_NATIVE_BYTES
        ):
            raise MailError("mail_unmanaged_mta")
        return [
            line.strip() for line in file.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")
        ]

    def check_exim_configuration(self, expected: str) -> None:
        # Exim may carry a smarthost/credential/rewrite policy while every Virtualmin
        # domain is mail-off. A zero queue does not authorize replacing that policy.
        flat = self.path("/etc/exim4/exim4.conf")
        if flat.exists() or flat.is_symlink():
            raise MailError("mail_unmanaged_mta")
        for name in ("/etc/exim4/passwd.client", "/etc/exim4/exim4.conf.localmacros", "/etc/email-addresses"):
            if self.active_configuration(name):
                raise MailError("mail_unmanaged_mta")
        known = {"conf.d", "exim4.conf.template", "passwd.client", "update-exim4.conf.conf", "exim4.conf.localmacros"}
        for index, file in enumerate(self.path("/etc/exim4").iterdir()):
            if index >= MAX_ALIASES or file.is_symlink():
                raise MailError("mail_unmanaged_mta")
            if file.name not in known and (file.is_dir() or self.active_configuration("/etc/exim4/" + file.name)):
                raise MailError("mail_unmanaged_mta")
        values = self.exim_debconf(expected)
        self.check_exim_packaged(values.get("dc_use_split_config") == "true")

    def exim_debconf(self, expected: str) -> dict[str, str]:
        values = {}
        known = {
            "dc_eximconfig_configtype",
            "dc_other_hostnames",
            "dc_local_interfaces",
            "dc_readhost",
            "dc_relay_domains",
            "dc_minimaldns",
            "dc_relay_nets",
            "dc_smarthost",
            "CFILEMODE",
            "dc_use_split_config",
            "dc_hide_mailname",
            "dc_mailname_in_oh",
            "dc_localdelivery",
        }
        for line in self.active_configuration("/etc/exim4/update-exim4.conf.conf"):
            key, separator, raw = line.partition("=")
            if not separator or key not in known or key in values:
                raise MailError("mail_unmanaged_mta")
            value = raw.strip().strip("\"'")
            if not re.fullmatch(r"[A-Za-z0-9_.;:/ @-]*", value):
                raise MailError("mail_unmanaged_mta")
            values[key] = value
        if values.get("dc_eximconfig_configtype", "local") not in {"local", "internet", "none"}:
            raise MailError("mail_unmanaged_mta")
        if any(values.get(key) for key in ("dc_smarthost", "dc_readhost", "dc_relay_domains", "dc_relay_nets")):
            raise MailError("mail_unmanaged_mta")
        destinations = {part.strip() for part in values.get("dc_other_hostnames", "").split(";") if part.strip()}
        if destinations - {expected, "localhost"}:
            raise MailError("mail_unmanaged_mta")
        return values

    def check_exim_packaged(self, split: bool) -> None:
        manifest = self.execute(["dpkg-query", "-W", "-f=${Conffiles}", "exim4-config"])
        expected = {}
        for line in manifest.splitlines():
            row = re.fullmatch(r"\s*(/\S+) ([a-f0-9]{32})(?: obsolete)?", line)
            if row and row[1].startswith("/etc/exim4/"):
                if row[1] in expected:
                    raise MailError("mail_unmanaged_mta")
                expected[row[1]] = row[2]
        template = "/etc/exim4/exim4.conf.template"
        if template not in expected:
            raise MailError("mail_unmanaged_mta")
        active = [template]
        if split:
            directory = self.path("/etc/exim4/conf.d")
            active = [
                "/" + str(path.relative_to(self.root))
                for path in directory.rglob("*")
                if path.is_file() or path.is_symlink()
            ]
            if not active or len(active) > MAX_ALIASES:
                raise MailError("mail_unmanaged_mta")
        for name in active:
            file = self.path(name)
            self.active_configuration(name)
            if (
                name not in expected
                or not file.is_file()
                or hashlib.md5(file.read_bytes(), usedforsecurity=False).hexdigest() != expected[name]
            ):
                raise MailError("mail_unmanaged_mta")

    def check_exim_spool(self) -> None:
        directory = self.path("/var/spool/exim4/input")
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise MailError("mail_queue_uncertain")
        if directory.exists():
            for index, file in enumerate(directory.rglob("*")):
                if index >= MAX_DOMAINS or file.is_symlink() or not file.is_dir():
                    raise MailError("mail_queue_uncertain")

    def check_procmail(self) -> None:
        path = self.path("/etc/procmailrc")
        if not path.exists():
            return
        allowed = {
            "LOGFILE=/var/log/procmail.log",
            "TRAP=/etc/webmin/virtual-server/procmail-logger.pl",
            "ORGMAIL=/var/mail/$LOGNAME",
            "DEFAULT=/var/mail/$LOGNAME",
            "DROPPRIVS=yes",
            "ORGMAIL=$HOME/Maildir/",
            "DEFAULT=$HOME/Maildir/",
        }
        if any(
            line.strip() and not line.lstrip().startswith("#") and line.strip() not in allowed
            for line in path.read_text().splitlines()
        ):
            raise MailError("mail_unmanaged_mta")

    def public_ports(self) -> list[int]:
        ports = set()
        for line in self.execute(["ss", "-H", "-lnt"]).splitlines():
            fields = line.split()
            if len(fields) < MIN_SS_FIELDS:
                raise MailError("mail_native_inspection_failed")
            address, _, raw_port = fields[3].rpartition(":")
            try:
                port = int(raw_port)
                loopback = ipaddress.ip_address(address.strip("[]")).is_loopback if address != "*" else False
            except ValueError as error:
                raise MailError("mail_native_inspection_failed") from error
            if port in ALL_MAIL_PORTS and not loopback:
                ports.add(port)
        return sorted(ports)

    def inspect_node(self, expected: str) -> dict[str, Any]:
        expected = self.profile(expected)
        inventory = self.native("inventory")
        ports = self.public_ports()
        configured = self.setup_driver().security(expected)
        return {
            "node_hostname": expected,
            "profile": self.profile_id,
            "configured": configured,
            "default_mail_off": inventory.get("mail_default_off") is True,
            "public_ports": ports,
        }

    def inspect_domain(self, expected: str, domain: str, owner: str, account_name: str) -> dict[str, Any]:
        expected = self.profile(expected)
        domain = hostname(domain)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", owner) or owner == "root":
            raise MailError("mail_domain_identity_mismatch")
        native = self.native("inspect_domain", domain=domain, owner=owner)
        uid = native.get("owner_uid")
        if (native.get("domain"), native.get("owner")) != (domain, owner) or type(uid) is not int or uid < MIN_UID:
            raise MailError("mail_domain_identity_mismatch")
        users, aliases = native.get("users"), native.get("aliases")
        if (
            not isinstance(users, list)
            or len(users) > MAX_USERS
            or not isinstance(aliases, list)
            or len(aliases) > MAX_ALIASES
        ):
            raise MailError("mail_native_inspection_failed")
        user_keys = ("login", "email", "uid", "enabled")
        alias_keys = ("address", "targets")
        if any(not isinstance(user, dict) for user in users) or any(not isinstance(alias, dict) for alias in aliases):
            raise MailError("mail_native_inspection_failed")
        certificates = self.probe(hostname(account_name)) if account_name else []
        enabled = native.get("mail_enabled") is True
        dkim = native.get("dkim")
        if dkim is not None and not isinstance(dkim, dict):
            raise MailError("mail_native_inspection_failed")
        return {
            "node_hostname": expected,
            "profile": self.profile_id,
            "domain": domain,
            "domain_id": native.get("domain_id"),
            "owner": owner,
            "owner_uid": uid,
            "mail_enabled": enabled,
            "users": [{key: user.get(key) for key in user_keys} for user in users],
            "aliases": [{key: alias.get(key) for key in alias_keys} for alias in aliases],
            "dkim": {key: dkim.get(key) for key in ("selector", "record_name", "record_value")}
            if dkim is not None
            else None,
            "certificates": certificates,
            # Enrollment must install/verify an exact hosted-user roster. Package availability,
            # native mail_feature and a certificate alone cannot establish that admission.
            "ready": False,
        }


def main() -> None:
    identity = os.environ.get("PRAHO_MAIL_ID", "")
    expected = os.environ.get("PRAHO_MAIL_NODE", "")
    action = os.environ.get("PRAHO_MAIL_ACTION", "")
    node = None
    try:
        if os.geteuid() != 0 or str(UUID(identity)) != identity:
            raise MailError("mail_native_inspection_failed")
        hostname(expected)
        with operation_lock() as lock:
            try:
                fcntl.flock(
                    lock,
                    (
                        fcntl.LOCK_EX
                        if action in {"setup", "reconcile_submitters", "reconcile_node_certificate"}
                        else fcntl.LOCK_SH
                    )
                    | fcntl.LOCK_NB,
                )
            except BlockingIOError as error:
                raise MailError("mail_operation_busy") from error
            node = MailNode()
            if action == "inspect_node":
                payload = node.inspect_node(expected)
            elif action == "inspect_domain":
                payload = node.inspect_domain(
                    expected,
                    os.environ.get("PRAHO_MAIL_DOMAIN", ""),
                    os.environ.get("PRAHO_MAIL_OWNER", ""),
                    os.environ.get("PRAHO_MAIL_ACCOUNT_NAME", ""),
                )
            elif action == "reconcile_submitters":
                payload = node.reconcile_submitters(expected, node.reserved_zones())
            elif action == "setup":
                payload = node.setup(expected)
            elif action == "reconcile_node_certificate":
                payload = node.reconcile_node_certificate(expected, identity)
            else:
                raise MailError("mail_setup_incomplete")
        encoded = json.dumps(payload)
        if len(encoded) > MAX_NATIVE_BYTES:
            raise MailError("mail_native_inspection_failed")
    except MailError as error:
        code = str(error)
        allowed = {
            "mail_profile_unsupported",
            "mail_node_identity_mismatch",
            "mail_domain_identity_mismatch",
            "mail_native_inspection_failed",
            "mail_setup_incomplete",
            "mail_unmanaged_mta",
            "mail_queue_uncertain",
            "mail_node_certificate_unproven",
            "mail_setup_review_required",
            "mail_unrelated_configuration_changed",
            "mail_operation_busy",
        }
        payload = {
            "error": code if code in allowed else "mail_native_inspection_failed",
            "stage": getattr(node, "stage", "inspection"),
        }
    except Exception:
        payload = {"error": "mail_native_inspection_failed", "stage": getattr(node, "stage", "inspection")}
    envelope = {"version": 1, "identity": identity, "node_hostname": expected, "action": action, "payload": payload}
    print("MAIL_RESULT=" + base64.b64encode(json.dumps(envelope).encode()).decode(), flush=True)


if __name__ == "__main__":
    main()
