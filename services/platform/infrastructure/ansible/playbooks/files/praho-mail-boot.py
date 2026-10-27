#!/usr/bin/env python3
"""Native unit pre-start guard: a crashed setup never starts package-default mail."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import re
import ssl
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

PROFILES = frozenset({"debian12-dovecot23", "ubuntu2604-dovecot24"})
START_TICK_INDEX = 19
CHAIN = "PRAHO_MAIL_SETUP"
PORTS = "25,110,143,465,587,993,995"
START_SECONDS = 120
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_LOCK_FD = 1_048_576
MAX_HOSTNAME_LENGTH = 253
START_UNITS = frozenset({"postfix.service", "postfix@-.service", "dovecot.service"})
CERTIFICATE_PATHS = frozenset({"/etc/praho-mail/node.pem", "/etc/praho-mail/node.key"})
RECORD_FIELDS = frozenset(
    {
        "version",
        "node",
        "profile",
        "identity",
        "status",
        "old_certificate_sha256",
        "new_certificate_sha256",
        "before_sha256",
    }
)
START_FIELDS = frozenset(
    {
        "pid",
        "start_tick",
        "boot_id",
        "lock_fd",
        "issued_at",
        "expires_at",
        "helper_path",
        "action",
    }
)


def execute(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=10).stdout  # noqa: S603


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def read_object(data: bytes) -> dict[str, Any]:
    record = json.loads(data, object_pairs_hook=strict_object)
    if type(record) is not dict:
        raise ValueError("invalid record")
    return record


def protocol() -> Any:
    specification = importlib.util.spec_from_file_location(
        "praho_mail_setup_protocol", Path(__file__).with_name("praho_mail_setup.py")
    )
    if specification is None or specification.loader is None:
        raise ValueError("mail setup protocol is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def configured(marker: dict[str, Any]) -> bool:
    spec = importlib.util.spec_from_file_location("praho_mail_node", Path(__file__).with_name("praho-mail.py"))
    if spec is None or spec.loader is None:
        raise ValueError("mail node helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    node = module.MailNode()
    expected = marker["node"]
    node.profile(expected)
    if node.profile_id != marker["profile"]:
        return False
    setup = node.setup_driver()
    if marker["status"] == "ready":
        setup.security_configuration(expected)
    elif marker["status"] == "certificate_starting":
        # The boot guard has already proved the complete candidate manifest and
        # live operation. Do not forge a ready journal before wire verification.
        setup.check_files(marker)
        setup._security_settings()
        certificate_public = setup.execute(["openssl", "x509", "-in", "/etc/praho-mail/node.pem", "-pubkey", "-noout"])
        key_public = setup.execute(["openssl", "pkey", "-in", "/etc/praho-mail/node.key", "-pubout"])
        if not certificate_public.strip() or certificate_public.strip() != key_public.strip():
            return False
    else:
        return False
    # Verify the actual owned server certificate, rather than the later Webmin source file.
    execute(setup.certificate_verify_command(expected, Path("/etc/praho-mail/node.pem")))
    return True


class MailBootGuard:
    def __init__(
        self,
        root: Path = Path("/"),
        *,
        execute: Callable[[list[str]], str | None] = execute,
        configured: Callable[[dict[str, Any]], bool] = configured,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.root = root
        self.execute = execute
        self.configured = configured
        self.clock = clock

    def allowed(self) -> bool:
        try:
            file = self.root / "var/lib/praho/mail/node.json"
            if file.is_symlink() or file.stat().st_uid != os.geteuid() or file.stat().st_mode & 0o022:
                raise ValueError("invalid mail journal")
            marker = json.loads(file.read_text())
            if marker.get("version") != 1 or marker.get("profile") not in PROFILES:
                return False
            if marker.get("status") == "ready":
                return self.configured(marker)
            if marker.get("status") == "certificate_starting":
                return self.certificate_start(marker)
            if not self.live_setup(marker):
                return False
            for program in ("iptables", "ip6tables"):
                self.execute([program, "-w", "5", "-C", "INPUT", "-j", CHAIN])
                self.execute(
                    [program, "-w", "5", "-C", CHAIN, "-p", "tcp", "-m", "multiport", "--dports", PORTS, "-j", "REJECT"]
                )
            return True
        except Exception:
            return False

    def owned_bytes(self, name: str, *, private: bool = False) -> bytes:
        """Read a bounded regular file through owned, non-writable directories."""
        parts = name.split("/")
        if not name.startswith("/") or any(part in {"", ".", ".."} for part in parts[1:]):
            raise ValueError("invalid owned path")
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                metadata = os.fstat(descriptor)
                if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                    raise ValueError("mutable owned directory")
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            try:
                metadata = os.fstat(leaf)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or metadata.st_mode & (0o077 if private else 0o022)
                    or metadata.st_size > MAX_FILE_BYTES
                ):
                    raise ValueError("invalid owned file")
                with os.fdopen(leaf, "rb", closefd=False) as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                after = os.fstat(leaf)
                if len(data) > MAX_FILE_BYTES or (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    raise ValueError("owned file changed")
                return data
            finally:
                os.close(leaf)
        finally:
            os.close(descriptor)

    def private_directory(self, name: str) -> None:
        directory = self.root / name.lstrip("/")
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError("invalid private directory")

    def proc_bytes(self, name: str) -> bytes:
        # Every path is fixed or derived from a strictly typed PID/descriptor.
        # proc files report size zero, so bound the actual read instead.
        with (self.root / "proc" / name).open("rb") as stream:
            value = stream.read(MAX_FILE_BYTES + 1)
        if len(value) > MAX_FILE_BYTES:
            raise ValueError("oversized process evidence")
        return value

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def leaf_digest(cls, data: bytes) -> str:
        match = re.search(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----", data)
        if match is None:
            raise ValueError("missing certificate leaf")
        return cls.digest(ssl.PEM_cert_to_DER_cert(match[0].decode("ascii")))

    def start_permit(self, record: dict[str, Any]) -> dict[str, Any]:
        permit = record["start"]
        if type(permit) is not dict or set(permit) != START_FIELDS:
            raise ValueError("invalid start authority")
        if type(permit["pid"]) is not int or permit["pid"] <= 1:
            raise ValueError("invalid owner pid")
        if type(permit["lock_fd"]) is not int or not 0 <= permit["lock_fd"] <= MAX_LOCK_FD:
            raise ValueError("invalid lock descriptor")
        if not isinstance(permit["start_tick"], str) or not re.fullmatch(r"[1-9][0-9]*", permit["start_tick"]):
            raise ValueError("invalid start tick")
        issued, expires, now = permit["issued_at"], permit["expires_at"], self.clock()
        if (
            type(issued) not in {int, float}
            or type(expires) not in {int, float}
            or not all(math.isfinite(value) for value in (issued, expires, now))
            or not 0 <= issued <= now < expires
            or not 0 < expires - issued <= START_SECONDS
        ):
            raise ValueError("expired start authority")
        if permit["action"] != "reconcile_node_certificate" or not isinstance(permit["helper_path"], str):
            raise ValueError("invalid owner action")
        if not re.fullmatch(r"/run/praho-mail-[A-Za-z0-9_-]{1,128}/praho-mail\.py", permit["helper_path"]):
            raise ValueError("invalid fixed helper path")
        if str(UUID(permit["boot_id"])) != permit["boot_id"]:
            raise ValueError("invalid boot identity")
        return permit

    def owner_process(self, record: dict[str, Any], permit: dict[str, Any]) -> None:
        pid = permit["pid"]
        if self.proc_bytes("sys/kernel/random/boot_id").decode().strip() != permit["boot_id"]:
            raise ValueError("owner boot changed")
        fields = self.proc_bytes(f"{pid}/stat").decode().rpartition(") ")[2].split()
        if len(fields) <= START_TICK_INDEX or fields[0] == "Z" or fields[START_TICK_INDEX] != permit["start_tick"]:
            raise ValueError("owner process changed")
        arguments = self.proc_bytes(f"{pid}/cmdline").decode().split("\0")
        if arguments[1:] != [permit["helper_path"], ""]:
            raise ValueError("unrelated owner command")
        if not re.fullmatch(r"(?:/usr/bin/)?python3(?:\.[0-9]+)?", arguments[0]):
            raise ValueError("unrelated owner interpreter")
        environment = [
            entry.partition("=") for entry in self.proc_bytes(f"{pid}/environ").decode().split("\0") if entry
        ]
        for key, expected in {
            "PRAHO_MAIL_ACTION": "reconcile_node_certificate",
            "PRAHO_MAIL_ID": record["identity"],
            "PRAHO_MAIL_NODE": record["node"],
        }.items():
            if [value for name, separator, value in environment if name == key and separator] != [expected]:
                raise ValueError("unrelated owner environment")
        groups = self.proc_bytes("self/cgroup").decode().splitlines()
        if len(groups) != 1 or not groups[0].startswith("0::/") or groups[0].rsplit("/", 1)[-1] not in START_UNITS:
            raise ValueError("unapproved service unit")

    def owner_lock(self, permit: dict[str, Any]) -> None:
        pid = permit["pid"]
        self.private_directory("/run/praho-mail")
        self.owned_bytes("/run/praho-mail/operation.lock", private=True)
        expected_lock = (self.root / "run/praho-mail/operation.lock").stat()
        actual_lock = (self.root / f"proc/{pid}/fd/{permit['lock_fd']}").stat()
        if (actual_lock.st_dev, actual_lock.st_ino) != (expected_lock.st_dev, expected_lock.st_ino):
            raise ValueError("unrelated operation lock")
        lock_lines = [
            line.split()
            for line in self.proc_bytes(f"{pid}/fdinfo/{permit['lock_fd']}").decode().splitlines()
            if line.startswith("lock:")
        ]
        device = f"{os.major(expected_lock.st_dev):02x}:{os.minor(expected_lock.st_dev):02x}:{expected_lock.st_ino}"
        if len(lock_lines) != 1 or lock_lines[0][2:] != [
            "FLOCK",
            "ADVISORY",
            "WRITE",
            str(pid),
            device,
            "0",
            "EOF",
        ]:
            raise ValueError("owner does not hold exclusive lock")

    def start_owner(self, record: dict[str, Any]) -> None:
        permit = self.start_permit(record)
        self.owner_process(record, permit)
        self.owner_lock(permit)

    def certificate_original(self, record: dict[str, Any]) -> dict[str, Any]:
        stage = "/var/lib/praho/mail/certificate-operations/" + record["identity"] + ".stage"
        self.private_directory(stage)
        if {entry.name for entry in (self.root / stage.lstrip("/")).iterdir()} != {
            "before.json",
            "old.pem",
            "old.key",
            "new.pem",
            "new.key",
        }:
            raise ValueError("incomplete certificate staging")
        before_bytes = self.owned_bytes(stage + "/before.json", private=True)
        if self.digest(before_bytes) != record["before_sha256"]:
            raise ValueError("original journal changed")
        before = read_object(before_bytes)
        if set(before) != {"version", "node", "profile", "status", "files"} or (
            type(before["version"]),
            before["version"],
            before["node"],
            before["profile"],
            before["status"],
        ) != (int, 1, record["node"], record["profile"], "ready"):
            raise ValueError("unrelated original journal")
        if type(before["files"]) is not dict or set(before["files"]) != set(record["files"]):
            raise ValueError("incomplete original manifest")
        original = {key: record[key] for key in RECORD_FIELDS}
        original["status"] = "applying"
        operation = self.owned_bytes(
            "/var/lib/praho/mail/certificate-operations/" + record["identity"] + ".json", private=True
        )
        operation_record = read_object(operation)
        if type(operation_record.get("version")) is not int or operation_record != original:
            raise ValueError("unrelated operation journal")
        return before

    def candidate_files(self, record: dict[str, Any]) -> None:
        specification = protocol()
        if type(record["files"]) is not dict or set(record["files"]) != set(specification.CONFIG_PATHS):
            raise ValueError("incomplete candidate manifest")
        for directory in (
            "/var/lib/praho/mail",
            "/var/lib/praho/mail/certificate-operations",
            "/etc/praho-mail",
            "/usr/lib/praho/mail",
        ):
            self.private_directory(directory)
        before = self.certificate_original(record)
        stage = "/var/lib/praho/mail/certificate-operations/" + record["identity"] + ".stage"
        for name, digest in record["files"].items():
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("invalid candidate hash")
            if self.digest(self.owned_bytes(name, private=name in CERTIFICATE_PATHS)) != digest:
                raise ValueError("candidate file changed")
            if name not in CERTIFICATE_PATHS and before["files"][name] != digest:
                raise ValueError("noncertificate configuration changed")
        for name in ("pem", "key"):
            path = "/etc/praho-mail/node." + name
            old, new = (
                self.owned_bytes(stage + "/old." + name, private=True),
                self.owned_bytes(stage + "/new." + name, private=True),
            )
            if self.digest(old) != before["files"][path] or self.digest(new) != record["files"][path]:
                raise ValueError("staged certificate pair changed")
            if name == "pem" and (self.leaf_digest(old), self.leaf_digest(new)) != (
                record["old_certificate_sha256"],
                record["new_certificate_sha256"],
            ):
                raise ValueError("unrelated candidate leaf")
        helper_directory = str(Path(record["start"]["helper_path"]).parent)
        self.private_directory(helper_directory)
        for name in specification.NATIVE_FILES:
            if (
                self.digest(self.owned_bytes(helper_directory + "/" + name, private=True))
                != record["files"]["/usr/lib/praho/mail/" + name]
            ):
                raise ValueError("unrelated staged helper")

    def certificate_fences(self) -> None:
        for program, rejection in (
            ("iptables-save", "icmp-port-unreachable"),
            ("ip6tables-save", "icmp6-port-unreachable"),
        ):
            snapshot = self.execute([program, "-t", "filter"])
            if not isinstance(snapshot, str) or len(snapshot) > MAX_FILE_BYTES:
                raise ValueError("missing firewall evidence")
            lines = [line for line in snapshot.splitlines() if line and not line.startswith("#")]
            jump = "-A INPUT -j " + CHAIN
            rules = [line for line in lines if line.startswith("-A ")]
            owned = [line for line in rules if line.startswith("-A " + CHAIN + " ")]
            if (
                lines.count("*filter") != 1
                or lines.count("COMMIT") != 1
                or len([line for line in lines if line.startswith(":" + CHAIN + " ")]) != 1
                or next((line for line in rules if line.startswith("-A INPUT ")), None) != jump
                or owned
                != [
                    "-A " + CHAIN + " -i lo -j RETURN",
                    "-A " + CHAIN + " -p tcp -m multiport --dports " + PORTS + " -j REJECT --reject-with " + rejection,
                ]
                or [line for line in rules if CHAIN in line.split() and line not in owned] != [jump]
            ):
                raise ValueError("mail fence is bypassable")

    def certificate_start(self, record: dict[str, Any]) -> bool:
        if set(record) != RECORD_FIELDS | {"start", "files", "fenced"} or record["fenced"] is not True:
            return False
        if type(record["version"]) is not int or str(UUID(record["identity"])) != record["identity"]:
            return False
        if (
            not isinstance(record["node"], str)
            or len(record["node"]) > MAX_HOSTNAME_LENGTH
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", record["node"])
        ):
            return False
        for _pass in range(2):
            if read_object(self.owned_bytes("/var/lib/praho/mail/node.json", private=True)) != record:
                return False
            self.start_owner(record)
            self.candidate_files(record)
            self.certificate_fences()
            if _pass == 0 and not self.configured(record):
                return False
        # Configuration and firewall probes can be slow; expiry/owner death is
        # checked again at the point where permission is actually returned.
        self.start_owner(record)
        return read_object(self.owned_bytes("/var/lib/praho/mail/node.json", private=True)) == record

    def live_setup(self, marker: dict[str, Any]) -> bool:
        if marker.get("status") != "applying" or marker.get("fenced") is not True:
            return False
        if type(marker.get("pid")) is not int or marker["pid"] <= 1:
            return False
        if (self.root / "proc/sys/kernel/random/boot_id").read_text().strip() != marker.get("boot_id"):
            return False
        stat = (self.root / f"proc/{marker['pid']}/stat").read_text().rpartition(") ")[2].split()
        return len(stat) > START_TICK_INDEX and stat[START_TICK_INDEX] == marker.get("start_tick")


if __name__ == "__main__":
    if os.geteuid() != 0 or not MailBootGuard().allowed():
        print("mail_startup_unproven", file=sys.stderr)
        raise SystemExit(1)
