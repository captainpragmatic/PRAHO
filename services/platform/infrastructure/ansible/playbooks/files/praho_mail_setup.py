"""Fixed versioned mail setup. Imported only by the root-only mail bundle."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import ssl
import stat
import sys
import tempfile
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

CHAIN = "PRAHO_MAIL_SETUP"
PORTS = "25,110,143,465,587,993,995"
MIN_MASTER_FIELDS = 2
MAX_AUTH_FAILURES = 20
MAX_AUTH_SECONDS = 3600
MIN_AUTH_SECONDS = 60
MAX_CERTIFICATE_BYTES = 1024 * 1024
MAX_CHAIN_CERTIFICATES = 16
MAX_CERTIFICATE_OPERATION_BYTES = 4096
CERTIFICATE_RELOAD_WAIT_SECONDS = 30
CERTIFICATE_RELOAD_POLL_SECONDS = 0.25
NATIVE_FILES = (
    "praho-mail.py",
    "praho_mail_setup.py",
    "praho-mail-native.pl",
    "praho-mail-boot.py",
    "praho_mail_submitters.py",
)
UNITS = ("postfix.service", "postfix@.service", "dovecot.service")
# Like the packaged Postfix preflight, this short root-only check needs the host's
# proc/firewall view. The daemon retains its native capability and mount restrictions.
UNIT_GUARD = b"[Service]\nExecStartPre=+/usr/bin/python3 /usr/lib/praho/mail/praho-mail-boot.py\n"
PACKAGES = (
    "postfix",
    "dovecot-imapd",
    "dovecot-pop3d",
    "dovecot-submissiond",
    "procmail",
    "procmail-wrapper",
    "opendkim",
    "libpam-modules",
)
CONFIG_PATHS = (
    "/etc/dovecot/conf.d/auth-praho.conf.ext",
    "/etc/dovecot/conf.d/99-zz-praho-mail.conf",
    "/etc/dovecot/conf.d/10-auth.conf",
    "/etc/pam.d/praho-dovecot",
    "/etc/praho-mail/node.pem",
    "/etc/praho-mail/node.key",
    "/etc/postfix/praho-system-recipients",
    "/etc/postfix/praho-system-recipients.db",
    "/usr/lib/praho/mail/pam.template",
    *("/usr/lib/praho/mail/" + name for name in NATIVE_FILES),
    *("/etc/systemd/system/" + name + ".d/praho-mail.conf" for name in UNITS),
)
POSTFIX = {
    "mynetworks": "127.0.0.0/8 [::1]/128",
    "smtpd_sasl_auth_enable": "no",
    "smtpd_sasl_type": "dovecot",
    "smtpd_sasl_path": "private/auth",
    "smtpd_relay_restrictions": "reject_unauth_destination",
    "smtpd_recipient_restrictions": "reject_unlisted_recipient",
    "local_recipient_maps": "hash:/etc/postfix/praho-system-recipients $alias_maps",
    "smtpd_tls_security_level": "may",
    "smtpd_tls_cert_file": "/etc/praho-mail/node.pem",
    "smtpd_tls_key_file": "/etc/praho-mail/node.key",
    "smtpd_tls_CAfile": "/etc/ssl/certs/ca-certificates.crt",
    "smtp_tls_security_level": "may",
    "smtp_tls_CAfile": "/etc/ssl/certs/ca-certificates.crt",
    "smtpd_authorized_xclient_hosts": "",
    "smtpd_sender_login_maps": "hash:/etc/postfix/praho-sender-logins",
    "local_login_sender_maps": "texthash:/etc/postfix/praho-local-senders",
    "home_mailbox": "Maildir/",
    "allow_percent_hack": "no",
    "resolve_dequoted_address": "no",
}
MASTER = """smtp inet n - y - - smtpd
  -o smtpd_sasl_auth_enable=no
127.0.0.1:1465 inet n - n - - smtpd
  -o smtpd_tls_wrappermode=yes
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_authorized_xclient_hosts=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o smtpd_sender_restrictions=reject_authenticated_sender_login_mismatch
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
"""


def atomic(path: Path, content: bytes, mode: int = 0o600) -> None:
    """Never truncate a live config/key; keep incomplete writes private until rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class MailSetup:
    def __init__(self, node: Any, error: type[Exception]) -> None:
        self.node = node
        self.error = error
        self.path = node.path
        self.execute = node.execute
        self.state = node.state
        self.templates = Path(__file__).with_name("mail-templates")

    def refuse(self, code: str) -> None:
        raise self.error(code)

    def certificate_verify_command(self, expected: str, certificate: Path) -> list[str]:
        # Match the actual TLS client's verification policy. Recent Python
        # runtimes enable strict X.509 checks; reject unusable material before setup.
        strict = ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT
        return [
            "openssl",
            "verify",
            *(["-x509_strict"] if strict else []),
            "-CAfile",
            str(self.path("/etc/ssl/certs/ca-certificates.crt")),
            "-purpose",
            "sslserver",
            "-verify_hostname",
            expected,
            "-untrusted",
            str(certificate),
            str(certificate),
        ]

    def certificate_chain(self, cert: Path, extra: Path | None = None) -> bytes:
        blocks = []
        for file in (cert, extra):
            if file is None:
                continue
            data = file.read_bytes()
            if len(data) > MAX_CERTIFICATE_BYTES:
                self.refuse("mail_node_certificate_unproven")
            blocks.extend(
                re.findall(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----", data)
            )
        unique = tuple(dict.fromkeys(block.strip() + b"\n" for block in blocks))
        if not unique or len(unique) > MAX_CHAIN_CERTIFICATES:
            self.refuse("mail_node_certificate_unproven")
        return b"".join(unique)

    def certificate(self, expected: str) -> tuple[bytes, bytes]:
        try:
            values = dict(
                line.split("=", 1)
                for line in self.path("/etc/webmin/miniserv.conf").read_text().splitlines()
                if "=" in line
            )
            key = self.path(values["keyfile"])
            cert = self.path(values.get("certfile") or values["keyfile"])
            for file in {key, cert}:
                if not file.is_file() or file.is_symlink() or file.stat().st_uid != 0:
                    self.refuse("mail_node_certificate_unproven")
            if key.stat().st_mode & 0o077:
                self.refuse("mail_node_certificate_unproven")
            extra_name = values.get("extracas", "")
            if extra_name and (not extra_name.startswith("/") or not self.path(extra_name).is_file()):
                self.refuse("mail_node_certificate_unproven")
            chain = self.certificate_chain(cert, self.path(extra_name) if extra_name else None)
            # Snapshot the matching key/chain before package work; a concurrent Webmin renewal
            # must not mix an earlier leaf with a later private key.
            key_material = self.execute(["openssl", "pkey", "-in", str(key)])
            with tempfile.NamedTemporaryFile(dir=self.path("/run"), prefix="praho-mail-chain-") as bundle:
                bundle.write(chain)
                bundle.flush()
                cert_public = self.execute(["openssl", "x509", "-in", bundle.name, "-pubkey", "-noout"])
                key_public = self.execute(["openssl", "pkey", "-pubout"], stdin=key_material)
                if not cert_public.strip() or cert_public.strip() != key_public.strip():
                    self.refuse("mail_node_certificate_unproven")
                self.execute(self.certificate_verify_command(expected, Path(bundle.name)))
                expiry = self.execute(["openssl", "x509", "-in", bundle.name, "-enddate", "-noout"]).strip()
            expiry_date = datetime.strptime(expiry.removeprefix("notAfter="), "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
            if expiry_date < datetime.now(UTC) + timedelta(days=7):
                self.refuse("mail_node_certificate_unproven")
            return chain, key_material.encode()
        except Exception as error:
            raise self.error("mail_node_certificate_unproven") from error

    def marker(self, expected: str) -> dict[str, Any] | None:
        path = self.state / "node.json"
        if not path.exists():
            return None
        try:
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                self.refuse("mail_setup_review_required")
            data = json.loads(path.read_text())
            if (type(data.get("version")), data.get("version")) != (int, 1) or (
                data.get("profile"),
                data.get("node"),
                data.get("status"),
            ) != (
                self.node.profile_id,
                expected,
                "ready",
            ):
                self.refuse("mail_setup_review_required")
            self.check_files(data)
            return data
        except (ValueError, OSError, TypeError, AttributeError) as error:
            raise self.error("mail_setup_review_required") from error

    def check_files(self, record: dict[str, Any]) -> None:
        if not isinstance(record.get("files"), dict) or set(record["files"]) != set(CONFIG_PATHS):
            self.refuse("mail_setup_review_required")
        for name, digest in record["files"].items():
            file = self.path(name)
            metadata = file.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                self.refuse("mail_setup_review_required")
            if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
                self.refuse("mail_setup_review_required")

    def private_directory(self, directory: Path) -> None:
        directory.mkdir(mode=0o700, exist_ok=True)
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            self.refuse("mail_setup_review_required")

    def leaf_digest(self, chain: bytes) -> str:
        block = re.search(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----", chain)
        if block is None:
            self.refuse("mail_node_certificate_unproven")
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(block[0].decode("ascii"))).hexdigest()

    def certificate_proof(self, expected: str, digest: str) -> str:
        rows = self.node.probe(expected)
        services = {"imap", "pop3", "submission", "smtp"}
        if set(self.node.public_ports()) != {25, 465, 993, 995} or len(rows) != len(services):
            self.refuse("mail_node_certificate_unproven")
        if {row.get("service") for row in rows} != services:
            self.refuse("mail_node_certificate_unproven")
        expiries = []
        for row in rows:
            if row.get("hostname") != expected or row.get("sha256") != digest:
                self.refuse("mail_node_certificate_unproven")
            expiry = datetime.fromisoformat(row["not_after"])
            if expiry.tzinfo is None or expiry <= datetime.now(UTC):
                self.refuse("mail_node_certificate_unproven")
            expiries.append(expiry)
        return min(expiries).isoformat()

    def certificate_result(self, expected: str, digest: str, outcome: str, *, pending: str = "") -> dict[str, Any]:
        return {
            "node_hostname": expected,
            "profile": self.node.profile_id,
            "configured": True,
            "default_mail_off": True,
            "public_ports": [25, 465, 993, 995],
            "outcome": outcome,
            "certificate_sha256": digest,
            "not_after": self.certificate_proof(expected, digest),
            "pending_code": pending,
        }

    def wait_for_certificate(self, expected: str, digest: str) -> dict[str, Any]:
        deadline = time.monotonic() + CERTIFICATE_RELOAD_WAIT_SECONDS
        while True:
            try:
                return self.certificate_result(expected, digest, "replaced")
            except self.error as error:
                if str(error) != "mail_node_certificate_unproven" or time.monotonic() >= deadline:
                    raise
                time.sleep(CERTIFICATE_RELOAD_POLL_SECONDS)
                if time.monotonic() >= deadline:
                    raise

    def completed_certificate_operation(self, path: Path, expected: str, identity: str) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            self.refuse("mail_setup_review_required")
        if metadata.st_size > MAX_CERTIFICATE_OPERATION_BYTES:
            self.refuse("mail_setup_review_required")
        record = json.loads(path.read_text())
        if (type(record.get("version")), record.get("version")) != (int, 1) or (
            record.get("node"),
            record.get("profile"),
            record.get("identity"),
            record.get("status"),
        ) != (expected, self.node.profile_id, identity, "completed"):
            self.refuse("mail_setup_review_required")
        return True

    def retire_certificate_stage(self, stage: Path) -> None:
        if not stage.exists() and not stage.is_symlink():
            return
        self.private_directory(stage)
        entries = tuple(stage.iterdir())
        if {entry.name for entry in entries} - {"old.pem", "old.key", "new.pem", "new.key", "before.json"}:
            self.refuse("mail_setup_review_required")
        for entry in entries:
            metadata = entry.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                self.refuse("mail_setup_review_required")
        for entry in entries:
            entry.unlink()
        stage.rmdir()
        descriptor = os.open(stage.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def certificate_record(self, before: dict[str, Any], identity: str, old: str, new: str) -> dict[str, Any]:
        return {
            "version": 1,
            "node": before["node"],
            "profile": before["profile"],
            "identity": identity,
            "status": "certificate_applying",
            "old_certificate_sha256": old,
            "new_certificate_sha256": new,
            "before_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
        }

    def reconcile_certificate(self, expected: str, identity: str) -> dict[str, Any]:
        self.node.stage = "certificate_preflight"
        self.node.profile(expected)
        if str(UUID(identity)) != identity:
            self.refuse("mail_native_inspection_failed")
        before = self.marker(expected)
        if before is None:
            self.refuse("mail_setup_review_required")
        self.private_directory(self.state)
        self.security_configuration(expected)
        if any(chain or jump for chain, jump in self.read_fences().values()):
            self.refuse("mail_setup_review_required")
        certificate, key = self.path("/etc/praho-mail/node.pem"), self.path("/etc/praho-mail/node.key")
        if key.stat().st_mode & 0o077:
            self.refuse("mail_setup_review_required")
        current = self.leaf_digest(certificate.read_bytes())
        operations = self.state / "certificate-operations"
        tombstone = operations / (identity + ".json")
        stage = operations / (identity + ".stage")
        if operations.exists() or operations.is_symlink():
            self.private_directory(operations)
            if self.completed_certificate_operation(tombstone, expected, identity):
                result = self.certificate_result(expected, current, "unchanged")
                self.retire_certificate_stage(stage)
                return result
        self.node.stage = "certificate_candidate"
        try:
            chain, private_key = self.certificate(expected)
        except self.error:
            return self.certificate_result(
                expected, current, "retained_previous", pending="mail_node_certificate_unproven"
            )
        if (certificate.read_bytes(), key.read_bytes()) == (chain, private_key):
            result = self.certificate_result(expected, current, "unchanged")
            self.private_directory(operations)
            record = self.certificate_record(before, identity, current, current)
            atomic(tombstone, json.dumps({**record, "status": "completed"}).encode())
            return result
        return self.install_certificate(before, identity, chain, private_key)

    def install_certificate(
        self, before: dict[str, Any], identity: str, chain: bytes, private_key: bytes
    ) -> dict[str, Any]:
        expected = before["node"]
        self.check_files(before)
        certificate, key = self.path("/etc/praho-mail/node.pem"), self.path("/etc/praho-mail/node.key")
        current, candidate = self.leaf_digest(certificate.read_bytes()), self.leaf_digest(chain)
        operations = self.state / "certificate-operations"
        tombstone, stage = operations / (identity + ".json"), operations / (identity + ".stage")
        self.private_directory(operations)
        if stage.exists() or stage.is_symlink():
            self.refuse("mail_setup_review_required")
        stage.mkdir(mode=0o700)
        record = self.certificate_record(before, identity, current, candidate)
        completed = False
        try:
            self.node.stage = "certificate_staging"
            atomic(self.state / "node.json", json.dumps(record).encode())
            atomic(tombstone, json.dumps({**record, "status": "applying"}).encode())
            for name, content in {
                "old.pem": certificate.read_bytes(),
                "old.key": key.read_bytes(),
                "new.pem": chain,
                "new.key": private_key,
                "before.json": json.dumps(before, sort_keys=True).encode(),
            }.items():
                atomic(stage / name, content)
            self.node.stage = "certificate_installing"
            atomic(certificate, chain)
            atomic(key, private_key)
            self.execute(["doveconf", "-n"])
            self.execute(["postfix", "check"])
            self.node.stage = "certificate_reload"
            self.execute(["systemctl", "reload", "dovecot"])
            self.execute(["postfix", "reload"])
            self.node.stage = "certificate_verification"
            response = self.wait_for_certificate(expected, candidate)
            ready = {
                **before,
                "files": {
                    **before["files"],
                    "/etc/praho-mail/node.pem": hashlib.sha256(chain).hexdigest(),
                    "/etc/praho-mail/node.key": hashlib.sha256(private_key).hexdigest(),
                },
            }
            self.check_files(ready)
            atomic(tombstone, json.dumps({**record, "status": "completed"}).encode())
            atomic(self.state / "node.json", json.dumps(ready).encode())
            self.retire_certificate_stage(stage)
            completed = True
            return response
        finally:
            if not completed:
                atomic(self.state / "node.json", json.dumps({**record, "status": "review_required"}).encode())

    def security(self, expected: str, *, allow_fence: bool = False) -> bool:
        self.node.stage = "verification_owned_files"
        if self.marker(expected) is None:
            return False
        self.security_configuration(expected)
        self.node.stage = "verification_firewall"
        if not allow_fence and any(chain or jump for chain, jump in self.read_fences().values()):
            return False
        self.node.stage = "verification_listeners"
        ports = set(self.node.public_ports())
        if ports != {25, 465, 993, 995}:
            self.refuse("mail_setup_review_required")
        self.node.stage = "verification_tls"
        certs = self.node.probe(expected)
        return {item.get("service") for item in certs} == {"imap", "pop3", "submission", "smtp"}

    def security_configuration(self, expected: str) -> None:
        if self.marker(expected) is None:
            self.refuse("mail_setup_review_required")
        self.node.stage = "verification_native_backend"
        inventory = self.node.native("inventory")
        if (
            inventory.get("mail_backend_selected") is not True
            or inventory.get("mail_default_off") is not True
            or inventory.get("mail_available") is not True
        ):
            self.refuse("mail_setup_review_required")
        self.node.stage = "verification_postfix_core"
        for key, value in POSTFIX.items():
            if self.execute(["postconf", "-h", key]).strip() != value:
                self.refuse("mail_setup_review_required")
        self.node.stage = "verification_submitters"
        sender_map = self.path("/etc/postfix/praho-local-senders")
        if (
            not sender_map.is_file()
            or sender_map.is_symlink()
            or sender_map.stat().st_uid != os.geteuid()
            or sender_map.stat().st_mode & 0o022
        ):
            self.refuse("mail_setup_review_required")
        self.node.stage = "verification_postfix_auth"
        override = self.execute(["postconf", "-P", "smtp/inet/smtpd_sasl_auth_enable"])
        key, separator, value = override.partition("=")
        if not separator or key.strip() != "smtp/inet/smtpd_sasl_auth_enable" or value.strip() != "no":
            self.refuse("mail_setup_review_required")
        self.node.stage = "verification_postfix_listeners"
        master = self.execute(["postconf", "-M"]).splitlines()
        allowed = {"smtp", "127.0.0.1:1465"}
        for line in master:
            parts = line.split()
            if len(parts) >= MIN_MASTER_FIELDS and parts[1] == "inet" and parts[0] not in allowed:
                self.refuse("mail_setup_review_required")
        if self.path("/etc/dovecot/praho-proxy-smtp").read_bytes():
            self.refuse("mail_setup_review_required")
        self.dovecot_security()
        self.execute(["postfix", "check"])

    def install_boot_guard(self) -> None:
        directory = self.path("/usr/lib/praho/mail")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        for name in NATIVE_FILES:
            atomic(directory / name, Path(__file__).with_name(name).read_bytes())
        for unit in UNITS:
            atomic(self.path("/etc/systemd/system/" + unit + ".d/praho-mail.conf"), UNIT_GUARD)
        self.execute(["systemctl", "daemon-reload"])

    def render_pam(self, *, failures: int, window: int, unlock: int) -> bytes:
        if any(type(value) is not int for value in (failures, window, unlock)):
            self.refuse("mail_auth_policy_invalid")
        if (
            not 1 <= failures <= MAX_AUTH_FAILURES
            or not MIN_AUTH_SECONDS <= window <= MAX_AUTH_SECONDS
            or not MIN_AUTH_SECONDS <= unlock <= MAX_AUTH_SECONDS
        ):
            self.refuse("mail_auth_policy_invalid")
        text = (self.templates / "pam").read_text()
        for token, value in {"FAILURES": failures, "WINDOW": window, "UNLOCK": unlock}.items():
            text = text.replace("@" + token + "@", str(value))
        return text.encode()

    def dovecot_security(self) -> None:
        self.node.stage = "verification_dovecot_auth"
        configuration = self.execute(["doveconf", "-n"])
        modern = self.node.profile_id == "ubuntu2604-dovecot24"
        if modern:
            self.dovecot24_auth(configuration)
        else:
            passdbs = re.findall(r"\bpassdb\s*\{([^{}]*)\}", configuration)
            expected_args = {"/etc/dovecot/praho-deny", "username_format=%u /etc/dovecot/praho-proxy-%s"}
            args = set()
            if len(passdbs) != MIN_MASTER_FIELDS:
                self.refuse("mail_setup_review_required")
            for block in passdbs:
                values = dict(line.strip().split(" = ", 1) for line in block.splitlines() if " = " in line)
                if values.get("driver") != "passwd-file":
                    self.refuse("mail_setup_review_required")
                args.add(values.get("args"))
            if args != expected_args:
                self.refuse("mail_setup_review_required")
        self.node.stage = "verification_dovecot_tls"
        cleartext = {"auth_allow_cleartext": "no"} if modern else {"disable_plaintext_auth": "yes"}
        for key, expected in {
            "ssl": "required",
            "ssl_min_protocol": "TLSv1.2",
            **cleartext,
            "login_trusted_networks": "",
            "auth_verbose_passwords": "no",
            "auth_cache_size": "0",
        }.items():
            if self.execute(["doveconf", "-h", key]).strip() != expected:
                self.refuse("mail_setup_review_required")

    def dovecot24_auth(self, configuration: str) -> None:
        # Use doveconf's canonical top-level blocks. Variable braces in field values
        # are not nested configuration sections, and must not truncate the parser.
        total = re.findall(r"(?m)^\s*passdb(?:\s+[^\s{}]+)?\s*\{", configuration)
        blocks = re.findall(r"(?m)^passdb ([^\s{}]+) \{\n((?:[ \t]+[^\n]*\n)*)\}", configuration)
        expected = [
            (
                "praho-deny",
                {
                    "driver": "passwd-file",
                    "deny": "yes",
                    "result_internalfail": "return-fail",
                    "passwd_file_path": "/etc/dovecot/praho-deny",
                },
            ),
            (
                "praho-proxy",
                {
                    "driver": "passwd-file",
                    "auth_username_format": "%{user}",
                    "result_failure": "return-fail",
                    "result_internalfail": "return-fail",
                    "result_success": "return-ok",
                    "passwd_file_path": "/etc/dovecot/praho-proxy-%{protocol}",
                },
            ),
        ]
        if len(total) != len(expected) or len(blocks) != len(expected):
            self.refuse("mail_setup_review_required")
        for (name, block), (wanted_name, wanted) in zip(blocks, expected, strict=True):
            lines = [line.strip().split(" = ", 1) for line in block.splitlines()]
            if any(len(line) != MIN_MASTER_FIELDS for line in lines):
                self.refuse("mail_setup_review_required")
            values = dict(lines)
            if name != wanted_name or len(values) != len(lines) or values != wanted:
                self.refuse("mail_setup_review_required")

    def install_fence(self) -> None:
        # Scope exclusively to mail ports, preserve existing/operator firewall chains.
        for program in ("iptables", "ip6tables"):
            self.execute([program, "-w", "5", "-N", CHAIN])
            self.execute(
                [program, "-w", "5", "-A", CHAIN, "-p", "tcp", "-m", "multiport", "--dports", PORTS, "-j", "REJECT"]
            )
            self.execute([program, "-w", "5", "-I", "INPUT", "1", "-j", CHAIN])

    def read_fences(self) -> dict[str, tuple[bool, bool]]:
        snapshots = {}
        for program in ("iptables", "ip6tables"):
            rules = self.execute([program + "-save", "-t", "filter"]).splitlines()
            if "*filter" not in rules or "COMMIT" not in rules:
                self.refuse("mail_setup_review_required")
            chain = any(line.startswith(":" + CHAIN + " ") for line in rules)
            jump = "-A INPUT -j " + CHAIN
            own = [line for line in rules if line.startswith("-A " + CHAIN + " ")]
            reject_type = "icmp-port-unreachable" if program == "iptables" else "icmp6-port-unreachable"
            allowed = {
                "-A " + CHAIN + " -i lo -j RETURN",
                "-A " + CHAIN + " -p tcp -m multiport --dports " + PORTS + " -j REJECT --reject-with " + reject_type,
            }
            references = [line for line in rules if "-j " + CHAIN in line]
            if any(line not in allowed for line in own) or references not in ([], [jump]) or (references and not chain):
                self.refuse("mail_setup_review_required")
            snapshots[program] = (chain, bool(references))
        return snapshots

    def cleanup_fence(self) -> None:
        # Read/validate both families before changing either. Partial previous teardown is replayable.
        for program, (chain, jump) in self.read_fences().items():
            if jump:
                self.execute([program, "-w", "5", "-D", "INPUT", "-j", CHAIN])
            if chain:
                self.execute([program, "-w", "5", "-F", CHAIN])
                self.execute([program, "-w", "5", "-X", CHAIN])

    def allow_local_probe(self) -> None:
        for program in ("iptables", "ip6tables"):
            self.execute([program, "-w", "5", "-I", CHAIN, "1", "-i", "lo", "-j", "RETURN"])

    @contextlib.contextmanager
    def package_policy(self) -> Iterator[None]:
        file = self.path("/usr/sbin/policy-rc.d")
        if file.is_symlink():
            self.refuse("mail_unmanaged_mta")
        original = (file.read_bytes(), file.stat().st_mode & 0o777) if file.exists() else None
        guard = b"#!/bin/sh\nexit 101\n"
        atomic(file, guard, 0o755)
        try:
            yield
        finally:
            if file.read_bytes() != guard:
                self.refuse("mail_setup_review_required")
            if original:
                atomic(file, *original)
            else:
                file.unlink()

    def candidates(self) -> None:
        _identifier, dovecot_prefix, postfix_prefix = self.node.profile_settings()
        for package, prefix in (("postfix", postfix_prefix), ("dovecot-core", "1:" + dovecot_prefix)):
            output = self.execute(["apt-cache", "policy", package])
            candidate = re.search(r"(?m)^\s*Candidate:\s*(\S+)$", output)
            if candidate is None or not candidate[1].startswith(prefix):
                self.refuse("mail_profile_unsupported")

    def provider_digest(self) -> str:
        hashes = []
        for name, permitted in (
            # Native collectinfo writes this timestamp through Webmin's own
            # scheduler, independently of setup and the system cron service.
            ("virtual-server", {"mail_system", "mail", "last_check", "last_letsencrypt_mass_renewal"}),
            ("mailboxes", {"mail_system"}),
        ):
            file = self.path("/etc/webmin/" + name + "/config")
            # Webmin rewrites parsed settings as key=value lines; blank-only
            # lines carry no policy and disappear during that native write.
            lines = [
                line
                for line in file.read_text().splitlines()
                if line.strip() and line.partition("=")[0] not in permitted
            ]
            hashes.append(hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest())
        return hashlib.sha256("".join(hashes).encode()).hexdigest()

    def configure(self, expected: str, certificate_pem: bytes, key_pem: bytes) -> None:
        for directory in ("/etc/praho-mail", "/var/lib/praho/mail", "/var/lib/praho/mail/faillock"):
            self.path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.path(directory), 0o700)
        atomic(self.path("/etc/praho-mail/node.pem"), certificate_pem)
        # Copy the verified private snapshot only into our root-private file; Webmin is unchanged.
        atomic(self.path("/etc/praho-mail/node.key"), key_pem)
        variant = {"debian12-dovecot23": "23", "ubuntu2604-dovecot24": "24"}[self.node.profile_id]
        for source, destination in (
            ("dovecot" + variant + ".conf", "/etc/dovecot/conf.d/99-zz-praho-mail.conf"),
            ("auth" + variant + ".conf", "/etc/dovecot/conf.d/auth-praho.conf.ext"),
        ):
            atomic(self.path(destination), (self.templates / source).read_bytes())
        # Policy is selected by explicit enrollment; default-off capability grants no Unix login.
        atomic(self.path("/etc/pam.d/praho-dovecot"), b"auth requisite pam_deny.so\naccount requisite pam_deny.so\n")
        atomic(self.path("/usr/lib/praho/mail/pam.template"), (self.templates / "pam").read_bytes())
        auth = self.path("/etc/dovecot/conf.d/10-auth.conf")
        text = auth.read_text()
        if text.count("!include auth-system.conf.ext") != 1:
            self.refuse("mail_unmanaged_mta")
        # No PAM fallback exists until an explicit hosted-user roster is installed.
        atomic(auth, text.replace("!include auth-system.conf.ext", "!include auth-praho.conf.ext").encode(), 0o644)
        for name in ("deny", "proxy-imap", "proxy-pop3", "proxy-submission", "proxy-smtp"):
            file = self.path("/etc/dovecot/praho-" + name)
            atomic(file, b"", 0o640)
            self.execute(["chown", "root:dovecot", str(file)])
        atomic(self.path("/etc/postfix/praho-sender-logins"), b"", 0o640)
        self.execute(["postmap", str(self.path("/etc/postfix/praho-sender-logins"))])
        atomic(self.path("/etc/postfix/praho-system-recipients"), b"root OK\npostmaster OK\n", 0o644)
        self.execute(["postmap", "hash:" + str(self.path("/etc/postfix/praho-system-recipients"))])
        for key_name, value in {**POSTFIX, "myhostname": expected}.items():
            self.execute(["postconf", "-e", key_name + "=" + value])
        master = self.path("/etc/postfix/master.cf")
        lines = []
        skip = False
        for line in master.read_text().splitlines():
            if line and not line.startswith((" ", "\t", "#")):
                fields = line.split()
                # Preserve smtp/unix and every unrelated native UNIX service.
                skip = len(fields) >= MIN_MASTER_FIELDS and fields[1] == "inet"
            if not skip:
                lines.append(line)
        atomic(master, ("\n".join(lines) + "\n" + MASTER).encode(), 0o644)
        self.execute(["doveconf", "-n"])
        self.execute(["postfix", "check"])

    def install_packages(self, expected: str, admission: dict[str, Any], applying: dict[str, Any]) -> None:
        self.node.stage = "packages"
        with self.package_policy():
            self.execute(["apt-get", "-o", "APT::Update::Error-Mode=any", "update"], timeout=120)
            self.candidates()
            self.execute(["apt-get", "install", "-y", "--no-install-recommends", "iptables"], timeout=120)
            self.install_fence()
            applying["fenced"] = True
            atomic(self.state / "node.json", json.dumps(applying).encode())
            if admission["mta"] == "exim4":
                self.execute(["systemctl", "stop", "exim4"])
            # Queue may have grown since the first inspection. Never discard accepted mail.
            self.node.preflight_setup(expected)
            self.execute(["apt-get", "install", "-y", "--no-install-recommends", *PACKAGES], timeout=300)
            self.node.check_exim_spool()

    def run(self, expected: str) -> dict[str, Any]:
        self.node.stage = "preflight"
        self.node.profile(expected)
        if self.marker(expected) is not None:
            if not self.security(expected, allow_fence=True):
                self.refuse("mail_setup_review_required")
            self.cleanup_fence()
            return self.node.inspect_node(expected)
        admission = self.node.preflight_setup(expected)
        zones = self.node.reserved_zones()
        if admission["mta"] == "postfix" and "texthash" not in self.execute(["postconf", "-m"]).split():
            self.refuse("mail_profile_unsupported")
        if self.state.exists():
            self.refuse("mail_setup_review_required")
        self.node.stage = "node_certificate"
        certificate_pem, key_pem = self.certificate(expected)
        baseline = self.provider_digest()
        self.state.mkdir(mode=0o700, parents=True)
        applying = {
            "version": 1,
            "profile": self.node.profile_id,
            "node": expected,
            "status": "applying",
            "pid": os.getpid(),
            "start_tick": self.path("/proc/self/stat").read_text().rpartition(") ")[2].split()[19],
            "fenced": False,
            "boot_id": self.path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        }
        atomic(
            self.state / "node.json",
            json.dumps(applying).encode(),
        )
        completed = False
        try:
            self.install_boot_guard()
            self.install_packages(expected, admission, applying)
            self.node.stage = "native_configuration"
            self.execute(
                ["virtualmin", "config-system", "--include", "Postfix", "Dovecot", "Procmail", "--test"], timeout=120
            )
            self.node.native("select_backend")
            self.node.stage = "secure_configuration"
            self.configure(expected, certificate_pem, key_pem)
            if "texthash" not in self.execute(["postconf", "-m"]).split():
                self.refuse("mail_profile_unsupported")
            self.node.native("reconcile_submitters", node=expected, reserved_zones=json.dumps(zones))
            if self.provider_digest() != baseline:
                self.refuse("mail_unrelated_configuration_changed")
            if self.node.native("inventory").get("mail_default_off") is not True:
                self.refuse("mail_setup_review_required")
            self.node.stage = "service_start"
            self.execute(["systemctl", "restart", "dovecot", "postfix"])
            self.allow_local_probe()
            files = {name: hashlib.sha256(self.path(name).read_bytes()).hexdigest() for name in CONFIG_PATHS}
            atomic(
                self.state / "node.json",
                json.dumps(
                    {"version": 1, "profile": self.node.profile_id, "node": expected, "status": "ready", "files": files}
                ).encode(),
            )
            # Validate with the fence still installed, including certificate/name/key proof.
            self.node.stage = "verification"
            if not self.security(expected, allow_fence=True):
                self.refuse("mail_setup_review_required")
            self.node.stage = "remove_fence"
            self.cleanup_fence()
            observation = self.node.inspect_node(expected)
            completed = True
            return observation
        finally:
            if not completed:
                self.hold_for_review(expected)

    def hold_for_review(self, expected: str) -> None:
        # Unknown partial installs remain fenced across reboot. Preserve process
        # interruptions as well as ordinary errors; never resume package defaults.
        atomic(
            self.state / "node.json",
            json.dumps(
                {
                    "version": 1,
                    "profile": self.node.profile_id,
                    "node": expected,
                    "status": "review_required",
                    "phase": self.node.stage,
                }
            ).encode(),
        )
        try:
            self.execute(["systemctl", "mask", "--now", "postfix.service", "dovecot.service"])
        except Exception:
            # Keep the original failure. Report the failed secondary safeguard
            # without copying command output or native configuration into logs.
            print("mail_service_mask_unproven", file=sys.stderr)
