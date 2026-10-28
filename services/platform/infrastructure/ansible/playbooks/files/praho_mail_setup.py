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
from typing import Any, NoReturn, cast
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
MAX_JOURNAL_BYTES = 64 * 1024
CERTIFICATE_PEM = "/etc/praho-mail/node.pem"
CERTIFICATE_KEY = "/etc/praho-mail/node.key"
CERTIFICATE_STAGE_FILES = frozenset({"before.json", "old.pem", "old.key", "new.pem", "new.key"})
LEGACY_RECORD_FIELDS = frozenset(
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
# Current records also bind the staged candidate file bytes, not only the leaf.
RECORD_FIELDS = LEGACY_RECORD_FIELDS | {"new_pem_sha256", "new_key_sha256"}
START_PERMIT_SECONDS = 120
# A ready-guard run took at most 3.6 s on the owned clones (5 samples per profile); the certificate
# path adds file and fence re-checks. Never start a unit with less permit time left than this.
GUARD_START_SECONDS = 20
UNIT_START_TIMEOUT_SECONDS = 60
UNIT_STOP_TIMEOUT_SECONDS = 90
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
DROPIN_PATHS = tuple("/etc/systemd/system/" + name + ".d/praho-mail.conf" for name in UNITS)
BUNDLE_PATHS = (*("/usr/lib/praho/mail/" + name for name in NATIVE_FILES), *DROPIN_PATHS)
# Helper bundles setup could have installed, keyed by the commit that shipped each (none reached
# master; each was installed by setup on lab clones). The drop-ins were UNIT_GUARD in all of them.
PREDECESSOR_BUNDLES: dict[str, dict[str, str]] = {
    "660cfec9": {
        "praho-mail.py": "cc615eaece5984136ab22e58dad57190962f17a96a758d24e051615853ea9e42",
        "praho_mail_setup.py": "b18d7deebcd65cb893331c315dd9ed55e1f06297a8a4a4e30ebbdd7f6684983f",
        "praho-mail-native.pl": "dc473408a4fabdbb04f8bbe568c52594af15c04e7c6c12b83348ce66c791e4bf",
        "praho-mail-boot.py": "62488151e1d2f9b98a02115fb8553d43912430a2576376eeeb0f2a25638b6186",
        "praho_mail_submitters.py": "9079f36b348845c730b5735fcd9db58d70fa4a2ade3809cd64d8f09b214858c8",
    },
    "5e718359": {
        "praho-mail.py": "cc615eaece5984136ab22e58dad57190962f17a96a758d24e051615853ea9e42",
        "praho_mail_setup.py": "409be32aec85aa77e64b98077737678a919104aaaa515aacf73cada64e9eaeb3",
        "praho-mail-native.pl": "dc473408a4fabdbb04f8bbe568c52594af15c04e7c6c12b83348ce66c791e4bf",
        "praho-mail-boot.py": "62488151e1d2f9b98a02115fb8553d43912430a2576376eeeb0f2a25638b6186",
        "praho_mail_submitters.py": "9079f36b348845c730b5735fcd9db58d70fa4a2ade3809cd64d8f09b214858c8",
    },
    "47124809": {
        "praho-mail.py": "2e93416554542e85b5f942feafb6e1cc363c21830285941e7736dbbc7bf73fa1",
        "praho_mail_setup.py": "b941fbca1de5e36e939b10e6d8baf61710d613422789d0f86f507e89c227924a",
        "praho-mail-native.pl": "dc473408a4fabdbb04f8bbe568c52594af15c04e7c6c12b83348ce66c791e4bf",
        "praho-mail-boot.py": "62488151e1d2f9b98a02115fb8553d43912430a2576376eeeb0f2a25638b6186",
        "praho_mail_submitters.py": "9079f36b348845c730b5735fcd9db58d70fa4a2ade3809cd64d8f09b214858c8",
    },
    "7947ce12": {
        "praho-mail.py": "2e93416554542e85b5f942feafb6e1cc363c21830285941e7736dbbc7bf73fa1",
        "praho_mail_setup.py": "d9abc863509dba7518ed607dee051fec5a8e6d3ec9cffd52a523a34b5b1bd693",
        "praho-mail-native.pl": "dc473408a4fabdbb04f8bbe568c52594af15c04e7c6c12b83348ce66c791e4bf",
        "praho-mail-boot.py": "36c781821362ffd82481fe19cbf3592a51c5488b9a9625f215aafc3c342fb0f1",
        "praho_mail_submitters.py": "9079f36b348845c730b5735fcd9db58d70fa4a2ade3809cd64d8f09b214858c8",
    },
    "bd0d9651": {
        "praho-mail.py": "04bc52973c66e5c59810361be95b30c049fa81e32965e926a2b23fa699bd7326",
        "praho_mail_setup.py": "d9abc863509dba7518ed607dee051fec5a8e6d3ec9cffd52a523a34b5b1bd693",
        "praho-mail-native.pl": "dc473408a4fabdbb04f8bbe568c52594af15c04e7c6c12b83348ce66c791e4bf",
        "praho-mail-boot.py": "4a5329109d42eb86b975e2337b747e7d7f3c99ff77e815ab58c786e3c723b4f3",
        "praho_mail_submitters.py": "9079f36b348845c730b5735fcd9db58d70fa4a2ade3809cd64d8f09b214858c8",
    },
}
COMPAT_RESULT = "mail_bundle_compatible"
GUARD_PATH = "/usr/lib/praho/mail/praho-mail-boot.py"
GUARD_COMPAT_TIMEOUT_SECONDS = 120
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
UNIT_PROPERTIES = (
    "Type",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "LoadState",
    "FragmentPath",
    "DropInPaths",
    "NeedDaemonReload",
    "ExecStartPre",
)
GUARD_START = ("/usr/bin/python3", "/usr/bin/python3 /usr/lib/praho/mail/praho-mail-boot.py")
STOPPED_STATES = frozenset({"inactive", "failed"})
# Loaded systemd state after setup, read with ``systemctl show`` on owned clones (2026-10-28).
# Eligible units start in this order; ``started`` is the state each must reach. Ubuntu's postfix@-
# is a disabled template instance: it is never started and must stay inactive.
UNIT_TOPOLOGY: dict[str, tuple[dict[str, Any], ...]] = {
    "debian12-dovecot23": (
        {
            "unit": "postfix@-.service",
            "type": "forking",
            "file_state": "enabled-runtime",
            "fragment": "/lib/systemd/system/postfix@.service",
            "dropin": "/etc/systemd/system/postfix@.service.d/praho-mail.conf",
            "start": True,
            "started": ("active", "running"),
        },
        {
            # The oneshot wrapper; it carries the guard drop-in too.
            "unit": "postfix.service",
            "type": "oneshot",
            "file_state": "enabled",
            "fragment": "/lib/systemd/system/postfix.service",
            "dropin": "/etc/systemd/system/postfix.service.d/praho-mail.conf",
            "start": True,
            "started": ("active", "exited"),
        },
        {
            "unit": "dovecot.service",
            "type": "notify",
            "file_state": "enabled",
            "fragment": "/lib/systemd/system/dovecot.service",
            "dropin": "/etc/systemd/system/dovecot.service.d/praho-mail.conf",
            "start": True,
            "started": ("active", "running"),
        },
    ),
    "ubuntu2604-dovecot24": (
        {
            "unit": "postfix.service",
            "type": "forking",
            "file_state": "enabled",
            "fragment": "/usr/lib/systemd/system/postfix.service",
            "dropin": "/etc/systemd/system/postfix.service.d/praho-mail.conf",
            "start": True,
            "started": ("active", "running"),
        },
        {
            "unit": "dovecot.service",
            "type": "notify",
            "file_state": "enabled",
            "fragment": "/usr/lib/systemd/system/dovecot.service",
            "dropin": "/etc/systemd/system/dovecot.service.d/praho-mail.conf",
            "start": True,
            "started": ("active", "running"),
        },
        {
            "unit": "postfix@-.service",
            "type": "forking",
            "file_state": "disabled",
            "fragment": "/usr/lib/systemd/system/postfix@.service",
            "dropin": "/etc/systemd/system/postfix@.service.d/praho-mail.conf",
            "start": False,
            "started": ("inactive", "dead"),
        },
    ),
}
MAX_FENCE_BYTES = 4 * 1024 * 1024
FENCE_FAMILIES = {"iptables": "icmp-port-unreachable", "ip6tables": "icmp6-port-unreachable"}
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


def fence_rules(rejection: str) -> list[list[str]]:
    """The certificate fence chain, in order: one loopback return, then the mail-port reject."""
    return [
        ["-A", CHAIN, "-i", "lo", "-j", "RETURN"],
        ["-A", CHAIN, "-p", "tcp", "-m", "multiport", "--dports", PORTS, "-j", "REJECT", "--reject-with", rejection],
    ]


def certificate_fence(snapshot: object, rejection: str) -> str:
    """Classify one family's ``*-save -t filter`` text as exact, absent, inert or foreign.

    Shared by the worker and the boot guard. Exact means the jump is the first INPUT rule, the
    chain is exactly the loopback return then the reject, and nothing else references the chain.
    Inert is an unreferenced chain holding a prefix of those rules, as an interrupted install leaves.
    """
    if not isinstance(snapshot, str) or len(snapshot) > MAX_FENCE_BYTES:
        return "foreign"
    lines = [line for line in snapshot.splitlines() if line and not line.startswith("#")]
    if lines.count("*filter") != 1 or lines.count("COMMIT") != 1:
        return "foreign"
    jump = "-A INPUT -j " + CHAIN
    rules = [line for line in lines if line.startswith("-A ")]
    declared = [line for line in lines if line.startswith(":" + CHAIN + " ")]
    owned = [line for line in rules if line.startswith("-A " + CHAIN + " ")]
    references = [line for line in rules if CHAIN in line.split() and line not in owned]
    expected = [" ".join(rule) for rule in fence_rules(rejection)]
    if not declared and not owned and not references:
        return "absent"
    if len(declared) == 1 and not references and owned == expected[: len(owned)]:
        return "inert"
    if (
        len(declared) == 1
        and next((line for line in rules if line.startswith("-A INPUT ")), None) == jump
        and owned == expected
        and references == [jump]
    ):
        return "exact"
    return "foreign"


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
        # The running helper bundle; a certificate start permit names it as its owner.
        self.bundle = Path(__file__).parent

    def refuse(self, code: str) -> NoReturn:
        raise self.error(code)

    def certificate_verify_command(self, expected: str, certificate: Path, *, check_time: bool = True) -> list[str]:
        # Match the actual TLS client's verification policy. Recent Python
        # runtimes enable strict X.509 checks; reject unusable material before setup.
        # Only the bundle upgrade's compatibility dry run skips the validity window.
        strict = ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT
        return [
            "openssl",
            "verify",
            *(["-x509_strict"] if strict else []),
            *([] if check_time else ["-no_check_time"]),
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
            if not isinstance(data, dict):
                self.refuse("mail_setup_review_required")
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

    def journal(self, expected: str) -> dict[str, Any]:
        """Read node.json in any state; a foreign, mutable or malformed journal is review evidence."""
        path = self.state / "node.json"
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
                or metadata.st_size > MAX_JOURNAL_BYTES
            ):
                self.refuse("mail_setup_review_required")
            data = json.loads(path.read_text())
            if (
                not isinstance(data, dict)
                or (type(data.get("version")), data.get("version")) != (int, 1)
                or (data.get("profile"), data.get("node")) != (self.node.profile_id, expected)
            ):
                self.refuse("mail_setup_review_required")
            return data
        except (ValueError, OSError, TypeError, AttributeError) as error:
            raise self.error("mail_setup_review_required") from error

    def operation_record(self, journal: dict[str, Any]) -> dict[str, Any]:
        """The certificate_applying record a certificate journal carries, in the current or legacy shape."""
        keys = set(journal) - ({"start", "files", "fenced"} if journal["status"] == "certificate_starting" else set())
        if keys not in (RECORD_FIELDS, LEGACY_RECORD_FIELDS) or not isinstance(journal.get("identity"), str):
            self.refuse("mail_setup_review_required")
        try:
            canonical = str(UUID(journal["identity"])) == journal["identity"]
        except ValueError:
            canonical = False
        digests = [journal[key] for key in keys if key.endswith("_sha256")]
        if not canonical or not all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in digests
        ):
            self.refuse("mail_setup_review_required")
        return {**{key: journal[key] for key in keys}, "status": "certificate_applying"}

    def certificate_operation(self, identity: str, expected: str) -> dict[str, Any] | None:
        path = self.state / "certificate-operations" / (identity + ".json")
        if not path.exists() and not path.is_symlink():
            return None
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            self.refuse("mail_setup_review_required")
        if metadata.st_size > MAX_CERTIFICATE_OPERATION_BYTES:
            self.refuse("mail_setup_review_required")
        record = json.loads(path.read_text())
        if (
            not isinstance(record, dict)
            or (type(record.get("version")), record.get("version")) != (int, 1)
            or (record.get("node"), record.get("profile"), record.get("identity"))
            != (
                expected,
                self.node.profile_id,
                identity,
            )
            or record.get("status") not in {"applying", "completed"}
        ):
            self.refuse("mail_setup_review_required")
        return record

    def pending_certificate_operations(self, identity: str) -> bool:
        """Another operation is in flight while its stage exists; it is retired last."""
        operations = self.state / "certificate-operations"
        if not operations.exists():
            return False
        return any(
            entry.name.endswith(".stage") and entry.name != identity + ".stage" for entry in operations.iterdir()
        )

    def retire_certificate_stage(self, stage: Path) -> None:
        if not stage.exists() and not stage.is_symlink():
            return
        self.private_directory(stage)
        entries = tuple(stage.iterdir())
        if {entry.name for entry in entries} - CERTIFICATE_STAGE_FILES:
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

    def stage_certificate(self, identity: str, files: dict[str, bytes]) -> Path:
        """Build the private stage under a hidden name; it is published only after the journal and tombstone."""
        operations = self.state / "certificate-operations"
        self.private_directory(operations)
        temporary = operations / ("." + identity + ".stage-" + secrets.token_hex(8))
        temporary.mkdir(mode=0o700)
        for name, content in files.items():
            atomic(temporary / name, content)
        return temporary

    def publish_stage(self, temporary: Path, stage: Path) -> None:
        os.rename(temporary, stage)
        descriptor = os.open(stage.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def sweep_certificate_temporaries(self) -> None:
        # Unpublished stages carry no intent: no journal or tombstone refers to them yet.
        for entry in (self.state / "certificate-operations").iterdir():
            if re.fullmatch(r"\.[0-9a-f-]{36}\.stage-[0-9a-f]{16}", entry.name):
                self.retire_certificate_stage(entry)

    def staged_certificate(
        self, record: dict[str, Any], *, temporary: bool = False
    ) -> tuple[Path, dict[str, Any], dict[str, bytes]]:
        """Read and verify this operation's complete stage against every digest its record holds."""
        operations = self.state / "certificate-operations"
        directory = operations / (record["identity"] + ".stage")
        if temporary and not directory.exists() and not directory.is_symlink():
            hidden = [entry for entry in operations.iterdir() if entry.name.startswith("." + directory.name + "-")]
            if len(hidden) != 1:
                self.refuse("mail_setup_review_required")
            directory = hidden[0]
        if not directory.is_dir() or directory.is_symlink():
            self.refuse("mail_setup_review_required")
        self.private_directory(directory)
        entries = {entry.name: entry for entry in directory.iterdir()}
        if set(entries) != CERTIFICATE_STAGE_FILES:
            self.refuse("mail_setup_review_required")
        files = {}
        for name, entry in entries.items():
            metadata = entry.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o077
                or metadata.st_size > MAX_CERTIFICATE_BYTES
            ):
                self.refuse("mail_setup_review_required")
            files[name] = entry.read_bytes()
        before = json.loads(files["before.json"])
        if (
            hashlib.sha256(files["before.json"]).hexdigest() != record["before_sha256"]
            or not isinstance(before, dict)
            or set(before) != {"version", "node", "profile", "status", "files"}
            or (before["version"], before["node"], before["profile"], before["status"])
            != (1, record["node"], record["profile"], "ready")
            or not isinstance(before["files"], dict)
            or set(before["files"]) != set(CONFIG_PATHS)
        ):
            self.refuse("mail_setup_review_required")
        if (
            hashlib.sha256(files["old.pem"]).hexdigest() != before["files"][CERTIFICATE_PEM]
            or hashlib.sha256(files["old.key"]).hexdigest() != before["files"][CERTIFICATE_KEY]
            or self.leaf_digest(files["old.pem"]) != record["old_certificate_sha256"]
            or self.leaf_digest(files["new.pem"]) != record["new_certificate_sha256"]
        ):
            self.refuse("mail_setup_review_required")
        if "new_pem_sha256" in record and (
            hashlib.sha256(files["new.pem"]).hexdigest(),
            hashlib.sha256(files["new.key"]).hexdigest(),
        ) != (record["new_pem_sha256"], record["new_key_sha256"]):
            self.refuse("mail_setup_review_required")
        return directory, before, files

    def certificate_record(
        self, before: dict[str, Any], identity: str, old: bytes, chain: bytes, private_key: bytes
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "node": before["node"],
            "profile": before["profile"],
            "identity": identity,
            "status": "certificate_applying",
            "old_certificate_sha256": self.leaf_digest(old),
            "new_certificate_sha256": self.leaf_digest(chain),
            "new_pem_sha256": hashlib.sha256(chain).hexdigest(),
            "new_key_sha256": hashlib.sha256(private_key).hexdigest(),
            "before_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
        }

    def not_after(self, certificate: Path) -> datetime:
        try:
            expiry = self.execute(["openssl", "x509", "-in", str(certificate), "-enddate", "-noout"]).strip()
            return datetime.strptime(expiry.removeprefix("notAfter="), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        except (ValueError, self.error) as error:
            raise self.error("mail_node_certificate_unproven") from error

    def bundle_current(self, before: dict[str, Any]) -> bool:
        """The guard admits a start only from helpers equal to the installed bundle."""
        return all(
            hashlib.sha256((self.bundle / name).read_bytes()).hexdigest()
            == before["files"]["/usr/lib/praho/mail/" + name]
            for name in NATIVE_FILES
        )

    def reconcile_certificate(self, expected: str, identity: str) -> dict[str, Any]:
        self.node.stage = "certificate_preflight"
        self.node.profile(expected)
        if str(UUID(identity)) != identity:
            self.refuse("mail_native_inspection_failed")
        self.private_directory(self.state)
        journal = self.journal(expected)
        operations = self.state / "certificate-operations"
        if operations.exists() or operations.is_symlink():
            self.private_directory(operations)
        tombstone = self.certificate_operation(identity, expected)
        # Identity first: an operation that left any state never starts a fresh recovery.
        if journal.get("status") in {"certificate_applying", "certificate_starting"}:
            record = self.operation_record(journal)
            if record["identity"] != identity:
                self.refuse("mail_node_operation_in_progress")
            if tombstone is not None and tombstone["status"] == "completed":
                return self.roll_forward_certificate(expected, journal, record)
            return self.resume_certificate(expected, journal, record, tombstone)
        if journal.get("status") == "bundle_upgrading":
            self.refuse("mail_node_operation_in_progress")
        return self.ready_certificate_operation(expected, identity, tombstone)

    def ready_certificate_operation(
        self, expected: str, identity: str, tombstone: dict[str, Any] | None
    ) -> dict[str, Any]:
        before = self.marker(expected)
        if before is None:
            self.refuse("mail_setup_review_required")
        stage = self.state / "certificate-operations" / (identity + ".stage")
        if tombstone is not None and tombstone["status"] == "applying":
            return self.finalize_certificate(expected, before, tombstone)
        if tombstone is not None and tombstone.get("fence_owner") is True:
            if self.pending_certificate_operations(identity):
                self.refuse("mail_node_operation_in_progress")
            return self.finish_certificate_cleanup(expected, tombstone)
        if tombstone is not None:
            # Completed: verification only. A later candidate is never installed for this identity.
            self.security_configuration(expected)
            current = self.leaf_digest(self.path(CERTIFICATE_PEM).read_bytes())
            result = self.certificate_result(expected, current, "unchanged")
            self.retire_certificate_stage(stage)
            return result
        if stage.exists() or stage.is_symlink():
            self.refuse("mail_setup_review_required")
        if self.pending_certificate_operations(identity):
            self.refuse("mail_node_operation_in_progress")
        return self.admit_certificate(expected, identity, before)

    def admit_certificate(self, expected: str, identity: str, before: dict[str, Any]) -> dict[str, Any]:
        self.security_configuration(expected)
        if any(chain or jump for chain, jump in self.read_fences().values()):
            self.refuse("mail_setup_review_required")
        certificate, key = self.path(CERTIFICATE_PEM), self.path(CERTIFICATE_KEY)
        if key.stat().st_mode & 0o077:
            self.refuse("mail_setup_review_required")
        current = self.leaf_digest(certificate.read_bytes())
        phase = self.unit_phase()
        if phase == "running":
            return self.rotate_certificate(expected, identity, before, current)
        # Stopped units with an unexpired leaf, or a mixed state, are not ours to start. Refuse
        # before any write so the journal stays byte-identical.
        if phase != "stopped" or self.not_after(certificate) > datetime.now(UTC):
            self.refuse("mail_node_services_unavailable")
        if not self.bundle_current(before):
            self.refuse("mail_node_bundle_upgrade_required")
        self.node.stage = "certificate_candidate"
        chain, private_key = self.certificate(expected)
        return self.recover_certificate(expected, identity, before, chain, private_key)

    def rotate_certificate(self, expected: str, identity: str, before: dict[str, Any], current: str) -> dict[str, Any]:
        """Routine rotation on live services: install, reload, prove; any failure parks for review."""
        certificate, key = self.path(CERTIFICATE_PEM), self.path(CERTIFICATE_KEY)
        operations = self.state / "certificate-operations"
        tombstone = operations / (identity + ".json")
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
            record = self.certificate_record(before, identity, chain, chain, private_key)
            atomic(tombstone, json.dumps({**record, "status": "completed"}).encode())
            return result
        return self.install_certificate(before, identity, chain, private_key)

    def install_certificate(
        self, before: dict[str, Any], identity: str, chain: bytes, private_key: bytes
    ) -> dict[str, Any]:
        expected = before["node"]
        self.check_files(before)
        certificate, key = self.path(CERTIFICATE_PEM), self.path(CERTIFICATE_KEY)
        candidate = self.leaf_digest(chain)
        operations = self.state / "certificate-operations"
        tombstone, stage = operations / (identity + ".json"), operations / (identity + ".stage")
        self.private_directory(operations)
        if stage.exists() or stage.is_symlink():
            self.refuse("mail_setup_review_required")
        record = self.certificate_record(before, identity, certificate.read_bytes(), chain, private_key)
        completed = False
        try:
            self.node.stage = "certificate_staging"
            temporary = self.stage_certificate(
                identity,
                {
                    "old.pem": certificate.read_bytes(),
                    "old.key": key.read_bytes(),
                    "new.pem": chain,
                    "new.key": private_key,
                    "before.json": json.dumps(before, sort_keys=True).encode(),
                },
            )
            atomic(self.state / "node.json", json.dumps(record).encode())
            atomic(tombstone, json.dumps({**record, "status": "applying"}).encode())
            self.publish_stage(temporary, stage)
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
                    CERTIFICATE_PEM: hashlib.sha256(chain).hexdigest(),
                    CERTIFICATE_KEY: hashlib.sha256(private_key).hexdigest(),
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

    def recover_certificate(
        self, expected: str, identity: str, before: dict[str, Any], chain: bytes, private_key: bytes
    ) -> dict[str, Any]:
        """Expired leaf, stopped units: stage, then journal and tombstone, then publish the stage."""
        self.node.stage = "certificate_staging"
        certificate, key = self.path(CERTIFICATE_PEM), self.path(CERTIFICATE_KEY)
        operations = self.state / "certificate-operations"
        self.private_directory(operations)
        self.sweep_certificate_temporaries()
        record = self.certificate_record(before, identity, certificate.read_bytes(), chain, private_key)
        temporary = self.stage_certificate(
            identity,
            {
                "old.pem": certificate.read_bytes(),
                "old.key": key.read_bytes(),
                "new.pem": chain,
                "new.key": private_key,
                "before.json": json.dumps(before, sort_keys=True).encode(),
            },
        )
        atomic(self.state / "node.json", json.dumps(record).encode())
        atomic(operations / (identity + ".json"), json.dumps({**record, "status": "applying"}).encode())
        self.publish_stage(temporary, operations / (identity + ".stage"))
        return self.advance_certificate(expected, record, before)

    def resume_certificate(
        self,
        expected: str,
        journal: dict[str, Any],
        record: dict[str, Any],
        tombstone: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Continue this same operation only when every recorded digest still matches exactly."""
        self.node.stage = "certificate_resume"
        if set(record) != RECORD_FIELDS:
            self.refuse("mail_setup_review_required")
        if tombstone is not None and tombstone != {**record, "status": "applying"}:
            self.refuse("mail_setup_review_required")
        directory, before, _files = self.staged_certificate(record, temporary=True)
        installed = tuple(
            hashlib.sha256(self.path(name).read_bytes()).hexdigest() for name in (CERTIFICATE_PEM, CERTIFICATE_KEY)
        )
        old = (before["files"][CERTIFICATE_PEM], before["files"][CERTIFICATE_KEY])
        new = (record["new_pem_sha256"], record["new_key_sha256"])
        # The pem is replaced before the key: old/old, new/old and new/new are the only resumable pairs.
        if installed not in {old, (new[0], old[1]), new}:
            self.refuse("mail_setup_review_required")
        self.check_files(
            {**before, "files": {**before["files"], CERTIFICATE_PEM: installed[0], CERTIFICATE_KEY: installed[1]}}
        )
        if not self.bundle_current(before):
            self.refuse("mail_node_bundle_upgrade_required")
        self.unit_phase()
        if "foreign" in self.certificate_fences().values():
            self.refuse("mail_setup_review_required")
        operations = self.state / "certificate-operations"
        if journal["status"] == "certificate_starting":
            # Revoke the dead owner's permit before anything else changes.
            atomic(self.state / "node.json", json.dumps(record).encode())
        if tombstone is None:
            atomic(operations / (record["identity"] + ".json"), json.dumps({**record, "status": "applying"}).encode())
        if directory.name != record["identity"] + ".stage":
            self.publish_stage(directory, operations / (record["identity"] + ".stage"))
        return self.advance_certificate(expected, record, before)

    def advance_certificate(self, expected: str, record: dict[str, Any], before: dict[str, Any]) -> dict[str, Any]:
        """Fence, install, validate offline, start under one fresh permit, prove, then commit ready."""
        operations = self.state / "certificate-operations"
        _directory, _before, files = self.staged_certificate(record)
        certificate, key = self.path(CERTIFICATE_PEM), self.path(CERTIFICATE_KEY)
        candidate = {
            **before,
            "files": {
                **before["files"],
                CERTIFICATE_PEM: record["new_pem_sha256"],
                CERTIFICATE_KEY: record["new_key_sha256"],
            },
        }
        starting = committed = False
        try:
            self.node.stage = "certificate_fence"
            self.ensure_certificate_fence()
            self.node.stage = "certificate_stop"
            self.stop_mail_units()
            self.node.stage = "certificate_installing"
            for path, name, digest in (
                (certificate, "new.pem", record["new_pem_sha256"]),
                (key, "new.key", record["new_key_sha256"]),
            ):
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    atomic(path, files[name])
            self.node.stage = "certificate_validation"
            self.validate_candidate(expected, candidate)
            self.node.stage = "certificate_start"
            permit = self.start_permit()
            starting = True
            atomic(
                self.state / "node.json",
                json.dumps(
                    {
                        **record,
                        "status": "certificate_starting",
                        "fenced": True,
                        "files": candidate["files"],
                        "start": permit,
                    }
                ).encode(),
            )
            self.start_mail_units(permit)
            self.node.stage = "certificate_verification"
            self.wait_for_proof(expected, record["new_certificate_sha256"])
            self._security_settings()
            self.node.stage = "certificate_commit"
            if set(self.certificate_fences().values()) != {"exact"}:
                self.refuse("mail_node_certificate_unproven")
            self.check_files(candidate)
            atomic(self.state / "node.json", json.dumps(candidate).encode())
            committed = True
        except Exception:
            if not committed:
                self.hold_certificate(record, revoke=starting)
            raise
        tombstone = operations / (record["identity"] + ".json")
        return self.finalize_certificate(expected, candidate, json.loads(tombstone.read_text()))

    def hold_certificate(self, record: dict[str, Any], *, revoke: bool) -> None:
        # First revoke: the guard refuses certificate_applying, so a queued start job cannot be
        # admitted after this point even though killing systemctl never cancels it. Then stop.
        try:
            if revoke:
                atomic(self.state / "node.json", json.dumps(record).encode())
        finally:
            try:
                self.stop_mail_units()
            except Exception:
                print("mail_service_stop_unproven", file=sys.stderr)

    def validate_candidate(self, expected: str, candidate: dict[str, Any]) -> None:
        certificate, key = self.path(CERTIFICATE_PEM), self.path(CERTIFICATE_KEY)
        certificate_public = self.execute(["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"])
        key_public = self.execute(["openssl", "pkey", "-in", str(key), "-pubout"])
        if not certificate_public.strip() or certificate_public.strip() != key_public.strip():
            self.refuse("mail_node_certificate_unproven")
        try:
            self.execute(self.certificate_verify_command(expected, certificate))
        except self.error as error:
            raise self.error("mail_node_certificate_unproven") from error
        if self.not_after(certificate) <= datetime.now(UTC):
            self.refuse("mail_node_certificate_unproven")
        self.check_files(candidate)
        self._security_settings()

    def start_permit(self) -> dict[str, Any]:
        """One permit per start phase, bound to this live owner and its held exclusive lock."""
        if self.node.operation_fd is None:
            self.refuse("mail_native_inspection_failed")
        arguments = self.path("/proc/self/cmdline").read_bytes().decode().split("\0")
        helper = arguments[1] if len(arguments) > 1 else ""
        if (
            not re.fullmatch(r"/run/praho-mail-[A-Za-z0-9_-]{1,128}/praho-mail\.py", helper)
            or self.path(helper).parent != self.bundle
        ):
            self.refuse("mail_native_inspection_failed")
        issued = time.monotonic()
        return {
            "pid": os.getpid(),
            "start_tick": self.path("/proc/self/stat").read_text().rpartition(") ")[2].split()[19],
            "boot_id": self.path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "lock_fd": self.node.operation_fd,
            "issued_at": issued,
            "expires_at": issued + START_PERMIT_SECONDS,
            "helper_path": helper,
            "action": "reconcile_node_certificate",
        }

    def start_mail_units(self, permit: dict[str, Any]) -> None:
        eligible = [unit["unit"] for unit in UNIT_TOPOLOGY[self.node.profile_id] if unit["start"]]
        self.execute(["systemctl", "reset-failed", *eligible], timeout=UNIT_START_TIMEOUT_SECONDS)
        for unit in eligible:
            # Each guard run re-checks the permit at its end; never start with less time than it needs.
            remaining = permit["expires_at"] - time.monotonic()
            if remaining < GUARD_START_SECONDS:
                self.refuse("mail_node_certificate_unproven")
            self.execute(["systemctl", "start", unit], timeout=int(min(remaining, UNIT_START_TIMEOUT_SECONDS)))
        if self.unit_phase() != "running":
            self.refuse("mail_node_certificate_unproven")

    def stop_mail_units(self) -> None:
        units = [unit["unit"] for unit in UNIT_TOPOLOGY[self.node.profile_id]]
        self.execute(["systemctl", "stop", *units], timeout=UNIT_STOP_TIMEOUT_SECONDS)

    def wait_for_proof(self, expected: str, digest: str) -> str:
        deadline = time.monotonic() + CERTIFICATE_RELOAD_WAIT_SECONDS
        while True:
            try:
                return self.certificate_proof(expected, digest)
            except self.error as error:
                if str(error) != "mail_node_certificate_unproven" or time.monotonic() >= deadline:
                    raise
                time.sleep(CERTIFICATE_RELOAD_POLL_SECONDS)

    def finalize_certificate(self, expected: str, ready: dict[str, Any], tombstone: dict[str, Any]) -> dict[str, Any]:
        """After the ready commit: mark completed with the fence owner, then clean up."""
        self.node.stage = "certificate_cleanup"
        record = {key: value for key, value in tombstone.items() if key != "status"}
        if set(tombstone) != RECORD_FIELDS or (ready["files"][CERTIFICATE_PEM], ready["files"][CERTIFICATE_KEY]) != (
            record["new_pem_sha256"],
            record["new_key_sha256"],
        ):
            self.refuse("mail_setup_review_required")
        completed = {**record, "status": "completed", "fence_owner": True}
        atomic(self.state / "certificate-operations" / (record["identity"] + ".json"), json.dumps(completed).encode())
        return self.finish_certificate_cleanup(expected, completed)

    def finish_certificate_cleanup(self, expected: str, tombstone: dict[str, Any]) -> dict[str, Any]:
        """Readiness is already committed; cleanup failures are resumable, never a downgrade."""
        self.node.stage = "certificate_cleanup"
        operations = self.state / "certificate-operations"
        record = {key: value for key, value in tombstone.items() if key != "fence_owner"}
        self.remove_certificate_fence()
        # Clear the owner marker before retiring the stage, so a stale replay never removes a later fence.
        atomic(operations / (record["identity"] + ".json"), json.dumps(record).encode())
        self.retire_certificate_stage(operations / (record["identity"] + ".stage"))
        return self.certificate_result(expected, record["new_certificate_sha256"], "recovered")

    def roll_forward_certificate(
        self, expected: str, journal: dict[str, Any], record: dict[str, Any]
    ) -> dict[str, Any]:
        """A completed tombstone whose ready write never landed: publish ready; never touch certificates."""
        self.node.stage = "certificate_resume"
        directory, before, files = self.staged_certificate(record)
        installed = {name: self.path(name).read_bytes() for name in (CERTIFICATE_PEM, CERTIFICATE_KEY)}
        if (installed[CERTIFICATE_PEM], installed[CERTIFICATE_KEY]) != (files["new.pem"], files["new.key"]):
            self.refuse("mail_setup_review_required")
        ready = {
            **before,
            "files": {
                **before["files"],
                **{name: hashlib.sha256(content).hexdigest() for name, content in installed.items()},
            },
        }
        fenced = journal["status"] == "certificate_starting"
        if fenced and journal.get("files") != ready["files"]:
            self.refuse("mail_setup_review_required")
        self.check_files(ready)
        if fenced and "foreign" in self.certificate_fences().values():
            self.refuse("mail_setup_review_required")
        atomic(self.state / "node.json", json.dumps(ready).encode())
        if fenced:
            self.remove_certificate_fence()
        self.retire_certificate_stage(directory)
        return self.certificate_result(expected, record["new_certificate_sha256"], "unchanged")

    def running_bundle(self) -> dict[str, bytes]:
        files = {"/usr/lib/praho/mail/" + name: (self.bundle / name).read_bytes() for name in NATIVE_FILES}
        return {**files, **dict.fromkeys(DROPIN_PATHS, UNIT_GUARD)}

    @staticmethod
    def bundle_entry(path: str) -> str:
        """Stage file name for a bundle path: the helper's own name, or ``<unit>.conf`` for a drop-in."""
        if path in DROPIN_PATHS:
            return path.split("/")[4].removesuffix(".d") + ".conf"
        return path.rsplit("/", 1)[-1]

    @staticmethod
    def bundle_result(expected: str, profile: str, digests: dict[str, str], outcome: str) -> dict[str, Any]:
        listing = "".join(path + "=" + digests[path] + "\n" for path in BUNDLE_PATHS)
        return {
            "node_hostname": expected,
            "profile": profile,
            "outcome": outcome,
            "bundle_sha256": hashlib.sha256(listing.encode()).hexdigest(),
        }

    def evidenced_bundle(self, installed: dict[str, str]) -> bool:
        if any(installed[path] != hashlib.sha256(UNIT_GUARD).hexdigest() for path in DROPIN_PATHS):
            return False
        helpers = {self.bundle_entry(path): installed[path] for path in BUNDLE_PATHS if path not in DROPIN_PATHS}
        return helpers in PREDECESSOR_BUNDLES.values()

    def remove_bundle_stage(self, directory: Path) -> None:
        self.private_directory(directory)
        entries = {entry.name: entry for entry in directory.iterdir()}
        if set(entries) - {"from", "to", "journal.json", "candidate.json"}:
            self.refuse("mail_setup_review_required")
        files = [entry for name, entry in entries.items() if name.endswith(".json")]
        for name in {"from", "to"} & set(entries):
            self.private_directory(entries[name])
            children = tuple(entries[name].iterdir())
            if {child.name for child in children} - {self.bundle_entry(path) for path in BUNDLE_PATHS}:
                self.refuse("mail_setup_review_required")
            files.extend(children)
        for file in files:
            metadata = file.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                self.refuse("mail_setup_review_required")
        for file in files:
            file.unlink()
        for name in {"from", "to"} & set(entries):
            entries[name].rmdir()
        directory.rmdir()
        descriptor = os.open(directory.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def retire_bundle_stages(self) -> None:
        """Remove upgrade staging no journal refers to: unpublished stages, and a published one whose
        upgrade already committed or restored (its candidate or original equals the ready journal)."""
        for entry in self.state.iterdir():
            if re.fullmatch(r"\.bundle-upgrade-[0-9a-f]{16}", entry.name):
                self.remove_bundle_stage(entry)
        stage = self.state / "bundle-upgrade"
        if stage.exists() or stage.is_symlink():
            self.private_directory(stage)
            current = (self.state / "node.json").read_bytes()
            known = [stage / name for name in ("candidate.json", "journal.json") if (stage / name).is_file()]
            if current not in {path.read_bytes() for path in known}:
                self.refuse("mail_setup_review_required")
            self.remove_bundle_stage(stage)

    def upgrade_bundle(self, expected: str, identity: str) -> dict[str, Any]:
        """Replace only the helpers and drop-ins of a ready node; never setup or configuration."""
        self.node.stage = "bundle_preflight"
        self.node.profile(expected)
        if str(UUID(identity)) != identity:
            self.refuse("mail_native_inspection_failed")
        self.private_directory(self.state)
        journal = self.journal(expected)
        if journal.get("status") == "bundle_upgrading":
            return self.resume_bundle_upgrade(expected, identity, journal)
        if journal.get("status") in {"certificate_applying", "certificate_starting"}:
            self.refuse("mail_node_operation_in_progress")
        original = (self.state / "node.json").read_bytes()
        before = self.marker(expected)
        if before is None:
            self.refuse("mail_setup_review_required")
        if self.pending_certificate_operations(""):
            self.refuse("mail_node_operation_in_progress")
        self.retire_bundle_stages()
        running = self.running_bundle()
        target = {path: hashlib.sha256(content).hexdigest() for path, content in running.items()}
        installed = {path: before["files"][path] for path in BUNDLE_PATHS}
        if installed == target:
            return self.bundle_result(expected, before["profile"], target, "unchanged")
        if not self.evidenced_bundle(installed):
            self.refuse("mail_setup_review_required")
        # Offline checks only: an expired, stopped node has no listeners to prove.
        self.security_configuration(expected)
        self.node.stage = "bundle_staging"
        temporary = self.state / (".bundle-upgrade-" + secrets.token_hex(8))
        temporary.mkdir(mode=0o700)
        for side, files in (("from", {path: self.path(path).read_bytes() for path in BUNDLE_PATHS}), ("to", running)):
            (temporary / side).mkdir(mode=0o700)
            for path in BUNDLE_PATHS:
                atomic(temporary / side / self.bundle_entry(path), files[path])
        atomic(temporary / "journal.json", original)
        atomic(temporary / "candidate.json", json.dumps({**before, "files": {**before["files"], **target}}).encode())
        record = {
            "version": 1,
            "node": expected,
            "profile": before["profile"],
            "status": "bundle_upgrading",
            "identity": identity,
            "from": installed,
            "to": target,
            "journal_sha256": hashlib.sha256(original).hexdigest(),
        }
        atomic(self.state / "node.json", json.dumps(record).encode())
        self.publish_stage(temporary, self.state / "bundle-upgrade")
        return self.advance_bundle_upgrade(expected, record)

    def staged_bundle(
        self, record: dict[str, Any], *, temporary: bool = False
    ) -> tuple[Path, bytes, dict[str, Any], dict[str, dict[str, bytes]]]:
        """Read and verify the upgrade stage against every digest the bundle_upgrading journal holds."""
        directory = self.state / "bundle-upgrade"
        if temporary and not directory.exists() and not directory.is_symlink():
            hidden = [entry for entry in self.state.iterdir() if entry.name.startswith(".bundle-upgrade-")]
            if len(hidden) != 1:
                self.refuse("mail_setup_review_required")
            directory = hidden[0]
        self.private_directory(directory)
        sides: dict[str, dict[str, bytes]] = {}
        for side in ("from", "to"):
            self.private_directory(directory / side)
            sides[side] = {}
            for path in BUNDLE_PATHS:
                content = (directory / side / self.bundle_entry(path)).read_bytes()
                if hashlib.sha256(content).hexdigest() != record[side][path]:
                    self.refuse("mail_setup_review_required")
                sides[side][path] = content
        original = (directory / "journal.json").read_bytes()
        before = json.loads(original)
        candidate = {**before, "files": {**before["files"], **record["to"]}}
        if (
            hashlib.sha256(original).hexdigest() != record["journal_sha256"]
            or set(before) != {"version", "node", "profile", "status", "files"}
            or (before["version"], before["node"], before["profile"], before["status"])
            != (1, record["node"], record["profile"], "ready")
            or any(before["files"][path] != record["from"][path] for path in BUNDLE_PATHS)
            or json.loads((directory / "candidate.json").read_bytes()) != candidate
        ):
            self.refuse("mail_setup_review_required")
        return directory, original, candidate, sides

    def resume_bundle_upgrade(self, expected: str, identity: str, journal: dict[str, Any]) -> dict[str, Any]:
        """Roll on only when every bundle file is exactly its from or its to copy."""
        self.node.stage = "bundle_resume"
        if set(journal) != {"version", "node", "profile", "status", "identity", "from", "to", "journal_sha256"}:
            self.refuse("mail_setup_review_required")
        if any(
            not isinstance(journal[side], dict) or set(journal[side]) != set(BUNDLE_PATHS) for side in ("from", "to")
        ):
            self.refuse("mail_setup_review_required")
        if journal["identity"] != identity:
            self.refuse("mail_node_operation_in_progress")
        directory, _original, candidate, _sides = self.staged_bundle(journal, temporary=True)
        installed = {path: hashlib.sha256(self.path(path).read_bytes()).hexdigest() for path in BUNDLE_PATHS}
        if any(installed[path] not in {journal["from"][path], journal["to"][path]} for path in BUNDLE_PATHS):
            self.refuse("mail_setup_review_required")
        self.check_files({**candidate, "files": {**candidate["files"], **installed}})
        if directory.name != "bundle-upgrade":
            self.publish_stage(directory, self.state / "bundle-upgrade")
        return self.advance_bundle_upgrade(expected, journal)

    def advance_bundle_upgrade(self, expected: str, record: dict[str, Any]) -> dict[str, Any]:
        """Helpers, then drop-ins, one daemon-reload, byte check, installed-guard dry run, then ready."""
        directory, original, candidate, sides = self.staged_bundle(record)
        committed = False
        try:
            self.node.stage = "bundle_replacing"
            for path in BUNDLE_PATHS:
                if hashlib.sha256(self.path(path).read_bytes()).hexdigest() != record["to"][path]:
                    atomic(self.path(path), sides["to"][path])
            self.execute(["systemctl", "daemon-reload"])
            if any(self.path(path).read_bytes() != sides["to"][path] for path in BUNDLE_PATHS):
                self.refuse("mail_setup_review_required")
            self.node.stage = "bundle_compatibility"
            self.compat_check()
            self.node.stage = "bundle_commit"
            self.check_files(candidate)
            atomic(self.state / "node.json", json.dumps(candidate).encode())
            committed = True
        except Exception:
            if not committed:
                # An incompatible new guard is never committed: put back the evidenced predecessor.
                failed = self.node.stage
                self.restore_bundle(record, directory, original, sides["from"])
                self.node.stage = failed
            raise
        self.remove_bundle_stage(directory)
        return self.bundle_result(expected, record["profile"], record["to"], "upgraded")

    def restore_bundle(
        self, record: dict[str, Any], directory: Path, original: bytes, previous: dict[str, bytes]
    ) -> None:
        self.node.stage = "bundle_restore"
        for path in BUNDLE_PATHS:
            if hashlib.sha256(self.path(path).read_bytes()).hexdigest() != record["from"][path]:
                atomic(self.path(path), previous[path])
        self.execute(["systemctl", "daemon-reload"])
        if any(self.path(path).read_bytes() != previous[path] for path in BUNDLE_PATHS):
            self.refuse("mail_setup_review_required")
        atomic(self.state / "node.json", original)
        self.remove_bundle_stage(directory)

    def compat_check(self) -> None:
        """Dry-run the installed guard; it can never authorize a start in this mode."""
        try:
            output = self.execute(
                ["/usr/bin/python3", GUARD_PATH, "--compat-check"], timeout=GUARD_COMPAT_TIMEOUT_SECONDS
            )
        except self.error as error:
            raise self.error("mail_node_bundle_incompatible") from error
        if output.strip() != COMPAT_RESULT:
            self.refuse("mail_node_bundle_incompatible")

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
        self._security_settings()

    def _security_settings(self) -> None:
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

    def unit_states(self) -> dict[str, tuple[str, str]]:
        """Read each profile unit's loaded state; anything outside the pinned topology is review evidence."""
        states = {}
        for unit in UNIT_TOPOLOGY[self.node.profile_id]:
            output = self.execute(["systemctl", "show", unit["unit"], "--property=" + ",".join(UNIT_PROPERTIES)])
            values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
            starts = re.findall(r"\{ path=([^ ;]*) ; argv\[\]=([^;]*?) ; ", values.get("ExecStartPre", ""))
            if (
                set(values) != set(UNIT_PROPERTIES)
                or (
                    values["LoadState"],
                    values["Type"],
                    values["UnitFileState"],
                    values["FragmentPath"],
                    values["DropInPaths"],
                    values["NeedDaemonReload"],
                )
                != ("loaded", unit["type"], unit["file_state"], unit["fragment"], unit["dropin"], "no")
                or starts != [GUARD_START]
                or values["ExecStartPre"].count("{") != 1
            ):
                self.refuse("mail_setup_review_required")
            states[unit["unit"]] = (values["ActiveState"], values["SubState"])
        return states

    def unit_phase(self) -> str:
        """Classify the profile's mail units as running, stopped or mixed."""
        states = self.unit_states()
        topology = UNIT_TOPOLOGY[self.node.profile_id]
        if any(states[unit["unit"]] != unit["started"] for unit in topology if not unit["start"]):
            self.refuse("mail_setup_review_required")
        eligible = [unit for unit in topology if unit["start"]]
        if all(states[unit["unit"]] == unit["started"] for unit in eligible):
            return "running"
        if all(states[unit["unit"]][0] in STOPPED_STATES for unit in eligible):
            return "stopped"
        return "mixed"

    def certificate_fences(self) -> dict[str, str]:
        return {
            program: certificate_fence(self.execute([program + "-save", "-t", "filter"]), rejection)
            for program, rejection in FENCE_FAMILIES.items()
        }

    def ensure_certificate_fence(self) -> None:
        """Install the exact fence in both families; the loopback return is inserted only here.

        Live rules do not survive a reboot, so every start phase calls this again. Read both
        families before changing either; any rule we did not write is review evidence.
        """
        states = self.certificate_fences()
        if "foreign" in states.values():
            self.refuse("mail_setup_review_required")
        for program, rejection in FENCE_FAMILIES.items():
            if states[program] == "exact":
                continue
            self.execute([program, "-w", "5", "-N" if states[program] == "absent" else "-F", CHAIN])
            for rule in fence_rules(rejection):
                self.execute([program, "-w", "5", *rule])
            # The jump goes last, so a half-built chain is never active.
            self.execute([program, "-w", "5", "-I", "INPUT", "1", "-j", CHAIN])
        if set(self.certificate_fences().values()) != {"exact"}:
            self.refuse("mail_setup_review_required")

    def remove_certificate_fence(self) -> None:
        states = self.certificate_fences()
        if not set(states.values()) <= {"exact", "inert", "absent"}:
            self.refuse("mail_setup_review_required")
        for program, state in states.items():
            if state == "exact":
                self.execute([program, "-w", "5", "-D", "INPUT", "-j", CHAIN])
            if state != "absent":
                self.execute([program, "-w", "5", "-F", CHAIN])
                self.execute([program, "-w", "5", "-X", CHAIN])
        if set(self.certificate_fences().values()) != {"absent"}:
            self.refuse("mail_setup_review_required")

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
            return cast(dict[str, Any], self.node.inspect_node(expected))
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
            observation = cast(dict[str, Any], self.node.inspect_node(expected))
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
