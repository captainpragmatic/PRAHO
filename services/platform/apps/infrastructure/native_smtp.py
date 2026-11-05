"""Private native-lab SMTP acceptance. No relay, production backend or readiness bypass."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import re
import smtplib
import socket
import socketserver
import stat
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from .native_lab import NativeAuthority, native_authority

if TYPE_CHECKING:
    from collections.abc import Sequence

OWNER = "praho-native-smtp"
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_MESSAGES = 100
MAX_RECIPIENTS = 50
MAX_MANIFEST_BYTES = 8192
SMTP_TIMEOUT = 5
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
MIN_PORT = 1024
MAX_PORT = 65535
SMTP_READY = 220
MAX_LINE_BYTES = 65536
MAX_LIFETIME_SECONDS = 6 * 60 * 60
MANIFEST_FIELDS = {
    "schema",
    "owner",
    "run",
    "vm_manifest",
    "authority",
    "instance",
    "host",
    "port",
    "phase",
    "expires_at",
}
RECORD_FIELDS = {"schema", "run", "instance", "accepted_at", "sender", "recipients", "mime", "sha256"}


def _private_read(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != PRIVATE_FILE_MODE
            or info.st_uid != os.getuid()
            or info.st_size > maximum
        ):
            raise ValueError("Native SMTP evidence must be a bounded private owned regular file")
        value = source.read(maximum + 1)
        if len(value) > maximum:
            raise ValueError("Native SMTP private evidence exceeds its bound")
        return value


def _write_private(path: Path, value: dict[str, Any]) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "w") as target:
        json.dump(value, target, sort_keys=True)
        target.flush()
        os.fsync(target.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _current(authority: NativeAuthority) -> NativeAuthority:
    current = native_authority(authority.path)
    if current.public_key != authority.public_key or current.manifest["run"] != authority.manifest["run"]:
        raise ValueError("Native SMTP VM authority changed")
    return current


def _identity(authority: NativeAuthority) -> str:
    return hashlib.sha256(authority.public_key.encode()).hexdigest()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Native SMTP timestamp is invalid")
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise ValueError("Native SMTP timestamp must include its timezone")
    return result


def validate_capture(authority: NativeAuthority, path: Path, *, live: bool = True) -> dict[str, Any]:
    """A fixed loopback endpoint is useful only while its exact owned instance is live."""
    current = _current(authority)
    try:
        value = json.loads(_private_read(path, MAX_MANIFEST_BYTES))
        if (
            not isinstance(value, dict)
            or set(value) != MANIFEST_FIELDS
            or type(value["schema"]) is not int
            or value["schema"] != 1
            or value["owner"] != OWNER
            or value["run"] != current.manifest["run"]
            or value["vm_manifest"] != str(current.path)
            or value["authority"] != _identity(current)
            or value["host"] != "127.0.0.1"
            or type(value["port"]) is not int
            or not MIN_PORT <= value["port"] <= MAX_PORT
            or value["phase"] not in ("serving", "closed")
            or not isinstance(value["instance"], str)
            or str(UUID(value["instance"])) != value["instance"]
        ):
            raise ValueError("Native SMTP capture manifest does not match this owned VM")
        expiry = _timestamp(value["expires_at"])
        if expiry > _timestamp(current.manifest["expires_at"]):
            raise ValueError("Native SMTP capture exceeds its VM authority lifetime")
        if live:
            if value["phase"] != "serving" or expiry <= datetime.now(UTC):
                raise ValueError("Native SMTP capture is closed or expired")
            with smtplib.SMTP(timeout=SMTP_TIMEOUT) as client:
                code, greeting = client.connect("127.0.0.1", value["port"])
                if code != SMTP_READY or greeting != (OWNER + " " + value["instance"]).encode():
                    raise ValueError("Native SMTP listener instance does not match its private manifest")
        return value
    except (OSError, smtplib.SMTPException, TypeError, KeyError) as error:
        raise ValueError("A current private owned live native SMTP capture is required") from error


def smtp_settings(authority: NativeAuthority, path: Path) -> dict[str, Any]:
    value = validate_capture(authority, path)
    return {
        "EMAIL_BACKEND": "django.core.mail.backends.smtp.EmailBackend",
        "EMAIL_PROVIDER": "smtp",
        "EMAIL_HOST": "127.0.0.1",
        "EMAIL_PORT": value["port"],
        "EMAIL_USE_TLS": False,
        "EMAIL_USE_SSL": False,
        "EMAIL_HOST_USER": "",
        "EMAIL_HOST_PASSWORD": "",
        "EMAIL_TIMEOUT": SMTP_TIMEOUT,
    }


class _Handler(socketserver.StreamRequestHandler):
    server: _Server
    sender: str | None
    recipients: list[str]

    def envelope(self, command: str, argument: str) -> None:
        prefix = "FROM:" if command == "MAIL" else "TO:"
        address = re.fullmatch(re.escape(prefix) + r"\s*<([^<>\r\n]*)>", argument, flags=re.IGNORECASE)
        if address is None or (command == "RCPT" and (self.sender is None or not address[1])):
            self.wfile.write(b"503 invalid envelope\r\n")
        elif command == "MAIL":
            self.sender, self.recipients = address[1], []
            self.wfile.write(b"250 sender accepted\r\n")
        elif len(self.recipients) >= MAX_RECIPIENTS:
            self.wfile.write(b"452 recipient bound exceeded\r\n")
        else:
            self.recipients.append(address[1])
            self.wfile.write(b"250 recipient accepted\r\n")

    def data(self) -> bool:
        if self.sender is None or not self.recipients:
            self.wfile.write(b"503 provide an envelope first\r\n")
            return True
        self.wfile.write(b"354 End with dot\r\n")
        mime = bytearray()
        while True:
            line = self.rfile.readline(MAX_LINE_BYTES + 1)
            if not line or len(line) > MAX_LINE_BYTES:
                return False
            if line == b".\r\n":
                break
            mime.extend(line[1:] if line.startswith(b"..") else line)
            if len(mime) > MAX_MESSAGE_BYTES:
                self.wfile.write(b"552 capture message bound exceeded\r\n")
                return False
        self.server.capture.persist(self.sender, self.recipients, bytes(mime))
        self.wfile.write(b"250 durably captured; not relayed\r\n")
        self.sender, self.recipients = None, []
        return True

    def handle(self) -> None:
        self.connection.settimeout(SMTP_TIMEOUT)
        self.wfile.write(("220 " + OWNER + " " + self.server.capture.instance + "\r\n").encode())
        self.sender = None
        self.recipients = []
        try:
            while self.server.capture.current():
                line = self.rfile.readline(MAX_LINE_BYTES + 1)
                if not line or len(line) > MAX_LINE_BYTES:
                    return
                command, _, argument = line.decode("ascii", errors="replace").strip().partition(" ")
                command = command.upper()
                if command in ("EHLO", "HELO", "NOOP"):
                    self.wfile.write(b"250 native acceptance only\r\n")
                elif command == "QUIT":
                    self.wfile.write(b"221 closing\r\n")
                    return
                elif command == "RSET":
                    self.sender, self.recipients = None, []
                    self.wfile.write(b"250 reset\r\n")
                elif command in ("MAIL", "RCPT"):
                    self.envelope(command, argument)
                elif command == "DATA":
                    if not self.data():
                        return
                else:
                    self.wfile.write(b"502 command unsupported\r\n")
        except (OSError, ValueError):
            # No successful DATA response is sent when persistence or authority fails.
            with contextlib.suppress(OSError):
                self.wfile.write(b"451 native capture unavailable\r\n")


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 8

    def __init__(self, capture: NativeSMTPCapture) -> None:
        self.capture = capture
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", 0), _Handler)

    def process_request(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]
    ) -> None:
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class NativeSMTPCapture:
    """Owned foreground-process resource; bound before publication and never daemonized."""

    def __init__(self, authority: NativeAuthority, path: Path, *, lifetime_seconds: int = 3600) -> None:
        current = _current(authority)
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= MAX_LIFETIME_SECONDS:
            raise ValueError("Native SMTP lifetime must be between one second and six hours")
        self.authority, self.path = current, path.absolute()
        self.instance = str(uuid4())
        self.expiry = min(
            datetime.now(UTC) + timedelta(seconds=lifetime_seconds), _timestamp(current.manifest["expires_at"])
        )
        self.spool = self.path.with_name(self.path.name + ".messages")
        self.active = False
        self.lock = threading.Lock()
        self.server: _Server | None = None
        self.thread: threading.Thread | None = None
        self.manifest: dict[str, Any] = {}

    @property
    def port(self) -> int:
        if self.server is None:
            raise ValueError("Native SMTP capture has not bound its socket")
        return int(self.server.server_address[1])

    def current(self) -> bool:
        return self.active and datetime.now(UTC) < self.expiry

    def __enter__(self) -> NativeSMTPCapture:
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("Native SMTP manifest already exists; preserve its original capture evidence")
        self.spool.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        with contextlib.ExitStack() as acquisition:
            acquisition.callback(self.close)
            self.server = _Server(self)
            self.manifest = {
                "schema": 1,
                "owner": OWNER,
                "run": self.authority.manifest["run"],
                "vm_manifest": str(self.authority.path),
                "authority": _identity(self.authority),
                "instance": self.instance,
                "host": "127.0.0.1",
                "port": self.port,
                "phase": "serving",
                "expires_at": self.expiry.isoformat(),
            }
            self.active = True
            self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            self.thread.start()
            _write_private(self.path, self.manifest)
            acquisition.pop_all()
            return self

    def persist(self, sender: str, recipients: list[str], mime: bytes) -> None:
        with self.lock:
            _current(self.authority)
            if not self.current() or len(list(self.spool.iterdir())) >= MAX_MESSAGES:
                raise ValueError("Native SMTP capture has expired or reached its acceptance bound")
            _write_private(
                self.spool / (str(uuid4()) + ".json"),
                {
                    "schema": 1,
                    "run": self.authority.manifest["run"],
                    "instance": self.instance,
                    "accepted_at": datetime.now(UTC).isoformat(),
                    "sender": sender,
                    "recipients": recipients,
                    "mime": base64.b64encode(mime).decode(),
                    "sha256": hashlib.sha256(mime).hexdigest(),
                },
            )

    def close(self) -> None:
        with self.lock:
            self.active = False
        if self.server is not None:
            if self.thread is not None:
                self.server.shutdown()
                self.thread.join(timeout=SMTP_TIMEOUT)
            self.server.server_close()
            self.server = None
        if self.path.exists() and json.loads(_private_read(self.path, MAX_MANIFEST_BYTES)) == self.manifest:
            temporary = self.path.with_name(self.path.name + "." + self.instance + ".closed")
            _write_private(temporary, {**self.manifest, "phase": "closed"})
            os.replace(temporary, self.path)

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()


@dataclass(frozen=True)
class AcceptedMessage:
    sender: str
    recipients: list[str]
    subject: str
    text: str
    html: str
    mime: bytes
    accepted_at: datetime


def _body(value: str) -> str:
    return value.replace("\r\n", "\n").removesuffix("\n")


def accepted_messages(authority: NativeAuthority, path: Path) -> list[AcceptedMessage]:
    """Read retained private evidence, including a closed capture; never infer delivery."""
    manifest = validate_capture(authority, path, live=False)
    spool = path.with_name(path.name + ".messages")
    info = spool.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != PRIVATE_DIRECTORY_MODE
        or info.st_uid != os.getuid()
    ):
        raise ValueError("Native SMTP spool must be a private owned directory")
    paths = sorted(spool.iterdir())
    if len(paths) > MAX_MESSAGES:
        raise ValueError("Native SMTP capture exceeds its acceptance bound")
    result = []
    for record_path in paths:
        record = json.loads(_private_read(record_path, MAX_MESSAGE_BYTES * 2))
        if (
            not isinstance(record, dict)
            or set(record) != RECORD_FIELDS
            or type(record["schema"]) is not int
            or record["schema"] != 1
            or record["run"] != manifest["run"]
            or record["instance"] != manifest["instance"]
            or not isinstance(record["sender"], str)
            or not isinstance(record["recipients"], list)
            or not 1 <= len(record["recipients"]) <= MAX_RECIPIENTS
            or any(not isinstance(address, str) for address in record["recipients"])
        ):
            raise ValueError("Native SMTP acceptance record does not match its capture")
        mime = base64.b64decode(record["mime"], validate=True)
        accepted_at = _timestamp(record["accepted_at"])
        if (
            len(mime) > MAX_MESSAGE_BYTES
            or hashlib.sha256(mime).hexdigest() != record["sha256"]
            or accepted_at > _timestamp(manifest["expires_at"])
        ):
            raise ValueError("Native SMTP acceptance record is invalid")
        message = BytesParser(policy=policy.default).parsebytes(mime)
        text_parts: list[str] = []
        html_parts: list[str] = []
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if not isinstance(payload, bytes):
                    raise ValueError("Native SMTP MIME body is not decodable")
                decoded = payload.decode(part.get_content_charset() or "utf-8")
                (html_parts if part.get_content_type() == "text/html" else text_parts).append(_body(decoded))
        result.append(
            AcceptedMessage(
                record["sender"],
                record["recipients"],
                str(message.get("Subject", "")),
                "\n".join(text_parts),
                "\n".join(html_parts),
                mime,
                accepted_at,
            )
        )
    return result


def verify_email_logs(authority: NativeAuthority, path: Path, email_log_ids: Sequence[str]) -> dict[str, Any]:
    """Correlate explicit stored rows to isolated SMTP acceptance, refusing ambiguous copies."""
    from apps.notifications.models import EmailLog  # noqa: PLC0415 -- Django only in the native verification action.
    from apps.notifications.services import stored_message  # noqa: PLC0415

    ids = [str(UUID(value)) for value in email_log_ids]
    if not ids or len(ids) != len(set(ids)) or len(ids) > MAX_MESSAGES:
        raise ValueError("Select distinct bounded stored EmailLog IDs explicitly")
    rows = {str(row.pk): row for row in EmailLog.objects.filter(pk__in=ids)}
    if set(rows) != set(ids):
        raise ValueError("Selected stored EmailLog rows do not exist")
    captures = accepted_messages(authority, path)
    selected: set[int] = set()
    for identifier in ids:
        row = rows[identifier]
        if row.provider != "smtp" or row.status != "sent" or row.delivery_attempts < 1 or row.claim_token is not None:
            raise ValueError("Stored EmailLog has no completed SMTP acceptance")
        outgoing = stored_message(row)
        recipients = sorted(parseaddr(value)[1].lower() for value in [*outgoing.to, *outgoing.cc, *outgoing.bcc])
        matches = [
            index
            for index, item in enumerate(captures)
            if item.sender.lower() == parseaddr(outgoing.from_email)[1].lower()
            and sorted(value.lower() for value in item.recipients) == recipients
            and item.subject == outgoing.subject
            and item.text == _body(outgoing.body_text)
            and item.html == _body(outgoing.body_html or "")
        ]
        if len(matches) != 1 or matches[0] in selected:
            raise ValueError("Stored EmailLog and captured envelope/MIME do not match unambiguously")
        selected.add(matches[0])
    return {
        "schema": 1,
        "run": authority.manifest["run"],
        "email_log_ids": ids,
        "accepted_count": len(selected),
        "inbox_delivery_proven": False,
    }
