#!/usr/bin/env python3
"""Serve the actual native Platform and Portal on owned inherited loopback sockets."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, cast
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

ROOT = Path(__file__).resolve().parents[3]
FILE_MODE = 0o600
MAX_AUTHORITY_BYTES = 8192


def authority_current(path: Path, digest: str) -> bool:
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) != FILE_MODE
                or info.st_uid != os.getuid()
                or info.st_size > MAX_AUTHORITY_BYTES
            ):
                return False
            raw = source.read(MAX_AUTHORITY_BYTES + 1)
        value = json.loads(raw)
        expiry = datetime.fromisoformat(value["expires_at"])
        return (
            hashlib.sha256(raw).hexdigest() == digest
            and value["phase"] == "serving"
            and expiry.tzinfo is not None
            and expiry > datetime.now(UTC)
        )
    except (OSError, ValueError, TypeError, KeyError):
        return False


class AuthorityGuard:
    def __init__(self, application: Any, path: Path, digest: str) -> None:
        self.application, self.path, self.digest = application, path, digest

    def __call__(self, environ: Any, start_response: Any) -> Any:
        if not authority_current(self.path, self.digest):
            start_response("503 Service Unavailable", [("Content-Type", "text/plain"), ("Cache-Control", "no-store")])
            return [b"Native UI authority closed, changed or expired.\n"]
        return self.application(environ, start_response)


class _Server(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    block_on_close = False


class _Handler(WSGIRequestHandler):
    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        # Even private logs need no one-use login/reset tokens or customer URL paths.
        self.log_message("%s status=%s bytes=%s", self.command, code, size)


def inherited_server(listener: socket.socket, application: Any) -> WSGIServer:
    server = _Server(listener.getsockname(), _Handler, bind_and_activate=False)
    server.socket.close()
    server.socket = listener
    server.server_name = "127.0.0.1"
    server.server_port = int(listener.getsockname()[1])
    server.setup_environ()
    server.set_app(application)
    server.timeout = 0.5
    return server


def child(role: str, descriptor: int, path: Path, digest: str) -> None:
    if descriptor < 3 or not authority_current(path, digest):
        raise ValueError("Native UI child requires its exact live authority and inherited listener")
    value = json.loads(path.read_bytes())
    listener = socket.socket(fileno=descriptor)
    if listener.getsockname() != ("127.0.0.1", value[role + "_port"]):
        listener.close()
        raise ValueError("Native UI inherited listener has a different scope")
    sys.path.insert(0, str(ROOT / "services" / role))
    from django.contrib.staticfiles.handlers import (  # noqa: PLC0415 -- Roles initialize in separate processes.
        StaticFilesHandler,
    )

    from config.wsgi import (  # noqa: PLC0415 -- Actual role-specific WSGI body/import isolation guards.
        application as real_application,
    )

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stop.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stop.set())
    # Django accepts this actual WSGI wrapper; its stubs require a nominal WSGIHandler.
    application = AuthorityGuard(StaticFilesHandler(cast("Any", real_application)), path, digest)
    with inherited_server(listener, application) as server:
        while not stop.is_set() and authority_current(path, digest):
            server.handle_request()


def stop_child(process: subprocess.Popen[bytes]) -> None:
    """Only a retained exact child handle; never process names, ports or provider inventories."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def coordinate(manifest: Path, ui_path: Path, lifetime: int) -> None:
    sys.path.insert(0, str(ROOT / "services/platform"))
    from apps.infrastructure.native_lab import (  # noqa: PLC0415 -- Coordinator alone may receive VM authority.
        native_authority,
    )
    from apps.infrastructure.native_portal import NativeUIPair, child_environment, validate_ui  # noqa: PLC0415

    authority = native_authority(manifest.absolute())
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stop.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stop.set())
    with NativeUIPair(authority, ui_path, lifetime_seconds=lifetime) as pair, contextlib.ExitStack() as stack:
        environments = {role: child_environment(pair, role, ROOT, dict(os.environ)) for role in ("platform", "portal")}
        digest = hashlib.sha256(pair.path.read_bytes()).hexdigest()
        processes: list[subprocess.Popen[bytes]] = []
        for role, command in (("platform", "createcachetable"), ("portal", "migrate")):
            log_path = pair.path.with_name(pair.path.name + "." + role + ".log")
            log = stack.enter_context(
                os.fdopen(os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILE_MODE), "wb")
            )
            subprocess.run(  # noqa: S603 -- Exact interpreter/management command and isolated role-specific environment.
                [sys.executable, "manage.py", command, *(["--noinput"] if role == "portal" else [])],
                cwd=ROOT / "services" / role,
                env=environments[role],
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=120,
                check=True,
            )
            listener = pair.listeners[role]
            process = subprocess.Popen(  # noqa: S603 -- Exact repository child and retained OS-owned listener descriptor.
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "child",
                    "--role",
                    role,
                    "--listener-fd",
                    str(listener.fileno()),
                    "--ui-authority",
                    str(pair.path),
                    "--authority-sha256",
                    digest,
                ],
                cwd=ROOT / "services" / role,
                env=environments[role],
                pass_fds=(listener.fileno(),),
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            processes.append(process)
            stack.callback(stop_child, process)
        print(
            "Native UI starting on owned loopback origins: "
            + ", ".join(f"{role}=http://127.0.0.1:{pair.value[role + '_port']}" for role in ("platform", "portal")),
            flush=True,
        )
        while not stop.wait(0.5):
            validate_ui(authority, pair.path)
            if any(process.poll() is not None for process in processes):
                raise RuntimeError("Owned native UI process exited; retained private logs contain its outcome")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve", "child"))
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--ui-authority", type=Path, required=True)
    parser.add_argument("--lifetime-seconds", type=int, default=10800)
    parser.add_argument("--role", choices=("platform", "portal"))
    parser.add_argument("--listener-fd", type=int)
    parser.add_argument("--authority-sha256")
    args = parser.parse_args()
    try:
        if args.action == "serve":
            if args.manifest is None or args.role is not None or args.listener_fd is not None:
                raise ValueError("Serve requires the exact VM manifest and no child-only arguments")
            coordinate(args.manifest, args.ui_authority, args.lifetime_seconds)
        else:
            if args.role is None or args.listener_fd is None or not args.authority_sha256 or args.manifest is not None:
                raise ValueError("Child is internal to the owned listener coordinator")
            expected = "config.settings.native_portal" if args.role == "platform" else "config.settings.native"
            if os.environ.get("DJANGO_SETTINGS_MODULE") != expected:
                raise ValueError("Native UI child must use the exact role-specific profile")
            child(args.role, args.listener_fd, args.ui_authority, args.authority_sha256)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        parser.exit(
            1, "Native UI refused or stopped; retain the private authority/logs and reconcile before retrying.\n"
        )


if __name__ == "__main__":
    main()
