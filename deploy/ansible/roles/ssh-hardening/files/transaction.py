"""Arbitrate SSH commit and rollback; a stale timer must never undo a newer deploy."""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

LOCK_DIRECTORY = Path("/run/praho-ssh-transition.lock")


@contextmanager
def phase_lock(snapshot: Path) -> Iterator[None]:
    with (snapshot / "phase.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def acquire(token: str) -> None:
    LOCK_DIRECTORY.mkdir(mode=0o700)
    (LOCK_DIRECTORY / "owner").write_text(token)


def release(token: str) -> None:
    """A delayed controller/timer cannot release another transition's lock."""
    owner = LOCK_DIRECTORY / "owner"
    if not owner.exists() or owner.read_text() != token:
        return
    phase = LOCK_DIRECTORY / "phase"
    if phase.exists():
        state = Path(phase.read_text()) / "state"
        if state.read_text() not in {"committed", "rolled-back"}:
            raise RuntimeError("unfinished SSH phase retains its transition lock")
        phase.unlink()
    owner.unlink()
    LOCK_DIRECTORY.rmdir()


def prepare(snapshot: Path, token: str) -> None:
    if (LOCK_DIRECTORY / "owner").read_text() != token:
        raise RuntimeError("SSH transition lock ownership changed")
    previous = LOCK_DIRECTORY / "phase"
    if previous.exists() and (Path(previous.read_text()) / "state").read_text() != "committed":
        raise RuntimeError("previous SSH phase has not committed")
    (snapshot / "state").write_text("pending")
    (LOCK_DIRECTORY / "phase").write_text(str(snapshot))


def require_owner(snapshot: Path) -> None:
    token = (snapshot / "token").read_text()
    owner, phase = LOCK_DIRECTORY / "owner", LOCK_DIRECTORY / "phase"
    if not owner.exists() or owner.read_text() != token or not phase.exists() or phase.read_text() != str(snapshot):
        raise RuntimeError("stale SSH phase does not own the transition")


def commit(snapshot: Path) -> None:
    with phase_lock(snapshot):
        state = (snapshot / "state").read_text()
        if state not in {"pending", "committed"}:
            raise RuntimeError("SSH rollback already started; refusing commit")
        require_owner(snapshot)
        (snapshot / "state").write_text("committed")


def replace_file(source: Path, destination: Path, mode: int) -> None:
    fd, name = tempfile.mkstemp(dir=destination.parent, prefix=".praho-ssh-")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def activate_service(socket_active: bool) -> None:
    commands = [["/usr/sbin/sshd", "-t"], ["/usr/bin/systemctl", "daemon-reload"]]
    commands.append(
        ["/usr/bin/systemctl", "restart", "ssh.socket", "ssh.service"]
        if socket_active
        else ["/usr/bin/systemctl", "reload-or-restart", "ssh.service"]
    )
    for command in commands:
        subprocess.run(command, check=True, timeout=45)  # noqa: S603 -- fixed commands, no shell


def apply_snapshot(snapshot: Path) -> None:
    metadata = json.loads((snapshot / "metadata.json").read_text())
    replace_file(snapshot / "candidate_sshd_config", Path("/etc/ssh/sshd_config"), 0o600)
    if metadata["socket_active"]:
        replace_file(
            snapshot / "candidate_socket.conf", Path("/etc/systemd/system/ssh.socket.d/99-praho-listen.conf"), 0o644
        )
    activate_service(metadata["socket_active"])


def activate(snapshot: Path, apply: Callable[[Path], None] = apply_snapshot) -> None:
    """A resumed controller cannot mutate live state after rollback relinquished ownership."""
    with phase_lock(snapshot):
        if (snapshot / "state").read_text() != "pending":
            raise RuntimeError("SSH phase is no longer pending; refusing activation")
        require_owner(snapshot)
        apply(snapshot)


def restore_snapshot(snapshot: Path) -> None:
    metadata = json.loads((snapshot / "metadata.json").read_text())
    replace_file(snapshot / "sshd_config", Path("/etc/ssh/sshd_config"), 0o600)
    if metadata["socket_active"]:
        socket_config = Path("/etc/systemd/system/ssh.socket.d/99-praho-listen.conf")
        if metadata["had_socket_override"]:
            replace_file(snapshot / "socket.conf", socket_config, 0o644)
        else:
            socket_config.unlink(missing_ok=True)
    activate_service(metadata["socket_active"])


def rollback(snapshot: Path, restore: Callable[[Path], None] = restore_snapshot) -> None:
    """Commit and rollback hold the same OS lock through their entire critical section."""
    with phase_lock(snapshot):
        state = (snapshot / "state").read_text()
        if state in {"committed", "rolled-back"}:
            return
        if state not in {"pending", "rolling-back"}:
            raise RuntimeError("unknown SSH transaction state")
        require_owner(snapshot)
        token = (snapshot / "token").read_text()
        (snapshot / "state").write_text("rolling-back")
        restore(snapshot)
        (snapshot / "state").write_text("rolled-back")
        release(token)


if __name__ == "__main__":
    try:
        action, argument = sys.argv[1:3]
        if action == "acquire":
            acquire(argument)
        elif action == "release":
            release(argument)
        elif action == "prepare":
            prepare(Path(argument), sys.argv[3])
        elif action == "commit":
            commit(Path(argument))
        elif action == "activate":
            activate(Path(argument))
        elif action == "rollback":
            rollback(Path(argument))
        else:
            raise ValueError("unknown SSH transaction operation")
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"SSH transaction failed: {error}", file=sys.stderr)
        sys.exit(1)
