"""Node-private user snapshot codec/store; no native mutations or production dispatch.

The public projection describes validated private state, not live verification.
Native callers must corroborate identities. Compatible with node Python 3.11.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_CRON_BYTES = 1024 * 1024
MAX_USERS = 4096
MAX_DOMAINS = 4096
MAX_CREDENTIAL_BYTES = 4096
MAX_DOMAIN_LENGTH = 253
MAX_PATH_LENGTH = 4096
MIN_PRINTABLE_CODEPOINT = 32
DELETE_CODEPOINT = 127
AGING_FIELDS = frozenset({"change", "min", "max", "warn", "inactive", "expire", "flag"})
PHASES = frozenset({"captured", "frozen"})
ROLES = frozenset({"owner", "mailbox", "ftp", "web", "companion"})
PUBLIC_USER_FIELDS = ("login", "canonical_login", "role", "domain_id", "uid", "gid")
REASONS = frozenset(
    {
        "invalid_identity",
        "snapshot_identity_changed",
        "invalid_schema",
        "invalid_scope",
        "invalid_user",
        "invalid_companion",
        "foreign_uid",
        "invalid_state",
        "unsupported_shadow_flag",
        "invalid_cron",
        "frozen_state_not_held",
        "duplicate_field",
        "malformed_snapshot",
        "oversized_snapshot",
        "invalid_phase",
        "invalid_action",
        "invalid_nonce",
        "unsafe_snapshot_directory",
        "unsafe_snapshot_file",
        "snapshot_missing",
        "immutable_snapshot",
        "captured_snapshot_missing",
        "snapshot_io_failed",
        "invalid_user_state",
        "root_required",
    }
)


class UserStateError(ValueError):
    """Fixed reasons only, even if a future caller mistakenly supplies private text."""

    def __init__(self, code: str) -> None:
        super().__init__(code if isinstance(code, str) and code in REASONS else "invalid_user_state")


def _object(value: Any, keys: set[str] | frozenset[str], reason: str = "invalid_schema") -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise UserStateError(reason)
    return value


def _name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_DOMAIN_LENGTH
        or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) is None for part in value.split("."))
    ):
        raise UserStateError("invalid_identity")
    return value


def _domain_id(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{1,30}", value) is None:
        raise UserStateError("invalid_identity")
    return value


def _uuid(value: Any, reason: str) -> str:
    try:
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError, TypeError):
        raise UserStateError(reason) from None
    return value


@dataclass(frozen=True)
class SnapshotIdentity:
    operation_id: str
    archive_name: str
    domain: str
    domain_id: str
    owner: str

    def __post_init__(self) -> None:
        _uuid(self.operation_id, "invalid_identity")
        _name(self.domain)
        _domain_id(self.domain_id)
        if (
            not isinstance(self.owner, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", self.owner) is None
            or not isinstance(self.archive_name, str)
            or not (
                self.archive_name == f"migration_{self.operation_id}.tar.gz"
                or re.fullmatch(r"virtualmin_backup_[0-9a-f]{32}\.tar\.gz", self.archive_name)
            )
        ):
            raise UserStateError("invalid_identity")


@dataclass(frozen=True, repr=False)
class PrivateSnapshot:
    identity: SnapshotIdentity
    phase: str
    _encoded: bytes = field(repr=False)
    _roster: bytes = field(repr=False)
    _user_count: int
    _uid_count: int

    def private_bytes(self) -> bytes:
        """Explicit private serialization; never use in receipts, logs or app state."""
        return self._encoded


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UserStateError("duplicate_field")
        result[key] = value
    return result


def _parse(payload: bytes, *, limit: int = MAX_SNAPSHOT_BYTES) -> Any:
    if len(payload) > limit:
        raise UserStateError("oversized_snapshot")
    try:
        return json.loads(payload, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, UserStateError):
            raise
        raise UserStateError("malformed_snapshot") from None


def _home(value: Any) -> PurePosixPath:
    if (
        not isinstance(value, str)
        or len(value) > MAX_PATH_LENGTH
        or any(ord(char) < MIN_PRINTABLE_CODEPOINT or ord(char) == DELETE_CODEPOINT for char in value)
    ):
        raise UserStateError("invalid_scope")
    path = PurePosixPath(value)
    if not path.is_absolute() or path == PurePosixPath("/") or ".." in path.parts or str(path) != value:
        raise UserStateError("invalid_scope")
    return path


def _domains(value: Any, identity: SnapshotIdentity) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_DOMAINS:
        raise UserStateError("invalid_scope")
    result: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for item in value:
        domain = _object(item, {"domain", "domain_id", "parent_id", "home"}, "invalid_scope")
        key, name = _domain_id(domain["domain_id"]), _name(domain["domain"])
        _home(domain["home"])
        if key in result or name in names:
            raise UserStateError("invalid_scope")
        result[key], names = domain, names | {name}
    parent = result.get(identity.domain_id)
    if not parent or parent["domain"] != identity.domain or parent["parent_id"] is not None:
        raise UserStateError("invalid_scope")
    for key, domain in result.items():
        if key != identity.domain_id and (
            domain["parent_id"] != identity.domain_id or not _home(domain["home"]).is_relative_to(_home(parent["home"]))
        ):
            raise UserStateError("invalid_scope")
    return result


def _login(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,255}", value) is None:
        raise UserStateError("invalid_user")
    return value


def _cron(value: Any) -> bytes:
    cron = _object(value, {"present", "content_b64"}, "invalid_cron")
    encoded = cron["content_b64"]
    if (
        type(cron["present"]) is not bool
        or not isinstance(encoded, str)
        or len(encoded) > 4 * ((MAX_CRON_BYTES + 2) // 3)
    ):
        raise UserStateError("invalid_cron")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise UserStateError("invalid_cron") from None
    if (
        len(content) > MAX_CRON_BYTES
        or base64.b64encode(content).decode() != encoded
        or b"\x00" in content
        or (not cron["present"] and content)
    ):
        raise UserStateError("invalid_cron")
    return content


def _state(value: Any, *, frozen: bool) -> None:
    state = _object(value, {"password", "aging", "shell", "mail_enabled", "cron"}, "invalid_state")
    password = state["password"]
    if (
        not isinstance(password, str)
        or not password.isascii()
        or len(password.encode()) > MAX_CREDENTIAL_BYTES
        or any(char in password for char in "\x00\r\n:")
        or type(state["mail_enabled"]) is not bool
    ):
        raise UserStateError("invalid_state")
    _home(state["shell"])
    aging = _object(state["aging"], AGING_FIELDS, "invalid_state")
    if aging["flag"] != "":
        raise UserStateError("unsupported_shadow_flag")
    if any(not isinstance(value, str) or re.fullmatch(r"(?:|[0-9]{1,10})", value) is None for value in aging.values()):
        raise UserStateError("invalid_state")
    content = _cron(state["cron"])
    runnable = any(
        line.strip()
        and not line.lstrip().startswith(b"#")
        and re.match(rb"\s*[A-Za-z_][A-Za-z0-9_]*\s*=", line) is None
        for line in content.splitlines()
    )
    if frozen and (not password.startswith(("!", "*")) or runnable):
        raise UserStateError("frozen_state_not_held")


def _user(value: Any, domains: dict[str, dict[str, Any]], phase: str) -> dict[str, Any]:
    user = _object(value, {*PUBLIC_USER_FIELDS, "home", "states"}, "invalid_user")
    _login(user["login"])
    _login(user["canonical_login"])
    if (
        not isinstance(user["role"], str)
        or user["role"] not in ROLES
        or not isinstance(user["domain_id"], str)
        or user["domain_id"] not in domains
        or any(type(user[field]) is not int or not 0 < user[field] < 2**31 for field in ("uid", "gid"))
        or not _home(user["home"]).is_relative_to(_home(domains[user["domain_id"]]["home"]))
    ):
        raise UserStateError("invalid_user")
    states = _object(user["states"], {"original", "frozen"}, "invalid_state")
    _state(states["original"], frozen=False)
    if phase == "frozen":
        _state(states["frozen"], frozen=True)
    elif states["frozen"] is not None:
        raise UserStateError("invalid_state")
    return user


def _relationships(users: list[dict[str, Any]], identity: SnapshotIdentity, domains: dict[str, dict[str, Any]]) -> None:
    by_name = {user["login"]: user for user in users}
    if len(by_name) != len(users):
        raise UserStateError("invalid_user")
    owners = [user for user in users if user["role"] == "owner"]
    if len(owners) != 1:
        raise UserStateError("invalid_user")
    owner = owners[0]
    if (owner["login"], owner["domain_id"], owner["home"]) != (
        identity.owner,
        identity.domain_id,
        domains[identity.domain_id]["home"],
    ):
        raise UserStateError("invalid_user")
    by_uid: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for user in users:
        canonical = by_name.get(user["canonical_login"])
        if user["role"] == "companion":
            if (
                not canonical
                or canonical["role"] not in {"mailbox", "ftp"}
                or "@" not in canonical["login"]
                or user["login"] != canonical["login"].replace("@", "-")
                or any(user[key] != canonical[key] for key in ("uid", "gid", "home", "domain_id"))
            ):
                raise UserStateError("invalid_companion")
        elif user["canonical_login"] != user["login"]:
            raise UserStateError("invalid_companion")
        if user["role"] == "web" and (user["uid"], user["gid"]) != (owner["uid"], owner["gid"]):
            raise UserStateError("foreign_uid")
        by_uid[user["uid"]].append(user)
    for group in by_uid.values():
        if len([user for user in group if user["role"] not in {"web", "companion"}]) != 1:
            raise UserStateError("foreign_uid")


def decode_snapshot(payload: bytes, *, expected: SnapshotIdentity) -> PrivateSnapshot:
    document = _object(_parse(payload), {"version", "identity", "phase", "domains", "users"})
    if type(document["version"]) is not int or document["version"] != 1:
        raise UserStateError("invalid_schema")
    identity = SnapshotIdentity(**_object(document["identity"], set(asdict(expected)), "invalid_identity"))
    if identity != expected:
        raise UserStateError("snapshot_identity_changed")
    phase = document["phase"]
    if not isinstance(phase, str) or phase not in PHASES:
        raise UserStateError("invalid_phase")
    domains = _domains(document["domains"], identity)
    if not isinstance(document["users"], list) or not 1 <= len(document["users"]) <= MAX_USERS:
        raise UserStateError("invalid_user")
    users = [_user(user, domains, phase) for user in document["users"]]
    _relationships(users, identity, domains)
    roster = {
        "domains": [
            {key: domain[key] for key in ("domain", "domain_id", "parent_id")} for _, domain in sorted(domains.items())
        ],
        "users": [
            {key: user[key] for key in PUBLIC_USER_FIELDS} for user in sorted(users, key=lambda user: user["login"])
        ],
    }
    encoded = _canonical(document)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise UserStateError("oversized_snapshot")
    return PrivateSnapshot(
        identity, phase, encoded, _canonical(roster), len(users), len({user["uid"] for user in users})
    )


def public_projection(snapshot: PrivateSnapshot, *, nonce: str) -> dict[str, Any]:
    # The dataclass is transport, not an authority token. Rebuild only the
    # allowlisted public roster, even if a caller constructed/replaced fields.
    snapshot = decode_snapshot(snapshot.private_bytes(), expected=snapshot.identity)
    return {
        "version": 1,
        "action": "project",
        "nonce": _uuid(nonce, "invalid_nonce"),
        "identity": asdict(snapshot.identity),
        "phase": snapshot.phase,
        "user_count": snapshot._user_count,
        "uid_count": snapshot._uid_count,
        "roster_sha256": hashlib.sha256(snapshot._roster).hexdigest(),
    }


def project_request(payload: bytes) -> str:
    request = _object(_parse(payload, limit=MAX_SNAPSHOT_BYTES + 16384), {"action", "nonce", "expected", "snapshot"})
    if request["action"] != "project":
        raise UserStateError("invalid_action")
    fields = _object(
        request["expected"], {"operation_id", "archive_name", "domain", "domain_id", "owner"}, "invalid_identity"
    )
    snapshot = decode_snapshot(_canonical(request["snapshot"]), expected=SnapshotIdentity(**fields))
    return (
        "USER_STATE_RESULT="
        + base64.b64encode(_canonical(public_projection(snapshot, nonce=request["nonce"]))).decode()
    )


class SnapshotStore:
    """Immutable current-user-owned files; the production entrypoint requires root.

    Interrupted exclusive writes remain private, unusable files needing review.
    Replay never overwrites incomplete JSON or claims it was captured.
    """

    def __init__(self, root: Path) -> None:
        self.root, self._uid = root, os.geteuid()
        if not root.is_absolute() or not root.name:
            raise UserStateError("unsafe_snapshot_directory")
        try:
            parent = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            raise UserStateError("unsafe_snapshot_directory") from None
        try:
            with suppress(FileExistsError):
                os.mkdir(root.name, mode=0o700, dir_fd=parent)
            descriptor = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                self._check(os.fstat(descriptor), directory=True)
            finally:
                os.close(descriptor)
            # The top-level private directory entry must survive too, including
            # a retry after creation succeeded but its parent flush failed.
            os.fsync(parent)
        except OSError:
            raise UserStateError("unsafe_snapshot_directory") from None
        finally:
            os.close(parent)

    def _check(self, info: os.stat_result, *, directory: bool) -> None:
        correct = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not correct or info.st_uid != self._uid or info.st_mode & 0o077 or (not directory and info.st_nlink != 1):
            raise UserStateError("unsafe_snapshot_directory" if directory else "unsafe_snapshot_file")

    @contextmanager
    def _scope(self, identity: SnapshotIdentity, *, create: bool) -> Iterator[int]:
        descriptors: list[int] = []
        try:
            parent = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(parent)
            self._check(os.fstat(parent), directory=True)
            for part in (identity.domain_id, identity.operation_id):
                if create:
                    with suppress(FileExistsError):
                        os.mkdir(part, 0o700, dir_fd=parent)
                    # Also repair an earlier interrupted mkdir/fsync boundary.
                    os.fsync(parent)
                parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                descriptors.append(parent)
                self._check(os.fstat(parent), directory=True)
            yield parent
        except OSError:
            raise UserStateError("unsafe_snapshot_directory") from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def _read(self, directory: int, name: str, *, durable: bool = False) -> bytes | None:
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError:
            raise UserStateError("unsafe_snapshot_file") from None
        try:
            info = os.fstat(descriptor)
            self._check(info, directory=False)
            if info.st_size > MAX_SNAPSHOT_BYTES:
                raise UserStateError("oversized_snapshot")
            payload = os.read(descriptor, MAX_SNAPSHOT_BYTES + 1)
            if len(payload) != info.st_size or os.fstat(descriptor).st_mtime_ns != info.st_mtime_ns:
                raise UserStateError("snapshot_io_failed")
            if durable:
                os.fsync(descriptor)
            return payload
        finally:
            os.close(descriptor)

    def load(self, identity: SnapshotIdentity, phase: str) -> PrivateSnapshot:
        if not isinstance(phase, str) or phase not in PHASES:
            raise UserStateError("invalid_phase")
        with self._scope(identity, create=False) as directory:
            payload = self._read(directory, phase + ".json")
        if payload is None:
            raise UserStateError("snapshot_missing")
        snapshot = decode_snapshot(payload, expected=identity)
        if snapshot.phase != phase:
            raise UserStateError("invalid_phase")
        return snapshot

    def _original_matches(self, snapshot: PrivateSnapshot, directory: int) -> None:
        payload = self._read(directory, "captured.json", durable=True)
        if payload is None:
            raise UserStateError("captured_snapshot_missing")
        original = decode_snapshot(payload, expected=snapshot.identity)
        document = json.loads(snapshot.private_bytes())
        document["phase"] = "captured"
        for user in document["users"]:
            user["states"]["frozen"] = None
        if original.phase != "captured" or _canonical(document) != original.private_bytes():
            raise UserStateError("immutable_snapshot")

    def save(self, snapshot: PrivateSnapshot) -> bool:
        snapshot = decode_snapshot(snapshot.private_bytes(), expected=snapshot.identity)
        with self._scope(snapshot.identity, create=True) as directory:
            if snapshot.phase == "frozen":
                self._original_matches(snapshot, directory)
            name = snapshot.phase + ".json"
            previous = self._read(directory, name, durable=True)
            if previous is not None:
                existing = decode_snapshot(previous, expected=snapshot.identity)
                if existing.private_bytes() != snapshot.private_bytes():
                    raise UserStateError("immutable_snapshot")
                os.fsync(directory)
                return False
            try:
                descriptor = os.open(
                    name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
                )
                with os.fdopen(descriptor, "wb") as output:
                    output.write(snapshot.private_bytes())
                    output.flush()
                    os.fsync(output.fileno())
                os.fsync(directory)
            except OSError:
                raise UserStateError("snapshot_io_failed") from None
        return True


def main() -> None:
    try:
        if os.geteuid() != 0:
            raise UserStateError("root_required")
        if sys.argv[1:] != ["project"]:
            raise UserStateError("invalid_action")
        print(project_request(sys.stdin.buffer.read(MAX_SNAPSHOT_BYTES + 16385)))
    except UserStateError as error:
        print("USER_STATE_ERROR=" + str(error), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
