#!/usr/bin/env python3
"""Stage archived cron and native credentials privately; activate only after ownership commits."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

# The same pure schema is shipped privately to the node; tests use the application module.
sys.path.insert(0, "/var/lib/praho/recovery")
try:
    from praho_owner_shadow import (
        decode_owner_shadow,  # type: ignore[import-not-found]  # Fixed playbook-staged sibling.
    )
except ModuleNotFoundError:
    from apps.provisioning.backup_owner_shadow import decode_owner_shadow

CRON_LIMIT = 1024 * 1024
HASH_LIMIT = 1024
NATIVE_CREDENTIAL_LIMIT = 4096
CREDENTIAL_HELPER = Path("/var/lib/praho/recovery/credentials.pl")
HASH_PATTERN = re.compile(r"(?:[!*]+|[!*]*\$[A-Za-z0-9][A-Za-z0-9./+_$=-]*|[!*]*[A-Za-z0-9./]{13})")


def owner_shadow_fields(content: bytes, *, domain: str, owner: str, archive_name: str) -> dict[str, str]:
    """Only a source-captured, archive-bound profile can describe the missing shadow columns."""
    fields = credential_fields(content, domain=domain, owner=owner)
    return decode_owner_shadow(fields, domain=domain, owner=owner, archive_name=archive_name)


def archive_members(archive: Path, domain: str, features: tuple[str, ...]) -> dict[str, bytes]:
    """Read bounded feature files in one pass without extracting archive paths."""
    names = {f"{domain}_{feature}": feature for feature in features}
    found: dict[str, bytes] = {}
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            feature = names.get(path.name)
            if feature is None:
                continue
            if (
                feature in found
                or not member.isfile()
                or member.size > CRON_LIMIT
                or ".." in path.parts
                or path.is_absolute()
            ):
                raise ValueError("The archive feature is duplicated, unsafe or oversized")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ValueError("The archive feature cannot be read")
            content = stream.read(CRON_LIMIT + 1)
            if len(content) > CRON_LIMIT or b"\0" in content:
                raise ValueError("The archive feature is not a bounded text file")
            content.decode("utf-8")
            found[feature] = content
    if set(found) != set(features):
        raise ValueError("The archive does not hold exactly one requested feature")
    return found


def archive_cron(archive: Path, domain: str) -> bytes:
    """Read exactly one regular Unix feature member, without extracting archive paths."""
    return archive_members(archive, domain, ("unix",))["unix"]


def credential_fields(content: bytes, *, domain: str = "", owner: str = "") -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in content.decode("utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in fields:
            raise ValueError("The backup metadata contains duplicate fields")
        fields[key] = value
    if (domain and fields.get("dom") != domain) or (owner and fields.get("user") != owner):
        raise ValueError("The backup metadata belongs to another domain or owner")
    return fields


def native_credentials(content: bytes, *, domain: str, owner: str) -> dict[str, str]:
    """Preserve only the native owner credential fields; never return or log unrelated metadata."""
    fields = credential_fields(content, domain=domain, owner=owner)
    saved = {key: fields.get(key, "") for key in ("pass", "mysql_pass", "mysql_enc_pass", "disabled_oldmysql")}
    if any(len(value.encode()) > NATIVE_CREDENTIAL_LIMIT for value in saved.values()):
        raise ValueError("An archived native credential exceeds the bounded format")
    return saved


def credential_hash(content: bytes, *, domain: str = "", owner: str = "") -> str:
    fields = credential_fields(content, domain=domain, owner=owner)
    if "backup_encpass" in fields:
        chosen = fields["backup_encpass"]
    elif fields.get("disabled") and "disabled_oldpass" in fields:
        chosen = fields["disabled_oldpass"]
    else:
        chosen = fields.get("enc_pass", "")
    if not chosen or len(chosen) > HASH_LIMIT or HASH_PATTERN.fullmatch(chosen) is None:
        raise ValueError("The backup has no usable Unix password hash")
    return chosen


def archive_credentials(archive: Path, domain: str) -> str:
    return credential_hash(archive_members(archive, domain, ("virtualmin",))["virtualmin"])


def suspended_cron(content: bytes) -> bytes:
    """Use Virtualmin's reversible job marker, preserving comments and environment assignments."""
    result: list[bytes] = []
    for line in content.splitlines(keepends=True):
        stripped = line.lstrip()
        if not stripped.strip() or stripped.startswith(b"#") or re.match(rb"[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
            result.append(line)
        else:
            ending = b"\n" if line.endswith(b"\n") else b""
            job = line.rstrip(b"\r\n")
            marker = b"" if re.search(rb"#\s+VIRTUALMIN\s+DISABLE", job) else b" # VIRTUALMIN DISABLE"
            result.append(b"# " + job + marker + ending)
    return b"".join(result)


def checked(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("The recovery artifact is not a private root-owned regular file")


def write(path: Path, content: bytes, *, replace: bool = False) -> None:
    if path.exists() or path.is_symlink():
        checked(path)
        if not replace and path.read_bytes() != content:
            raise ValueError("Recovery identity was reused with different inputs")
        if not replace:
            return
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run(arguments: list[str], *, content: bytes | None = None) -> bytes:
    if arguments[0] not in {"virtualmin", "crontab", "perl"}:
        raise ValueError("Unsupported recovery command")
    return subprocess.run(  # noqa: S603  # Fixed programs and validated separate arguments; no shell
        arguments, input=content, capture_output=True, check=True, timeout=120
    ).stdout


def stage_cron(archive: Path, checksum: str, cron: Path, metadata: Path, identity: dict[str, str]) -> None:
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("The recovery archive is not a regular file")
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if digest != checksum:
        raise ValueError("The recovery archive checksum changed")
    members = archive_members(archive, identity["domain"], ("unix", "virtualmin"))
    content = members["unix"]
    password = credential_hash(members["virtualmin"], domain=identity["domain"], owner=identity["owner"])
    credentials = native_credentials(members["virtualmin"], domain=identity["domain"], owner=identity["owner"])
    owner_shadow = owner_shadow_fields(
        members["virtualmin"], domain=identity["domain"], owner=identity["owner"], archive_name=archive.name
    )
    write(cron, content)
    write(
        metadata,
        json.dumps(
            {
                **identity,
                "sha256": hashlib.sha256(content).hexdigest(),
                "credential_hash": password,
                "native_credentials": credentials,
                "owner_shadow": owner_shadow,
            }
        ).encode(),
    )


def apply_activation(payload: dict[str, Any], cron: Path) -> None:
    """Restore the archived hash through native Webmin callbacks, then the intended cron state."""
    checked(cron)
    content = cron.read_bytes()
    if payload.get("sha256") != hashlib.sha256(content).hexdigest():
        raise ValueError("The staged cron changed")
    checked(CREDENTIAL_HELPER)
    run(["perl", str(CREDENTIAL_HELPER)], content=json.dumps(payload).encode())
    if payload["enabled"] is not True:
        content = suspended_cron(content)
    run(["crontab", "-u", payload["owner"], "-"], content=content)
    if run(["crontab", "-u", payload["owner"], "-l"]) != content:
        raise ValueError("The restored cron could not be verified")


def activate_once(marker: Path, payload: dict[str, Any], cron: Path) -> None:
    """A durable intent precedes activation; completed replays never rewrite exposed credentials or jobs."""
    immutable = {key: value for key, value in payload.items() if key != "enabled"}
    digest = hashlib.sha256(json.dumps(immutable, sort_keys=True).encode()).hexdigest()
    intent = {"state": "applying", "payload_sha256": digest}
    if marker.exists() or marker.is_symlink():
        checked(marker)
        previous = json.loads(marker.read_text())
        compatible = {digest}
        # Historical completed markers included policy; either boolean still
        # has to match every immutable staged field exactly.
        for enabled in (False, True):
            compatible.add(
                hashlib.sha256(json.dumps({**immutable, "enabled": enabled}, sort_keys=True).encode()).hexdigest()
            )
        if previous.get("payload_sha256") in compatible and previous.get("state") == "completed":
            return
        if previous.get("payload_sha256") in compatible and previous.get("state") == "applying":
            raise ValueError("Recovery activation was interrupted; verify the node before retrying")
        raise ValueError("Recovery activation identity changed")
    write(marker, json.dumps(intent).encode())
    apply_activation(payload, cron)
    write(marker, json.dumps({**intent, "state": "completed"}).encode(), replace=True)


def activate_staged(cron: Path, metadata: Path, marker: Path, identity: dict[str, str], enabled: str) -> None:
    checked(metadata)
    payload = json.loads(metadata.read_text())
    if any(payload.get(key) != value for key, value in identity.items()):
        raise ValueError("Recovery activation belongs to another domain")
    if enabled not in {"0", "1"}:
        raise ValueError("Invalid recovery enabled state")
    payload["enabled"] = enabled == "1"
    activate_once(marker, payload, cron)


def reconcile_policy(directory: Path, operation: str, identity: dict[str, str], enabled: bool) -> dict[str, Any]:
    """Converge current policy only after activation; never replay staged credentials or jobs."""
    marker = directory / f"{operation}.activation"
    if not marker.exists():
        raise ValueError("Current policy requires completed target activation")
    checked(marker)
    if json.loads(marker.read_text()).get("state") != "completed":
        raise ValueError("Current policy requires completed target activation")
    metadata = directory / f"{operation}.json"
    binding = metadata if metadata.exists() else directory / f"{operation}.cleaned"
    checked(binding)
    surface = json.loads(binding.read_text())
    if any(surface.get(key) != value for key, value in identity.items()):
        raise ValueError("Current policy target identity changed")
    checked(CREDENTIAL_HELPER)
    output = run(
        ["perl", str(CREDENTIAL_HELPER)],
        content=json.dumps(
            {
                **identity,
                "action": "reconcile-policy",
                "enabled": enabled,
                "operation_id": operation,
                "activation_scope": "recovery",
            }
        ).encode(),
    )
    matches = re.findall(rb"PRAHO_POLICY_RESULT=([A-Za-z0-9+/=]+)", output)
    if len(matches) != 1:
        raise ValueError("Current policy proof is missing")
    proof = json.loads(base64.b64decode(matches[0], validate=True))
    if (
        not isinstance(proof, dict)
        or type(proof.get("enabled")) is not bool
        or proof != {"domain_id": identity["domain_id"], "owner": identity["owner"], "enabled": enabled}
    ):
        raise ValueError("Current policy proof does not match the requested state")
    return proof


def verify_held(identity: dict[str, str]) -> None:
    """Native domain metadata and Unix shadow must both remain disabled before ownership commits."""
    checked(CREDENTIAL_HELPER)
    run(["perl", str(CREDENTIAL_HELPER)], content=json.dumps({**identity, "action": "verify-held"}).encode())
    try:
        cron = run(["crontab", "-u", identity["owner"], "-l"])
    except subprocess.CalledProcessError as error:
        if error.returncode != 1 or error.stdout or b"no crontab for" not in (error.stderr or b"").lower():
            raise
        cron = b""
    for line in cron.splitlines():
        stripped = line.lstrip()
        if stripped and not stripped.startswith(b"#") and re.match(rb"[A-Za-z_][A-Za-z0-9_]*\s*=", stripped) is None:
            raise ValueError("The held target has an active cron job")


def require_open_identity(directory: Path, identity: str, surface: dict[str, str]) -> None:
    tombstone = directory / f"{identity}.cleaned"
    if tombstone.exists() or tombstone.is_symlink():
        checked(tombstone)
        if json.loads(tombstone.read_text()) != surface:
            raise ValueError("The cleaned target belongs to another identity")
        raise ValueError("The held target has already been cleaned; late activation is refused")


def cleanup_staged(directory: Path, staging: Path, identity: str, surface: dict[str, str]) -> None:
    """Forget secrets only after a terminal controller decision; retain small replay-blocking evidence."""
    metadata = directory / f"{identity}.json"
    if metadata.exists() or metadata.is_symlink():
        checked(metadata)
        payload = json.loads(metadata.read_text())
        if any(payload.get(key) != value for key, value in surface.items()):
            raise ValueError("The staged target belongs to another identity")
    # Persist this before deleting secrets, including when an activation never completed.
    write(directory / f"{identity}.cleaned", json.dumps(surface, sort_keys=True).encode())
    paths = [directory / f"{identity}.cron", metadata]
    paths.extend(staging / f"recovery-ssl-{identity}-{label}.tar.gz" for label in ("base", "differential"))
    for path in paths:
        if path.exists() or path.is_symlink():
            checked(path)
            path.unlink()


def validate_request(surface: dict[str, str], identity: str, action: str, name: str, checksum: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", surface["domain"]):
        raise ValueError("Invalid domain")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_-]{0,31}", surface["owner"]) or not re.fullmatch(
        r"[0-9]{1,30}", surface["domain_id"]
    ):
        raise ValueError("Invalid owner or node domain identity")
    if action not in {"capture-owner", "stage", "activate", "verify-held", "cleanup", "reconcile_policy"}:
        raise ValueError("Invalid recovery action")
    if action not in {"cleanup", "reconcile_policy"} and (
        not (re.fullmatch(r"virtualmin_backup_[0-9a-f]{32}\.tar\.gz", name) or name == f"migration_{identity}.tar.gz")
        or (action != "capture-owner" and not re.fullmatch(r"[0-9a-f]{64}", checksum))
    ):
        raise ValueError("Invalid archive identity")


def main() -> None:  # noqa: PLR0915  # Explicit allowlisted node-operation dispatch under its domain lock.
    if os.geteuid() != 0:
        raise ValueError("Recovery requires root")
    identity = str(UUID(os.environ["PRAHO_RECOVERY_ID"]))
    domain = os.environ["PRAHO_DOMAIN"]
    owner = os.environ["PRAHO_USERNAME"]
    domain_id = os.environ["PRAHO_DOMAIN_ID"]
    surface = {"domain": domain, "owner": owner, "domain_id": domain_id}
    action = os.environ["PRAHO_RECOVERY_ACTION"]
    name = os.environ["PRAHO_ARCHIVE"]
    checksum = os.environ["PRAHO_SHA256"]
    validate_request(surface, identity, action, name, checksum)
    directory = Path("/var/lib/praho/recovery")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("The recovery directory is not private")
    lock = Path(f"/run/praho/chain-{domain_id}.lock")
    lock.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with lock.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB if action == "reconcile_policy" else fcntl.LOCK_EX)
        if action == "capture-owner":
            checked(CREDENTIAL_HELPER)
            run(
                ["perl", str(CREDENTIAL_HELPER)],
                content=json.dumps(
                    {
                        **surface,
                        "action": action,
                        "archive": name,
                        "require_fenced": os.environ.get("PRAHO_REQUIRE_FENCED") == "1",
                    }
                ).encode(),
            )
            print("PRAHO_RECOVERY_OK")
            return
        if action == "reconcile_policy":
            raw_enabled = os.environ["PRAHO_ENABLED"]
            if raw_enabled not in {"0", "1"}:
                raise ValueError("Invalid current policy")
            proof = reconcile_policy(directory, identity, surface, raw_enabled == "1")
            print("PRAHO_POLICY_RESULT=" + base64.b64encode(json.dumps(proof).encode()).decode())
            print("PRAHO_RECOVERY_OK")
            return
        if action == "cleanup":
            # The target may have been conclusively deleted during abandonment. Cleanup only
            # touches this UUID's root-private files, after checking any staged owner metadata.
            cleanup_staged(directory, Path("/var/lib/praho-transfer"), identity, surface)
            print("PRAHO_RECOVERY_OK")
            return
        require_open_identity(directory, identity, surface)
        if run(["virtualmin", "list-domains", "--domain", domain, "--user-only"]).decode().strip() != owner:
            raise ValueError("The target domain owner changed")
        if run(["virtualmin", "list-domains", "--domain", domain, "--id-only"]).decode().strip() != domain_id:
            raise ValueError("The target node identity changed")
        cron = directory / f"{identity}.cron"
        metadata = directory / f"{identity}.json"
        if action == "stage":
            disabled = run(["virtualmin", "list-domains", "--disabled", "--name-only"]).decode().splitlines()
            if domain not in disabled:
                raise ValueError("The recovery target is not disabled")
            verify_held(surface)
            stage_cron(Path("/var/lib/praho-transfer") / name, checksum, cron, metadata, surface)
        elif action == "verify-held":
            verify_held(surface)
        else:
            activate_staged(cron, metadata, directory / f"{identity}.activation", surface, os.environ["PRAHO_ENABLED"])
    print("PRAHO_RECOVERY_OK")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        if b"(owner_shadow_reserved_flag;" in (error.stderr or b""):
            print("PRAHO_OWNER_SHADOW_RESERVED_FLAG", flush=True)
        elif b"(owner_shadow_credential_binding;" in (error.stderr or b""):
            print("PRAHO_OWNER_SHADOW_CREDENTIAL_CHANGED", flush=True)
        raise
    except ValueError as error:
        if str(error).startswith("Archive owner shadow aging is unknown"):
            print("PRAHO_OWNER_SHADOW_UNKNOWN", flush=True)
        elif str(error).startswith("Archive owner shadow credential changed"):
            print("PRAHO_OWNER_SHADOW_CREDENTIAL_CHANGED", flush=True)
        raise
