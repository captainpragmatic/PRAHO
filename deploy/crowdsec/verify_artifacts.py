#!/usr/bin/env python3
"""Authenticate the committed CrowdSec repository chain before host mutation."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import NoReturn, cast

PRIMARY = "6A89E3C2303A901A889971D3376ED5326E93CD0C"
MAX_METADATA = 256 * 1024
MAX_INDEX = 8 * 1024 * 1024
LEAF_COUNT = 14
PARSER_COMPONENTS = 4
SCENARIO_COMPONENTS = 3
CLI_ARGUMENTS = 2
PORTAL_FILES = frozenset(
    {
        "/etc/crowdsec/parsers/s01-parse/praho-portal-auth.yaml",
        "/etc/crowdsec/scenarios/praho-portal-auth-bf.yaml",
        "/etc/crowdsec/scenarios/praho-portal-auth-throttle.yaml",
    }
)


class ArtifactVerificationError(ValueError):
    """An unauthenticated or inconsistent input cannot authorize installation."""


def _fail(message: str = "Artifact verification failed") -> NoReturn:
    raise ArtifactVerificationError(message)


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail()
    return cast("dict[str, object]", value)


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        _fail()
    return value


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _relative(root: Path, value: object) -> Path:
    name = Path(_string(value))
    if name.is_absolute() or ".." in name.parts or "\\" in str(name):
        _fail()
    path = root / name
    if not path.resolve().is_relative_to(root):
        _fail()
    return path


def _bytes(path: Path, maximum: int = MAX_METADATA) -> bytes:
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    if not raw or len(raw) > maximum:
        _fail()
    return raw


def _checked(root: Path, name: object, digest: object) -> tuple[Path, bytes]:
    expected = _string(digest)
    if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        _fail()
    path = _relative(root, name)
    raw = _bytes(path)
    if hashlib.sha256(raw).hexdigest() != expected:
        _fail()
    return path, raw


def _run(argv: list[str]) -> str:
    result = subprocess.run(  # noqa: S603 -- resolved GPG executables, fixed flags and checked metadata paths
        argv,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
        env={"PATH": os.environ.get("PATH", os.defpath), "LANG": "C", "LC_ALL": "C"},
    )
    if result.returncode:
        _fail("Repository signature verification failed")
    if len(result.stdout.encode()) > MAX_METADATA:
        _fail()
    return result.stdout


def _signature(key: Path, release: Path, signing: str) -> None:
    gpg, gpgv = shutil.which("gpg"), shutil.which("gpgv")
    if gpg is None or gpgv is None:
        _fail("Artifact verification requires controller gpg and gpgv")
    with tempfile.TemporaryDirectory(prefix="praho-crowdsec-gpg-") as directory:
        home = Path(directory)
        common = [gpg, "--no-options", "--batch", "--no-autostart", "--homedir", str(home)]
        listing = _run([*common, "--with-colons", "--show-keys", str(key)])
        primary = []
        expect_primary = False
        for row in listing.splitlines():
            fields = row.split(":")
            if fields[0] in {"pub", "sub"}:
                expect_primary = fields[0] == "pub"
            elif fields[0] == "fpr" and expect_primary:
                primary.append(fields[9])
                expect_primary = False
        if primary != [PRIMARY]:
            _fail()
        keyring = home / "repository.gpg"
        _run([*common, "--dearmor", "--output", str(keyring), str(key)])
        status = _run([gpgv, "--homedir", str(home), "--keyring", str(keyring), "--status-fd", "1", str(release)])
        signatures = [row.split() for row in status.splitlines() if row.startswith("[GNUPG:] VALIDSIG ")]
        if len(signatures) != 1 or signatures[0][2] != signing or signatures[0][-1] != PRIMARY:
            _fail("Repository signature verification failed")


def _records(raw: bytes) -> list[dict[str, str]]:
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
        decoded = compressed.read(MAX_INDEX + 1)
    if len(decoded) > MAX_INDEX:
        _fail()
    return [
        dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" "))
        for paragraph in decoded.decode().split("\n\n")
    ]


def _verify_package(
    architecture: str,
    name: str,
    package: dict[str, object],
    rows: list[dict[str, str]],
    url: str,
) -> None:
    expected_version = "1.8.2" if name == "crowdsec" else "0.0.36"
    matches = [row for row in rows if row.get("Package") == name and row.get("Version") == expected_version]
    if len(matches) != 1:
        _fail()
    row = matches[0]
    if (
        row["Architecture"] != architecture
        or package["version"] != expected_version
        or package["sha256"] != row["SHA256"]
        or type(package["size"]) is not int
        or package["size"] != int(row["Size"])
        or package["url"] != url + row["Filename"]
    ):
        _fail()


def _verify_repository(root: Path, repository: dict[str, object], packages: dict[str, object]) -> int:
    if repository["primary_fingerprint"] != PRIMARY:
        _fail()
    key, _ = _checked(root, repository["key_file"], repository["key_sha256"])
    release, raw = _checked(root, repository["inrelease_file"], repository["inrelease_sha256"])
    _signature(key, release, _string(repository["signing_fingerprint"]))
    checksums = raw.decode().split("\nSHA256:\n", 1)[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)[0]
    indexes = _object(repository["indexes"])
    if set(indexes) != {"amd64", "arm64"} or set(packages) != set(indexes):
        _fail()
    package_count = 0
    for architecture, value in indexes.items():
        index = _object(value)
        _, compressed = _checked(root, index["file"], index["sha256"])
        if type(index["size"]) is not int or len(compressed) != index["size"]:
            _fail()
        if f" {index['sha256']} {index['size']} {index['path']}\n" not in checksums:
            _fail()
        rows = _records(compressed)
        selected = _object(packages[architecture])
        if set(selected) != {"crowdsec", "crowdsec-firewall-bouncer-nftables"}:
            _fail()
        for name, package_value in selected.items():
            _verify_package(architecture, name, _object(package_value), rows, _string(repository["url"]))
            package_count += 1
    return package_count


def _destination(path: str) -> str:
    parts = path.split("/")
    if any(re.fullmatch(r"[A-Za-z0-9_.-]+", part) is None or part in {".", ".."} for part in parts):
        _fail()
    if not parts[-1].endswith(".yaml"):
        _fail()
    if len(parts) == PARSER_COMPONENTS and parts[0] == "parsers" and parts[1] in {"s00-raw", "s01-parse", "s02-enrich"}:
        return f"/etc/crowdsec/parsers/{parts[1]}/{parts[3]}"
    if len(parts) == SCENARIO_COMPONENTS and parts[0] == "scenarios":
        return f"/etc/crowdsec/scenarios/{parts[2]}"
    _fail()


def _verify_hub(hub: dict[str, object]) -> int:
    leaves = hub["files"]
    if re.fullmatch(r"[0-9a-f]{40}", _string(hub["commit"])) is None:
        _fail()
    if not isinstance(leaves, list) or len(leaves) != LEAF_COUNT:
        _fail()
    destinations: set[str] = set()
    for value in leaves:
        leaf = _object(value)
        expected = _destination(_string(leaf["path"]))
        if leaf["installed_path"] != expected or expected in destinations:
            _fail()
        destinations.add(expected)
        if re.fullmatch(r"[0-9a-f]{64}", _string(leaf["sha256"])) is None:
            _fail()
        kinds = leaf["host_kinds"]
        if not isinstance(kinds, list) or not kinds or any(kind not in {"node", "portal"} for kind in kinds):
            _fail()
        if leaf["url"] != f"https://raw.githubusercontent.com/crowdsecurity/hub/{hub['commit']}/{leaf['path']}":
            _fail()
    return len(leaves)


def _verify_portal(root: Path, value: object) -> None:
    block = _object(value)
    files = block.get("files")
    if set(block) != {"files"} or not isinstance(files, list) or len(files) != len(PORTAL_FILES):
        _fail()
    seen: set[str] = set()
    for row in files:
        item = _object(row)
        path = _string(item.get("installed_path"))
        if set(item) != {"installed_path", "sha256"} or path not in PORTAL_FILES or path in seen:
            _fail()
        _checked(root, "portal/" + Path(path).name, item["sha256"])
        seen.add(path)


def _verify(lock_path: Path) -> dict[str, object]:
    root = lock_path.resolve().parent
    lock = _object(json.loads(_bytes(lock_path), object_pairs_hook=_pairs))
    if type(lock.get("schema")) is not int or lock["schema"] != 1:
        _fail()
    _verify_portal(root, lock["praho_portal"])
    package_count = _verify_repository(root, _object(lock["repository"]), _object(lock["packages"]))
    build = _object(lock["bouncer_build"])
    for field in ("patch", "recipe", "build_script"):
        component = _object(build[field])
        _checked(root, component["path"], component["sha256"])
    return {"verified": True, "package_count": package_count, "hub_leaf_count": _verify_hub(_object(lock["hub"]))}


def verify(lock_path: Path) -> dict[str, object]:
    try:
        return _verify(lock_path)
    except ArtifactVerificationError:
        raise
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        EOFError,
        RecursionError,
        subprocess.SubprocessError,
    ) as error:
        raise ArtifactVerificationError("Artifact verification failed") from error


def main() -> int:
    try:
        if len(sys.argv) != CLI_ARGUMENTS:
            _fail()
        print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))
        return 0
    except ArtifactVerificationError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
