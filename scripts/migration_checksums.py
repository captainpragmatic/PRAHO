"""Append-only checksums of repository migrations, not proof of production application."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

MANIFEST_PATH = "scripts/migration_checksums.json"
ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"[a-f0-9]{64}")


class ManifestError(ValueError):
    """The current files or proposed baseline violate the frozen migration contract."""


def migration_path(path: str) -> bool:
    parts = Path(path).parts
    return (
        len(parts) == 6
        and parts[0] == "services"
        and parts[1] in {"platform", "portal"}
        and parts[2] == "apps"
        and parts[4] == "migrations"
        and parts[5].endswith(".py")
        and parts[5] != "__init__.py"
        and ".." not in parts
    )


def file_hashes(root: Path) -> dict[str, str]:
    files = {}
    for path in sorted(root.glob("services/*/apps/*/migrations/*.py")):
        relative = path.relative_to(root).as_posix()
        if not migration_path(relative):
            continue
        if path.is_symlink():
            raise ManifestError(f"Migration must not be a symlink: {relative}")
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def _entries(manifest: dict[str, Any]) -> dict[str, str]:
    files = manifest.get("files")
    if manifest.get("version") != 1 or not isinstance(manifest.get("baseline_commit"), str):
        raise ManifestError("Invalid migration baseline metadata")
    if not isinstance(files, dict) or any(
        not isinstance(path, str)
        or not migration_path(path)
        or not isinstance(digest, str)
        or not SHA256.fullmatch(digest)
        for path, digest in files.items()
    ):
        raise ManifestError("Invalid migration baseline entries")
    return files


def verify_manifest(
    root: Path,
    manifest: dict[str, Any],
    *,
    previous: dict[str, Any] | None = None,
    allow_new: bool = False,
) -> None:
    frozen = _entries(manifest)
    if previous is not None:
        original = _entries(previous)
        if manifest["baseline_commit"] != previous["baseline_commit"] or any(
            frozen.get(path) != digest for path, digest in original.items()
        ):
            raise ManifestError("Frozen migration baseline entries cannot be replaced or removed")
    current = file_hashes(root)
    for path, digest in frozen.items():
        if path not in current:
            raise ManifestError(f"Frozen migration missing: {path}")
        if current[path] != digest:
            raise ManifestError(f"Frozen migration changed: {path}")
    if not allow_new and (new := sorted(current.keys() - frozen.keys())):
        raise ManifestError(f"Migration unlisted; use --extend after review: {new[0]}")


def extend_manifest(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    verify_manifest(root, manifest, allow_new=True)
    additions = {path: digest for path, digest in file_hashes(root).items() if path not in manifest["files"]}
    return {**manifest, "files": {**manifest["files"], **additions}}


def _git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.PIPE)


def repository_baseline(base_ref: str) -> dict[str, Any]:
    commit = _git("rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}").decode().strip()
    probe = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}:{MANIFEST_PATH}"], cwd=ROOT, capture_output=True, check=False
    )
    if probe.returncode == 0:
        return json.loads(_git("show", f"{commit}:{MANIFEST_PATH}"))
    paths = _git("ls-tree", "-r", "--name-only", commit, "--", "services").decode().splitlines()
    files = {
        path: hashlib.sha256(_git("show", f"{commit}:{path}")).hexdigest() for path in paths if migration_path(path)
    }
    if not files:
        raise ManifestError("The comparison revision contains no repository migrations")
    return {"version": 1, "baseline_commit": commit, "files": files}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", default="origin/master", help="Trusted comparison revision supplied by CI")
    parser.add_argument(
        "--extend", action="store_true", help="Add new migration hashes without changing frozen entries"
    )
    args = parser.parse_args()
    try:
        previous = repository_baseline(args.base_ref)
        path = ROOT / MANIFEST_PATH
        if not path.exists() and not args.extend:
            raise ManifestError("Migration baseline manifest missing; initialize with --extend")
        manifest = json.loads(path.read_text()) if path.exists() else previous
        verify_manifest(ROOT, manifest, previous=previous, allow_new=args.extend)
        if args.extend:
            manifest = extend_manifest(ROOT, manifest)
            path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        print(f"Verified {len(manifest['files'])} repository migration checksums (production application unverified)")
    except (subprocess.CalledProcessError, ValueError, OSError) as exc:
        print(f"Migration checksum check failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
