"""Record the exact Docker application images, database major and hashes of a backup pair."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")


def docker(*arguments: str) -> str:
    return subprocess.check_output(["docker", *arguments], text=True).strip()


def checksum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def manifest_path(dump: Path) -> Path:
    return dump.with_name(dump.name.removesuffix(".sql.gz") + ".metadata.json")


def create(dump: Path) -> Path:
    """Write only after both artifacts exist; a legacy restore can still use the original pair."""
    if not dump.name.endswith(".sql.gz"):
        raise ValueError("expected a plain SQL gzip backup")
    media = dump.with_name(dump.name.removesuffix(".sql.gz") + ".media.tar.gz")
    if not dump.is_file() or not media.is_file() or not dump.stat().st_size or not media.stat().st_size:
        raise ValueError("both nonempty database and media artifacts are required")
    names = docker("ps", "-a", "--format", "{{.Names}}").splitlines()
    if not {"praho_platform", "praho_db"} <= set(names):
        raise ValueError("local Platform and bundled database containers are required")
    images: dict[str, dict[str, str]] = {}
    for role in ("platform", "portal", "qcluster"):
        name = f"praho_{role}"
        if name not in names:
            continue
        image_id = docker("inspect", "--format", "{{.Image}}", name)
        reference = docker("inspect", "--format", "{{.Config.Image}}", name)
        if not IMAGE_ID.fullmatch(image_id) or not reference or any(char.isspace() for char in reference):
            raise ValueError("cannot determine an immutable source application image")
        images[role] = {"id": image_id, "reference": reference}
    server_version = docker("exec", "praho_db", "psql", "-U", "praho", "-d", "praho", "-Atc", "SHOW server_version_num")
    if not server_version.isdigit() or int(server_version) < 100000:
        raise ValueError("cannot determine the database major version")
    data = {
        "format_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017 -- operator hosts may use Python 3.9.
        "database_major": int(server_version) // 10000,
        "images": images,
        "database": {"file": dump.name, "sha256": checksum(dump)},
        "media": {"file": media.name, "sha256": checksum(media)},
    }
    destination = manifest_path(dump)
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=dump.parent, prefix=destination.name, suffix=".partial", delete=False
        ) as output:
            temporary = output.name
            json.dump(data, output, indent=2)
            output.write("\n")
        os.replace(temporary, destination)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create",))
    parser.add_argument("dump", type=Path)
    args = parser.parse_args()
    try:
        create(args.dump)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Backup metadata failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
