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


def validate(dump: Path, database_major: int, *, portal: bool) -> dict[str, str]:
    """Bind the exact pair to source image IDs and the running database major, never an mtime."""
    data: object = json.loads(manifest_path(dump).read_text())
    if not isinstance(data, dict) or data.get("format_version") != 1 or data.get("database_major") != database_major:
        raise ValueError("unsupported metadata or database major mismatch")
    media = dump.with_name(dump.name.removesuffix(".sql.gz") + ".media.tar.gz")
    for key, path in (("database", dump), ("media", media)):
        artifact = data.get(key)
        if (
            not isinstance(artifact, dict)
            or artifact.get("file") != path.name
            or artifact.get("sha256") != checksum(path)
        ):
            raise ValueError("backup pair filename or checksum mismatch")
    images = data.get("images")
    if not isinstance(images, dict):
        raise ValueError("source application image metadata is missing")
    expected: dict[str, str] = {}
    for role in ("platform", "portal") if portal else ("platform",):
        image = images.get(role)
        if not isinstance(image, dict) or not isinstance(image.get("id"), str) or not IMAGE_ID.fullmatch(image["id"]):
            raise ValueError("source application image ID is missing or invalid")
        expected[role] = image["id"]
    if "qcluster" in images:
        worker = images["qcluster"]
        if not isinstance(worker, dict) or worker.get("id") != expected["platform"]:
            raise ValueError("source worker and Platform images differ; operator review required")
    return expected


def compose_images(*, portal: bool) -> dict[str, str]:
    """Read Compose JSON in-process and emit image references only, never its environment values."""
    data: object = json.load(sys.stdin)
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict):
        raise ValueError("Compose service configuration is missing")
    references: dict[str, str] = {}
    for role in ("platform", "portal", "qcluster") if portal else ("platform", "qcluster"):
        service = services.get(role)
        reference = service.get("image") if isinstance(service, dict) else None
        if not isinstance(reference, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", reference):
            raise ValueError("target application image reference is missing or invalid")
        references[role] = reference
    if references.pop("qcluster") != references["platform"]:
        raise ValueError("target worker and Platform image references differ")
    return references


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    producer = commands.add_parser("create")
    producer.add_argument("dump", type=Path)
    consumer = commands.add_parser("validate")
    consumer.add_argument("dump", type=Path)
    consumer.add_argument("--database-major", type=int, required=True)
    consumer.add_argument("--portal", action="store_true")
    images = commands.add_parser("images")
    images.add_argument("--portal", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "create":
            create(args.dump)
        else:
            result = (
                validate(args.dump, args.database_major, portal=args.portal)
                if args.action == "validate"
                else compose_images(portal=args.portal)
            )
            for role, value in result.items():
                print(f"{role}={value}")
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Backup metadata failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
