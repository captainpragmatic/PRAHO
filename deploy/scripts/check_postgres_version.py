"""Refuse implicit PostgreSQL major upgrades; read an existing data volume without starting it."""

from __future__ import annotations

import json
import re
import subprocess
import sys

READ_VERSION = 'if [ -f /database/PG_VERSION ]; then cat /database/PG_VERSION; elif [ -z "$(ls -A /database)" ]; then echo empty; else echo unknown; fi'


def docker(*arguments: str) -> str:
    return subprocess.check_output(["docker", *arguments], text=True).strip()


def check(configuration: object) -> None:
    if not isinstance(configuration, dict) or not isinstance(configuration.get("services"), dict):
        raise ValueError("invalid Compose configuration")
    database = configuration["services"].get("db")
    if database is None:
        return
    if not isinstance(database, dict):
        raise ValueError("invalid bundled database configuration")
    image = database.get("image")
    if not isinstance(image, str) or not re.fullmatch(r"postgres:16(?:-[A-Za-z0-9._-]+)?", image):
        raise ValueError("bundled database image must select PostgreSQL 16 explicitly")
    mounts = database.get("volumes")
    if not isinstance(mounts, list):
        raise ValueError("database data volume is missing")
    data = next(
        (mount for mount in mounts if isinstance(mount, dict) and mount.get("target") == "/var/lib/postgresql/data"),
        None,
    )
    if not isinstance(data, dict) or data.get("type") != "volume":
        raise ValueError("expected the bundled named database volume")
    source = data.get("source")
    if not isinstance(source, str):
        raise ValueError("database volume source is missing")
    volumes = configuration.get("volumes")
    volume = volumes.get(source) if isinstance(volumes, dict) else None
    name = volume.get("name") if isinstance(volume, dict) else None
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
        raise ValueError("cannot resolve the database volume name")
    if name not in docker("volume", "ls", "--format", "{{.Name}}").splitlines():
        return
    version = docker(
        "run",
        "--rm",
        "--read-only",
        "--network",
        "none",
        "--mount",
        f"type=volume,src={name},dst=/database,readonly",
        "--entrypoint",
        "sh",
        image,
        "-c",
        READ_VERSION,
    )
    if version not in {"16", "empty"}:
        # Never echo unknown data from the volume or secret-bearing Compose configuration.
        detail = f"major {version}" if re.fullmatch(r"[0-9]{1,3}", version) else "unrecognized data"
        raise ValueError(
            f"existing PostgreSQL {detail}; follow docs/deployment/POSTGRESQL_16_UPGRADE.md before deployment"
        )


def main() -> int:
    try:
        check(json.load(sys.stdin))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"PostgreSQL preflight failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
