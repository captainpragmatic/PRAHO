"""Refuse code rollback that loses applied business migrations; never reverse migrations."""

from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path

import django
from django.db.migrations.recorder import MigrationRecorder
from native_env import validate_rollback_migrations


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("--service", choices=("platform", "portal"), default="platform")
    parser.add_argument("--no-fetch", action="store_true")
    parser.add_argument("--repository", default="origin")
    args = parser.parse_args()
    django.setup()
    root = Path(os.environ.get("PRAHO_NATIVE_SOURCE_ROOT", str(Path(__file__).resolve().parents[2])))
    if not args.no_fetch:
        subprocess.run(["git", "-C", str(root), "fetch", "--no-tags", "--", args.repository, args.revision], check=True)
    result = subprocess.run(
        ["git", "-c", f"safe.directory={root}", "-C", str(root), "ls-tree", "-r", "--name-only", args.revision],
        capture_output=True,
        text=True,
        check=True,
    )
    apps = {path.name for path in (root / f"services/{args.service}/apps").iterdir() if path.is_dir()}
    applied = {
        (app, name) for app, name in MigrationRecorder.Migration.objects.values_list("app", "name") if app in apps
    }
    validate_rollback_migrations(applied, set(result.stdout.splitlines()), service=args.service)


if __name__ == "__main__":
    main()
