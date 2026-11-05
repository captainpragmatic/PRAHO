"""Distinguish a partial checkout from application data requiring recovery protection."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from native_env import read_env


def query_database(database: str, sql: str) -> str:
    result = subprocess.run(
        [
            shutil.which("runuser") or "/usr/sbin/runuser",
            "-u",
            "postgres",
            "--",
            shutil.which("psql") or "/usr/bin/psql",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            f"--dbname={database}",
            "--command",
            sql,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode:
        raise ValueError("Existing PostgreSQL state could not be inspected; repair access before retrying")
    return result.stdout.strip()


def inspect_installation(  # noqa: PLR0913 -- Explicit data locations keep read-only state inspection testable.
    service: str, root: Path, state: Path, media: Path, database: str, postgres: Path = Path("/var/lib/postgresql")
) -> bool:
    env = root / (".env" if service == "platform" else ".portal.env")
    installed = read_env(env) if env.exists() else {}
    if service == "platform":
        if installed.get("DB_HOST", "localhost") not in {"", "localhost", "127.0.0.1", "::1"}:
            raise ValueError("Native recovery inspection requires the installed local Platform database")
        media = Path(installed.get("MEDIA_ROOT") or str(media))
        protected = media.exists() and any(media.iterdir())
        if postgres.exists():
            database = installed.get("DB_NAME") or database
            if not database or any(
                character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                for character in database
            ):
                raise ValueError("Native database name cannot be inspected safely")
            if database in query_database("postgres", "SELECT datname FROM pg_database").splitlines():
                present = query_database(
                    database,
                    "SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n "
                    "ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') "
                    "AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','m','S','v','f'))",
                )
                if present not in {"t", "f"}:
                    raise ValueError("Existing PostgreSQL state returned an invalid inspection result")
                protected = present == "t" or protected
        elif env.exists():
            raise ValueError("Installed Platform environment has no inspectable local PostgreSQL state")
        required = [env, root / "scripts/backup.sh"]
    else:
        session = Path(installed.get("SESSION_DB_PATH") or str(state / "portal.sqlite3"))
        protected = session.exists() or (state.exists() and any(state.iterdir()))
        required = [env]
    if protected and not all(path.exists() for path in [*required, root / "src/.git", root / ".venv-linux/bin/python"]):
        raise ValueError(
            "Application data exists but installed recovery prerequisites are incomplete; repair them before deployment"
        )
    return protected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", required=True, choices=("platform", "portal"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--state", type=Path, default=Path("/var/lib/praho-portal"))
    parser.add_argument("--media", type=Path, default=Path("/opt/praho/media"))
    parser.add_argument("--database", default="praho")
    args = parser.parse_args()
    try:
        protected = inspect_installation(args.service, args.root, args.state, args.media, args.database)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(
            str(error) if isinstance(error, ValueError) else "Application state could not be inspected", file=sys.stderr
        )
        return 1
    print(json.dumps({"protected": protected}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
