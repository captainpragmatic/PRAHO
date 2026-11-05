"""Publish provenance only for a validated PostgreSQL 16 database/media pair."""

import sys
from pathlib import Path

from native_env import validate_backup_pair

if __name__ == "__main__":
    try:
        print(validate_backup_pair(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]))
    except (OSError, ValueError, IndexError):
        print("Native backup pair validation failed", file=sys.stderr)
        sys.exit(1)
