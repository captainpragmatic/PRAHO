"""Check a saved native adoption plan without applying it or printing its sensitive values."""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from native_env import validate_adoption_plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--existing-topology", required=True, choices=("split", "combined"))
    args = parser.parse_args()
    try:
        result = subprocess.run(
            [shutil.which("terraform") or "terraform", "show", "-json", str(args.plan.resolve())],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise ValueError("Cannot decode the saved Terraform plan")
        validate_adoption_plan(json.loads(result.stdout), args.existing_topology)
    except (OSError, ValueError) as error:
        print(
            str(error)
            if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError)
            else "Saved adoption plan could not be validated",
            file=sys.stderr,
        )
        return 1
    print("Saved adoption plan retains the recorded servers and RDNS; no deletions or replacements")
    return 0


if __name__ == "__main__":
    sys.exit(main())
