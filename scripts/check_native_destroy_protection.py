"""Prove missed staging topology fails against existing, entirely mocked server state."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    command = ["terraform", "-chdir=deploy/terraform"]
    initialized = subprocess.run(
        [*command, "init", "-backend=false", "-input=false", "-test-directory=tests/negative_adoption"], check=False
    )
    if initialized.returncode:
        return initialized.returncode
    result = subprocess.run(
        [*command, "test", "-no-color", "-test-directory=tests/negative_adoption"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    expected = (
        'run "existing_split_staging"... pass',
        'run "missed_staging_topology_must_fail"... fail',
        "Resource hcloud_server.portal[0] has lifecycle.prevent_destroy set",
    )
    if result.returncode != 0 and all(item in output for item in expected) and output.count("Error:") == 1:
        print("Existing split staging: omitted topology correctly refuses Portal destruction")
        return 0
    print(output, file=sys.stderr)
    print("The negative adoption gate did not prove the required lifecycle refusal", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
