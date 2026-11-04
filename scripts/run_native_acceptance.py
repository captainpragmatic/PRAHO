"""The explicit native gate fails on unavailable prerequisites, skips, or empty collection."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="praho-native-results-") as temporary:
        report = Path(temporary) / "results.xml"
        retained = Path(tempfile.mkdtemp(prefix="praho-native-acceptance-"))
        print(f"Native acceptance diagnostics: {retained}", flush=True)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-o",
                "addopts=",
                "-v",
                "-x",
                "-m",
                "docker",
                "tests/deploy/test_native_acceptance.py",
                f"--junitxml={report}",
                f"--basetemp={retained}",
            ],
            env=dict(os.environ),
            check=False,
        )
        if result.returncode:
            return result.returncode
        if not report.exists():
            print("Native acceptance did not produce its required result", file=sys.stderr)
            return 1
        cases = ET.parse(report).getroot().findall(".//testcase")  # noqa: S314 -- local pytest-generated XML
        if not cases or any(case.find(tag) is not None for case in cases for tag in ("skipped", "failure", "error")):
            print("Native acceptance requires executed tests without skips, failures or errors", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
