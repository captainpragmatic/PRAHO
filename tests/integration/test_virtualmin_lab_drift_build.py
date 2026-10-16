"""The drift build installs the GPL Virtualmin, resolved before apt runs.

`make test-virtualmin-drift` builds the lab image from the repository's latest packages. The repository carries a
GPL and a licensed `-pro` build of webmin-virtual-server under one name, and the `-pro` one has the higher version
but answers 401 without a licence. The Dockerfile therefore resolves the highest `-gpl` version itself, with
`apt-cache madison`, instead of handing apt a wildcard after `=`. No Docker is needed here: the test runs the very
awk program the Dockerfile contains.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
LAB_DIR = REPO / "deploy/virtualmin-lab"
DOCKERFILE = (LAB_DIR / "virtualmin/Dockerfile").read_text()
LAB_SH = (LAB_DIR / "lab.sh").read_text()

MADISON_HEADER = "webmin-virtual-server | {version} | https://download.virtualmin.com virtualmin/main {arch} Packages"


def madison(*versions: str) -> str:
    """`apt-cache madison` output: highest version first, one row per architecture."""
    return "\n".join(MADISON_HEADER.format(version=v, arch=arch) for v in versions for arch in ("arm64", "all")) + "\n"


def gpl_selector() -> tuple[str, str]:
    """The field separator and program of the awk call that picks the GPL version in the Dockerfile."""
    match = re.search(r"awk (-F'[^']*') '([^']*-gpl[^']*)'", DOCKERFILE)
    assert match, "the Dockerfile no longer selects the highest -gpl version of webmin-virtual-server"
    return match.group(1)[2:].strip("'"), match.group(2)


def select_gpl(rows: str) -> str:
    separator, program = gpl_selector()
    done = subprocess.run(  # noqa: S603  # The awk program of the Dockerfile, run on sample text.
        [shutil.which("awk") or "awk", f"-F{separator}", program], input=rows, capture_output=True, text=True, check=True, timeout=30
    )
    return done.stdout.strip()


class TestGplVersionIsResolvedBeforeApt:
    @pytest.mark.parametrize(
        ("versions", "expected"),
        [
            (("8.3.0-1-pro", "8.3.0-1-gpl"), "8.3.0-1-gpl"),
            (("8.4.0-1-pro", "8.4.0-1-gpl", "8.3.0-1-pro", "8.3.0-1-gpl"), "8.4.0-1-gpl"),
            (("8.4.0-1-pro", "8.3.0-1-gpl"), "8.3.0-1-gpl"),
            (("8.4.0-1-pro",), ""),
        ],
    )
    def test_the_highest_gpl_version_is_chosen_whatever_the_pro_build_does(
        self, versions: tuple[str, ...], expected: str
    ) -> None:
        assert select_gpl(madison(*versions)) == expected

    def test_the_build_stops_when_there_is_no_gpl_build(self) -> None:
        assert re.search(r'\[ -n "\$\{virtual_server_version\}" \] \|\| \{ echo "[^"]*-gpl[^"]*" >&2; exit 1; \}', DOCKERFILE)

    def test_apt_is_given_the_resolved_version_not_a_wildcard(self) -> None:
        assert '"webmin-virtual-server=${virtual_server_version}"' in DOCKERFILE
        assert "VIRTUAL_SERVER_VERSION=*" not in LAB_SH
        assert "*-gpl" not in LAB_SH
