"""The drift build: which Virtualmin it installs, that it is built fresh, and that it never becomes the lab's default.

`make test-virtualmin-drift` builds the lab image from the repository's latest packages and runs the contract
suite against it. Three things must hold, and none needs Docker here: `lab.sh` runs against a stub `docker` that
records its arguments, and the package selection runs the very awk program the Dockerfile contains.

1. webmin-virtual-server is resolved to the highest `-gpl` version before apt runs. The repository also carries a
   licensed `-pro` build with a higher version that answers 401 without a licence, and a wildcard after `=` is
   not something apt promises to expand.
2. The drift build is built with `--no-cache`, so a rerun cannot reuse the previous run's packages.
3. The drift tag is passed through the environment of that run only: it is never written to `.state/lab.env`,
   which every later ordinary `make virtualmin-lab-up` reads.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO = Path(__file__).resolve().parents[2]
LAB_DIR = REPO / "deploy/virtualmin-lab"
DOCKERFILE = (LAB_DIR / "virtualmin/Dockerfile").read_text()
LAB_SH = (LAB_DIR / "lab.sh").read_text()
MAKEFILE = (REPO / "Makefile").read_text()

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


class StubDocker:
    """A `docker` on PATH that records every call, and a copy of lab.sh whose .state directory is its own."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = root / "docker.calls"
        self.lab_sh = root / "lab" / "lab.sh"
        self.lab_sh.parent.mkdir()
        shutil.copy(LAB_DIR / "lab.sh", self.lab_sh)
        (self.lab_sh.parent / "compose.yml").write_text("services: {}\n")
        stub = root / "bin" / "docker"
        stub.parent.mkdir()
        stub.write_text(f'#!/bin/sh\necho "$*" >> "{self.calls}"\nexit 0\n')
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)

    def run(self, command: str, **env: str) -> subprocess.CompletedProcess[str]:
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith(("VIRTUALMIN_LAB", "LAB_"))
        }
        environment["PATH"] = f"{self.root / 'bin'}{os.pathsep}{environment['PATH']}"
        environment.update(env)
        return subprocess.run(  # noqa: S603  # A copy of lab.sh against a stub docker.
            [shutil.which("bash") or "bash", str(self.lab_sh), command], capture_output=True, text=True, env=environment, timeout=60, check=True
        )

    def builds(self) -> list[str]:
        return [line for line in self.calls.read_text().splitlines() if line.startswith("build ")]

    def state_tag(self) -> str:
        lines = (self.lab_sh.parent / ".state/lab.env").read_text().splitlines()
        return next(line for line in lines if line.startswith("VIRTUALMIN_LAB_TAG=")).split("=", 1)[1]


@pytest.fixture
def lab(tmp_path: Path) -> StubDocker:
    return StubDocker(tmp_path)


class TestTheDriftTagIsNeverPersisted:
    def test_a_drift_run_that_creates_the_state_still_records_the_pinned_tag(self, lab: StubDocker) -> None:
        lab.run("status", VIRTUALMIN_LAB_TAG="latest", VIRTUALMIN_LAB_UNPINNED="1")

        assert lab.state_tag() == "8.3.0"

    def test_an_ordinary_run_records_the_pinned_tag(self, lab: StubDocker) -> None:
        lab.run("status")

        assert lab.state_tag() == "8.3.0"

    def test_existing_state_is_left_alone(self, lab: StubDocker) -> None:
        lab.run("status")
        before = (lab.lab_sh.parent / ".state/lab.env").read_text()

        lab.run("status", VIRTUALMIN_LAB_TAG="latest", VIRTUALMIN_LAB_UNPINNED="1")

        assert (lab.lab_sh.parent / ".state/lab.env").read_text() == before


class TestTheDriftImageIsBuiltFresh:
    def test_the_image_build_can_bypass_the_cache(self, lab: StubDocker) -> None:
        lab.run("build", VIRTUALMIN_LAB_TAG="latest", VIRTUALMIN_LAB_UNPINNED="1", VIRTUALMIN_LAB_NO_CACHE="1")

        virtualmin_build, node_build = lab.builds()
        assert "--no-cache" in virtualmin_build.split()
        assert "-t praho-virtualmin-lab:latest" in virtualmin_build
        assert "--no-cache" not in node_build.split()

    def test_an_ordinary_build_keeps_the_cache(self, lab: StubDocker) -> None:
        lab.run("build")

        assert all("--no-cache" not in build.split() for build in lab.builds())

    def test_the_unpinned_build_hands_the_dockerfile_empty_versions_not_a_glob(self, lab: StubDocker) -> None:
        lab.run("build", VIRTUALMIN_LAB_TAG="latest", VIRTUALMIN_LAB_UNPINNED="1")

        arguments = lab.builds()[0].split()
        for name in (
            "WEBMIN_VERSION",
            "VIRTUAL_SERVER_VERSION",
            "VIRTUALMIN_CORE_VERSION",
            "VIRTUALMIN_CONFIG_VERSION",
            "VIRTUALMIN_STACK_VERSION",
        ):
            assert f"{name}=" in arguments, name
        assert "*" not in lab.builds()[0]

    def test_the_drift_target_builds_fresh_before_it_starts_the_lab(self) -> None:
        match = re.search(r"^test-virtualmin-drift:(?P<body>.*?)(?=^\S)", MAKEFILE, re.MULTILINE | re.DOTALL)
        assert match
        body = match.group("body")

        build = re.search(r"VIRTUALMIN_LAB_NO_CACHE=1\s+\$\(VIRTUALMIN_LAB_SH\)\s+build", body)
        assert build, "the drift target must force a cache-busting build"
        assert build.start() < body.index("virtualmin-lab-up")
