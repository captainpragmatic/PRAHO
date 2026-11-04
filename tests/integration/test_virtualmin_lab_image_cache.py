"""Published lab image caches must match the current Dockerfile and copied source inputs."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.integration
REPO = Path(__file__).resolve().parents[2]


class CachedLab:
    def __init__(self, root: Path) -> None:
        self.repository = root / "checkout"
        self.directory = self.repository / "deploy/virtualmin-lab"
        self.directory.mkdir(parents=True)
        shutil.copyfile(REPO / "deploy/virtualmin-lab/lab.sh", self.directory / "lab.sh")
        (self.directory / "compose.yml").write_text("services: {}\n")
        for name in (
            "common/rootfs/usr/local/sbin/lab-node-credentials",
            "common/rootfs/etc/ssh/sshd_config",
            "virtualmin/rootfs/usr/local/sbin/virtualmin-lab-firstboot",
            "virtualmin/Dockerfile",
        ):
            path = self.directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("original image input\n")
        guard = self.repository / "services/platform/infrastructure/ansible/playbooks/files/praho-home-symlinks.conf"
        guard.parent.mkdir(parents=True)
        guard.write_text("fixture runtime guard\n")
        self.calls = root / "docker.calls"
        self.bin = root / "bin"
        self.bin.mkdir()
        stub = self.bin / "docker"
        stub.write_text("""#!/bin/sh
printf '%s\\n' "$*" >> "$LAB_CACHE_CALLS"
if [ "$1 $2" = 'image inspect' ]; then
  [ "$LAB_CACHE_PRESENT" = 1 ] || exit 1
  printf '%s\\n' "$LAB_CACHE_REVISION"
elif [ "$1" = inspect ]; then
  printf 'healthy\\n'
fi
""")
        stub.chmod(0o700)
        self.git("init", "--quiet")
        self.git("config", "user.name", "PRAHO test fixture")
        self.git("config", "user.email", "fixture@example.test")
        self.commit()
        self.revision = self.git("rev-parse", "HEAD").stdout.strip()

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 -- isolated temporary Git repository, fixed fixture argv.
            [shutil.which("git") or "git", "-C", str(self.repository), *arguments],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )

    def commit(self) -> None:
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "fixture")

    def run(self, command: str = "up", *, revision: str | None = None, present: bool = True) -> None:
        environment = {
            key: value for key, value in os.environ.items() if not key.startswith(("LAB_", "VIRTUALMIN_LAB"))
        }
        environment.update(
            PATH=str(self.bin) + os.pathsep + environment["PATH"],
            LAB_CACHE_CALLS=str(self.calls),
            LAB_CACHE_REVISION=self.revision if revision is None else revision,
            LAB_CACHE_PRESENT=str(int(present)),
        )
        completed = subprocess.run(  # noqa: S603 -- actual copied driver; every Docker action is a local recorder.
            [shutil.which("bash") or "bash", str(self.directory / "lab.sh"), command],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr

    def builds(self) -> list[str]:
        return [line for line in self.calls.read_text().splitlines() if line.startswith("build ")]


@pytest.fixture
def cached_lab(tmp_path: Path) -> CachedLab:
    return CachedLab(tmp_path)


@pytest.mark.parametrize(
    "name",
    [
        "common/rootfs/usr/local/sbin/lab-node-credentials",
        "common/rootfs/etc/ssh/sshd_config",
        "virtualmin/rootfs/usr/local/sbin/virtualmin-lab-firstboot",
        "virtualmin/Dockerfile",
        ".dockerignore",
    ],
)
def test_published_cache_with_changed_image_inputs_is_rebuilt(cached_lab: CachedLab, name: str) -> None:
    (cached_lab.directory / name).write_text("updated image input\n")
    cached_lab.commit()
    cached_lab.run()
    assert len(cached_lab.builds()) == 2


def test_unrelated_new_billing_commit_keeps_matching_published_cache(cached_lab: CachedLab) -> None:
    (cached_lab.repository / "billing.py").write_text("unrelated billing change\n")
    cached_lab.commit()
    cached_lab.run()
    assert cached_lab.builds() == []


@pytest.mark.parametrize("revision", ["", "unknown", "0" * 40])
def test_unknown_or_unavailable_image_revision_forces_rebuild(cached_lab: CachedLab, revision: str) -> None:
    cached_lab.run(revision=revision)
    assert len(cached_lab.builds()) == 2


def test_working_tree_image_input_change_invalidates_current_revision_label(cached_lab: CachedLab) -> None:
    (cached_lab.directory / "common/rootfs/usr/local/sbin/lab-node-credentials").write_text("dirty credential writer\n")
    cached_lab.run()
    assert len(cached_lab.builds()) == 2


def test_untracked_even_git_ignored_copied_input_invalidates_cache(cached_lab: CachedLab) -> None:
    (cached_lab.repository / ".gitignore").write_text("*.local\n")
    extra = cached_lab.directory / "common/rootfs/new-credential-writer.local"
    extra.write_text("new Docker COPY input\n")
    cached_lab.run()
    assert len(cached_lab.builds()) == 2


def test_image_only_validation_rebuilds_without_recreating_running_nodes(cached_lab: CachedLab) -> None:
    (cached_lab.directory / "virtualmin/Dockerfile").write_text("new image input\n")
    cached_lab.run("ensure-image")
    assert len(cached_lab.builds()) == 2
    assert not any(line.startswith(("compose ", "exec ", "cp ")) for line in cached_lab.calls.read_text().splitlines())


def test_standalone_components_validate_base_before_building_source_image() -> None:
    makefile = (REPO / "Makefile").read_text()
    body = makefile.split("virtualmin-lab-component-source-up:", 1)[1].split("\n.PHONY:", 1)[0]
    assert body.index("$(VIRTUALMIN_LAB_SH) ensure-image") < body.index("docker build")


@pytest.mark.parametrize(
    "workflow,job",
    [
        ("virtualmin-lab-pr.yml", "pull-request"),
        ("virtualmin-lab.yml", "nightly-containers"),
        ("virtualmin-lab.yml", "native-full"),
    ],
)
def test_image_cache_users_have_commit_history_for_source_comparison(workflow: str, job: str) -> None:
    document = yaml.safe_load((REPO / ".github/workflows" / workflow).read_text())
    checkout = next(
        step for step in document["jobs"][job]["steps"] if step.get("uses", "").startswith("actions/checkout@")
    )
    assert checkout.get("with", {}).get("fetch-depth") == 0
