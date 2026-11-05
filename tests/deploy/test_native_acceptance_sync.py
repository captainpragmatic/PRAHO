"""The concurrency probe must observe its current deployment, even with delayed thread scheduling."""

import subprocess
import threading
from pathlib import Path

import pytest

from tests.deploy.test_native_acceptance import _deploy_while_refusing_a_competing_controller

PHASE = "PLAY [Drain Platform workers and active backups before stopping web writers]"


class DelayedDeployment:
    """A scheduler boundary for the harness unit test; real deployment acceptance uses actual applications."""

    controller = "controller"
    platform = "platform"
    environment = "prod"
    sha = "a" * 40

    def __init__(self, log: Path) -> None:
        self.log = log
        self.log.write_text(PHASE)
        self.begin = threading.Event()
        self.started = threading.Event()
        self.finish = threading.Event()
        self.reads = 0

    def deploy(self) -> subprocess.CompletedProcess[str]:
        assert self.begin.wait(timeout=5), "The phase observer never started"
        self.log.write_text("")
        self.log.write_text(PHASE)
        self.started.set()
        assert self.finish.wait(timeout=5), "The competing-controller check never finished"
        return subprocess.CompletedProcess([], 0, "", "")

    def wait_for_phase(self, phase: str) -> None:
        assert phase == PHASE
        # Force the reader to run before deploy() can truncate its log. This
        # reproduces the CI schedule instead of hoping the race happens locally.
        stale = self.log.read_text() == PHASE
        self.begin.set()
        assert self.started.wait(timeout=5)
        if stale:
            self.finish.set()
            pytest.fail("The concurrency probe consumed a previous deployment's phase")

    def execute(self, host: str, *arguments: str, **_options: object) -> subprocess.CompletedProcess[str]:
        if host == self.controller and arguments == ("truncate", "-s", "0", "/fixture/deployment.log"):
            self.log.write_text("")
            return subprocess.CompletedProcess([], 0, "", "")
        if host == self.platform and arguments == ("cat", "/etc/praho-native-operation/owner"):
            self.reads += 1
            if self.reads == 2:
                self.finish.set()
            return subprocess.CompletedProcess([], 0, "current-controller\n", "")
        if host == self.platform and arguments[0] == "stat":
            return subprocess.CompletedProcess([], 0, "root:root:700\n", "")
        assert host == self.controller and "--rollback" in arguments
        return subprocess.CompletedProcess([], 1, "Native operation lock exists on Platform", "")


def test_concurrency_probe_discards_stale_phases_before_launching_the_thread(tmp_path: Path) -> None:
    lab = DelayedDeployment(tmp_path / "deployment.log")
    result = _deploy_while_refusing_a_competing_controller(lab)
    assert result.returncode == 0 and lab.reads == 2
