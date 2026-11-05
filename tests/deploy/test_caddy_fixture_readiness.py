"""The real Caddy fixture waits for Docker's published-port metadata."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import test_caddy_routing as routing


class EdgeBoundary:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, responses: list[tuple[int, str, str] | None]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, ...]] = []
        self.port_timeouts: list[float] = []
        self.now = 0.0
        monkeypatch.setattr(routing.subprocess, "run", self.docker)
        monkeypatch.setattr(routing.time, "monotonic", lambda: self.now)
        monkeypatch.setattr(routing.time, "sleep", self.sleep)

    def sleep(self, duration: float) -> None:
        assert duration >= 0
        self.now += duration

    def docker(self, command: list[str], *, timeout: float, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        assert command[0] == "docker"
        args = tuple(command[1:])
        self.calls.append(args)
        if args[0] != "port":
            return subprocess.CompletedProcess(args, 0, "fixture-ready", "")
        self.port_timeouts.append(timeout)
        response = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if response is None:
            self.now += timeout
            raise subprocess.TimeoutExpired(args, timeout)
        return subprocess.CompletedProcess(args, *response)

    def assert_cleanup(self) -> None:
        assert self.calls[-2][0:3] == ("rm", "-f", "-v")
        assert self.calls[-1][0:2] == ("network", "rm")
        assert self.calls[-2][-1].startswith("routing-")
        assert self.calls[-1][-1].startswith("routing-")


def test_running_edge_waits_for_the_observed_missing_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = EdgeBoundary(
        monkeypatch,
        [
            (1, "", "no public port '80/tcp' published for routing-fixture-edge\n"),
            (0, "0.0.0.0:49152\n[::]:49152\n", ""),
        ],
    )
    with routing._running_edge("portal", tmp_path) as (_edge, _peer, address):
        assert address == "host.docker.internal:49152"
    assert len(boundary.port_timeouts) == 2
    boundary.assert_cleanup()


@pytest.mark.parametrize("response", [(1, "", "no public port '80/tcp' published"), None], ids=["absent", "timeout"])
def test_running_edge_publication_failure_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, response: tuple[int, str, str] | None
) -> None:
    boundary = EdgeBoundary(monkeypatch, [response])
    with pytest.raises(AssertionError, match="80/tcp"), routing._running_edge("portal", tmp_path):
        pytest.fail("An unverified published port reached the test")
    assert len(boundary.port_timeouts) > 1
    assert 0 < boundary.now <= 6
    assert all(0 < timeout <= 1 for timeout in boundary.port_timeouts)
    boundary.assert_cleanup()


@pytest.mark.parametrize(
    "output",
    ["", "not-a-binding", "localhost:49152\n", "0.0.0.0:0\n", "0.0.0.0:65536\n"],
)
def test_running_edge_refuses_malformed_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    boundary = EdgeBoundary(monkeypatch, [(0, output, "")])
    with pytest.raises(AssertionError, match="80/tcp"), routing._running_edge("portal", tmp_path):
        pytest.fail("Malformed publication reached the test")
    assert len(boundary.port_timeouts) == 1
    boundary.assert_cleanup()


@pytest.mark.parametrize(
    "output",
    ["0.0.0.0:49152\n", "[::]:49152\n", "127.0.0.1:49152\n[::1]:49152\n", "0.0.0.0:49152\n[::]:49153\n"],
)
def test_running_edge_preserves_healthy_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str
) -> None:
    boundary = EdgeBoundary(monkeypatch, [(0, output, "")])
    with routing._running_edge("portal", tmp_path) as (_edge, _peer, address):
        assert address == "host.docker.internal:49152"
    assert len(boundary.port_timeouts) == 1
    boundary.assert_cleanup()
