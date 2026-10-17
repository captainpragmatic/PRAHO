"""Settling a node after a fault: nothing a fault left running can make the next calls wait (make test-virtualmin-faults).

A fault can leave a Virtualmin command running on the node after PRAHO has given up on its answer, and the command
holds Virtualmin's locks until it ends. `Chaos.settle` waits for such commands and for live lock holders, records
what it found (CI keeps the record), and ends only what outlives the wait, by PID, verifying that it is gone.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.virtualmin_lab.faults import harness
from tests.virtualmin_lab.faults.harness import Chaos, docker, held_locks, in_flight_operations

COMMAND = "/usr/share/webmin/virtual-server/restore-domain.pl"
LOCK = "/var/webmin/praho-lab-standin.lock"


def _standin(chaos: Chaos, body: str) -> str:
    """Start a process named exactly like a Virtualmin command, holding a Webmin-style lock file with its PID."""
    container = chaos.bench.node("vm-a").container
    docker("exec", "-d", container, "bash", "-c", f"echo $$ > {LOCK}; {body}")
    assert any(COMMAND in line for line in in_flight_operations(container)), "the stand-in did not start"
    return container


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(harness, "DRAIN_WAIT_SECONDS", 6)
    monkeypatch.setattr(harness, "DIAGNOSTICS_DIR", tmp_path)
    return tmp_path


def _records(directory: Path) -> str:
    return "\n".join(path.read_text() for path in sorted(directory.glob("*.txt")))


def test_settle_ends_a_stranded_command_and_frees_its_lock(chaos: Chaos, quick: Path) -> None:
    container = _standin(chaos, f"exec -a {COMMAND} sleep 600")
    assert held_locks(container), "the stand-in's lock is not seen as held"

    chaos.settle("vm-a")

    assert in_flight_operations(container) == []
    assert held_locks(container) == []
    record = _records(quick)
    assert COMMAND in record and LOCK in record and "ended" in record


def test_settle_escalates_when_a_command_ignores_termination(chaos: Chaos, quick: Path) -> None:
    container = _standin(chaos, f"trap '' TERM; exec -a {COMMAND} sleep 600")

    chaos.settle("vm-a")

    assert in_flight_operations(container) == []
    assert "KILL" in _records(quick)


def test_settle_lets_a_command_finish_by_itself(chaos: Chaos, quick: Path) -> None:
    container = _standin(chaos, f"exec -a {COMMAND} sleep 2")

    chaos.settle("vm-a")

    assert in_flight_operations(container) == []
    record = _records(quick)
    assert "finished by itself" in record and "ended" not in record


def test_settle_records_nothing_on_a_quiet_node(chaos: Chaos, quick: Path) -> None:
    chaos.settle("vm-a")

    assert list(quick.glob("*.txt")) == []


def test_settle_leaves_virtualmins_own_daemon_running(chaos: Chaos, quick: Path) -> None:
    daemon = "/usr/share/webmin/virtual-server/lookup-domain-daemon.pl"
    pid_file = "/run/praho-lab-standin-daemon.pid"
    container = chaos.bench.node("vm-a").container
    docker("exec", "-d", container, "bash", "-c", f"echo $$ > {pid_file}; exec -a {daemon} sleep 600")
    pid = docker("exec", container, "sh", "-c", f"sleep 1; cat {pid_file}").strip()
    assert pid, "the stand-in daemon did not start"
    try:
        chaos.settle("vm-a")

        assert pid in docker("exec", container, "ps", "-eo", "pid=").split(), "settle ended Virtualmin's own daemon"
        assert list(quick.glob("*.txt")) == []
    finally:
        docker("exec", container, "kill", "-KILL", pid, check=False)


def test_settle_ends_a_live_lock_holder_that_is_not_a_command(chaos: Chaos, quick: Path) -> None:
    container = chaos.bench.node("vm-a").container
    docker("exec", "-d", container, "bash", "-c", f"echo $$ > {LOCK}; exec sleep 600")
    assert held_locks(container) and not in_flight_operations(container)

    chaos.settle("vm-a")

    assert held_locks(container) == []
    assert LOCK in _records(quick)


def test_settle_ends_the_children_a_command_started(chaos: Chaos, quick: Path) -> None:
    child_pid_file = "/run/praho-lab-standin-child.pid"
    container = _standin(chaos, f"exec -a {COMMAND} bash -c 'sleep 600 & echo $! > {child_pid_file}; wait'")
    child = docker("exec", container, "sh", "-c", f"sleep 1; cat {child_pid_file}").strip()
    assert child, "the stand-in's child did not start"

    chaos.settle("vm-a")

    assert child not in docker("exec", container, "ps", "-eo", "pid=").split(), "a child outlived its stranded parent"


def test_a_failed_listing_is_an_error_not_an_empty_node() -> None:
    with pytest.raises(AssertionError):
        in_flight_operations("vmlab-does-not-exist")
    with pytest.raises(AssertionError):
        held_locks("vmlab-does-not-exist")
