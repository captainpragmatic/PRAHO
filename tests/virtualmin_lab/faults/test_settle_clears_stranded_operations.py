"""Settling a node after a fault: nothing a fault left running can make the next calls wait (make test-virtualmin-faults).

A fault can leave a Virtualmin command running on the node after PRAHO has given up on its answer, and the command
holds Virtualmin's locks until it ends. `Chaos.settle` waits for such commands and for live lock holders, records
what it found (CI keeps the record), and ends only what outlives the wait, by PID, verifying that it is gone.
"""

from __future__ import annotations

import shlex
import shutil
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from time import monotonic
from uuid import uuid4

import pytest

from tests.virtualmin_lab.faults import harness
from tests.virtualmin_lab.faults.harness import Chaos, docker, held_locks, in_flight_operations
from tests.virtualmin_lab.workflows.harness import Bench, build_bench

COMMAND = "/usr/share/webmin/virtual-server/restore-domain.pl"
LOCK = "/var/webmin/praho-lab-standin.lock"


@dataclass(frozen=True)
class OwnedStandin:
    container: str
    pid: str
    start_time: str
    lock: str = LOCK


def _process_start(container: str, pid: str) -> str:
    script = """import sys
from pathlib import Path
try:contents=(Path('/proc')/sys.argv[1]/'stat').read_text()
except FileNotFoundError:print('')
else:print(contents.rpartition(')')[2].split()[19])
"""
    return docker("exec", container, "python3", "-c", script, pid).strip()


def _capture_standin(container: str, lock: str) -> OwnedStandin:
    deadline, poll = monotonic() + 2, Event()
    while monotonic() < deadline:
        pid = docker("exec", container, "cat", lock, check=False).strip()
        if pid.isdecimal() and (start := _process_start(container, pid)):
            return OwnedStandin(container, pid, start, lock)
        poll.wait(0.02)
    raise AssertionError("The owned stand-in did not publish its live process identity")


def _assert_standin_settled(owned: OwnedStandin) -> None:
    assert _process_start(owned.container, owned.pid) != owned.start_time, "The original stand-in is still running"
    assert not any(line.split()[0] == owned.lock for line in held_locks(owned.container)), (
        "The original lock is still held"
    )


def _standin(chaos: Chaos, body: str) -> OwnedStandin:
    """Start a process named exactly like a Virtualmin command, holding a Webmin-style lock file with its PID."""
    container = chaos.bench.node("vm-a").container
    docker("exec", "-d", container, "bash", "-c", f"echo $$ > {LOCK}; {body}")
    assert any(COMMAND in line for line in in_flight_operations(container)), "the stand-in did not start"
    return _capture_standin(container, LOCK)


@pytest.fixture
def owned_chaos(settle_bench: Bench) -> Chaos:
    """Use the shared process-only bench without repairing or removing hosting fixtures."""
    return Chaos(settle_bench)


def _cleanup_owned(owned: OwnedStandin, *paths: str) -> None:
    script = """import os,signal,stat,sys
from contextlib import suppress
from pathlib import Path
pid,start,lock,*extra=sys.argv[1:];p=Path('/proc')/pid/'stat'
with suppress(ProcessLookupError,FileNotFoundError):
 fd=os.pidfd_open(int(pid))
 try:
  if p.read_text().rpartition(')')[2].split()[19]!=start:raise RuntimeError('Owned PID was reused')
  signal.pidfd_send_signal(fd,signal.SIGKILL)
 finally:os.close(fd)
for name in [lock,*extra]:
 p=Path(name)
 if not p.exists():continue
 info=p.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1:raise RuntimeError('Unsafe fixture path')
 if name==lock and p.read_text().strip()!=pid:continue
 p.unlink()
"""
    docker("exec", owned.container, "python3", "-c", script, owned.pid, owned.start_time, owned.lock, *paths)


@contextmanager
def _new_arrival(container: str) -> Iterator[OwnedStandin]:
    token = uuid4().hex
    lock, release, completed = (
        f"/var/webmin/praho-arrival-{token}.lock",
        f"/run/praho-arrival-{token}.release",
        f"/run/praho-arrival-{token}.done",
    )
    program = (
        "import time;from pathlib import Path;"
        f"release=Path({release!r});deadline=time.monotonic()+30;"
        "\nwhile not release.exists() and time.monotonic()<deadline:time.sleep(.01)"
        "\nassert release.exists(),'Owned arrival was not released'"
        f"\nPath({completed!r}).write_text('natural')"
    )
    command = "/usr/share/webmin/virtual-server/backup-domain.pl"
    docker(
        "exec", "-d", container, "bash", "-c", f"echo $$ > {lock}; exec -a {command} python3 -c {shlex.quote(program)}"
    )
    owned = _capture_standin(container, lock)
    try:
        yield owned
    finally:
        try:
            assert _process_start(container, owned.pid) == owned.start_time, (
                "The new arrival was ended by the assertion"
            )
            docker("exec", container, "touch", release)
            deadline, poll = monotonic() + 5, Event()
            while _process_start(container, owned.pid) == owned.start_time and monotonic() < deadline:
                poll.wait(0.02)
            assert _process_start(container, owned.pid) != owned.start_time, "The new task did not finish naturally"
            assert docker("exec", container, "cat", completed).strip() == "natural"
        finally:
            _cleanup_owned(owned, release, completed)


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Path]:
    artifact_directory = harness.DIAGNOSTICS_DIR / "settle" / tmp_path.name / uuid4().hex
    monkeypatch.setattr(harness, "DRAIN_WAIT_SECONDS", 6)
    monkeypatch.setattr(harness, "DIAGNOSTICS_DIR", tmp_path)
    try:
        yield tmp_path
    finally:
        records = list(tmp_path.glob("*.txt"))
        if records:
            artifact_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            for record in records:
                shutil.copyfile(record, artifact_directory / record.name)


@pytest.fixture
def settle_bench() -> Iterator[Bench]:
    """Use real admitted A/B gateways without a fleet-wide health sweep or network repair."""
    from apps.provisioning.management.commands._virtualmin_lab import (  # noqa: PLC0415
        lab_transport,
        load_state,
        refuse_unless_lab_settings,
    )

    refuse_unless_lab_settings()
    state = load_state()
    with lab_transport(state):
        selected = build_bench(state)
        selected.reset_meters()
        try:
            yield selected
        finally:
            selected.reset_meters()


def _standin_locked(container: str) -> bool:
    """Whether the stand-in's lock is still held. Webmin's own scheduled jobs (the status monitor) take locks of their
    own at any moment, so asserting that no lock at all is held races them."""
    return any(line.split()[0] == LOCK for line in held_locks(container))


def _records(directory: Path) -> str:
    return "\n".join(path.read_text() for path in sorted(directory.glob("*.txt")))


def _start_time(container: str, pid: str) -> str:
    fields = docker("exec", container, "cat", f"/proc/{pid}/stat", check=False).split()
    return fields[21] if len(fields) > 21 else ""


def _late_standin(container: str, lock: str, completed_file: str, seconds: int) -> tuple[str, str]:
    program = (
        f"import time; from pathlib import Path; time.sleep({seconds}); Path({completed_file!r}).write_text('natural')"
    )
    command = "/usr/share/webmin/virtual-server/backup-domain.pl"
    docker(
        "exec",
        "-d",
        container,
        "bash",
        "-c",
        f"echo $$ > {lock}; exec -a {command} /usr/bin/python3 -c {shlex.quote(program)}",
    )
    deadline, poll = monotonic() + 2, Event()
    while monotonic() < deadline:
        pid = docker("exec", container, "cat", lock, check=False).strip()
        if pid.isdecimal() and (identity := _start_time(container, pid)):
            return pid, identity
        poll.wait(0.02)
    raise AssertionError("The real late command never acquired its own live lock")


def test_settle_ends_a_stranded_command_and_frees_its_lock(chaos: Chaos, quick: Path) -> None:
    owned = _standin(chaos, f"exec -a {COMMAND} sleep 600")
    container = owned.container
    assert _standin_locked(container), "the stand-in's lock is not seen as held"

    chaos.settle("vm-a")

    _assert_standin_settled(owned)
    assert not _standin_locked(container)
    record = _records(quick)
    assert COMMAND in record and LOCK in record and "ended" in record


def test_settle_escalates_when_a_command_ignores_termination(chaos: Chaos, quick: Path) -> None:
    owned = _standin(chaos, f"trap '' TERM; exec -a {COMMAND} sleep 600")

    chaos.settle("vm-a")

    _assert_standin_settled(owned)
    assert "KILL" in _records(quick)


def test_settle_lets_a_command_finish_by_itself(chaos: Chaos, quick: Path) -> None:
    owned = _standin(chaos, f"exec -a {COMMAND} sleep 2")

    chaos.settle("vm-a")

    _assert_standin_settled(owned)
    record = _records(quick)
    assert "finished by itself within the wait" in record.splitlines()
    # Full process diagnostics can contain "unattended-upgrades". Only a
    # termination action line means settle ended the command itself.
    assert not any(line.startswith("ended after ") for line in record.splitlines())


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
    assert _standin_locked(container) and not in_flight_operations(container)

    chaos.settle("vm-a")

    assert not _standin_locked(container)
    assert LOCK in _records(quick)


def test_settle_ends_the_children_a_command_started(chaos: Chaos, quick: Path) -> None:
    child_pid_file = "/run/praho-lab-standin-child.pid"
    container = _standin(chaos, f"exec -a {COMMAND} bash -c 'sleep 600 & echo $! > {child_pid_file}; wait'").container
    child = docker("exec", container, "sh", "-c", f"sleep 1; cat {child_pid_file}").strip()
    assert child, "the stand-in's child did not start"

    chaos.settle("vm-a")

    assert child not in docker("exec", container, "ps", "-eo", "pid=").split(), "a child outlived its stranded parent"


@pytest.mark.parametrize("seconds", [3, 30])
def test_settle_passively_drains_new_work_after_its_original_cohort_ends(
    settle_bench: Bench, quick: Path, monkeypatch: pytest.MonkeyPatch, seconds: int
) -> None:
    # Use the genuine bench without the chaos fixture's unrelated network-repair
    # path. Only this test's exact stand-ins need cleanup; no endpoint reconnect.
    chaos = Chaos(settle_bench)
    nonce = uuid4().hex
    child_file = f"/run/praho-lab-settle-child-{nonce}.pid"
    late_lock = f"/var/webmin/praho-lab-settle-late-{nonce}.lock"
    completed_file = f"/run/praho-lab-settle-completed-{nonce}"
    container = _standin(chaos, f"exec -a {COMMAND} bash -c 'sleep 600 & echo $! > {child_file}; wait'").container
    parent = docker("exec", container, "cat", LOCK).strip()
    child = docker("exec", container, "sh", "-c", f"sleep 1; cat {child_file}").strip()
    assert parent.isdecimal() and child.isdecimal()
    real_docker = harness.docker
    original = {parent, child}
    observed: dict[str, str] = {}
    terminated = False
    arrived_at = 0.0
    owned = {pid: _start_time(container, pid) for pid in original}
    assert all(owned.values()), "Both original processes must exist before settling"

    def observe_docker(*argv: str, check: bool = True) -> str:
        nonlocal terminated, arrived_at
        result = real_docker(*argv, check=check)
        if argv[:4] == ("exec", container, "kill", "-TERM") and original <= set(argv[4:]):
            terminated = True
        if argv == ("exec", container, "ps", "-eo", "pid=,ppid=") and terminated and not observed:
            live = {line.split()[0] for line in result.splitlines() if line.split()}
            if original.isdisjoint(live):
                # This is AFTER a real listing proves the captured cohort gone.
                # Fresh normal work can arrive before settle's final global read.
                arrived_at = monotonic()
                late_pid, identity = _late_standin(container, late_lock, completed_file, seconds)
                observed["pid"] = late_pid
                owned[late_pid] = identity
        return result

    monkeypatch.setattr(harness, "docker", observe_docker)
    try:
        if seconds == 3:
            chaos.settle("vm-a")
            assert real_docker("exec", container, "cat", completed_file).strip() == "natural"
        else:
            with pytest.raises(AssertionError, match="work remains after settling"):
                chaos.settle("vm-a")
            assert monotonic() - arrived_at < harness.DRAIN_WAIT_SECONDS + 5
            assert _start_time(container, observed["pid"]) == owned[observed["pid"]], "New work was prematurely killed"
            real_docker("exec", container, "test", "!", "-e", completed_file)
        assert terminated and observed, "The after-cohort arrival boundary must actually execute"
        if seconds == 3:
            _assert_standin_settled(OwnedStandin(container, observed["pid"], owned[observed["pid"]], late_lock))
            assert not any(line.split()[0] == late_lock for line in held_locks(container))
        assert all(_process_start(container, pid) != owned[pid] for pid in original)
        assert COMMAND in _records(quick), "The original cohort must retain its diagnostic record"
    finally:
        for pid, identity in owned.items():
            if identity and _start_time(container, pid) == identity:
                real_docker("exec", container, "kill", "-KILL", pid, check=False)
        real_docker("exec", container, "rm", "-f", child_file, late_lock, completed_file)


def test_a_failed_listing_is_an_error_not_an_empty_node() -> None:
    with pytest.raises(AssertionError):
        in_flight_operations("vmlab-does-not-exist")
    with pytest.raises(AssertionError):
        held_locks("vmlab-does-not-exist")


def test_post_return_arrival_does_not_invalidate_the_owned_settle_proof(owned_chaos: Chaos, quick: Path) -> None:
    owned = _standin(owned_chaos, f"exec -a {COMMAND} sleep 2")
    try:
        owned_chaos.settle("vm-a")
        with _new_arrival(owned.container) as arrival:
            assert _process_start(arrival.container, arrival.pid) == arrival.start_time
            assert any(line.split()[0] == arrival.lock for line in held_locks(arrival.container))
            _assert_standin_settled(owned)
    finally:
        _cleanup_owned(owned)


def test_owned_settle_assertion_rejects_a_live_original_process(owned_chaos: Chaos) -> None:
    owned = _standin(owned_chaos, f"exec -a {COMMAND} sleep 600")
    try:
        with pytest.raises(AssertionError, match="original stand-in is still running"):
            _assert_standin_settled(owned)
    finally:
        _cleanup_owned(owned)


def test_owned_settle_assertion_rejects_a_new_holder_of_the_original_lock(owned_chaos: Chaos, quick: Path) -> None:
    original = _standin(owned_chaos, f"exec -a {COMMAND} sleep 2")
    try:
        owned_chaos.settle("vm-a")
        assert _process_start(original.container, original.pid) != original.start_time
        holder = _standin(owned_chaos, f"exec -a {COMMAND} sleep 600")
        try:
            with pytest.raises(AssertionError, match="original lock is still held"):
                _assert_standin_settled(original)
        finally:
            _cleanup_owned(holder)
    finally:
        _cleanup_owned(original)


def test_a_failed_identity_probe_is_an_error_not_a_settled_process() -> None:
    with pytest.raises(AssertionError):
        _process_start("vmlab-does-not-exist", "1")


def test_owned_process_exiting_immediately_before_stat_read_is_gone(
    owned_chaos: Chaos, monkeypatch: pytest.MonkeyPatch
) -> None:
    owned = _standin(owned_chaos, f"exec -a {COMMAND} sleep 600")
    actual_docker, intercepted = docker, False
    read_boundary = f"""import os,signal,time
from pathlib import Path
real_read=Path.read_text
def stop_before_read(path,*args,**kwargs):
 if str(path)=={("/proc/" + owned.pid + "/stat")!r}:
  fd=os.pidfd_open({int(owned.pid)})
  try:
   if real_read(path).rpartition(')')[2].split()[19]!={owned.start_time!r}:raise RuntimeError('Owned PID changed')
   signal.pidfd_send_signal(fd,signal.SIGKILL)
  finally:os.close(fd)
  deadline=time.monotonic()+5
  while path.exists() and time.monotonic()<deadline:time.sleep(.01)
  assert not path.exists(),'Owned process did not exit at the read boundary'
 return real_read(path,*args,**kwargs)
Path.read_text=stop_before_read
"""

    def intercept(*arguments: str, **options: bool) -> str:
        nonlocal intercepted
        assert arguments[:4] == ("exec", owned.container, "python3", "-c") and arguments[5] == owned.pid
        assert not intercepted
        intercepted = True
        changed = [*arguments]
        changed[4] = read_boundary + changed[4]
        return actual_docker(*changed, **options)

    try:
        with monkeypatch.context() as seam:
            seam.setattr(sys.modules[__name__], "docker", intercept)
            assert _process_start(owned.container, owned.pid) == ""
        assert intercepted
        assert _process_start(owned.container, owned.pid) == ""
    finally:
        _cleanup_owned(owned)
