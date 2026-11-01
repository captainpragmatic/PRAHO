"""Observer timeouts cannot leave the exact controller subprocess running or unreaped."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
from pathlib import Path
from time import time_ns

import pytest

from tests.virtualmin_lab.components.site_observation import _WATCH, _stop_observer

pytestmark = pytest.mark.integration


def test_actual_observer_events_include_wall_clock_timestamps_for_log_correlation(tmp_path: Path) -> None:
    before = time_ns()
    process = subprocess.Popen(  # noqa: S603 -- actual read-only observer, local interpreter and nonexistent exact fixture
        [sys.executable, "-u", "-c", _WATCH, "component-contract-0000000000.praho.test"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        started = json.loads(process.stdout.readline())
        assert started["event"] == "started"

        _stop_observer(process, tmp_path / "observer.jsonl", timeout=1)

        events = [started, *(json.loads(line) for line in process.stdout)]
        after = time_ns()
        assert events[-1]["event"] == "stopped"
        for event in events:
            assert type(event.get("time_ns")) is int
            assert before <= event["time_ns"] <= after
        assert events[-1]["elapsed"] >= 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()


@pytest.mark.parametrize("exit_code", [0, 7])
def test_observer_eof_reaps_the_child_and_preserves_its_exit_result(tmp_path: Path, exit_code: int) -> None:
    process = subprocess.Popen(  # noqa: S603 -- own Python interpreter and literal EOF/exit fixture only
        [
            sys.executable,
            "-u",
            "-c",
            "import sys; print('ready', flush=True); sys.stdin.read(); sys.exit(int(sys.argv[1]))",
            str(exit_code),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline() == "ready\n"
        if exit_code:
            with pytest.raises(RuntimeError, match="observer exited 7"):
                _stop_observer(process, tmp_path / "observer.jsonl", timeout=1)
        else:
            _stop_observer(process, tmp_path / "observer.jsonl", timeout=1)
        assert process.returncode == exit_code
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()


def test_a_timed_out_observer_that_ignores_termination_is_killed_and_reaped(tmp_path: Path) -> None:
    process = subprocess.Popen(  # noqa: S603 -- own Python interpreter and literal signal-handling fixture only
        [
            sys.executable,
            "-u",
            "-c",
            "import signal, threading; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); threading.Event().wait()",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline() == "ready\n", "The real child must install SIGTERM refusal before cleanup"

        with pytest.raises(subprocess.TimeoutExpired) as expired:
            _stop_observer(process, tmp_path / "observer.jsonl", timeout=0.1)

        assert expired.value.timeout == 0.1, "Cleanup must preserve the original diagnostic timeout"
        assert expired.value.cmd == process.args
        assert process.returncode == -signal.SIGKILL, "The exact timed-out child was left alive or unreaped"
        assert process.poll() == -signal.SIGKILL
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()
