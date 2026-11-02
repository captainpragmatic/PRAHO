"""Observer timeouts cannot leave the exact controller subprocess running or unreaped."""

from __future__ import annotations

import json
import signal
import subprocess
import sys
from pathlib import Path
from time import time_ns

import pytest

from tests.virtualmin_lab.components import site_observation
from tests.virtualmin_lab.components.site_observation import _WATCH, _stop_observer

pytestmark = pytest.mark.integration


def test_inventory_refusal_reports_only_the_exact_entry_and_keeps_the_native_failure(tmp_path: Path) -> None:
    entry = tmp_path / "123.lock"
    entry.write_text("private content must not appear in diagnostics")
    helper = (
        Path(__file__).resolve().parents[2]
        / "services/platform/infrastructure/ansible/playbooks/files/praho-component-inspect.py"
    )
    script = (
        getattr(site_observation, "INSPECTION_ERROR_OBSERVATION", "")
        + r"""
import importlib.util,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('actual_inspection',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
directory=Path(sys.argv[2]);module.Path=lambda unused:directory
module._related_domains('fixture-owner')
"""
    )
    result = subprocess.run(  # noqa: S603 -- actual inspection against one owned temporary fixture
        [sys.executable, "-c", script, str(helper), str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 1
    assert "Native retained-domain inventory is unclassified or exceeds its bound" in result.stderr
    diagnostics = [line for line in result.stderr.splitlines() if line.startswith("PRAHO_INSPECTION_REFUSAL=")]
    assert len(diagnostics) == 1, result.stderr
    evidence = json.loads(diagnostics[0].partition("=")[2])
    assert evidence["entry"] == "123.lock"
    assert evidence["index"] == 0
    assert type(evidence["time_ns"]) is int
    assert "private content" not in result.stderr


@pytest.mark.parametrize("script,code", [("print('ordinary stdout')", 0), ("raise ValueError('ordinary failure')", 1)])
def test_inspection_diagnostics_preserve_unrelated_script_outcomes(script: str, code: int) -> None:
    prefix = getattr(site_observation, "INSPECTION_ERROR_OBSERVATION", "")
    result = subprocess.run(  # noqa: S603 -- literal local success/failure control only
        [sys.executable, "-c", prefix + script], capture_output=True, text=True, timeout=5, check=False
    )
    assert result.returncode == code
    assert "PRAHO_INSPECTION_REFUSAL=" not in result.stderr
    assert result.stdout == ("ordinary stdout\n" if code == 0 else "")


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
