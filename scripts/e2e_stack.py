#!/usr/bin/env python3
"""Owned, local E2E servers and a strict test runner. No background task workers."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from functools import partial
from pathlib import Path
from uuid import uuid4

import requests

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / "logs"
STATE = LOGS / "e2e-stack.json"
FIXTURES = LOGS / "e2e-fixtures.json"
SERVICES = {"platform": 8700, "portal": 8701}
# Server-side coverage data. The browser suite exercises the app inside the `runserver`
# subprocesses, so measuring the pytest process would report almost nothing - it drives a
# browser and imports no business code. Opt-in via E2E_COVERAGE=1, because coverage tracing
# slows every request and the 311 browser tests have timeouts; a default-on tracer would trade
# suite stability for a number.
COVERAGE_DIR = ROOT / "output" / "playwright" / "coverage"


def environment(service: str = "platform") -> dict[str, str]:
    # Intentionally do not inherit credentials/provider endpoints or load .env.
    allowed = (
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "VIRTUAL_ENV",
        "CSP_PROFILE",
        "CSP_REPORT_ONLY",
        "EXPECTED_CSP_PROFILE",
    )
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(
        DJANGO_SETTINGS_MODULE="config.settings.e2e",
        TESTING="1",
        PRAHO_SKIP_DOTENV="1",
        PYTHONUNBUFFERED="1",
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONNOUSERSITE="1",
        RATE_LIMITING_ENABLED="false",
        E2E_STRICT="1",
        PYTHONPATH=str(ROOT / "services/platform") if service == "platform" else "",
    )
    return env


def manage(service: str, *args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "manage.py", *args],
        cwd=ROOT / "services" / service,
        env=environment(service),
        check=True,
        text=True,
        capture_output=capture,
    )


def require_free_ports() -> None:
    for port in SERVICES.values():
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise RuntimeError(
                    f"Port {port} is occupied. Stop its owner before make dev-e2e; no process was killed."
                ) from exc


def read_state() -> dict:
    if not STATE.exists():
        raise RuntimeError("No owned E2E stack found. Start make dev-e2e in another terminal.")
    state = json.loads(STATE.read_text())
    command = subprocess.run(
        ["ps", "-p", str(state["pid"]), "-o", "args="], capture_output=True, text=True, check=False
    )
    if str(Path(__file__).resolve()) not in command.stdout or state["instance"] not in command.stdout:
        raise RuntimeError("E2E supervisor is no longer running; the stored PID will not be used. Run make dev-e2e.")
    return state


def login(base: str, path: str, email: str, password: str, expected_path: str) -> requests.Session:
    session = requests.Session()
    response = session.get(base + path, timeout=10)
    response.raise_for_status()
    token = session.cookies.get("csrftoken")
    if not token:
        raise RuntimeError(f"No CSRF cookie from {base + path}")
    response = session.post(
        base + path,
        data={"email": email, "password": password, "csrfmiddlewaretoken": token},
        headers={"Referer": base + path},
        timeout=20,
    )
    response.raise_for_status()
    if requests.utils.urlparse(response.url).path != expected_path:
        raise RuntimeError(f"E2E login failed for {email} at {base}; ended at {response.url}")
    # A second request proves that DB-backed sessions survive the login response.
    response = session.get(base + expected_path, timeout=20)
    response.raise_for_status()
    if requests.utils.urlparse(response.url).path != expected_path:
        raise RuntimeError(f"E2E session did not persist for {email}")
    return session


def check(*, during_startup: bool = False) -> dict:
    state = read_state()
    if not during_startup and not state.get("ready"):
        raise RuntimeError("E2E setup is still running. Wait for the ready message.")
    require_stack_source(state)
    for service in SERVICES:
        path = LOGS / f"{service}_e2e.log"
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f"Required server log is missing or empty: {path}")
    fixtures = json.loads(manage("platform", "validate_e2e", capture=True).stdout)
    login("http://localhost:8700", "/auth/login/", "e2e-admin@test.local", "test123", "/dashboard/").close()
    for index, customer in enumerate(fixtures["customers"]):
        with login(
            "http://localhost:8701",
            "/login/",
            customer["email"],
            "test123" if index == 0 else "admin123",
            "/dashboard/",
        ) as session:
            response = session.get("http://localhost:8701/company/", timeout=20)
            response.raise_for_status()
            if customer["name"] not in response.text:
                raise RuntimeError(
                    f"Portal did not return the expected company through its signed API: {customer['email']}"
                )
    FIXTURES.write_text(json.dumps(fixtures, indent=2) + "\n")
    return state


def report_coverage() -> None:
    """Combine and report what each SERVER executed, one dataset per service.

    Each server wrote to its own `COVERAGE_FILE` base, so `combine` globs only that service's
    per-process files and the two codebases never mix. Reporting runs with the service directory
    as the working directory because the root config's `source = ["apps", "config", "ui"]` is
    relative - the same relative names have to resolve to the same tree they were measured in.
    """
    for service in SERVICES:
        produced = sorted(COVERAGE_DIR.glob(f".coverage.{service}.*"))
        if not produced:
            print(f"E2E coverage: no data for {service}. Did its server start under coverage?")
            continue
        service_dir = ROOT / "services" / service
        env = {
            **os.environ,
            "COVERAGE_RCFILE": str(ROOT / "pyproject.toml"),
            "COVERAGE_FILE": str(COVERAGE_DIR / f".coverage.{service}"),
        }
        run = partial(subprocess.run, cwd=service_dir, env=env, check=False)
        run([sys.executable, "-m", "coverage", "combine", "--quiet"])
        run([sys.executable, "-m", "coverage", "xml", "-o", str(COVERAGE_DIR / f"coverage-e2e-{service}.xml")])
        summary = subprocess.run(
            [sys.executable, "-m", "coverage", "report"],
            cwd=service_dir,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        # Only the TOTAL: the per-file table is hundreds of lines and the xml already holds it.
        total = next((line for line in summary.stdout.splitlines() if line.startswith("TOTAL")), None)
        print(f"E2E coverage [{service}] from {len(produced)} process file(s): {total or 'no TOTAL reported'}")
    print(f"E2E coverage: xml written to {COVERAGE_DIR}")


def serve(instance: str) -> None:
    require_free_ports()
    LOGS.mkdir(exist_ok=True)
    children: list[subprocess.Popen] = []
    stopping = False
    measuring_coverage = os.environ.get("E2E_COVERAGE") == "1"
    if measuring_coverage:
        COVERAGE_DIR.mkdir(parents=True, exist_ok=True)
        # Stale data from an earlier stack would be combined into this one and report lines
        # nothing in this run executed.
        for stale in COVERAGE_DIR.glob(".coverage.*"):
            stale.unlink()
        print("E2E coverage: servers will run under coverage; the report follows shutdown.")

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with contextlib.ExitStack() as files:
        try:
            state = {
                "pid": os.getpid(),
                "instance": instance,
                "root": str(ROOT),
                "ready": False,
                "source": source_version(),
                "coverage": measuring_coverage,
            }
            STATE.write_text(json.dumps(state))
            for service, port in SERVICES.items():
                log = files.enter_context((LOGS / f"{service}_e2e.log").open("w"))
                commands = [["migrate", "--noinput"]]
                if service == "platform":
                    commands.append(["seed_e2e"])
                for args in commands:
                    print(f"E2E {service}: {' '.join(args)}", flush=True)
                    command = [sys.executable, "manage.py", *args]
                    setup = subprocess.Popen(
                        command,
                        cwd=ROOT / "services" / service,
                        env=environment(service),
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                    children.append(setup)
                    while setup.poll() is None:
                        if stopping:
                            raise RuntimeError("E2E setup cancelled.")
                        time.sleep(0.1)
                    children.remove(setup)
                    if setup.returncode:
                        raise subprocess.CalledProcessError(setup.returncode, command)
                    if stopping:
                        raise RuntimeError("E2E setup cancelled.")
                server_command = [sys.executable, "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload"]
                server_env = environment(service)
                if measuring_coverage:
                    # `coverage run` rather than a sitecustomize hook: the stack owns this
                    # launch, so making it explicit here beats mutating site-packages.
                    server_command = [sys.executable, "-m", "coverage", "run", *server_command[1:]]
                    server_env.update(
                        COVERAGE_RCFILE=str(ROOT / "pyproject.toml"),
                        COVERAGE_FILE=str(COVERAGE_DIR / f".coverage.{service}"),
                    )
                children.append(
                    subprocess.Popen(
                        server_command,
                        cwd=ROOT / "services" / service,
                        env=server_env,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                )
            state["children"] = [child.pid for child in children]
            STATE.write_text(json.dumps(state))
            for _ in range(60):
                if stopping or any(child.poll() is not None for child in children):
                    raise RuntimeError("E2E server exited during startup. See logs/*_e2e.log.")
                try:
                    responses = [
                        requests.get(
                            f"http://localhost:{port}{'/auth/login/' if name == 'platform' else '/login/'}", timeout=1
                        )
                        for name, port in SERVICES.items()
                    ]
                    if all(response.status_code == 200 for response in responses):
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.5)
            else:
                raise RuntimeError("E2E startup timed out. See logs/*_e2e.log.")
            check(during_startup=True)
            ready = json.loads(STATE.read_text())
            ready["ready"] = True
            STATE.write_text(json.dumps(ready))
            print("E2E ready. Run make test-e2e in another terminal. Logs: logs/{platform,portal}_e2e.log", flush=True)
            while not stopping:
                if any(child.poll() is not None for child in children):
                    raise RuntimeError("An E2E server exited. See logs/*_e2e.log.")
                time.sleep(0.5)
        finally:
            for child in children:
                if child.poll() is None:
                    child.terminate()
            for child in children:
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # A killed server never ran its SIGTERM handler, so its coverage is lost.
                    print("E2E coverage: a server had to be killed; its data for this run is incomplete.")
                    child.kill()
                    child.wait()
            if measuring_coverage:
                # Reported here and not in `test()`: coverage writes on SIGTERM, which
                # `child.terminate()` above is what sends, so the data is only whole now.
                try:
                    report_coverage()
                except Exception as error:  # never mask the real shutdown reason
                    print(f"E2E coverage: reporting failed ({error}). Data kept in {COVERAGE_DIR}.")
            if STATE.exists() and json.loads(STATE.read_text()).get("instance") == instance:
                STATE.unlink()


def start() -> None:
    require_free_ports()
    LOGS.mkdir(exist_ok=True)
    instance = uuid4().hex
    with (LOGS / "e2e-supervisor.log").open("w") as log:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "serve", "--instance", instance],
            cwd=ROOT,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    for _ in range(600):
        if process.poll() is not None:
            raise RuntimeError("E2E setup failed. See logs/e2e-supervisor.log and logs/*_e2e.log.")
        if STATE.exists():
            state = json.loads(STATE.read_text())
            if state.get("instance") == instance and state.get("ready"):
                print("E2E ready in background. Run make test-e2e; stop with make stop-e2e.")
                return
        time.sleep(0.5)
    process.terminate()
    process.wait(timeout=20)
    raise RuntimeError("E2E setup timed out; stopped only the supervisor created by this command.")


def stop() -> None:
    state = read_state()
    os.kill(state["pid"], signal.SIGTERM)
    for _ in range(200):
        if not STATE.exists() or json.loads(STATE.read_text()).get("instance") != state["instance"]:
            return
        time.sleep(0.1)
    raise RuntimeError("Owned E2E supervisor did not finish stopping. Inspect logs/e2e-supervisor.log.")


def test(paths: list[str]) -> int:
    state = check()
    # Recheck after health probes: runserver --noreload must still be executing this source.
    source = require_stack_source(state)
    artifact = ROOT / "output/playwright/runs" / time.strftime("%Y%m%d-%H%M%S")
    artifact.mkdir(parents=True, exist_ok=False)
    command = [
        sys.executable,
        "-m",
        "pytest",
        *(paths or ["tests/e2e/"]),
        "-v",
        # The pytest process drives a browser and imports no business code; the coverage that
        # matters is collected inside the servers, by `serve()`.
        "--no-cov",
        f"--junitxml={artifact / 'junit.xml'}",
        # Playwright tracing is dropped when the servers are under coverage. Measured: the same
        # file gives 21 passed / 0 errors normally and 21 passed / 3 errors with both
        # instrumentations on, every error a `Tracing.stop: ENOENT` on the trace artifact rather
        # than a test failure. A coverage run wants the number; `make test-e2e` keeps the traces.
        "--tracing=off" if state.get("coverage") else "--tracing=retain-on-failure",
        "--screenshot=only-on-failure",
        f"--output={artifact / 'browser'}",
    ]
    with (artifact / "pytest.log").open("w") as log:
        process = subprocess.Popen(
            command, cwd=ROOT, env=environment(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        assert process.stdout is not None
        for line in process.stdout:
            print(line, end="", flush=True)
            log.write(line)
        pytest_code = process.wait()
    source_changed = source != source_version()
    code = pytest_code or int(source_changed)
    if source_changed:
        print("E2E source changed during the run; results are diagnostic only. Restart the stack and repeat.")
    for service in SERVICES:
        shutil.copy2(LOGS / f"{service}_e2e.log", artifact)
    shutil.copy2(FIXTURES, artifact)
    (artifact / "run.json").write_text(
        json.dumps(
            {
                **source,
                "source_changed_during_run": source_changed,
                "pytest_exit_code": pytest_code,
                "exit_code": code,
                "command": command,
                "stack": state,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"E2E evidence: {artifact}")
    return code


def source_version() -> dict[str, str | bool]:
    """Bind the source tree to its commit, including commits with identical trees."""
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    return {"head": head, **source_fingerprint()}


def require_stack_source(state: dict) -> dict[str, str | bool]:
    source = source_version()
    if state.get("source") != source:
        raise RuntimeError(
            "E2E stack source differs from the current checkout or has no startup fingerprint. "
            "Run make stop-e2e, then make dev-e2e before testing."
        )
    return source


def source_fingerprint() -> dict[str, str | bool]:
    """Include staged, unstaged and untracked source, without copying its contents."""
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT)
    diff = subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=ROOT)
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT)
    digest = hashlib.sha256(tree + b"\0" + diff)
    for raw_name in sorted(untracked.split(b"\0")):
        if raw_name:
            digest.update(raw_name + b"\0")
            digest.update((ROOT / os.fsdecode(raw_name)).read_bytes())
    return {"source_sha256": digest.hexdigest(), "dirty": bool(diff or untracked)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve", "start", "stop", "check", "test"))
    parser.add_argument("--instance", default=uuid4().hex)
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()
    try:
        if args.action == "serve":
            if "--instance" not in sys.argv:
                os.execv(  # noqa: S606 -- replace with this interpreter and this owned script, without a shell
                    sys.executable,
                    [sys.executable, str(Path(__file__).resolve()), "serve", "--instance", args.instance],
                )
            serve(args.instance)
        elif args.action == "start":
            start()
        elif args.action == "stop":
            stop()
        elif args.action == "check":
            check()
            print(
                "E2E prerequisites verified: owned servers, logs, fixtures, sessions and signed portal communication."
            )
        else:
            return test(args.paths)
    except (RuntimeError, subprocess.CalledProcessError, requests.RequestException) as exc:
        print(f"E2E: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
