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
from pathlib import Path
from uuid import uuid4

import requests

ROOT = Path(__file__).resolve().parents[1]
LOGS = ROOT / "logs"
STATE = LOGS / "e2e-stack.json"
FIXTURES = LOGS / "e2e-fixtures.json"
SERVICES = {"platform": 8700, "portal": 8701}


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


def serve(instance: str) -> None:
    require_free_ports()
    LOGS.mkdir(exist_ok=True)
    children: list[subprocess.Popen] = []
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with contextlib.ExitStack() as files:
        try:
            STATE.write_text(json.dumps({"pid": os.getpid(), "instance": instance, "root": str(ROOT), "ready": False}))
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
                children.append(
                    subprocess.Popen(
                        [sys.executable, "manage.py", "runserver", f"127.0.0.1:{port}", "--noreload"],
                        cwd=ROOT / "services" / service,
                        env=environment(service),
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                )
            STATE.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "instance": instance,
                        "root": str(ROOT),
                        "children": [child.pid for child in children],
                    }
                )
            )
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
                    child.kill()
                    child.wait()
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
    artifact = ROOT / "output/playwright/runs" / time.strftime("%Y%m%d-%H%M%S")
    artifact.mkdir(parents=True, exist_ok=False)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    fingerprint = source_fingerprint()
    command = [
        sys.executable,
        "-m",
        "pytest",
        *(paths or ["tests/e2e/"]),
        "-v",
        "--no-cov",
        f"--junitxml={artifact / 'junit.xml'}",
        "--tracing=retain-on-failure",
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
        code = process.wait()
    for service in SERVICES:
        shutil.copy2(LOGS / f"{service}_e2e.log", artifact)
    shutil.copy2(FIXTURES, artifact)
    (artifact / "run.json").write_text(
        json.dumps(
            {
                "head": head,
                **fingerprint,
                "source_changed_during_run": fingerprint != source_fingerprint(),
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


def source_fingerprint() -> dict[str, str | bool]:
    """Include staged, unstaged and untracked source, without copying its contents."""
    diff = subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=ROOT)
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=ROOT)
    digest = hashlib.sha256(diff)
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
