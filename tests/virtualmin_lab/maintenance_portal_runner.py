"""Run real HTTP/HMAC acceptance with owned noncredential fixture DBs and captured mail."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.e2e_stack import source_version  # noqa: E402 -- canonical source freeze implementation


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def stop(child: subprocess.Popen[bytes]) -> None:
    """Only children started here; never a port owner, process name or unrelated worker."""
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def wait_ready(child: subprocess.Popen[bytes], url: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("Owned HTTP service exited during startup; see its captured log")
        try:
            with urlopen(url, timeout=2) as response:  # noqa: S310 -- generated exact loopback HTTP origin
                if response.status == 200:
                    return
        except (URLError, TimeoutError):
            pass
        time.sleep(0.25)
    raise RuntimeError("Owned HTTP listener did not become ready")


def main() -> int:  # noqa: PLR0915 -- keep the owned fixture and child cleanup in one visible lifecycle
    os.umask(0o077)
    initial_source = source_version()
    artifacts = ROOT / "output" / "playwright" / "maintenance-lab" / uuid4().hex
    artifacts.mkdir(parents=True, mode=0o700)
    print(f"Maintenance acceptance evidence: {artifacts}", flush=True)
    with tempfile.TemporaryDirectory(prefix="praho-maintenance-portal-") as temporary, ExitStack() as stack:
        run_dir = Path(temporary).resolve()
        platform_port, portal_port = free_port(), free_port()
        while portal_port == platform_port:
            portal_port = free_port()
        authority = run_dir / "authority.json"
        authority.write_text(
            json.dumps(
                {
                    "secret": secrets.token_urlsafe(48),
                    "platform_port": platform_port,
                    "portal_port": portal_port,
                }
            )
        )
        authority.chmod(0o600)
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT"}
        }
        env.update(
            {
                "PRAHO_SKIP_DOTENV": "1",
                "DJANGO_SETTINGS_MODULE": "config.settings.lab",
                "VIRTUALMIN_MAINTENANCE_LAB": "1",
                "VIRTUALMIN_MAINTENANCE_AUTHORITY": str(authority),
                "VIRTUALMIN_MAINTENANCE_MANIFEST": str(run_dir / "manifest.json"),
                "VIRTUALMIN_LAB_DATABASE": str(run_dir / "seed.sqlite3"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
            }
        )

        def service_env(service: str) -> dict[str, str]:
            return {**env, "PYTHONPATH": f"{ROOT / 'services/platform'}:{ROOT}" if service == "platform" else ""}

        def manage(service: str, *args: str) -> None:
            with (artifacts / f"{service}-setup.log").open("ab") as output:
                subprocess.run(  # noqa: S603 -- current interpreter, fixed management commands and owned fixture paths
                    [sys.executable, "manage.py", *args],
                    cwd=ROOT / "services" / service,
                    env=service_env(service),
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=1200,
                    check=True,
                )

        print("Migrating an owned Platform seed database", flush=True)
        manage("platform", "migrate", "--noinput")
        fixture_source = ROOT / "tests" / "virtualmin_lab" / "maintenance_fixtures.py"
        manage("platform", "shell", "-c", f"import runpy\nrunpy.run_path({str(fixture_source)!r})['seed']()")
        source = sqlite3.connect(f"file:{run_dir / 'seed.sqlite3'}?mode=ro", uri=True)
        target = sqlite3.connect(run_dir / "platform.sqlite3")
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        env["VIRTUALMIN_LAB_DATABASE"] = str(run_dir / "platform.sqlite3")
        manage("portal", "migrate", "--noinput")
        processes = {}
        children = {}
        for service, port in (("platform", platform_port), ("portal", portal_port)):
            log = stack.enter_context((artifacts / f"{service}.log").open("wb"))
            command = "virtualmin_lab_runserver" if service == "platform" else "runserver"
            args = [sys.executable, "manage.py", command, f"127.0.0.1:{port}", "--noreload"]
            if service == "platform":
                args.append("--maintenance-fixture")
            child = subprocess.Popen(  # noqa: S603 -- current interpreter, fixed command and owned loopback address
                args,
                cwd=ROOT / "services" / service,
                env=service_env(service),
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            stack.callback(stop, child)
            processes[service] = child.pid
            children[service] = child
            login_path = "/auth/login/" if service == "platform" else "/login/"
            wait_ready(child, f"http://127.0.0.1:{port}{login_path}")
        test_env = service_env("platform")
        test_env.update(
            {
                "VIRTUALMIN_E2E": "1",
                "E2E_STRICT": "1",
                "DJANGO_ALLOW_ASYNC_UNSAFE": "true",
                "PLATFORM_BASE_URL": f"http://127.0.0.1:{platform_port}",
                "PORTAL_BASE_URL": f"http://127.0.0.1:{portal_port}",
                "VIRTUALMIN_MAINTENANCE_ARTIFACTS": str(artifacts),
            }
        )
        result = subprocess.run(  # noqa: S603 -- current interpreter, fixed acceptance test and caller-supplied pytest filters
            [
                sys.executable,
                "-m",
                "pytest",
                "-c",
                "tests/virtualmin_lab/pytest.ini",
                "--rootdir",
                str(ROOT),
                "-m",
                "virtualmin_maintenance_lab",
                "--tracing=retain-on-failure",
                "--screenshot=only-on-failure",
                f"--output={artifacts / 'browser'}",
                f"--junitxml={artifacts / 'junit.xml'}",
                "tests/e2e/platform/test_virtualmin_lab_maintenance.py",
                *sys.argv[1:],
            ],
            cwd=ROOT,
            env=test_env,
            timeout=900,
            check=False,
        )
        stack.close()
        for name in ("worker.jsonl",):
            receipt = run_dir / name
            if receipt.is_file():
                shutil.copy2(receipt, artifacts / name)
        if (run_dir / "mail").is_dir():
            shutil.copytree(run_dir / "mail", artifacts / "mail")
        source_unchanged = initial_source == source_version()
        (artifacts / "run.json").write_text(
            json.dumps(
                {
                    "source": initial_source,
                    "source_unchanged": source_unchanged,
                    "process_ids": processes,
                    "process_exit_codes": {service: child.returncode for service, child in children.items()},
                    "ports": {"platform": platform_port, "portal": portal_port},
                    "pytest_exit_code": result.returncode,
                    "fixture": "owned current-schema seed copied with SQLite backup API; no native or provider credentials",
                },
                indent=2,
            )
        )
        if not source_unchanged:
            print("Source changed during acceptance; result is diagnostic only. Repeat on frozen source.", flush=True)
            return 1
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
