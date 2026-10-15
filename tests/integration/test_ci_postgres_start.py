"""CI starts the same real PostgreSQL major even when the first official registry fails."""

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
STUB = """#!{python}
import json, os, sys
args = sys.argv[1:]
with open(os.environ["TRACE"], "a") as output: output.write(json.dumps(args) + "\\n")
if args[0] == "pull":
    if os.environ.get("BOTH_FAIL") or ("public.ecr.aws" in args[-1] and os.environ.get("FIRST_FAIL")): sys.exit(1)
elif args[0] == "run":
    with open(args[args.index("--cidfile") + 1], "w") as output: output.write("a" * 64)
elif args[0] == "inspect": print("unhealthy" if os.environ.get("UNHEALTHY") else "healthy")
elif args[0] == "exec": print("160010")
"""


def execute(tmp_path: Path, *arguments: str, **extra: str) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    executable = tmp_path / "docker"
    executable.write_text(STUB.format(python=sys.executable))
    executable.chmod(0o755)
    trace = tmp_path / "trace"
    environment = {
        **os.environ,
        "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        "TRACE": str(trace),
        "RUNNER_TEMP": str(tmp_path),
        "POSTGRES_PASSWORD": secrets.token_urlsafe(24),
        **extra,
    }
    completed = subprocess.run(  # noqa: S603 -- fixed CI helper with a temporary Docker recorder.
        ["/bin/bash", str(ROOT / "scripts/start_ci_postgres.sh"), *arguments],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return completed, [json.loads(line) for line in trace.read_text().splitlines()]


@pytest.mark.parametrize("tag", ["16", "16-alpine"])
def test_registry_failure_falls_back_without_changing_major_or_readiness(tmp_path: Path, tag: str) -> None:
    completed, calls = execute(tmp_path, tag, FIRST_FAIL="1")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert [call[-1] for call in calls if call[0] == "pull"] == [
        f"public.ecr.aws/docker/library/postgres:{tag}",
        f"docker.io/library/postgres:{tag}",
    ]
    run = next(call for call in calls if call[0] == "run")
    assert run[-1] == f"docker.io/library/postgres:{tag}" and "--health-cmd" in run
    assert "127.0.0.1:5432:5432" in run
    assert any(call[0] == "exec" and "SHOW server_version_num" in call for call in calls)
    if tag == "16-alpine":
        assert "--tmpfs" in run and "--shm-size=256mb" in run and "POSTGRES_INITDB_ARGS" in run
    stopped, cleanup = execute(tmp_path, "--stop")
    assert stopped.returncode == 0
    assert ["rm", "--force", "--volumes", "a" * 64] in cleanup
    assert not (tmp_path / "praho-ci-postgres.cid").exists()


def test_both_registry_failures_abort_before_database_start(tmp_path: Path) -> None:
    completed, calls = execute(tmp_path, "16", BOTH_FAIL="1")
    assert completed.returncode != 0
    assert "unavailable from both registries" in completed.stderr
    assert not any(call[0] == "run" for call in calls)


def test_failed_health_cleans_up_its_own_container(tmp_path: Path) -> None:
    completed, calls = execute(tmp_path, "16", UNHEALTHY="1")
    assert completed.returncode != 0
    assert ["rm", "--force", "--volumes", "a" * 64] in calls
    assert not (tmp_path / "praho-ci-postgres.cid").exists()
