"""PostgreSQL 15 data is inspected read-only and never upgraded by an image replacement."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
STUB = """#!{python}
import json,os,sys
args=sys.argv[1:]
with open(os.environ["TRACE"],"a") as output:output.write(json.dumps(args)+"\\n")
if os.environ.get("DAEMON_FAIL"):sys.exit(1)
if args[:2]==["volume","ls"]:
 if not os.environ.get("MISSING"):print("deploy_postgres_data")
elif args[0]=="run":print(os.environ.get("DATA_VERSION","16"))
"""


@pytest.mark.parametrize(
    ("version", "accepted"), [("15", False), ("16", True), ("empty", True), ("unknown-private-data", False)]
)
def test_existing_volume_is_checked_without_starting_postgres(tmp_path: Path, version: str, accepted: bool) -> None:
    stub = tmp_path / "docker"
    stub.write_text(STUB.format(python=sys.executable))
    stub.chmod(0o755)
    trace = tmp_path / "trace"
    configuration = {
        "services": {
            "db": {
                "image": "postgres:16-alpine",
                "volumes": [{"type": "volume", "source": "postgres_data", "target": "/var/lib/postgresql/data"}],
            }
        },
        "volumes": {"postgres_data": {"name": "deploy_postgres_data"}},
    }
    result = subprocess.run(  # noqa: S603 -- fixed helper, fixture configuration and a recording Docker stub.
        [sys.executable, str(ROOT / "deploy/scripts/check_postgres_version.py")],
        input=json.dumps(configuration),
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            "TRACE": str(trace),
            "DATA_VERSION": version,
        },
    )
    assert (result.returncode == 0) == accepted, result.stderr
    calls = [json.loads(line) for line in trace.read_text().splitlines()]
    holder = next(call for call in calls if call[0] == "run")
    assert "--read-only" in holder and "--entrypoint" in holder
    assert "type=volume,src=deploy_postgres_data,dst=/database,readonly" in holder
    assert holder[holder.index("--entrypoint") + 1] == "sh"
    assert "unknown-private-data" not in result.stdout + result.stderr


def test_fresh_compose_defaults_and_native_cluster_gate_select_16() -> None:
    for name in ("single-server", "platform-only", "dev"):
        image = yaml.safe_load((ROOT / f"deploy/docker-compose.{name}.yml").read_text())["services"]["db"]["image"]
        assert image in {"postgres:16", "postgres:16-alpine"}
    tasks = yaml.safe_load((ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml").read_text())
    names = [task["name"] for task in tasks]
    assert names.index("Refuse implicit native PostgreSQL major upgrades") < names.index("Install PostgreSQL 16")
    gate = tasks[names.index("Refuse implicit native PostgreSQL major upgrades")]["assert"]
    assert "reject('equalto', 16)" in gate["that"][0] and "DB_PORT" in gate["that"][1]


@pytest.mark.parametrize(
    ("major", "port", "accepted"), [(None, "5432", True), (16, "5432", True), (15, "5432", False), (16, "5433", False)]
)
def test_real_native_preflight_checks_clusters_before_mutation(
    tmp_path: Path, major: int | None, port: str, accepted: bool
) -> None:
    import shutil  # noqa: PLC0415

    tasks = yaml.safe_load((ROOT / "deploy/ansible/roles/praho-native/tasks/main.yml").read_text())
    selected = [
        task
        for task in tasks
        if task["name"]
        in {
            "Detect existing PostgreSQL cluster tool",
            "Inspect registered PostgreSQL clusters",
            "Record existing PostgreSQL major versions",
            "Refuse implicit native PostgreSQL major upgrades",
        }
    ]
    tool = tmp_path / "pg_lsclusters"
    tool.write_text(
        "#!/bin/sh\n"
        + (f"printf '{major} main 5432 online postgres /fixture /fixture/log\\n'\n" if major else "exit 0\n")
    )
    tool.chmod(0o755)
    selected[0]["stat"]["path"] = str(tool)
    selected[1]["command"] = f"{tool} --no-header"
    marker = tmp_path / "changed"
    play = [
        {
            "hosts": "localhost",
            "gather_facts": False,
            "vars": {"deployed_env": {"DB_PORT": port}},
            "tasks": [*selected, {"copy": {"content": "mutation", "dest": str(marker)}}],
        }
    ]
    path = tmp_path / "preflight.yml"
    path.write_text(yaml.safe_dump(play))
    local = Path(sys.executable).with_name("ansible-playbook")
    controller = str(local) if local.is_file() else (shutil.which("ansible-playbook") or "ansible-playbook")
    completed = subprocess.run(  # noqa: S603 -- actual selected role tasks use only local fixture paths.
        [controller, "-i", "localhost,", "-c", "local", str(path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
        env={
            **os.environ,
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible"),
            "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote-ansible"),
        },
    )
    assert (completed.returncode == 0) == accepted, completed.stdout + completed.stderr
    assert marker.exists() == accepted
    if not accepted:
        assert "Migrate and retire legacy clusters explicitly" in completed.stdout


def test_absent_volume_can_initialize_but_daemon_failure_is_not_absence() -> None:
    from unittest.mock import patch  # noqa: PLC0415

    from deploy.scripts.check_postgres_version import check  # noqa: PLC0415

    configuration = {
        "services": {
            "db": {
                "image": "postgres:16",
                "volumes": [{"type": "volume", "source": "data", "target": "/var/lib/postgresql/data"}],
            }
        },
        "volumes": {"data": {"name": "fixture_data"}},
    }
    with patch("deploy.scripts.check_postgres_version.docker", return_value="") as backend:
        check(configuration)
        assert backend.call_count == 1
    with patch(
        "deploy.scripts.check_postgres_version.docker", side_effect=subprocess.CalledProcessError(1, "docker")
    ) as backend:
        with pytest.raises(subprocess.CalledProcessError):
            check(configuration)
        assert backend.call_count == 1
