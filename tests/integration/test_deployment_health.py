"""Health must reflect the local topology and fail closed on ambiguous Docker state."""

import json
from pathlib import Path

import pytest
import yaml

from tests.integration.test_deploy_scripts import Project

ROOT = Path(__file__).resolve().parents[2]
DOCKER = '''#!{python}
import json, os, sys
args = sys.argv[1:]
if os.environ.get("INVENTORY_ERROR"):
    sys.exit(1)
if args[0] == "ps":
    print(os.environ["INVENTORY"])
elif args[0] == "inspect":
    if os.environ.get("INSPECT_ERROR"):
        sys.exit(1)
    print(json.loads(os.environ["STATES"]).get(args[-1], "running healthy"))
'''


@pytest.mark.parametrize(("topology", "inventory", "args"), [
    ("single-server", "praho_db praho_platform praho_portal praho_qcluster praho_caddy", []),
    ("platform-only", "praho_platform praho_qcluster", []),
    ("platform-only", "praho_platform praho_qcluster praho_db praho_caddy", ["--with-db", "--with-caddy"]),
    ("portal-only", "praho_portal", []),
    ("portal-only", "praho_portal praho_portal_caddy", ["--with-caddy"]),
    ("container-service", "praho_platform praho_portal praho_qcluster", []),
])
def test_each_topology_checks_its_local_services(tmp_path: Path, topology: str, inventory: str, args: list[str]) -> None:
    import sys  # noqa: PLC0415

    project = Project(tmp_path)
    (tmp_path / "bin/docker").write_text(DOCKER.format(python=sys.executable))
    states = dict.fromkeys(("praho_qcluster", "praho_caddy", "praho_portal_caddy"), "running no-healthcheck")
    result = project.run("health-check.sh", topology, *args, INVENTORY="\n".join(inventory.split()), STATES=json.dumps(states))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "[FAIL]" not in result.stdout
    if "praho_qcluster" in inventory:
        assert "job execution requires a separate queue check" in result.stdout


@pytest.mark.parametrize("state", ["running starting", "running unhealthy", "running unknown", "running", "exited healthy", "running no-healthcheck"])
def test_ambiguous_or_failed_web_health_fails(tmp_path: Path, state: str) -> None:
    import sys  # noqa: PLC0415

    project = Project(tmp_path)
    (tmp_path / "bin/docker").write_text(DOCKER.format(python=sys.executable))
    result = project.run("health-check.sh", "portal-only", INVENTORY="praho_portal", STATES=json.dumps({"praho_portal": state}))
    assert result.returncode != 0
    assert "[FAIL] praho_portal" in result.stdout


@pytest.mark.parametrize("failure", [{"INVENTORY_ERROR": "1"}, {"INSPECT_ERROR": "1"}, {"INVENTORY": ""}])
def test_missing_services_and_docker_errors_fail(tmp_path: Path, failure: dict[str, str]) -> None:
    import sys  # noqa: PLC0415

    project = Project(tmp_path)
    (tmp_path / "bin/docker").write_text(DOCKER.format(python=sys.executable))
    result = project.run("health-check.sh", "portal-only", **{"INVENTORY": "praho_portal", "STATES": "{}", **failure})
    assert result.returncode != 0
    assert "[FAIL]" in result.stdout + result.stderr


def test_dev_worker_reuses_platform_inputs_and_waits_for_completed_setup() -> None:
    services = yaml.safe_load((ROOT / "deploy/docker-compose.dev.yml").read_text())["services"]
    platform, worker = services["platform"], services["qcluster"]
    for key in ("build", "volumes", "environment"):
        assert worker[key] == platform[key]
    assert worker["build"]["target"] == "dev"
    assert worker["depends_on"] == {"platform": {"condition": "service_healthy"}}
    assert worker["command"] == "python manage.py qcluster" and worker["healthcheck"]["disable"] is True
    assert "health/" in str(platform["healthcheck"])
    assert "migrate --noinput &&" in platform["command"] and "setup_initial_data &&" in platform["command"]


def test_make_forwards_selected_topology_and_optional_components() -> None:
    import subprocess  # noqa: PLC0415

    completed = subprocess.run(["make", "-n", "health-check", "DEPLOY_TYPE=portal-only", "HEALTH_FLAGS=--with-caddy"], cwd=ROOT, capture_output=True, text=True, check=True)  # noqa: S607
    assert 'health-check.sh "portal-only" --with-caddy' in completed.stdout
