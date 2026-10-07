"""The split Docker stacks must not publish the application ports to the network.

docker-compose.platform-only.yml and docker-compose.portal-only.yml published 8700 and 8701 on every
host interface, so anyone who could reach the host bypassed Caddy: its TLS, its HSTS and, for the
platform, the PLATFORM_ALLOWED_CIDRS staff allowlist. Their Caddy reaches the app over the Docker
network, so the host port only serves a proxy on the same machine; it is now bound to 127.0.0.1 unless
PLATFORM_BIND / PORTAL_BIND says otherwise (an external load balancer).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = PROJECT_ROOT / "deploy"
# Every variable either file requires (both portal key spellings, so it holds before and after the
# portal gets its own key).
REQUIRED_ENV = (
    "DJANGO_SECRET_KEY=s\nPORTAL_DJANGO_SECRET_KEY=p\nDB_PASSWORD=d\nPLATFORM_API_SECRET=h\n"
    "PLATFORM_TO_PORTAL_WEBHOOK_SECRET=w\nPLATFORM_API_BASE_URL=https://platform.example.com/api\n"
    "PORTAL_TRUSTED_PROXY_CIDRS=10.0.0.0/8\n"
)
APP_PORTS = {"platform-only": ("platform", 8700, "PLATFORM_BIND"), "portal-only": ("portal", 8701, "PORTAL_BIND")}


def _published(name: str, tmp_path: Path, extra: str = "") -> list[dict[str, Any]]:
    env_file = tmp_path / ".env.prod"
    env_file.write_text(REQUIRED_ENV + extra)
    result = subprocess.run(  # noqa: S603  # Fixed docker invocation.
        [shutil.which("docker") or "docker", "compose", "--env-file", str(env_file), "-f",
         str(DEPLOY / f"docker-compose.{name}.yml"), "config", "--format", "json"],
        # Only what the docker CLI needs: a shell variable would beat the env file.
        env={
            **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME") or k.startswith("DOCKER_")},
            "PRAHO_ENV_FILE": str(env_file),
        },
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stderr
    service, port, _ = APP_PORTS[name]
    ports: list[dict[str, Any]] = json.loads(result.stdout)["services"][service].get("ports", [])
    return [p for p in ports if p["target"] == port]


class TestSplitStackPorts:
    @pytest.mark.integration
    @pytest.mark.parametrize("name", sorted(APP_PORTS))
    def test_the_app_port_is_loopback_only_by_default(self, name: str, tmp_path: Path) -> None:
        published = _published(name, tmp_path)
        assert published, name
        assert {p.get("host_ip") for p in published} == {"127.0.0.1"}

    @pytest.mark.integration
    @pytest.mark.parametrize("name", sorted(APP_PORTS))
    def test_an_external_proxy_can_ask_for_another_address(self, name: str, tmp_path: Path) -> None:
        variable = APP_PORTS[name][2]
        published = _published(name, tmp_path, f"{variable}=0.0.0.0\n")
        assert {p.get("host_ip") for p in published} == {"0.0.0.0"}

    @pytest.mark.integration
    @pytest.mark.parametrize("compose_file", sorted(DEPLOY.glob("docker-compose.*.yml")))
    def test_no_standalone_file_publishes_an_app_port_without_a_host_address(self, compose_file: Path) -> None:
        services = yaml.safe_load(compose_file.read_text())["services"]
        for name, service in services.items():
            for entry in service.get("ports", []):
                # `${PORT:-8700}` holds a colon of its own: count the parts with each expression collapsed.
                parts = re.sub(r"\$\{[^}]*\}", "X", str(entry)).split(":")
                if parts[-1] in ("8700", "8701") and compose_file.name != "docker-compose.dev.yml":
                    assert len(parts) == 3, (compose_file.name, name, entry)
