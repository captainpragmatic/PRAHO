"""Native origins use peer restrictions and durable maintenance gates."""

import shutil
import subprocess
from pathlib import Path

import pytest
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[2]


def render(platform: bool, portal: bool, legacy: bool = False) -> str:
    return Environment(undefined=StrictUndefined).from_string(  # noqa: S701 -- Caddy configuration
        (ROOT / "deploy/ansible/roles/praho-native/templates/Caddyfile.native.j2").read_text()
    ).render(native_platform=platform, native_portal=portal, native_legacy_portal_origin=legacy, native_topology="split", praho_env="prod",
             deployed_env={"PLATFORM_DOMAIN": "staff.example.test", "PORTAL_DOMAIN": "portal.example.test",
                           "PRAHO_PORTAL_API_SOURCE_CIDRS": "192.0.2.20/32",
                           "PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS": "192.0.2.10/32",
                           "PRAHO_MONITORING_CIDRS": "192.0.2.30/32",
                           "PRAHO_ADDRESS_IPV4_DOMAIN": "v4.example.test",
                           "PRAHO_ADDRESS_IPV6_DOMAIN": "v6.example.test"},
             platform_port=8700, portal_port=8701, project_root="/opt/praho",
             ansible_default_ipv4={"address": "192.0.2.10"})


def test_only_owned_origins_are_rendered() -> None:
    platform = render(True, False)
    portal = render(False, True)
    assert "\nstaff.example.test {" in platform
    assert "\nportal.example.test {" not in platform
    assert "\nportal.example.test {" in portal
    assert "\nstaff.example.test {" not in portal


def test_owned_sites_share_security_headers() -> None:
    config = render(True, True)
    assert config.count("(native_security) {") == 1
    for domain in ("staff.example.test", "portal.example.test", "v4.example.test", "v6.example.test"):
        block = config.split(f"\n{domain} {{", 1)[1].split("\n}", 1)[0]
        assert "import native_security" in block, domain


def test_cutover_retains_a_maintenance_only_old_portal_origin() -> None:
    config = render(True, False, legacy=True)
    portal = config.split("\nportal.example.test {", 1)[1].split("\nstaff.example.test {", 1)[0]
    assert 'respond "Scheduled maintenance" 503' in portal
    assert 'Retry-After "600"' in portal
    assert "reverse_proxy" not in portal


def test_health_precedes_api_and_has_independent_peer_allowlist() -> None:
    config = render(True, False)
    assert "path /api/users/health /api/users/health/*" in config
    assert "remote_ip 192.0.2.30/32 127.0.0.1/32 ::1/128" in config
    assert config.index("handle @platform_health") < config.index("handle @api")
    assert "remote_ip 192.0.2.20/32" in config
    assert "client_ip" not in config


def test_maintenance_and_callback_gates_are_files_outside_deployed_code() -> None:
    config = render(True, True)
    assert "root /etc/praho-native" in config
    assert "try_files hold-platform" in config
    assert "try_files hold-portal" in config
    assert "try_files hold-callbacks" in config
    assert '"error":"maintenance"' in config
    assert 'header Retry-After "600"' in config
    assert "respond" in config and "503" in config


def test_address_origins_are_caddy_only_and_reject_forwarded_headers() -> None:
    config = render(False, True)
    for name in ("v4.example.test", "v6.example.test"):
        block = config.split(f"{name} {{", 1)[1]
        assert "method GET" in block and "path /" in block
        assert "{remote_host}" in block
        assert 'Access-Control-Allow-Origin "https://portal.example.test"' in block
        assert 'Cache-Control "no-store"' in block
        assert "header X-Forwarded-For *" in block
        assert "header Forwarded *" in block
        assert "reverse_proxy" not in block


@pytest.mark.docker
@pytest.mark.parametrize("platform,portal,legacy", [(True, False, True), (False, True, False), (True, True, False)])
def test_caddy_validates_role_specific_origins_and_address_pair(platform: bool, portal: bool, legacy: bool) -> None:
    result = subprocess.run([shutil.which("docker") or "docker", "run", "--rm", "-i", "--tmpfs", "/var/log/caddy",  # noqa: S603 -- repository Caddy template, no shell
                             "public.ecr.aws/docker/library/caddy:2-alpine", "caddy", "validate", "--config", "/dev/stdin", "--adapter", "caddyfile"],
                            input=render(platform, portal, legacy), capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
