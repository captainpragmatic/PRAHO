"""Behind Caddy, the edge owns HSTS, and its value comes from one per-environment setting.

Every Caddy config used to hardcode `max-age=31536000; includeSubDomains; preload`, inside a
`header` block that also deletes `Server`. That deletion defers the block, and a deferred header
REPLACES the upstream's (verified against caddy:2-alpine 2.11.7). Staging's one-hour policy in Django
therefore never reached a browser, and `preload` was sent for a domain that was never submitted to
the preload list.

The value is now `HSTS_POLICY`, which staging sets to `max-age=3600`. Each site sets it twice, on
purpose:
- the deferred block replaces whatever HSTS Django sends;
- an immediate `header` line covers responses Caddy generates itself (a 502 with the upstream down),
  which skip deferred headers. Also verified: 200 and 502, GET and HEAD, each carry exactly one
  header.

An `HSTS_POLICY` that is set but EMPTY makes Caddy send an empty header, which turns HSTS off. So
every place that forwards the variable carries the non-empty default itself.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = PROJECT_ROOT / "deploy"
DEFAULT_POLICY = "max-age=31536000; includeSubDomains"
CADDY_VALUE = "{$HSTS_POLICY:" + DEFAULT_POLICY + "}"
TEMPLATE_VALUE = "{{ hsts_policy }}"

# Named so the scan below is checked against them: a glob that silently matched nothing would pass.
KNOWN_CADDY_CONFIGS = {
    "deploy/caddy/Caddyfile",
    "deploy/caddy/Caddyfile.portal",
    "deploy/caddy/Caddyfile.platform",
    "deploy/ansible/roles/praho/templates/Caddyfile.j2",
    "deploy/ansible/roles/praho-native/templates/Caddyfile.native.j2",
}

# Any Caddy spelling of the field: the one-line directive, or a line inside a `header { }` block,
# with or without an operation prefix.
_HSTS_VALUE = re.compile(r'^\s*(?:header\s+)?[+?>]?Strict-Transport-Security\s+"([^"]*)"', re.IGNORECASE | re.MULTILINE)
_IMMEDIATE_HSTS = re.compile(r"^\s*header\s+Strict-Transport-Security\s", re.IGNORECASE | re.MULTILINE)


def _relative(path: Path) -> str:
    return str(path.relative_to(PROJECT_ROOT))


def _caddy_configs() -> list[Path]:
    return sorted(path for path in DEPLOY.rglob("Caddyfile*") if path.is_file())


def _site_count(text: str) -> int:
    # Every site's deferred header block deletes Server, so this counts the site blocks.
    return text.count("-Server")


class TestEdgeHstsPolicy:
    @pytest.mark.integration
    @pytest.mark.security
    def test_the_scan_sees_every_known_caddy_config(self):
        assert {_relative(path) for path in _caddy_configs()} >= KNOWN_CADDY_CONFIGS

    @pytest.mark.integration
    @pytest.mark.security
    def test_every_caddy_hsts_value_is_the_environment_policy(self):
        offending = {}
        for path in _caddy_configs():
            text = path.read_text()
            expected = TEMPLATE_VALUE if path.suffix == ".j2" else CADDY_VALUE
            values = _HSTS_VALUE.findall(text)
            if len(values) != 2 * _site_count(text) or any(value != expected for value in values):
                offending[_relative(path)] = values
        assert offending == {}, f"each site must set HSTS to {CADDY_VALUE!r} (templates: {TEMPLATE_VALUE!r}) twice"

    @pytest.mark.integration
    @pytest.mark.security
    def test_every_site_also_sets_hsts_outside_the_deferred_block(self):
        offending = {
            _relative(path): len(_IMMEDIATE_HSTS.findall(path.read_text()))
            for path in _caddy_configs()
            if len(_IMMEDIATE_HSTS.findall(path.read_text())) != _site_count(path.read_text())
        }
        assert offending == {}, "a deferred header is skipped on Caddy-generated errors, so each site needs both"

    @pytest.mark.integration
    @pytest.mark.security
    def test_no_edge_default_preloads(self):
        for path in _caddy_configs():
            hsts_lines = [line for line in path.read_text().splitlines() if "strict-transport-security" in line.lower()]
            assert not any("preload" in line for line in hsts_lines), _relative(path)

    @pytest.mark.integration
    @pytest.mark.security
    def test_compose_forwards_the_policy_with_a_non_empty_default(self):
        forwarded = f"HSTS_POLICY=${{HSTS_POLICY:-{DEFAULT_POLICY}}}"
        mounting = [path for path in sorted(DEPLOY.glob("docker-compose*.yml")) if "Caddyfile" in path.read_text()]
        assert len(mounting) >= 3, [_relative(path) for path in mounting]
        missing = [_relative(path) for path in mounting if forwarded not in path.read_text()]
        assert missing == [], f"forward {forwarded!r}: an empty HSTS_POLICY disables HSTS"

    @pytest.mark.integration
    @pytest.mark.security
    def test_staging_sets_the_short_policy(self):
        assert "\nHSTS_POLICY=max-age=3600" in (PROJECT_ROOT / ".env.example.staging").read_text()

    @pytest.mark.integration
    @pytest.mark.security
    def test_both_ansible_roles_resolve_the_policy_with_a_default(self):
        native = (DEPLOY / "ansible/roles/praho-native/templates/Caddyfile.native.j2").read_text()
        assert "deployed_env.HSTS_POLICY" in native
        assert "'max-age=3600' if (praho_env | default('prod')) == 'staging'" in native  # upgraded staging
        assert DEFAULT_POLICY in native
        docker_defaults = (DEPLOY / "ansible/roles/praho/defaults/main.yml").read_text()
        assert "hsts_policy:" in docker_defaults
        assert "max-age=3600" in docker_defaults
        assert DEFAULT_POLICY in docker_defaults
