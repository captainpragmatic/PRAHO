"""Caddy deployment contracts and Docker acceptance checks.

Run structural checks with: pytest -o addopts='' tests/deploy/test_caddy_routing.py -m 'not docker'
Run container checks with: pytest -o addopts='' tests/deploy/test_caddy_routing.py -m docker -s
Docker checks require a working daemon and the official caddy:2-alpine image.
"""

from __future__ import annotations

import ast
import ipaddress
import json
import re
import shlex
import shutil
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

import pytest
import yaml
from jinja2 import Environment, StrictUndefined

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "caddy:2-alpine"
LOOPBACK = ["127.0.0.1/32", "::1/128"]
PORTAL_HOST = "portal.example.test"
PLATFORM_HOST = "platform.example.test"
CONFIGS = {
    "combined": "deploy/caddy/Caddyfile",
    "platform": "deploy/caddy/Caddyfile.platform",
    "portal": "deploy/caddy/Caddyfile.portal",
    "native": "deploy/ansible/roles/praho-native/templates/Caddyfile.native.j2",
    "docker": "deploy/ansible/roles/praho/templates/Caddyfile.j2",
}
# Public API paths the edge must route to the right upstream, with and without a
# trailing slash. This is a CADDY ROUTING contract only. It used to double as the
# middleware's HMAC-exemption list, and the two purposes disagreed: six more endpoints
# were marked public in code than were named here. The exemption contract is now
# PUBLIC_API_VIEWS below, read from the decorator itself.
PUBLIC_ROUTED_PATHS = {"/api/users/health", "/api/orders/products"}

# Views carrying @public_api_endpoint. The middleware no longer keeps a parallel path
# list; it resolves the request and reads this marker, so this set IS the contract for
# what bypasses HMAC authentication. The previous hardcoded path list named only two of
# these eight, which is why the other six answered 401 while being documented as public.
PUBLIC_API_VIEWS = {
    "available_service_plans_api",
    "currencies_api",
    "customer_register_api",
    "health_check",
    "obtain_token",
    "product_detail",
    "product_list",
    "support_categories_api",
}
STAFF_SESSION_PREFIXES = ["/api/customers/"]
# Equal to Django's DATA_UPLOAD_MAX_MEMORY_SIZE (10485760). That limit excludes file uploads,
# so the equivalence holds only because no public Platform route accepts multipart files.
PLATFORM_PUBLIC_BODY_CAP = "10MiB"
SHARED_PATHS = ("/dashboard/", "/billing/", "/tickets/", "/i18n/", "/cookie-policy/", "/auth/login/")
PUBLIC_ROUTES = (
    ("GET", "/api/users/health/"),
    ("POST", "/integrations/webhooks/stripe/"),
    ("POST", "/notifications/webhooks/mailgun/"),
    ("GET", "/notifications/unsubscribe/00000000-0000-0000-0000-000000000000/"),
    ("POST", "/api/users/login/"),
    ("POST", "/api/users/password-reset/"),
    ("GET", "/api/customers/1/services/"),  # Staff-session GET exception remains inside the public API.
)


def _read(path: str) -> str:
    return (ROOT / path).read_text()


def _config(name: str, allowed: list[str] | None = None, hsts_policy: str | None = None) -> str:
    source = _read(CONFIGS[name])
    if name in {"native", "docker"}:
        context: dict[str, object] = {
            "deployed_env": {
                "PORTAL_DOMAIN": PORTAL_HOST,
                "PLATFORM_DOMAIN": PLATFORM_HOST,
                "ACME_EMAIL": "admin@example.test",
                **({} if hsts_policy is None else {"HSTS_POLICY": hsts_policy}),
            },
            # The Docker role's default (deploy/ansible/roles/praho/defaults/main.yml) for prod.
            "hsts_policy": hsts_policy or "max-age=31536000; includeSubDomains",
            "portal_domain": PORTAL_HOST,
            "platform_domain": PLATFORM_HOST,
            "acme_email": "admin@example.test",
            "project_root": "/srv",
            "portal_port": 8701,
            "platform_port": 8700,
            "deploy_portal": True,
            "deploy_platform": True,
            "ansible_default_ipv4": {"address": "192.0.2.10"},
        }
        if allowed is not None:
            context["platform_allowed_ips"] = allowed
        env = Environment(undefined=StrictUndefined, autoescape=False)  # noqa: S701  # Caddy configuration, not HTML.
        return env.from_string(source).render(**context)
    values = {
        "PORTAL_DOMAIN": PORTAL_HOST,
        "PLATFORM_DOMAIN": PLATFORM_HOST,
        "ACME_EMAIL": "admin@example.test",
    }

    def expand(match: re.Match[str]) -> str:
        key, _, default = match.group(1).partition(":")
        return values.get(key, default)

    return re.sub(r"{\$([^}]+)}", expand, source)


@dataclass
class Directive:
    words: tuple[str, ...]
    children: list[Directive] = field(default_factory=list)


def _parse(source: str) -> list[Directive]:
    """Parse the emitted line-oriented subset, keeping sibling boundaries."""
    root: list[Directive] = []
    stack = [root]
    for raw in source.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "}":
            assert len(stack) > 1
            stack.pop()
            continue
        block = line.endswith(" {")
        words = tuple(shlex.split(line[:-2] if block else line, comments=True))
        node = Directive(words)
        stack[-1].append(node)
        if block:
            stack.append(node.children)
    assert len(stack) == 1
    return root


def _walk(nodes: list[Directive]) -> Iterator[Directive]:
    for node in nodes:
        yield node
        yield from _walk(node.children)


def _one(nodes: list[Directive], *words: str) -> Directive:
    matches = [node for node in nodes if node.words == words]
    assert len(matches) == 1, (words, [node.words for node in nodes])
    return matches[0]


def _proxy_targets(nodes: list[Directive]) -> list[str]:
    return [node.words[1] for node in _walk(nodes) if node.words[0] == "reverse_proxy"]


def _assert_contract(name: str, source: str, allowed: list[str] | None = None) -> None:
    sites = _parse(source)
    if name != "platform":
        portal = _one(sites, PORTAL_HOST).children
        assert all(target.endswith(":8701") for target in _proxy_targets(portal))
        assert _proxy_targets(_one(portal, "handle", "/status/").children)
        static = _one(portal, "handle_path", "/static/*").children
        expected_root = "/srv/static" if name == "portal" else "/srv/portal-static"
        _one(static, "root", "*", expected_root)
        fallback = _one(portal, "handle").children
        _one(_one(fallback, "request_body").children, "max_size", "5MB")
        assert len(_proxy_targets(fallback)) == 1
    if name != "portal":
        platform = _one(sites, PLATFORM_HOST).children
        handles = [node for node in platform if node.words[0] == "handle"]
        assert [node.words for node in handles] == [
            ("handle", "/api/users/health/*"),
            ("handle", "/integrations/webhooks/*"),
            ("handle", "/notifications/webhooks/*"),
            ("handle", "/notifications/unsubscribe/*"),
            ("handle", "/api/*"),
            ("handle", "@staff"),
        ]
        _one(platform, "@staff", "remote_ip", *(allowed or LOOPBACK))
        denial = _one(platform, "respond", "Access denied", "403")
        assert platform.index(denial) > platform.index(handles[-1])
        assert all(target.endswith(":8700") for target in _proxy_targets(platform))
        for public in handles[:5]:
            assert len(_proxy_targets(public.children)) == 1
            # Unauthenticated handles must not stream an unbounded body into a worker.
            _one(_one(public.children, "request_body").children, "max_size", PLATFORM_PUBLIC_BODY_CAP)
            assert not any(node.words[0].startswith("@") for node in _walk(public.children))
        assert not any(node.words[0] in {"handle_path", "reverse_proxy"} for node in platform)
        staff = handles[-1].children
        _one(staff, "handle_path", "/static/*")
        _one(staff, "handle_path", "/media/*")
        assert len(_proxy_targets(_one(staff, "handle").children)) == 1
    obsolete = {("handle", "/health/*"), ("handle", "/portal-health/*")}
    assert not any(node.words in obsolete for node in _walk(sites))


def _middleware_assignment(name: str) -> ast.expr:
    tree = ast.parse(_read("services/platform/apps/common/middleware.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            assert node.value is not None
            return node.value
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return node.value
    raise AssertionError(f"Missing middleware contract: {name}")


def _public_api_views() -> set[str]:
    """Every view marked @public_api_endpoint, asserting the marker sits outermost.

    Position is load-bearing, not style. The decorator only sets an attribute on the
    callable it is given, and the middleware reads that attribute off resolve().func.
    Applied BELOW @api_view the attribute lands on the inner function, api_view returns
    a new wrapper without it, and the endpoint answers 401 while still looking public in
    the source. That is the defect this contract exists to prevent recurring.
    """
    found: set[str] = set()
    for path in sorted((ROOT / "services" / "platform" / "apps" / "api").rglob("views.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            names = [d.id for d in node.decorator_list if isinstance(d, ast.Name)]
            if "public_api_endpoint" not in names:
                continue
            first = node.decorator_list[0]
            assert isinstance(first, ast.Name) and first.id == "public_api_endpoint", (
                f"{path.relative_to(ROOT)}:{node.lineno} {node.name}: @public_api_endpoint must be "
                "the outermost decorator or the middleware cannot see it and the endpoint 401s"
            )
            found.add(node.name)
    return found


@pytest.mark.parametrize("name", CONFIGS)
def test_route_ownership_and_public_exemptions(name: str) -> None:
    _assert_contract(name, _config(name))
    assert _public_api_views() == PUBLIC_API_VIEWS
    prefixes = _middleware_assignment("staff_session_allowed_prefixes")
    assert ast.literal_eval(prefixes) == STAFF_SESSION_PREFIXES


@pytest.mark.parametrize("name", ["native", "docker"])
@pytest.mark.parametrize("allowed", [[], ["198.51.100.10/32", "2001:db8:1234::/64"]])
def test_template_empty_list_stays_restricted_and_custom_list_is_preserved(name: str, allowed: list[str]) -> None:
    _assert_contract(name, _config(name, allowed), allowed or LOOPBACK)


@pytest.mark.parametrize("role", ["praho", "praho-native"])
def test_role_defaults_restrict_staff(role: str) -> None:
    values = yaml.safe_load(_read(f"deploy/ansible/roles/{role}/defaults/main.yml"))
    assert values["platform_allowed_ips"] == LOOPBACK


@pytest.mark.parametrize("environment", ["dev", "prod", "staging"])
def test_env_examples_use_distinct_domains_and_space_separated_cidrs(environment: str) -> None:
    source = _read(f".env.example.{environment}")
    values = dict(
        line.split("=", 1) for line in source.splitlines() if line and not line.startswith("#") and "=" in line
    )
    cidrs = shlex.split(values["PLATFORM_ALLOWED_CIDRS"])
    assert len(cidrs) == 1  # Quote the entire value so it is safe to source as well as parse as dotenv.
    assert cidrs[0].split() == LOOPBACK
    assert "," not in cidrs[0]
    for cidr in cidrs[0].split():
        ipaddress.ip_network(cidr)
    assert "PORTAL_DOMAIN" in values and "PLATFORM_DOMAIN" in values
    if environment == "dev":
        assert values["PORTAL_DOMAIN"] != values["PLATFORM_DOMAIN"]


@pytest.mark.parametrize("topology", ["single-server", "platform-only", "portal-only"])
def test_compose_forwards_domains_hosts_and_staff_cidrs(topology: str) -> None:
    services = yaml.safe_load(_read(f"deploy/docker-compose.{topology}.yml"))["services"]
    portal = "${PORTAL_DOMAIN:-${DOMAIN:-localhost}}"
    platform = (
        "${PLATFORM_DOMAIN:-${DOMAIN:-platform.localhost}}"
        if topology == "platform-only"
        else "${PLATFORM_DOMAIN:-platform.localhost}"
    )
    for service in ("platform", "portal", "caddy"):
        if service not in services:
            continue
        env = dict(item.split("=", 1) for item in services[service]["environment"])
        assert env["PLATFORM_DOMAIN"] == platform
        assert env["PORTAL_DOMAIN"] == portal
        if service == "caddy":
            assert env["PLATFORM_ALLOWED_CIDRS"] == "${PLATFORM_ALLOWED_CIDRS:-127.0.0.1/32 ::1/128}"
        else:
            host = platform if service == "platform" else portal
            assert env["ALLOWED_HOSTS"] == f"{host},localhost,{service}"
            assert env["CSRF_TRUSTED_ORIGINS"] == f"https://{host}"


@pytest.mark.parametrize(
    ("deployed", "expected"),
    [
        (None, "max-age=31536000; includeSubDomains"),
        ("", "max-age=31536000; includeSubDomains"),  # empty must not become an empty header
        ("max-age=3600", "max-age=3600"),
    ],
)
def test_native_template_renders_the_deployed_hsts_policy(deployed: str | None, expected: str) -> None:
    rendered = _config("native", hsts_policy=deployed)
    values = re.findall(r'Strict-Transport-Security "([^"]*)"', rendered)
    assert values and set(values) == {expected}


def _docker(*args: str, source: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["docker", *args],  # noqa: S607
        input=source,
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )


def _docker_ok(*args: str, source: str | None = None) -> str:
    result = _docker(*args, source=source)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


@pytest.fixture(scope="module")
def docker_daemon() -> None:
    """Skip the container checks where no Docker daemon is reachable."""
    if shutil.which("docker") is None or _docker("info").returncode != 0:
        pytest.skip("Docker daemon unavailable")


@pytest.mark.docker
@pytest.mark.parametrize("name", CONFIGS)
def test_official_caddy_validates_each_config(name: str, docker_daemon: None) -> None:
    source = _config(name)
    _assert_contract(name, source)
    _docker_ok(
        "run",
        "--rm",
        "-i",
        "--tmpfs",
        "/var/log/caddy",
        IMAGE,
        "caddy",
        "validate",
        "--adapter",
        "caddyfile",
        "--config",
        "/dev/stdin",
        source=source,
    )


@pytest.mark.docker
@pytest.mark.parametrize("name", ["combined", "platform", "native", "docker"])
def test_comma_separated_staff_cidrs_fail_validation(name: str, docker_daemon: None) -> None:
    source = _config(name)
    _assert_contract(name, source)
    invalid = source.replace("remote_ip 127.0.0.1/32 ::1/128", "remote_ip 127.0.0.1/32,::1/128")
    assert invalid != source
    result = _docker(
        "run",
        "--rm",
        "-i",
        "--tmpfs",
        "/var/log/caddy",
        IMAGE,
        "caddy",
        "validate",
        "--adapter",
        "caddyfile",
        "--config",
        "/dev/stdin",
        source=invalid,
    )
    assert result.returncode != 0
    assert "IP" in result.stderr or "CIDR" in result.stderr


def _http_fixture(source: str) -> str:
    # Keep every production matcher/proxy; substitute local HTTP transport and observable upstreams.
    source = re.sub(r"^    tls .+\n", "", source, flags=re.MULTILINE)
    for host in (PORTAL_HOST, PLATFORM_HOST):
        source = source.replace(host + " {", "http://" + host + " {")
    source = re.sub(r"output file [^\n]+ \{\s+roll_size \S+\s+roll_keep \d+\s+\}", "output stdout", source)
    return (
        source
        + """
:8700 {
    respond "platform {method} {uri}" 200
}
:8701 {
    respond "portal {method} {uri}" 200
}
"""
    )


def _observed_peer(edge: str, trace: str) -> str:
    for _ in range(20):
        logs = _docker("logs", edge)
        for line in (logs.stdout + logs.stderr).splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            request = record.get("request", {})
            if request.get("headers", {}).get("X-Test-Request") == [trace]:
                remote = request["remote_ip"]
                assert isinstance(remote, str)
                return remote
        time.sleep(0.05)
    raise AssertionError(f"No access log for request {trace}")


def _request(  # noqa: PLR0913  # Explicit transport, host, path and request data for routing checks.
    container: str, address: str, host: str, path: str, method: str = "GET", headers: tuple[str, ...] = (), *, edge: str
) -> tuple[int, str, str]:
    trace = uuid4().hex
    args = [
        "exec",
        container,
        "wget",
        "-S",
        "-O",
        "-",
        "-T",
        "5",
        "--header",
        f"Host: {host}",
        "--header",
        f"X-Test-Request: {trace}",
    ]
    for header in headers:
        args.extend(("--header", header))
    if method == "POST":
        args.append("--post-data=probe")
    result = _docker(*args, f"http://{address}{path}")
    statuses = re.findall(r"HTTP/1\.[01] (\d+)", result.stderr)
    assert statuses, result.stdout + result.stderr
    return int(statuses[-1]), result.stdout.strip(), _observed_peer(edge, trace)


@contextmanager
def _running_edge(name: str, tmp_path: Path, *, upstream_reads_body: bool = False) -> Iterator[tuple[str, str, str]]:
    suffix = uuid4().hex[:12]
    network, edge, peer = (f"routing-{suffix}-{part}" for part in ("net", "edge", "peer"))
    config = tmp_path / "Caddyfile"
    fixture = _http_fixture(_config(name))
    if upstream_reads_body:
        # The default responder answers without reading the body, so the proxy never hits a
        # request_body cap. Django reads it; consuming it here is what makes the cap observable.
        fixture = fixture.replace('respond "platform {method} {uri}" 200', 'respond "{http.request.body}" 200')
    config.write_text(fixture)
    _docker_ok("network", "create", network)
    try:
        _docker_ok(
            "run",
            "--rm",
            "-d",
            "--name",
            edge,
            "--network",
            network,
            "--publish",
            "0:80",
            "--add-host",
            "platform:127.0.0.1",
            "--add-host",
            "portal:127.0.0.1",
            "--tmpfs",
            "/var/log/caddy",
            "--volume",
            f"{config}:/etc/caddy/Caddyfile:ro",
            IMAGE,
        )
        _docker_ok(
            "run",
            "--rm",
            "-d",
            "--name",
            peer,
            "--network",
            network,
            "--add-host",
            "host.docker.internal:host-gateway",
            "--entrypoint",
            "sleep",
            IMAGE,
            "300",
        )
        for _ in range(30):
            ready = _docker("exec", edge, "wget", "-q", "-O", "-", "http://127.0.0.1:8700/")
            if ready.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise AssertionError(_docker("logs", edge).stderr)
        port = _docker_ok("port", edge, "80/tcp").splitlines()[0].rsplit(":", 1)[1]
        yield edge, peer, f"host.docker.internal:{port}"
    finally:
        _docker("rm", "-f", "-v", peer, edge)
        _docker_ok("network", "rm", network)


def _ownership_table(name: str) -> Iterator[tuple[str, str, str, str]]:
    public = list(PUBLIC_ROUTES)
    for path in sorted(PUBLIC_ROUTED_PATHS):
        public.extend((("GET", path), ("GET", path + "/")))
    if name != "platform":
        for method, path in [("GET", "/status/"), *public, *(("GET", path) for path in SHARED_PATHS)]:
            yield PORTAL_HOST, method, path, "portal"
        yield PORTAL_HOST, "POST", "/i18n/setlang/", "portal"
    if name != "portal":
        for method, path in public:
            yield PLATFORM_HOST, method, path, "platform"


@pytest.mark.docker
@pytest.mark.parametrize("name", CONFIGS)
def test_live_routing_spoofed_headers_and_published_port(name: str, tmp_path: Path, docker_daemon: None) -> None:
    _assert_contract(name, _config(name))
    with _running_edge(name, tmp_path) as (edge, peer, published):
        for host, method, path, owner in _ownership_table(name):
            status, body, remote = _request(peer, edge, host, path, method, edge=edge)
            assert (status, body) == (200, f"{owner} {method} {path}")
            assert not ipaddress.ip_address(remote).is_loopback
        if name == "portal":
            return
        for path in (*SHARED_PATHS, "/static/probe.css", "/media/probe.txt", "/unknown/"):
            status, _, _ = _request(peer, edge, PLATFORM_HOST, path, edge=edge)
            assert status == 403
        status, body, remote = _request(edge, "127.0.0.1", PLATFORM_HOST, "/dashboard/", edge=edge)
        assert (status, body) == (200, "platform GET /dashboard/")
        assert ipaddress.ip_address(remote).is_loopback
        for address in (edge, published):
            for headers in (
                (),
                ("X-Forwarded-For: 127.0.0.1",),
                ("X-Real-IP: 127.0.0.1",),
                ("X-Forwarded-For: ::1", "X-Real-IP: ::1"),
            ):
                status, _, remote = _request(peer, address, PLATFORM_HOST, "/dashboard/", headers=headers, edge=edge)
                assert not ipaddress.ip_address(remote).is_loopback, f"{address} presented loopback peer {remote}"
                assert status == 403, (address, headers, remote)
                print(f"{name}: {address} observed peer {remote}; status={status}; headers={headers}")


def test_platform_public_body_cap_matches_django_upload_limit() -> None:
    """The edge cap and Django's own limit must move together, or one silently wins."""
    tree = ast.parse(_read("services/platform/config/settings/base.py"))
    limits = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "DATA_UPLOAD_MAX_MEMORY_SIZE" for target in node.targets)
    ]
    assert len(limits) == 1 and isinstance(limits[0], ast.Constant)
    assert PLATFORM_PUBLIC_BODY_CAP == "10MiB"
    assert limits[0].value == 10 * 1024 * 1024


def _post_size(peer: str, edge: str, path: str, size: int) -> int:
    """POST ``size`` bytes to the Platform host from the peer and return the final status."""
    # Not NUL bytes: busybox wget sends --post-file as a C string, so a NUL body posts nothing.
    _docker_ok("exec", peer, "sh", "-c", f"head -c {size} /dev/zero | tr '\\0' a > /tmp/body")
    result = _docker(
        "exec",
        peer,
        "wget",
        "-S",
        "-O",
        "/dev/null",
        "-T",
        "15",
        "--header",
        f"Host: {PLATFORM_HOST}",
        "--post-file=/tmp/body",
        f"http://{edge}{path}",
    )
    statuses = re.findall(r"HTTP/1\.[01] (\d+)", result.stderr)
    assert statuses, result.stdout + result.stderr
    return int(statuses[-1])


@pytest.mark.docker
@pytest.mark.parametrize("name", [name for name in CONFIGS if name != "portal"])
def test_live_platform_public_body_cap(name: str, tmp_path: Path, docker_daemon: None) -> None:
    """At the cap a public POST is proxied; one byte over, the edge refuses it with 413."""
    limit = 10 * 1024 * 1024
    with _running_edge(name, tmp_path, upstream_reads_body=True) as (edge, peer, _published):
        for path in ("/integrations/webhooks/stripe/", "/api/users/login/"):
            assert _post_size(peer, edge, path, limit) == 200, path
            assert _post_size(peer, edge, path, limit + 1) == 413, path
