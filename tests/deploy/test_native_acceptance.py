"""Real native deployments: Ubuntu/systemd, SSH, frozen dependencies, PostgreSQL and verified TLS.

Run only with make test-native-deploy. Prerequisite failures are errors, never skips.
Every container and network belongs to this fixture; production is never contacted.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "praho-native-acceptance:26.04"
SPLIT = ("prod", "split")
DOCKER = shutil.which("docker") or "docker"
pytestmark = pytest.mark.docker


def docker(*arguments: str, data: str | None = None, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    result = subprocess.run([DOCKER, *arguments], input=data, capture_output=True, text=True, check=False, timeout=timeout)  # noqa: S603
    if check:
        assert result.returncode == 0, result.stdout[-5000:] + result.stderr[-5000:]
    return result


@dataclass
class NativeLab:
    controller: str
    platform: str
    portal: str
    monitor: str
    outsider: str
    environment: str
    mode: str
    sha: str
    addresses: dict[str, tuple[str, str]]
    artifact_directory: Path

    def execute(self, container: str, *arguments: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
        return docker("exec", container, *arguments, check=check, timeout=timeout)

    def deploy(self, *, rollback: bool = False) -> subprocess.CompletedProcess[str]:
        self.execute(self.controller, "truncate", "-s", "0", "/fixture/deployment.log")
        wrapper = """
import os, runpy, sys
from pathlib import Path
if os.getpid() != os.getpgrp():
    os.setsid()
Path('/fixture/deploy.pid').write_text(str(os.getpid()))
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name='__main__')
"""
        hosts = tuple(dict.fromkeys((self.controller, self.platform, self.portal)))
        for host in hosts:
            docker("cp", str(ROOT / "tests/deploy/native/argv_watch.py"), f"{host}:/fixture/argv_watch.py")
            self.execute(host, "rm", "-f", "/fixture/argv-watch.json")
            self.execute(host, "touch", "/fixture/argv-watch.running")
            # Each target observes only credentials it is authorized to hold.
            paths = ["/fixture/environment"] if host == self.controller else ["/opt/praho/.portal.env", "/opt/praho/.portal-static.env"]
            if host == self.platform:
                paths += ["/opt/praho/.env", "/opt/praho/.platform-deploy.env"]
            docker("exec", "-d", host, "/usr/bin/python3", "/fixture/argv_watch.py", *paths)
        try:
            result = docker("exec", "-e", "ANSIBLE_LOG_PATH=/fixture/deployment.log", self.controller,
                                "/opt/controller/bin/python", "-c", wrapper, "/work/deploy/scripts/native_env.py", "run",
                                "--env", self.environment, "--env-file", "/fixture/environment", "--version", self.sha,
                                *(["--rollback"] if rollback else []), check=False, timeout=1800)
        finally:
            for host in hosts:
                self.execute(host, "rm", "-f", "/fixture/argv-watch.running")
                deadline = time.monotonic() + 10
                while self.execute(host, "test", "-f", "/fixture/argv-watch.json", check=False).returncode:
                    assert time.monotonic() < deadline, "Credential observer did not finish"
                    time.sleep(0.1)
                report = json.loads(self.execute(host, "cat", "/fixture/argv-watch.json").stdout)
                (self.artifact_directory / f"{host}.argv.json").write_text(json.dumps(report))
                assert report["scans"] > 0 and report["exposures"] == 0, f"Credential exposure detected on {host}: {report}"
                if host == self.controller:
                    assert report["credentials_observed"] >= 6, report
        (self.artifact_directory / "deployment.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            for host in dict.fromkeys((self.platform, self.portal)):
                diagnostics = self.execute(host, "journalctl", "--no-pager", "-n", "80", "-u", "praho-platform", "-u", "praho-portal", check=False)
                (self.artifact_directory / f"{host}.journal.log").write_text(diagnostics.stdout + diagnostics.stderr)
            probe = docker("exec", "--user", "praho-portal", self.portal, "/bin/bash", "-c",
                           "set -a; . /opt/praho/.portal.env; set +a; "
                           "export PLATFORM_API_BASE_URL=https://staff.native.test/api; "
                           "/opt/praho/.venv-linux/bin/python /usr/local/lib/praho/native_probe.py api", check=False)
            (self.artifact_directory / "api-probe.log").write_text(probe.stdout + probe.stderr)
        return result

    def wait_for_phase(self, phase: str) -> None:
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            log = self.execute(self.controller, "cat", "/fixture/deployment.log", check=False).stdout
            if phase in log:
                return
            if "FAILED!" in log or "UNREACHABLE!" in log:
                pytest.fail("Deployment failed before the injected fault: " + log[-4000:])
            time.sleep(1)
        pytest.fail("Deployment never reached the required fault phase: " + phase)

    def revision(self, files: dict[str, str]) -> str:
        program = """
import json, sys
from pathlib import Path
for name, content in json.load(sys.stdin).items():
    path = Path('/fixture/repo') / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
"""
        docker("exec", "-i", self.controller, "/opt/controller/bin/python", "-c", program, data=json.dumps(files))
        self.execute(self.controller, "git", "-C", "/fixture/repo", "add", ".")
        self.execute(self.controller, "git", "-C", "/fixture/repo", "-c", "user.name=Deployment Fixture",
                     "-c", "user.email=fixture@example.test", "commit", "-qm", "test: native failure fixture")
        sha = self.execute(self.controller, "git", "-C", "/fixture/repo", "rev-parse", "HEAD").stdout.strip()
        self.execute(self.controller, "git", "-C", "/fixture/repo", "bundle", "create", "/fixture/revision.bundle", "--all")
        bundle = self.artifact_directory / "revision.bundle"
        docker("cp", f"{self.controller}:/fixture/revision.bundle", str(bundle))
        for host in dict.fromkeys((self.platform, self.portal)):
            docker("cp", str(bundle), f"{host}:/fixture/revision.bundle")
            self.execute(host, "git", "-C", "/fixture/repo", "fetch", "/fixture/revision.bundle", "HEAD")
            self.execute(host, "git", "-C", "/fixture/repo", "update-ref", "refs/heads/native-acceptance", sha)
        return sha

    def assert_coherent(self) -> None:
        for host in dict.fromkeys((self.platform, self.portal)):
            assert self.execute(host, "runuser", "-u", "praho", "--", "git", "-C", "/opt/praho/src", "rev-parse", "HEAD").stdout.strip() == self.sha

    def reboot(self) -> None:
        hosts = tuple(dict.fromkeys((self.platform, self.portal)))
        for host in hosts:
            docker("restart", host)
        deadline = time.monotonic() + 90
        for host in hosts:
            # Docker exec can run before PID 1 has even opened the system bus;
            # is-system-running may return "offline" instead of waiting for boot.
            while self.execute(host, "systemctl", "is-active", "--quiet", "caddy", check=False).returncode:
                assert time.monotonic() < deadline, f"Caddy did not become ready after reboot on {host}"
                time.sleep(0.2)

    def http(self, actor: str, domain: str, path: str, *, family: int = 4, headers: tuple[str, ...] = ()) -> tuple[int, str]:
        response = self.execute(actor, "curl", f"-{family}", "--silent", "--show-error", "--noproxy", "*",
                                "--max-time", "20", "--write-out", "\n%{http_code}",
                                *(argument for header in headers for argument in ("-H", header)), f"https://{domain}{path}")
        body, status = response.stdout.rsplit("\n", 1)
        return int(status), body

    def assert_held(self) -> None:
        for host, path in ((self.platform, "hold-platform"), (self.portal, "hold-portal"), (self.platform, "hold-workers")):
            self.execute(host, "test", "-f", "/etc/praho-native/" + path)
        active = self.execute(self.platform, "systemctl", "is-active", "praho-qcluster", check=False)
        assert active.returncode != 0
        actor = self.outsider if self.environment == "prod" else self.controller
        assert self.http(actor, "portal.native.test", "/")[0] == 503
        # The Portal trust store itself is deliberately damaged by the TLS fault.
        # Use the independent approved controller to observe the maintenance response.
        status, response = self.http(self.controller, "staff.native.test", "/api/customers/")
        assert status == 503 and json.loads(response) == {
            "error": "maintenance", "detail": "The platform is temporarily unavailable for scheduled maintenance.", "retry_after": 600,
        }
        assert self.http(self.outsider, "staff.native.test", "/integrations/webhooks/stripe/")[0] == 503
        assert self.http(self.platform, "portal.native.test", "/order/payment/webhook/")[0] == 503

    def management(self, program: str) -> subprocess.CompletedProcess[str]:
        return docker("exec", "-i", "--user", "praho", self.platform, "/bin/bash", "-c",
                      "set -a; . /opt/praho/.env; set +a; cd /opt/praho/src/services/platform; "
                      "exec /opt/praho/.venv-linux/bin/python manage.py shell -c \"exec(__import__('sys').stdin.read())\"", data=program)


def _snapshot_source(controller: str, directory: Path) -> str:
    # Snapshot tracked and newly added source files, excluding ignored operator state.
    names = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # noqa: S607
                           cwd=ROOT, capture_output=True, check=True).stdout.decode().split("\0")
    archive = directory / "source.tar"
    with tarfile.open(archive, "w") as output:
        for name in names:
            if name and (ROOT / name).is_file():
                output.add(ROOT / name, arcname=name, recursive=False)
    docker("exec", controller, "mkdir", "-p", "/fixture/repo", "/work")
    _validate_argv_observer(controller)
    docker("cp", str(archive), f"{controller}:/fixture/source.tar")
    docker("exec", controller, "tar", "-xf", "/fixture/source.tar", "-C", "/fixture/repo")
    docker("exec", controller, "cp", "-a", "/fixture/repo/.", "/work/")
    for args in (("init", "-q"), ("add", "."), ("-c", "user.name=Deployment Fixture", "-c", "user.email=fixture@example.test", "commit", "-qs", "-m", "test: native deployment fixture")):
        docker("exec", controller, "git", "-C", "/fixture/repo", *args)
    sha = docker("exec", controller, "git", "-C", "/fixture/repo", "rev-parse", "HEAD").stdout.strip()
    return sha


def _validate_argv_observer(controller: str) -> None:
    # An unrelated throwaway canary proves the observer detects argument exposure.
    docker("cp", str(ROOT / "tests/deploy/native/argv_watch.py"), f"{controller}:/fixture/argv_watch.py")
    program = """
import json, secrets, subprocess, sys, time
from pathlib import Path
marker = secrets.token_urlsafe(40)
environment = Path('/fixture/observer-control.env')
environment.write_text('DJANGO_SECRET_KEY=' + marker + '\\n')
environment.chmod(0o600)
running = Path('/fixture/argv-watch.running')
running.touch()
observer = subprocess.Popen([sys.executable, '/fixture/argv_watch.py', str(environment)])
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)', marker])
try:
    time.sleep(1)
finally:
    running.unlink()
    observer.wait(timeout=10)
    child.terminate()
    child.wait(timeout=10)
assert observer.returncode == 0
report = json.loads(Path('/fixture/argv-watch.json').read_text())
assert report['exposures'] > 0 and report['credentials_observed'] == 1, report
environment.unlink()
print('Argument privacy observer detected its throwaway positive control')
"""
    docker("exec", "-i", controller, "/usr/bin/python3", "-", data=program)


def _prepare_ssh(controller: str, targets: tuple[str, ...], ips: dict[str, tuple[str, str]], directory: Path) -> None:
    docker("exec", controller, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/fixture/controller")
    public = docker("exec", controller, "cat", "/fixture/controller.pub").stdout
    pins = []
    for target in targets:
        docker("exec", target, "systemctl", "is-system-running", "--wait", check=False)
        docker("exec", target, "sh", "-c", "rm -f /etc/ssh/ssh_host_* && ssh-keygen -A && mkdir -p /root/.ssh")
        docker("exec", "-i", target, "tee", "/root/.ssh/authorized_keys", data=public)
        docker("exec", target, "chmod", "600", "/root/.ssh/authorized_keys")
        docker("exec", target, "systemctl", "restart", "ssh.socket", "ssh.service")
        key = docker("exec", target, "cat", "/etc/ssh/ssh_host_ed25519_key.pub").stdout
        pins.append(ips[target][0] + " " + key)
        docker("cp", f"{controller}:/fixture/repo", str(directory / target))
        docker("cp", str(directory / target), f"{target}:/fixture")
        docker("exec", target, "chmod", "-R", "a+rX", "/fixture")
        docker("exec", target, "git", "config", "--system", "--add", "safe.directory", "/fixture/repo")
        docker("exec", target, "chmod", "-R", "a+rwX", "/var/cache/praho-uv")
    docker("exec", "-i", controller, "tee", "/fixture/known_hosts", data="".join(pins))


def _prepare_certificates(controller: str, targets: tuple[str, ...], clients: tuple[str, ...], directory: Path) -> None:
    # A real fixture CA signs the service origins; every process uses the system trust store.
    docker("exec", controller, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
           "-addext", "keyUsage=critical,keyCertSign,cRLSign",
           "-subj", "/CN=PRAHO Native Fixture CA", "-keyout", "/fixture/ca.key", "-out", "/fixture/ca.crt")
    docker("exec", controller, "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=portal.native.test",
           "-keyout", "/fixture/service.key", "-out", "/fixture/service.csr")
    docker("exec", "-i", controller, "tee", "/fixture/extensions", data="subjectAltName=DNS:staff.native.test,DNS:portal.native.test,DNS:v4.native.test,DNS:v6.native.test\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    docker("exec", controller, "openssl", "x509", "-req", "-days", "2", "-in", "/fixture/service.csr", "-CA", "/fixture/ca.crt",
           "-CAkey", "/fixture/ca.key", "-CAcreateserial", "-extfile", "/fixture/extensions", "-out", "/fixture/service.crt")
    docker("exec", controller, "openssl", "verify", "-x509_strict", "-CAfile", "/fixture/ca.crt", "/fixture/service.crt")
    for filename in ("ca.crt", "service.crt", "service.key"):
        docker("cp", f"{controller}:/fixture/{filename}", str(directory / filename))
    for target in dict.fromkeys(clients):
        docker("cp", str(directory / "ca.crt"), f"{target}:/usr/local/share/ca-certificates/native-fixture.crt")
        docker("exec", target, "update-ca-certificates")
        # requests' policy-owned certifi store also trusts the fixture issuer. Verification stays on.
        docker("exec", target, "/usr/bin/python3", "-c",
               "import sys; from pathlib import Path; ca=Path('/usr/local/share/ca-certificates/native-fixture.crt').read_bytes(); "
               "bundles=list(Path('/var/cache/praho-uv').glob('archive-v0/*/certifi/cacert.pem')); "
               "assert sys.argv[1]!='application' or len(bundles)==1, bundles; "
               "[bundle.write_bytes(bundle.read_bytes()+b'\\n'+ca) for bundle in bundles]",
               "application" if target in targets else "client")
    for target in targets:
        docker("exec", target, "groupadd", "--system", "caddy")
        for filename in ("service.crt", "service.key"):
            docker("cp", str(directory / filename), f"{target}:/fixture/{filename}")
            docker("exec", target, "chown", "root:caddy", f"/fixture/{filename}")
            docker("exec", target, "chmod", "640", f"/fixture/{filename}")


@pytest.fixture(scope="module")
def image(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    docker("info")
    context = tmp_path_factory.mktemp("native-image")
    for name in ("pyproject.toml", "uv.lock", "services/platform/pyproject.toml", "services/portal/pyproject.toml"):
        target = context / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    images = {role: IMAGE + "-" + role for role in ("runtime", "controller", "platform", "portal")}
    for role, tag in images.items():
        docker("build", "--target", role, "-t", tag, "-f", str(ROOT / "tests/deploy/native/Dockerfile"), str(context), timeout=1800)
    return images


@pytest.fixture(scope="module", params=[SPLIT, ("staging", "combined"), ("prod", "combined")])
def lab(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory, image: dict[str, str]) -> Iterator[NativeLab]:
    environment, mode = request.param
    directory = tmp_path_factory.mktemp("native-lab")
    prefix = "praho-native-" + uuid4().hex[:10]
    network = prefix + "-net"
    containers: list[str] = []
    failed = True
    docker("network", "create", "--ipv6", "--subnet", f"fd42:{secrets.randbelow(65535):x}::/64", network)
    try:
        def start(role: str, *, dns: str = "", systemd: bool = False) -> str:
            name = prefix + "-" + role
            docker("run", "-d", "--name", name, "--network", network,
                   *(["--dns", dns] if dns else []),
                   *(["--privileged", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock"] if systemd else []),
                   image.get(role, image["runtime"]), *([] if systemd else ["sleep", "infinity"]))
            containers.append(name)
            return name

        def addresses(container: str) -> tuple[str, str]:
            settings = json.loads(docker("inspect", container).stdout)[0]["NetworkSettings"]["Networks"][network]
            return settings["IPAddress"], settings["GlobalIPv6Address"]

        dns = start("dns")
        controller = start("controller", dns=addresses(dns)[0])
        platform = start("platform", dns=addresses(dns)[0], systemd=True)
        portal = start("portal", dns=addresses(dns)[0], systemd=True) if mode == "split" else platform
        monitor, outsider = start("monitor", dns=addresses(dns)[0]), start("outsider", dns=addresses(dns)[0])
        ips = {name: addresses(name) for name in containers}
        records = ["no-resolv", "server=127.0.0.11", "local=/native.test/", "bind-interfaces"]
        for domain, host in (("staff.native.test", platform), ("portal.native.test", portal)):
            records.append(f"host-record={domain},{','.join(ips[host])}")
        records.extend((f"host-record=v4.native.test,{ips[portal][0]}", f"host-record=v6.native.test,{ips[portal][1]}"))
        docker("exec", "-i", dns, "tee", "/etc/native-dns.conf", data="\n".join(records) + "\n")
        docker("exec", "-d", dns, "dnsmasq", "--keep-in-foreground", "--conf-file=/etc/native-dns.conf")
        sha = _snapshot_source(controller, directory)
        _prepare_ssh(controller, tuple(dict.fromkeys((platform, portal))), ips, directory)
        _prepare_certificates(controller, tuple(dict.fromkeys((platform, portal))), (controller, platform, portal, monitor, outsider), directory)
        portal_key = secrets.token_urlsafe(48)
        values = {
            "PRAHO_NATIVE_TOPOLOGY": mode, "PRAHO_PLATFORM_SERVER": ips[platform][0], "PRAHO_PORTAL_SERVER": ips[portal][0],
            "PRAHO_PLATFORM_PUBLIC_IPV4": ips[platform][0], "PRAHO_PLATFORM_PUBLIC_IPV6": ips[platform][1],
            "PRAHO_PORTAL_PUBLIC_IPV4": ips[portal][0], "PRAHO_PORTAL_PUBLIC_IPV6": ips[portal][1],
            "PRAHO_PORTAL_API_SOURCE_CIDRS": f"{ips[portal][0]}/32 {ips[portal][1]}/128",
            "PRAHO_PLATFORM_WEBHOOK_SOURCE_CIDRS": f"{ips[platform][0]}/32 {ips[platform][1]}/128",
            "PLATFORM_ALLOWED_CIDRS": f"{ips[controller][0]}/32 {ips[controller][1]}/128",
            "PRAHO_MONITORING_CIDRS": f"{ips[monitor][0]}/32 {ips[monitor][1]}/128",
            "PRAHO_SSH_ALLOWED_CIDRS": f"{ips[controller][0]}/32 {ips[controller][1]}/128",
            "PRAHO_SSH_PORT": "22", "PRAHO_SSH_KEY": "/fixture/controller",
            "PRAHO_SSH_PUBLIC_KEYS_FILE": "/fixture/controller.pub", "PRAHO_DEPLOY_KNOWN_HOSTS_FILE": "/fixture/known_hosts",
            "PLATFORM_DOMAIN": "staff.native.test", "PORTAL_DOMAIN": "portal.native.test", "PRAHO_GIT_REPO": "file:///fixture/repo",
            "PORTAL_ID": "portal-001", "PORTAL_HMAC_SECRET": portal_key, "PORTAL_HMAC_MODE": "enforce",
            "PORTAL_HMAC_CREDENTIALS": json.dumps({"portal-001": portal_key}),
            "PRAHO_ADDRESS_IPV4_DOMAIN": "v4.native.test", "PRAHO_ADDRESS_IPV6_DOMAIN": "v6.native.test",
            "PRAHO_NATIVE_TLS_CERTIFICATE": "/fixture/service.crt", "PRAHO_NATIVE_TLS_KEY": "/fixture/service.key",
            "PRAHO_NATIVE_UV_CACHE_DIRECTORY": "/var/cache/praho-uv",
            "PRAHO_NATIVE_MANAGE_SWAP": "false",
            "DJANGO_SECRET_KEY": secrets.token_urlsafe(64), "PORTAL_DJANGO_SECRET_KEY": secrets.token_urlsafe(64),
            "HMAC_SECRET": secrets.token_urlsafe(48), "PLATFORM_TO_PORTAL_WEBHOOK_SECRET": secrets.token_urlsafe(48),
            "DJANGO_ENCRYPTION_KEY": secrets.token_urlsafe(32) + "=", "CREDENTIAL_VAULT_MASTER_KEY": secrets.token_urlsafe(32) + "=",
            "DB_PASSWORD": secrets.token_urlsafe(32), "DB_SSLMODE": "disable", "SENTRY_DSN": "", "REDIS_URL": "",
            "COMPANY_NAME": "Native fixture", "COMPANY_CUI": "RO12345678", "COMPANY_COUNTRY_CODE": "RO",
            "ANAF_TRANSPORT_ENABLED": "false", "DJANGO_SECURE_SSL_REDIRECT": "false",
        }
        # The controller and targets resolve the identical local fixture repository.
        for target in dict.fromkeys((platform, portal)):
            docker("exec", target, "mkdir", "-p", "/fixture/repo")
            docker("exec", target, "cp", "-a", "/fixture/.git", "/fixture/repo/.git")
            # Keep the source tree as the fixture repository, not an extra editable working tree.
            docker("exec", target, "git", "-C", "/fixture/repo", "reset", "--hard", sha)
        import shlex  # noqa: PLC0415 -- serialize literal fixture values
        encoded = "".join(f"{key}={shlex.quote(value)}\n" for key, value in values.items())
        docker("exec", "-i", controller, "tee", "/fixture/environment", data=encoded)
        docker("exec", controller, "chmod", "600", "/fixture/environment")
        instance = NativeLab(controller, platform, portal, monitor, outsider, environment, mode, sha, ips, directory)
        deployed = instance.deploy()
        assert deployed.returncode == 0, deployed.stdout[-15000:] + deployed.stderr[-3000:]
        yield instance
        failed = request.session.testsfailed > 0
    finally:
        if failed and os.environ.get("PRAHO_NATIVE_KEEP_FAILED") == "1":
            print("Failed disposable lab retained for diagnosis: " + ", ".join(containers), flush=True)
        else:
            if containers:
                docker("rm", "-f", *reversed(containers), check=False)
            docker("network", "rm", network, check=False)


def test_real_services_use_one_sha_and_portal_has_no_platform_state(lab: NativeLab) -> None:
    for host in dict.fromkeys((lab.platform, lab.portal)):
        assert lab.execute(host, "runuser", "-u", "praho", "--", "git", "-C", "/opt/praho/src", "rev-parse", "HEAD").stdout.strip() == lab.sha
    if lab.mode == "split":
        for path in ("/opt/praho/.env", "/opt/praho/.platform-deploy.env", "/opt/praho/credentials", "/opt/praho/media", "/var/lib/postgresql",
                     "/etc/praho/operator_authorized_keys", "/opt/praho-ansible", "/opt/controller",
                     "/root/.ssh/praho-node-operator", "/etc/systemd/system/praho-platform.service",
                     "/etc/systemd/system/praho-qcluster.service",
                     "/fixture-dependencies/.venv", "/opt/praho/.venv-linux/bin/ansible-playbook"):
            assert lab.execute(lab.portal, "test", "!", "-e", path, check=False).returncode == 0, path
        environment = lab.execute(lab.portal, "cat", "/opt/praho/.portal.env").stdout
        assert not any(key in environment for key in ("DB_PASSWORD=", "DJANGO_ENCRYPTION_KEY=", "STRIPE_SECRET_KEY="))
        for service in ("praho-platform", "praho-qcluster", "postgresql"):
            assert lab.execute(lab.portal, "systemctl", "is-enabled", service, check=False).returncode != 0


def test_ipv4_and_ipv6_peer_staff_monitor_and_untrusted_policies(lab: NativeLab) -> None:
    for family in (4, 6):
        assert lab.http(lab.controller, "staff.native.test", "/auth/login/", family=family)[0] in (200, 302)
        assert lab.http(lab.monitor, "staff.native.test", "/api/users/health/", family=family)[0] == 200
        for path in ("/api/users/health", "/api/users/health/descendant", "/api/users/%68ealth/"):
            # Staff and peers do not inherit the separate monitoring permission.
            assert lab.http(lab.controller, "staff.native.test", path, family=family)[0] == 403
            assert lab.http(lab.portal, "staff.native.test", path, family=family)[0] == 403
        for path in ("/api/users/health", "/api/users/health/", "/api/users/health/descendant", "/api/localisation/", "/auth/login/", "/static/example.css"):
            for headers in ((), ("X-Forwarded-For: " + lab.addresses[lab.controller][0],), ("X-Real-IP: ::1",)):
                assert lab.http(lab.outsider, "staff.native.test", path, family=family, headers=headers)[0] == 403
        actor = lab.outsider if lab.environment == "prod" else lab.controller
        assert lab.http(actor, "portal.native.test", "/login/", family=family)[0] in (200, 302)
        assert lab.http(lab.outsider, "portal.native.test", "/order/payment/webhook/", family=family)[0] == 403
        if lab.environment == "staging":
            assert lab.http(lab.outsider, "portal.native.test", "/login/", family=family)[0] == 403


def test_real_customer_login_through_caddy_keeps_an_authenticated_session(lab: NativeLab) -> None:
    password = secrets.token_urlsafe(32)
    for host in (lab.platform, lab.controller):
        docker("exec", "-i", host, "tee", "/fixture/customer-password", data=password)
        lab.execute(host, "chmod", "600", "/fixture/customer-password")
    lab.execute(lab.platform, "chown", "praho:praho", "/fixture/customer-password")
    lab.management("""
from pathlib import Path
from apps.users.models import User, CustomerMembership
from apps.customers.models import Customer
user = User.objects.create_user(email='native-customer@example.test', password=Path('/fixture/customer-password').read_text())
customer = Customer.objects.create(name='Native Customer', primary_email=user.email, status='active')
CustomerMembership.objects.create(user=user, customer=customer, role='owner', is_primary=True)
print('Native fixture customer created')
""")
    lab.execute(lab.platform, "rm", "/fixture/customer-password")
    program = """
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, HTTPCookieProcessor, Request, ProxyHandler
cookies = CookieJar()
client = build_opener(HTTPCookieProcessor(cookies), ProxyHandler({}))
origin = 'https://portal.native.test'
with client.open(origin + '/login/', timeout=30) as response:
    assert response.status == 200
tokens = [cookie.value for cookie in cookies if 'csrf' in cookie.name]
assert len(tokens) == 1
body = urlencode({'csrfmiddlewaretoken': tokens[0], 'email': 'native-customer@example.test',
                  'password': Path('/fixture/customer-password').read_text()}).encode()
request = Request(origin + '/login/', data=body, headers={'Referer': origin + '/login/', 'Origin': origin})
with client.open(request, timeout=30) as response:
    assert response.status == 200 and urlsplit(response.url).path == '/dashboard/'
with client.open(origin + '/dashboard/', timeout=30) as response:
    assert response.status == 200 and b'Native Customer' in response.read()
print('Authenticated Portal session verified through HTTPS Caddy')
"""
    response = lab.execute(lab.controller, "/opt/controller/bin/python", "-c", program)
    assert "Authenticated Portal session verified" in response.stdout


def test_public_provider_callbacks_and_unsubscribe_reach_application_verification(lab: NativeLab) -> None:
    for family in (4, 6):
        actor = lab.outsider if lab.environment == "prod" else lab.controller
        for path in ("/integrations/webhooks/stripe/", "/notifications/webhooks/mailgun/"):
            assert lab.http(actor, "staff.native.test", path, family=family)[0] == 405
        status, body = lab.http(actor, "staff.native.test", "/notifications/unsubscribe/00000000-0000-0000-0000-000000000000/", family=family)
        assert status == 400 and "The unsubscribe link is invalid or has expired." in body


def test_address_check_origins_return_only_the_peer_and_reject_forwarding(lab: NativeLab) -> None:
    for family in (4, 6):
        host = f"v{family}.native.test"
        assert lab.http(lab.outsider, host, "/", family=family) == (200, lab.addresses[lab.outsider][family == 6])
        assert lab.http(lab.outsider, host, "/elsewhere", family=family)[0] == 404
        for header in ("X-Forwarded-For: 127.0.0.1", "Forwarded: for=127.0.0.1", "X-Real-IP: ::1", "X-Forwarded-Proto: https"):
            assert lab.http(lab.outsider, host, "/", family=family, headers=(header,))[0] == 400
        headers = lab.execute(lab.outsider, "curl", f"-{family}", "--silent", "--show-error", "--noproxy", "*",
                              "--dump-header", "-", "--output", "/dev/null", "-H", "Origin: https://untrusted.example.test",
                              f"https://{host}/").stdout.lower()
        assert "content-type: text/plain; charset=utf-8" in headers and "cache-control: no-store" in headers
        assert "access-control-allow-origin: https://portal.native.test" in headers
        assert "set-cookie:" not in headers
        assert lab.execute(lab.outsider, "curl", f"-{family}", "--silent", "--show-error", "--noproxy", "*",
                           "-X", "POST", "--output", "/dev/null", "--write-out", "%{http_code}", f"https://{host}/").stdout == "404"


def test_caddy_updates_preserve_maintenance_and_reboot_holds(lab: NativeLab) -> None:
    # Exercise the actual persisted gates and systemd's reboot policy, then recover through the launcher.
    for host, names in ((lab.platform, ("hold-platform", "hold-workers")), (lab.portal, ("hold-portal", "hold-callbacks"))):
        lab.execute(host, "touch", *("/etc/praho-native/" + name for name in names))
    lab.execute(lab.platform, "systemctl", "stop", "praho-qcluster")
    result = lab.execute(lab.controller, "/opt/controller/bin/python", "/work/deploy/scripts/native_env.py", "run",
                         "--env", lab.environment, "--env-file", "/fixture/environment", "--caddy-only", check=False)
    assert result.returncode == 0, result.stdout[-5000:] + result.stderr[-2000:]
    lab.assert_held()
    lab.reboot()
    lab.assert_held()
    backup = lab.execute(lab.platform, "runuser", "-u", "praho", "--", "/usr/local/lib/praho/native_exec.sh",
                         "/opt/praho/.env", "--", "/opt/praho/scripts/backup.sh")
    selected = re.findall(r"Backup created: (\S+)", backup.stdout)
    assert len(selected) == 1 and "Backup completed successfully" in backup.stdout
    restored = docker("exec", "-i", lab.platform, "/opt/praho/scripts/restore-platform.sh",
                      "--leave-stopped", selected[0], data="yes\n", check=False)
    assert restored.returncode == 0, restored.stdout[-4000:] + restored.stderr[-2000:]
    assert "coordinated maintenance remains active" in restored.stdout
    lab.assert_held()
    recovered = lab.deploy()
    assert recovered.returncode == 0, recovered.stdout[-12000:] + recovered.stderr[-3000:]


@pytest.mark.parametrize("lab", [SPLIT], indirect=True)
def test_contaminated_portal_is_refused_before_changing_either_host(lab: NativeLab) -> None:
    paths = ("/etc/caddy/Caddyfile", "/opt/praho/.portal.env")
    before = {path: lab.execute(lab.portal, "sha256sum", path).stdout for path in paths}
    sentinel = "Existing Platform state must be preserved\n"
    docker("exec", "-i", lab.portal, "tee", "/opt/praho/.env", data=sentinel)
    try:
        refused = lab.deploy()
        assert refused.returncode != 0 and "Select a clean host" in refused.stdout
        assert lab.execute(lab.portal, "cat", "/opt/praho/.env").stdout == sentinel
        assert all(lab.execute(lab.portal, "sha256sum", path).stdout == before[path] for path in paths)
        for host, name in ((lab.platform, "hold-platform"), (lab.portal, "hold-portal")):
            lab.execute(host, "test", "!", "-e", "/etc/praho-native/" + name)
        assert lab.execute(lab.platform, "systemctl", "is-active", "praho-qcluster").stdout.strip() == "active"
    finally:
        lab.execute(lab.portal, "rm", "/opt/praho/.env")


def _fail_running_deployment(lab: NativeLab, fault: str, previous: str) -> subprocess.CompletedProcess[str]:
    if fault == "sha":
        lab.sha = lab.revision({"native-sha-fixture.txt": "Pinned SHA mismatch acceptance fixture\n"})
    lab.execute(lab.controller, "truncate", "-s", "0", "/fixture/deployment.log")
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(lab.deploy)
        lab.wait_for_phase("PLAY [Deploy Platform at the pinned SHA]")
        if fault == "ssh":
            lab.execute(lab.portal, "systemctl", "stop", "ssh.socket", "ssh.service")
        elif fault == "sha":
            lab.wait_for_phase("PLAY [Deploy clean Portal at the same pinned SHA]")
            lab.execute(lab.platform, "runuser", "-u", "praho", "--", "git", "-C", "/opt/praho/src", "update-ref", "HEAD", previous)
        else:
            pid = lab.execute(lab.controller, "cat", "/fixture/deploy.pid").stdout.strip()
            lab.execute(lab.controller, "kill", "-INT", "--", "-" + pid)
        return pending.result(timeout=1800)


def _failed_task(result: subprocess.CompletedProcess[str]) -> str:
    before_failure = result.stdout.split("fatal:", 1)[0]
    tasks = re.findall(r"TASK \[(.*?)\]", before_failure)
    assert "fatal:" in result.stdout and tasks, "Expected an actual Ansible task failure"
    return tasks[-1]


def _assert_fault_reached_application(lab: NativeLab, fault: str, failed: subprocess.CompletedProcess[str]) -> None:
    if fault in {"migration", "portal-startup"}:
        host, marker = ((lab.platform, "/opt/praho/logs/native-migration-failed") if fault == "migration"
                        else (lab.portal, "/var/log/praho/portal/native-startup-failed"))
        assert lab.execute(host, "cat", marker).stdout == "intentional native acceptance fault"
    elif fault in {"caddy", "certificate", "sha"}:
        expected = {"caddy": "praho-native : Template Caddyfile",
                    "certificate": "Verify existing ingress returns maintenance over trusted HTTPS",
                    "sha": "Require the same pinned SHA on every host"}
        assert _failed_task(failed) == expected[fault]
    elif fault == "ssh":
        assert "UNREACHABLE!" in failed.stdout and "recovery is unverified" in failed.stdout
    else:
        assert failed.returncode == 130


@pytest.mark.parametrize("lab", [SPLIT], indirect=True)
@pytest.mark.parametrize("fault", ["migration", "portal-startup", "caddy", "certificate", "ssh", "sha", "interrupt"])
def test_real_failures_leave_durable_holds_and_allow_coordinated_recovery(lab: NativeLab, fault: str) -> None:
    previous = lab.sha
    template = "/work/deploy/ansible/roles/praho-native/templates/Caddyfile.native.j2"
    original = lab.execute(lab.controller, "cat", template).stdout
    restore_certificate = False
    try:
        if fault == "migration":
            lab.execute(lab.platform, "rm", "-f", "/opt/praho/logs/native-migration-failed")
            lab.sha = lab.revision({"services/platform/apps/common/migrations/0007_native_failure_fixture.py": """
from pathlib import Path
from django.db import migrations
def fail(apps, schema_editor):
    Path('/opt/praho/logs/native-migration-failed').write_text('intentional native acceptance fault')
    raise RuntimeError('Native acceptance migration fault')
class Migration(migrations.Migration):
    dependencies = [('common', '0006_noderesourcehourlysummary_systemcheckstate')]
    operations = [migrations.RunPython(fail)]
"""})
        elif fault == "portal-startup":
            lab.execute(lab.portal, "rm", "-f", "/var/log/praho/portal/native-startup-failed")
            lab.sha = lab.revision({"services/portal/config/wsgi.py": "from pathlib import Path\nPath('/var/log/praho/portal/native-startup-failed').write_text('intentional native acceptance fault')\nraise RuntimeError('Native acceptance Portal startup fault')\n"})
        elif fault == "caddy":
            docker("exec", "-i", lab.controller, "tee", template, data=original + "\ninvalid_native_fixture_directive\n")
        elif fault == "certificate":
            lab.execute(lab.portal, "rm", "/usr/local/share/ca-certificates/native-fixture.crt")
            lab.execute(lab.portal, "update-ca-certificates", "--fresh")
            restore_certificate = True
        if fault in {"ssh", "sha", "interrupt"}:
            failed = _fail_running_deployment(lab, fault, previous)
        else:
            failed = lab.deploy()
        assert failed.returncode != 0, f"The real {fault} fault was incorrectly accepted"
        _assert_fault_reached_application(lab, fault, failed)
        lab.assert_held()
        # Recovery must survive real systemd boot with the failure still present.
        lab.reboot()
        lab.assert_held()
    finally:
        docker("exec", "-i", lab.controller, "tee", template, data=original)
        if restore_certificate:
            docker("cp", str(lab.artifact_directory / "ca.crt"), f"{lab.portal}:/usr/local/share/ca-certificates/native-fixture.crt")
            lab.execute(lab.portal, "update-ca-certificates")
        if fault == "ssh":
            lab.execute(lab.portal, "systemctl", "start", "ssh.socket", "ssh.service")
        lab.sha = previous
        # Future fault revisions fork the coherent release, never an earlier broken fixture.
        lab.execute(lab.controller, "git", "-C", "/fixture/repo", "reset", "--hard", previous)
    recovered = lab.deploy(rollback=fault in {"migration", "portal-startup", "sha"})
    assert recovered.returncode == 0, recovered.stdout[-15000:] + recovered.stderr[-3000:]
    lab.assert_coherent()
    assert lab.http(lab.outsider, "portal.native.test", "/login/")[0] == 200


@pytest.mark.parametrize("lab", [SPLIT], indirect=True)
def test_actual_queue_work_drains_before_the_recovery_backup(lab: NativeLab) -> None:
    lab.sha = lab.revision({"services/platform/apps/common/native_acceptance_task.py": """
import time
from pathlib import Path
def drain():
    Path('/opt/praho/logs/native-task-started').write_text('started')
    deadline = time.monotonic() + 300
    while not Path('/etc/praho-native/hold-workers').exists():
        if time.monotonic() > deadline:
            raise RuntimeError('Deployment did not request a worker drain')
        time.sleep(0.2)
    time.sleep(15)
    Path('/opt/praho/logs/native-task-finished').write_text(str(time.time()))
    return 'drained'
"""})
    deployed = lab.deploy()
    assert deployed.returncode == 0, deployed.stdout[-10000:] + deployed.stderr[-2000:]
    lab.management("from django_q.tasks import async_task; print(async_task('apps.common.native_acceptance_task.drain', task_name='native-drain-fixture'))")
    deadline = time.monotonic() + 120
    while lab.execute(lab.platform, "test", "-f", "/opt/praho/logs/native-task-started", check=False).returncode:
        assert time.monotonic() < deadline, "The actual worker never began the queued fixture task"
        time.sleep(1)
    deployed = lab.deploy()
    assert deployed.returncode == 0, deployed.stdout[-10000:] + deployed.stderr[-2000:]
    lab.management("""
import json
from pathlib import Path
from django_q.models import Task
task = Task.objects.get(name='native-drain-fixture')
assert task.success and task.result == 'drained'
finished = float(Path('/opt/praho/logs/native-task-finished').read_text())
metadata = max(Path('/opt/praho/backups').glob('*.recovery.json'), key=lambda path: path.stat().st_mtime)
database = metadata.parent / json.loads(metadata.read_text())['database']['file']
assert finished <= database.stat().st_mtime, 'Backup preceded the final worker write'
print('Actual queued work completed before the recovery database backup')
""")


@pytest.mark.parametrize("lab", [SPLIT], indirect=True)
@pytest.mark.parametrize("service", ["platform", "portal"])
def test_code_only_rollback_refuses_an_applied_migration_absent_from_target(lab: NativeLab, service: str) -> None:
    previous = lab.sha
    number, dependency = ("0007", "0006_noderesourcehourlysummary_systemcheckstate") if service == "platform" else ("0002", "0001_initial")
    lab.sha = lab.revision({f"services/{service}/apps/common/migrations/{number}_native_applied_fixture.py": f"""
from django.db import migrations
class Migration(migrations.Migration):
    dependencies = [('common', '{dependency}')]
    operations = []
"""})
    deployed = lab.deploy()
    assert deployed.returncode == 0, deployed.stdout[-10000:] + deployed.stderr[-2000:]
    host = lab.platform if service == "platform" else lab.portal
    owner = "praho" if service == "platform" else "praho-portal"
    environment = "/opt/praho/.env" if service == "platform" else "/opt/praho/.portal.env"
    migration = number + "_native_applied_fixture"
    docker("exec", "--user", owner, "-w", f"/opt/praho/src/services/{service}", host,
           "/usr/local/lib/praho/native_exec.sh", environment, "--", "/opt/praho/.venv-linux/bin/python", "manage.py", "shell", "-c",
           "from django.db.migrations.recorder import MigrationRecorder; "
           f"assert MigrationRecorder.Migration.objects.filter(app='common', name={migration!r}).exists()")
    current = lab.sha
    lab.sha = previous
    refused = lab.deploy(rollback=True)
    assert refused.returncode != 0
    expected = ("Check rollback migration compatibility before checkout" if service == "platform"
                else "Check Portal rollback migrations using its installed private environment")
    assert _failed_task(refused) == expected
    reason = docker("exec", "--user", owner, "-e", f"PYTHONPATH=/opt/praho/src/services/{service}",
                    "-e", "PRAHO_NATIVE_SOURCE_ROOT=/opt/praho/src", host,
                    "/usr/local/lib/praho/native_exec.sh", environment, "--", "/opt/praho/.venv-linux/bin/python",
                    "/usr/local/lib/praho/native_migration_guard.py", "--service", service, "--no-fetch", previous, check=False)
    assert reason.returncode != 0 and "Code-only rollback would discard applied migrations:" in reason.stderr
    assert "common." + migration in reason.stderr
    lab.sha = current
    lab.assert_coherent()
    lab.assert_held()
    retry = lab.deploy()
    assert retry.returncode == 0, retry.stdout[-10000:] + retry.stderr[-2000:]
