"""Deploy a Virtualmin node from scratch on the bare Debian lab node (make test-virtualmin-node-deploy).

Two phases, driven by tests/virtualmin_lab/run_node_deploy.sh around a freshly created `praho-debian-node`:

- `prepare`: register the node's deployment and managed SSH key (a new key per run), pin its fresh SSH host
  keys in a known_hosts file of its own, and set the node admin allowlist (ADR-0060) to the lab's address, the
  compose network gateway Platform reaches every node from. The key is installed on the node by
  `lab-node-credentials`, which the runner executes next.
- `deploy`: run `virtualmin.yml` (the Virtualmin 8 installer and the API user) and `virtualmin_harden.yml`
  through AnsibleService, as the production pipeline does with the API credential it generates; register the
  node as a VirtualminServer pinned to the certificate the installer produced; activate it through
  `NodeRegistrationService.verify_and_activate`, so the credential is proven over the pinned TLS exactly as
  a deployment proves it; then check the controls ADR-0060 requires on the node.

The contract smoke checks run afterwards, against the node this command leaves.

Refuses to run unless DJANGO_SETTINGS_MODULE=config.settings.lab and DEBUG.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import shutil
import ssl
import string
import subprocess
from argparse import ArgumentParser
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.provisioning.management.commands._virtualmin_lab import (
    DEPLOY_NODE,
    DEPLOY_NODE_ZONE,
    LAB_LOOPBACK,
    LabState,
    container_address,
    ensure_lab_deployment,
    lab_transport,
    load_state,
    refuse_unless_lab_settings,
    with_deploy_node,
    write_private,
)
from apps.provisioning.management.commands.virtualmin_lab_bootstrap import _scan_host_keys
from apps.provisioning.management.commands.virtualmin_lab_roundtrip import node_exec

logger = logging.getLogger(__name__)

API_USER = "praho-api"
PLAYBOOK_TIMEOUT = 3600
FACT_CACHE = Path("/tmp/ansible_facts_cache")  # noqa: S108  # Ansible's own fact cache (ansible.cfg), keyed by inventory hostname
SSH_PORT = 22
HTTP_PORT = 80
WEBMIN_PORT = 10000
IP_LOCK_FIELD = 4  # miniserv.users: name:password:pass-expiry:module-list:ip-allow-list:...

# Two customers and an account-name sub-server on the deployed node. The first customer points its web root at
# things; the second holds a secret. Each case prints "<label> <HTTP status> <first line of the body>", fetched on the
# node itself (the bare image has python3 but no curl). $1 and $2 are random tokens: a 200 must serve the first, and
# no answer may carry the second. Any failed step stops the probe, so a stale link can never pass as a refusal.
WEB_ROOT_LINKS_PROBE = r"""
set -euo pipefail
OWN=$1 SECRET=$2
V=/usr/sbin/virtualmin
A=linkprobe-a.test B=linkprobe-b.test SUB=linkprobe-acct.test
cleanup() {
  local name names
  names=$($V list-domains --name-only) || { echo "cleanup-failed listing -"; return 0; }
  for name in "$SUB" "$A" "$B"; do
    if printf '%s\n' "$names" | grep -qx "$name"; then
      $V delete-domain --domain "$name" >/dev/null 2>&1 || echo "cleanup-failed $name -"
    fi
  done
}
trap cleanup EXIT
cleanup
$V create-domain --domain "$A" --pass "Lp-$RANDOM-a1" --unix --dir --web >/dev/null
$V create-domain --domain "$B" --pass "Lp-$RANDOM-b1" --unix --dir --web >/dev/null
$V create-domain --domain "$SUB" --parent "$A" --dir --web >/dev/null
UA=$($V list-domains --domain "$A" --user-only)
UB=$($V list-domains --domain "$B" --user-only)
HA=$(getent passwd "$UA" | cut -d: -f6)
HB=$(getent passwd "$UB" | cut -d: -f6)
HS=$($V list-domains --domain "$SUB" --multiline | awk '/Home directory:/ {print $3}')
for dir in "$HA/public_html" "$HB/public_html" "$HS"; do [ -d "$dir" ] || { echo "setup-failed $dir -"; exit 1; }; done
echo "$OWN" > "$HA/public_html/own.txt"
chown "$UA:$UA" "$HA/public_html/own.txt"
echo "$SECRET" > "$HB/public_html/secret.txt"
chown "$UB:$UB" "$HB/public_html/secret.txt"
fetch() {
  python3 - "$2" "$3" <<'PY'
import sys, urllib.error, urllib.request
request = urllib.request.Request("http://127.0.0.1" + sys.argv[2], headers={"Host": sys.argv[1]})
try:
    with urllib.request.urlopen(request, timeout=10) as answer:
        status, body = answer.status, answer.read()
except urllib.error.HTTPError as error:
    status, body = error.code, error.read()
first = body.decode("utf-8", "replace").strip().splitlines()
print(status, first[0] if first else "-")
PY
}
report() { echo "$1 $(fetch "$1" "$2" "$3")"; }
as_a() { su -s /bin/sh "$UA" -c "$1"; }
points_to() { [ "$(readlink "$1")" = "$2" ] || { echo "link-failed $1 -"; exit 1; }; }
report plain "$A" /own.txt
as_a 'mv ~/public_html ~/site'
as_a 'ln -s site ~/public_html'
points_to "$HA/public_html" site
report own-link "$A" /own.txt
as_a 'rm ~/public_html'
as_a "ln -s $HB/public_html ~/public_html"
points_to "$HA/public_html" "$HB/public_html"
report other-customer "$A" /secret.txt
as_a 'rm ~/public_html'
as_a 'ln -s /etc ~/public_html'
points_to "$HA/public_html" /etc
report system "$A" /hostname
as_a 'rm ~/public_html'
as_a 'mv ~/site ~/public_html'
as_a "ln -s $HB/public_html/secret.txt ~/public_html/peek.txt"
points_to "$HA/public_html/peek.txt" "$HB/public_html/secret.txt"
report nested "$A" /peek.txt
rm -rf "$HS/public_html"
ln -s ../../public_html "$HS/public_html"
chown -h "$UA:$UA" "$HS/public_html"
points_to "$HS/public_html" ../../public_html
report subserver "$SUB" /own.txt
chown -h root:root "$HS/public_html"
report subserver-root-link "$SUB" /own.txt
"""


# label -> (expected HTTP status, whether it serves the customer's own file)
WEB_ROOT_EXPECTED = {
    "plain": ("200", True),
    "own-link": ("200", True),
    "other-customer": ("403", False),
    "system": ("403", False),
    "nested": ("403", False),
    "subserver": ("200", True),
    "subserver-root-link": ("403", False),
}


class Command(BaseCommand):
    help = "Prepare and run a from-scratch Virtualmin node deploy on the bare Debian lab node (lab only)"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("phase", choices=("prepare", "deploy", "cleanup"))

    def handle(self, *args: Any, **options: Any) -> None:
        refuse_unless_lab_settings()
        state = load_state()
        if options["phase"] == "prepare":
            self._prepare(state)
        elif options["phase"] == "deploy":
            self._deploy(state)
        else:
            self._forget_server()

    # -------------------------------------------------------------- prepare

    def _prepare(self, state: LabState) -> None:
        from apps.settings.services import SettingsService  # noqa: PLC0415

        state_dir = Path(state.state_dir)
        self._forget_server()
        # Ansible caches facts by inventory hostname for an hour; a rebuilt node must not inherit the last one's.
        shutil.rmtree(FACT_CACHE, ignore_errors=True)
        # Nothing of an earlier run may survive: the server row (and its vault credential) belongs to a node
        # whose certificate and API password no longer exist.
        ensure_lab_deployment(DEPLOY_NODE, state_dir, dns_zone=DEPLOY_NODE_ZONE)

        # Host keys are generated at every boot: pin this run's, next to the two lab nodes' keys.
        known_hosts = Path(state.known_hosts).read_text() + _scan_host_keys(DEPLOY_NODE.ssh_port)
        write_private(Path(with_deploy_node(state).known_hosts), known_hosts)

        allowed = [f"{container_address(DEPLOY_NODE.container, 'Gateway')}/32"]
        result = SettingsService.update_setting("infrastructure.node_admin_allowed_cidrs", allowed)
        if result.is_err():
            raise CommandError(f"Could not set the node admin allowlist: {result.unwrap_err()}")
        self.stdout.write(f"Prepared {DEPLOY_NODE.server_hostname}; node admin allowlist {allowed}")

    def _forget_server(self) -> None:
        """Nothing of the node may outlive its container: the lab's health and placement sweeps would see it."""
        from apps.common.credential_vault import EncryptedCredential  # noqa: PLC0415
        from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        NodeDeployment.objects.filter(hostname=DEPLOY_NODE.deployment_hostname).update(virtualmin_server=None)
        VirtualminServer.objects.filter(hostname=DEPLOY_NODE.server_hostname).delete()
        EncryptedCredential.objects.filter(
            service_type="virtualmin", service_identifier=DEPLOY_NODE.server_hostname
        ).delete()

    # --------------------------------------------------------------- deploy

    def _deploy(self, state: LabState) -> None:
        from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415
        from apps.infrastructure.registration_service import NodeRegistrationService  # noqa: PLC0415

        deployment = NodeDeployment.objects.get(hostname=DEPLOY_NODE.deployment_hostname)
        password = "".join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*") for _ in range(24))
        with lab_transport(with_deploy_node(state)):
            self._run_playbook(
                deployment, "virtualmin.yml", {"praho_api_user": API_USER, "praho_api_password": password}
            )
            self._run_playbook(deployment, "virtualmin_harden.yml", None)
            self._check_web_root_links()
            # Someone disables the guard by hand; the next hardening run must put it back in force.
            node_exec(DEPLOY_NODE.container, "sh", "-c", "a2disconf -q praho-home-symlinks && systemctl reload apache2")
            self._run_playbook(deployment, "virtualmin_harden.yml", None)
            server = self._register(deployment, password)
            activated = NodeRegistrationService().verify_and_activate(server)
            if activated.is_err():
                raise CommandError(f"The node's API credential did not activate it: {activated.unwrap_err()}")
            self._ok("verify_and_activate proves the API user over the pinned certificate", server.status == "active")
        self._check_controls()
        self._check_web_root_links()
        self.stdout.write(self.style.SUCCESS(f"Node deploy OK: {server.hostname} is active"))

    def _check_web_root_links(self) -> None:
        """virtualmin_harden.yml: a web root can link only to what its customer owns (not another home, not /etc)."""
        own, secret = f"own-{secrets.token_hex(6)}", f"secret-{secrets.token_hex(6)}"
        output = node_exec(DEPLOY_NODE.container, "bash", "-c", WEB_ROOT_LINKS_PROBE, "probe", own, secret)
        seen = {label: rest for label, _, rest in (line.partition(" ") for line in output.splitlines() if line)}
        self._ok(
            "the web root probe ran every case and cleaned up",
            not any(label.endswith("-failed") for label in seen) and len(seen) == len(WEB_ROOT_EXPECTED),
            output,
        )
        for label, (status, serves_own) in WEB_ROOT_EXPECTED.items():
            answer = seen.get(label, "")
            good = answer.split(" ", 1)[0] == status and (own in answer if serves_own else own not in answer)
            self._ok(f"web root case {label} answers {status}", good and secret not in answer, output)

    def _ok(self, label: str, condition: bool, detail: object = "") -> None:
        if not condition:
            raise CommandError(f"{label}: FAILED {detail}")
        self.stdout.write(f"  ok  {label}")

    def _run_playbook(self, deployment: Any, playbook: str, extra: dict[str, Any] | None) -> None:
        from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415

        self.stdout.write(f"Running {playbook} on the bare node (the installer takes several minutes)...")
        result = AnsibleService().run_playbook(deployment, playbook, extra, timeout_seconds=PLAYBOOK_TIMEOUT)
        if result.is_err():
            raise CommandError(f"{playbook} could not run: {result.unwrap_err()}")
        outcome = result.unwrap()
        if not outcome.success:
            raise CommandError(f"{playbook} failed (rc={outcome.return_code}):\n{outcome.stdout[-3000:]}")
        self._ok(f"{playbook} finished with failed=0", True)

    def _register(self, deployment: Any, password: str) -> Any:
        """What NodeRegistrationService.register_node records, with the lab's published API port.

        register_node itself reads the certificate over SSH port 22 and records API port 10000, neither of
        which a published container offers; the row and the vault entry it writes are the same.
        """
        from apps.common.credential_vault import CredentialData, get_credential_vault  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

        pem = ssl.get_server_certificate((LAB_LOOPBACK, DEPLOY_NODE.api_port), timeout=15)
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        server = VirtualminServer.objects.create(
            name=f"Node: {deployment.hostname}",
            hostname=deployment.fqdn,
            api_port=DEPLOY_NODE.api_port,
            use_ssl=True,
            ssl_verify=False,
            ssl_cert_fingerprint=fingerprint,
            status="disabled",
            api_username=API_USER,
            encrypted_api_password=b"",
            max_domains=50,
        )
        stored = get_credential_vault().store_credential(
            CredentialData(
                service_type="virtualmin",
                service_identifier=server.hostname,
                username=API_USER,
                password=password,
                metadata={"deployment_hostname": deployment.hostname, "auto_registered": True},
                expires_in_days=30,
                user=None,
                reason="Lab node deploy from scratch",
            )
        )
        if stored.is_err():
            raise CommandError(f"Could not store the API credential: {stored.unwrap_err()}")
        deployment.virtualmin_server = server
        deployment.save(update_fields=["virtualmin_server", "updated_at"])
        return server

    def _check_controls(self) -> None:
        """NODE_DEPLOY_DRILL step 3: the API user, its IP lock and the firewall, read on the node."""
        from apps.infrastructure.ansible_service import node_admin_allowed_cidrs  # noqa: PLC0415

        container = DEPLOY_NODE.container
        allowed = node_admin_allowed_cidrs()
        acl = node_exec(container, "grep", f"^{API_USER}:", "/etc/webmin/webmin.acl").strip()
        self._ok("the API user's only module is virtual-server", acl == f"{API_USER}: virtual-server", acl)
        users = node_exec(container, "grep", f"^{API_USER}:", "/etc/webmin/miniserv.users").strip()
        lock = users.split(":")[IP_LOCK_FIELD] if users.count(":") > IP_LOCK_FIELD else ""
        self._ok("the API user's IP lock is the allowlist", lock == "allow " + " ".join(allowed), lock)
        ufw = node_exec(container, "ufw", "status")
        for port in (SSH_PORT, WEBMIN_PORT):
            rules = [line for line in ufw.splitlines() if line.startswith(f"{port}/tcp") and "ALLOW" in line]
            # ufw prints a /32 host as the bare address.
            sources = {line.split()[-1].removesuffix("/32") for line in rules}
            self._ok(
                f"ufw lets {port}/tcp in only from the allowlist",
                bool(sources) and sources == {cidr.removesuffix("/32") for cidr in allowed},
                ufw,
            )
        # A host outside the allowlist (vm-a, on the same network) must not reach the panel.
        address = container_address(container)
        probe = subprocess.run(  # Fixed argv against local lab containers
            ["docker", "exec", "vmlab-a", "timeout", "6", "bash", "-c", f"exec 3<>/dev/tcp/{address}/{WEBMIN_PORT}"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self._ok("a host outside the allowlist cannot reach port 10000", probe.returncode != 0, probe.stderr)
