"""Owned disposable Docker nodes; fixed checks and production Ansible, never shared lab nodes."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

REPO = Path(__file__).resolve().parents[2]
PLAYBOOK = REPO / "services/platform/infrastructure/ansible/playbooks/virtualmin_mail.yml"
NATIVE = PLAYBOOK.parent / "files/praho-mail-native.pl"
LABEL = "io.praho.mail-lab.run"
PROFILE_LABEL = "io.praho.mail-lab.profile"
BOOT_TIMEOUT = 1800
PLAYBOOK_TIMEOUT = 1050
_ID = re.compile(r"[a-f0-9]{64}")
_PUBLIC_CODES = {
    "mail_profile_unsupported",
    "mail_node_identity_mismatch",
    "mail_domain_identity_mismatch",
    "mail_native_inspection_failed",
    "mail_setup_incomplete",
    "mail_unmanaged_mta",
    "mail_queue_uncertain",
    "mail_node_certificate_unproven",
    "mail_setup_review_required",
    "mail_unrelated_configuration_changed",
    "mail_operation_busy",
}
_PUBLIC_STAGES = {
    "inspection",
    "packages",
    "preflight",
    "node_certificate",
    "native_configuration",
    "secure_configuration",
    "service_start",
    "verification",
    "remove_fence",
    "verification_owned_files",
    "verification_firewall",
    "verification_listeners",
    "verification_tls",
    "verification_native_backend",
    "verification_postfix_core",
    "verification_submitters",
    "verification_postfix_auth",
    "verification_postfix_listeners",
    "verification_dovecot_auth",
    "verification_dovecot_tls",
    "certificate_preflight",
    "certificate_candidate",
    "certificate_staging",
    "certificate_installing",
    "certificate_reload",
    "certificate_verification",
}


class MailLabError(RuntimeError):
    """Fixed failures only: never propagate subprocess argv, output or credentials."""


@dataclass(frozen=True)
class MailProfile:
    key: str
    image: str
    os_id: str
    os_version: str
    native_profile: str


PROFILES = {
    "debian12": MailProfile("debian12", "praho-virtualmin-lab:8.3.0", "debian", "12", "debian12-dovecot23"),
    "ubuntu2604": MailProfile(
        "ubuntu2604", "praho-adr61-ubuntu26-virtualmin:8.3.0", "ubuntu", "26.04", "ubuntu2604-dovecot24"
    ),
}


def _run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, **kwargs)  # noqa: S603 -- fixed test-owned argv


def _private_json(path: Path, value: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, sort_keys=True)


def _certificate_receipt(payload: dict[str, Any]) -> dict[str, Any]:
    expiry = datetime.fromisoformat(payload["not_after"])
    if expiry.tzinfo is None or expiry <= datetime.now(UTC):
        raise ValueError
    if re.fullmatch(r"[a-f0-9]{64}", payload["certificate_sha256"]) is None:
        raise ValueError
    if (payload["outcome"], payload["pending_code"]) not in {
        ("unchanged", ""),
        ("replaced", ""),
        ("retained_previous", "mail_node_certificate_unproven"),
    }:
        raise ValueError
    return {key: payload[key] for key in ("outcome", "pending_code", "certificate_sha256", "not_after")}


def _certificate(hostname: str) -> dict[str, str]:
    """Ephemeral strict CA/leaf; private material travels only over stdin into the owned node."""
    now = datetime.now(UTC)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable PRAHO mail-node test CA")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
    )
    ca = builder.sign(issuer_key, hashes.SHA256())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=20))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .sign(issuer_key, hashes.SHA256())
    )
    return {
        "ca": ca.public_bytes(serialization.Encoding.PEM).decode(),
        "pem": (
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
            + leaf.public_bytes(serialization.Encoding.PEM)
        ).decode(),
    }


class MailClone:
    def __init__(
        self,
        profile: MailProfile,
        artifacts: Path,
        *,
        image: str = "",
        dns: str = "",
        runner: Callable[..., subprocess.CompletedProcess[str]] = _run,
    ):
        self.profile, self.artifacts, self.runner = profile, artifacts, runner
        self.image = image or profile.image
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,254}", self.image) is None:
            raise MailLabError("Invalid test image reference")
        self.dns = str(ipaddress.ip_address(dns)) if dns else ""
        self.run_id = uuid4().hex
        self.name = f"praho-mail-{profile.key}-{self.run_id[:12]}"
        self.network_name = self.name + "-net"
        self.hostname = f"node-{self.run_id[:12]}.mail-lab.praho.test"
        self.directory = f"/var/lib/praho-mail-lab/{self.run_id}"
        self.container_id = self.network_id = self.image_id = ""
        if artifacts.is_symlink():
            raise MailLabError("Refusing symlinked test artifacts")
        artifacts.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.facts: list[dict[str, object]] = []

    @property
    def labels(self) -> dict[str, str]:
        return {LABEL: self.run_id, PROFILE_LABEL: self.profile.key}

    def _call(
        self,
        argv: list[str],
        *,
        payload: str | None = None,
        timeout: int = 60,
        required: bool = True,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = self.runner(argv, input=payload, timeout=timeout, **({"env": environment} if environment else {}))
        except (subprocess.SubprocessError, OSError):
            raise MailLabError("A bounded test command failed; owned node retained for diagnosis") from None
        if required and result.returncode:
            raise MailLabError("A test command was refused; owned node retained for diagnosis")
        return result

    def _docker(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return self._call(["docker", *args], **kwargs)

    def _inspect(self, args: list[str]) -> dict[str, Any]:
        try:
            values = json.loads(self._docker(args).stdout)
            if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
                raise ValueError
            return values[0]
        except (ValueError, TypeError):
            raise MailLabError("Invalid Docker ownership evidence") from None

    def _owned(self) -> dict[str, Any]:
        state = self._inspect(["inspect", self.container_id])
        networks = state.get("NetworkSettings", {}).get("Networks", {})
        actual_ports = state.get("NetworkSettings", {}).get("Ports", {})
        ports_unpublished = actual_ports is None or (
            isinstance(actual_ports, dict) and all(bindings in (None, []) for bindings in actual_ports.values())
        )
        if (
            state.get("Id") != self.container_id
            or state.get("Image") != self.image_id
            or state.get("Config", {}).get("Hostname") != self.hostname
            or any(state.get("Config", {}).get("Labels", {}).get(key) != value for key, value in self.labels.items())
            or state.get("HostConfig", {}).get("PortBindings") not in ({}, None)
            or not ports_unpublished
            or {entry.get("NetworkID") for entry in networks.values()} != {self.network_id}
        ):
            raise MailLabError("Refusing changed or foreign test container")
        return state

    def _network(self) -> dict[str, Any]:
        state = self._inspect(["network", "inspect", self.network_id])
        if state.get("Id") != self.network_id or any(
            state.get("Labels", {}).get(key) != value for key, value in self.labels.items()
        ):
            raise MailLabError("Refusing foreign test network")
        if set(state.get("Containers", {})) - {self.container_id}:
            raise MailLabError("Refusing a test network with foreign endpoints")
        return state

    def create(self) -> None:
        self.image_id = self._inspect(["image", "inspect", self.image])["Id"]
        if re.fullmatch(r"sha256:[a-f0-9]{64}", self.image_id) is None:
            raise MailLabError("Invalid test image identity")
        labels = [part for key, value in self.labels.items() for part in ("--label", key + "=" + value)]
        self.network_id = self._docker(["network", "create", *labels, self.network_name]).stdout.strip()
        if _ID.fullmatch(self.network_id) is None:
            raise MailLabError("Invalid test network identity")
        args = [
            "run",
            "--detach",
            "--name",
            self.name,
            *labels,
            "--hostname",
            self.hostname,
            "--network",
            self.network_id,
            "--privileged",
            "--cgroupns=host",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "--stop-signal",
            "SIGRTMIN+3",
            "--volume",
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        ]
        if self.dns:
            args.extend(["--dns", self.dns])
        self.container_id = self._docker([*args, self.image_id, "/sbin/init"], timeout=120).stdout.strip()
        if _ID.fullmatch(self.container_id) is None:
            raise MailLabError("Invalid test container identity")
        _private_json(
            self.artifacts / "ownership.json",
            {
                "run_id": self.run_id,
                "container_id": self.container_id,
                "network_id": self.network_id,
                "image_id": self.image_id,
                "profile": self.profile.key,
            },
        )
        self._wait_boot()
        self._stage()
        self.check_profile()

    def _wait_boot(self) -> None:
        deadline = time.monotonic() + BOOT_TIMEOUT
        while time.monotonic() < deadline:
            self._owned()
            result = self._docker(
                ["exec", self.container_id, "systemctl", "is-system-running"], required=False, timeout=15
            )
            if result.stdout.strip() in {"running", "degraded"}:
                health = self._docker(
                    ["exec", self.container_id, "/usr/local/sbin/virtualmin-lab-health"], required=False, timeout=15
                )
                if health.returncode == 0:
                    return
            time.sleep(1)
        raise MailLabError("Owned test node did not finish first boot")

    def _stage(self) -> None:
        self._owned()
        self._docker(["exec", self.container_id, "install", "-d", "-m", "0700", self.directory])
        for source, name in (
            (Path(__file__).with_name("node_checks.py"), "node_checks.py"),
            (NATIVE, "praho-mail-native.pl"),
        ):
            self._docker(["cp", str(source), self.container_id + ":" + self.directory + "/" + name])
        self._docker(
            [
                "exec",
                self.container_id,
                "chmod",
                "0600",
                self.directory + "/node_checks.py",
                self.directory + "/praho-mail-native.pl",
            ]
        )

    def check_profile(self) -> None:
        facts = self.node("profile")
        if (facts.get("os_id"), facts.get("os_version"), facts.get("virtualmin")) != (
            self.profile.os_id,
            self.profile.os_version,
            "8.3.0-1-gpl",
        ):
            raise MailLabError("Clean image has the wrong OS or Virtualmin profile")
        if type(facts.get("domain_count")) is not int or facts["domain_count"] != 0:
            raise MailLabError("Clean test image already contains customer domains")

    def node(self, action: str, *, material: dict[str, str] | None = None, case: str = "") -> dict[str, Any]:
        if action not in {
            "profile",
            "prepare",
            "preserved",
            "new_default",
            "denied",
            "boot_state",
            "certificate_candidate",
            "certificate_unchanged",
            "certificate_replaced",
        }:
            raise MailLabError("Unknown fixed test action")
        self._owned()
        request = {
            "action": action,
            "run_id": self.run_id,
            "hostname": self.hostname,
            **({"material": material} if material else {}),
            **({"case": case} if case else {}),
        }
        result = self._docker(
            ["exec", "-i", self.container_id, "python3", self.directory + "/node_checks.py"],
            payload=json.dumps(request),
            timeout=600,
        )
        try:
            facts = json.loads(result.stdout)
            if not isinstance(facts, dict) or facts.get("ok") is not True:
                raise ValueError
        except (ValueError, TypeError):
            raise MailLabError("A fixed node check failed; private clone journal retained") from None
        self.facts.append({"stage": action, "ok": True})
        _private_json(self.artifacts / "facts.json", self.facts)
        return facts

    def playbook(self, action: str, *, operation_id: UUID | None = None) -> dict[str, Any]:
        if action not in {"setup", "inspect_node", "reconcile_submitters", "reconcile_node_certificate"}:
            raise MailLabError("Unknown production mail action")
        identity = str(uuid4() if operation_id is None else operation_id)
        try:
            if str(UUID(identity)) != identity:
                raise ValueError
        except (ValueError, TypeError):
            raise MailLabError("Invalid production mail operation identity") from None
        self._owned()
        binary = Path(sys.executable).with_name("ansible-playbook")
        values = {
            "mail_action": action,
            "mail_operation_id": identity,
            "mail_expected_node_hostname": self.hostname,
            "mail_reserved_account_zones": json.dumps(["accounts.mail-lab.praho.test"]),
            "mail_account_zone": "accounts.mail-lab.praho.test",
        }
        environment = {**os.environ, "ANSIBLE_LOCAL_TEMP": str(self.artifacts / "ansible-local")}
        result = self._call(
            [
                str(binary),
                "--inventory",
                self.container_id + ",",
                "--connection",
                "community.docker.docker",
                str(PLAYBOOK),
                "--extra-vars",
                json.dumps(values),
            ],
            timeout=PLAYBOOK_TIMEOUT,
            environment=environment,
        )
        self._owned()
        try:
            records = re.findall(r"MAIL_RESULT=([A-Za-z0-9+/=]+)", result.stdout)
            if len(records) != 1:
                raise ValueError
            envelope = json.loads(base64.b64decode(records[0], validate=True))
            payload = envelope["payload"]
            if not isinstance(envelope, dict) or not isinstance(payload, dict):
                raise ValueError
            code, stage = payload.get("error"), payload.get("stage")
            _private_json(
                self.artifacts / ("receipt-" + action + ".json"),
                {
                    "envelope_bound": (type(envelope.get("version")), envelope.get("version")) == (int, 1)
                    and (envelope.get("action"), envelope.get("identity"), envelope.get("node_hostname"))
                    == (action, identity, self.hostname),
                    "payload_bound": payload.get("node_hostname") == self.hostname,
                    "profile_bound": payload.get("profile") == self.profile.native_profile,
                    "code": code if isinstance(code, str) and code in _PUBLIC_CODES else "unknown",
                    "stage": stage if isinstance(stage, str) and stage in _PUBLIC_STAGES else "unknown",
                },
            )
            if (type(envelope.get("version")), envelope.get("version")) != (int, 1):
                raise ValueError
            if (envelope["action"], envelope["identity"], envelope.get("node_hostname")) != (
                action,
                identity,
                self.hostname,
            ):
                raise ValueError
            if (
                payload.get("node_hostname") != self.hostname
                or payload.get("error")
                or payload.get("profile") != self.profile.native_profile
                or payload.get("configured") is not True
                or payload.get("default_mail_off") is not True
            ):
                raise ValueError
            if action in {"setup", "inspect_node", "reconcile_node_certificate"} and set(
                payload.get("public_ports", [])
            ) != {25, 465, 993, 995}:
                raise ValueError
            proof = _certificate_receipt(payload) if action == "reconcile_node_certificate" else {}
            if (
                action == "reconcile_submitters"
                and re.fullmatch(r"[a-f0-9]{64}", payload.get("maps_sha256", "")) is None
            ):
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise MailLabError("Production playbook did not prove ready mail capability") from None
        self.facts.append({"stage": action, "ok": True, "profile": self.profile.native_profile})
        _private_json(self.artifacts / "facts.json", self.facts)
        return {"configured": True, "profile": self.profile.native_profile, **proof}

    def prepare(self) -> None:
        self.node("prepare", material=_certificate(self.hostname))

    def certificate_candidate(self, case: str) -> None:
        if case not in {"valid", "wrong_name"}:
            raise MailLabError("Unknown fixed certificate fixture")
        name = self.hostname if case == "valid" else "foreign." + self.hostname
        self.node("certificate_candidate", material=_certificate(name), case=case)

    def reboot(self) -> None:
        before = self._owned()["State"]["StartedAt"]
        self._docker(["restart", "--timeout", "20", self.container_id], timeout=90)
        self._wait_boot()
        if self._owned()["State"]["StartedAt"] == before:
            raise MailLabError("Owned node did not actually restart")
        self.node("boot_state")

    def cleanup(self) -> None:
        if self.network_id:
            self._network()
        if self.container_id:
            self._owned()
            self._docker(["rm", "--force", self.container_id], timeout=90)
        if self.network_id:
            state = self._network()
            if state.get("Containers"):
                raise MailLabError("Owned network did not become empty")
            self._docker(["network", "rm", self.network_id])

    def finish(self, *, success: bool, cleanup_failure: bool = False) -> None:
        if success or cleanup_failure:
            self.cleanup()
        else:
            _private_json(
                self.artifacts / "retained.json",
                {
                    "container_id": self.container_id,
                    "network_id": self.network_id,
                    "run_id": self.run_id,
                    "profile": asdict(self.profile),
                    "journal": "retained inside owned container",
                },
            )
