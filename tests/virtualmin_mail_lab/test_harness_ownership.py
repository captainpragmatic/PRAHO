"""The real harness must refuse foreign resources before any destructive Docker call."""

from __future__ import annotations

import base64
import importlib.util
import io
import json
import re
import subprocess
import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tests.virtualmin_mail_lab import node_checks
from tests.virtualmin_mail_lab.harness import (
    _PUBLIC_CODES,
    _PUBLIC_STAGES,
    PLAYBOOK,
    PROFILES,
    MailClone,
    MailLabError,
    _certificate,
)

CID = "1" * 64
NID = "2" * 64
IMAGE = "sha256:" + "3" * 64
SECRET = "fake-password-must-never-enter-a-traceback"


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.container = None
        self.network = None
        self.fail = None
        self.receipt_override = {}
        self.payload_override = {}
        self.ansible_result = None
        self.runtime = {
            "ok": True,
            "os_id": "debian",
            "os_version": "12",
            "virtualmin": "8.3.0-1-gpl",
            "domain_count": 0,
        }

    def receipt(self, argv):
        values = json.loads(argv[argv.index("--extra-vars") + 1])
        payload = {
            "node_hostname": values["mail_expected_node_hostname"],
            "profile": "debian12-dovecot23",
            "configured": True,
            "default_mail_off": True,
            "public_ports": [25, 465, 993, 995],
            "maps_sha256": "a" * 64,
            "outcome": "unchanged",
            "certificate_sha256": "b" * 64,
            "not_after": (datetime.now(UTC) + timedelta(days=20)).isoformat(),
            "pending_code": "",
            **self.payload_override,
        }
        envelope = {
            "version": 1,
            "action": values["mail_action"],
            "identity": values["mail_operation_id"],
            "node_hostname": values["mail_expected_node_hostname"],
            "payload": payload,
            **self.receipt_override,
        }
        return "MAIL_RESULT=" + base64.b64encode(json.dumps(envelope).encode()).decode()

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.fail is not None:
            raise self.fail
        if Path(argv[0]).name == "ansible-playbook":
            output, code = self.ansible_result or (self.receipt(argv), 0)
            return subprocess.CompletedProcess(argv, code, output, "")
        return subprocess.CompletedProcess(argv, 0, self.docker(argv[1:]), "")

    def docker(self, command):
        output = ""
        if command[:2] == ["image", "inspect"]:
            output = json.dumps([{"Id": IMAGE}])
        elif command[:2] == ["network", "create"]:
            self.network = {"Id": NID, "Labels": self.labels(command), "Containers": {}}
            output = NID
        elif command[:1] == ["run"]:
            self.container = {
                "Id": CID,
                "Image": IMAGE,
                "Config": {"Labels": self.labels(command), "Hostname": command[command.index("--hostname") + 1]},
                "HostConfig": {"PortBindings": {}},
                "NetworkSettings": {
                    "Networks": {command[command.index("--network") + 1]: {"NetworkID": NID}},
                    "Ports": {"25/tcp": None, "993/tcp": None},
                },
                "State": {"Running": True, "StartedAt": "first-start"},
            }
            output = CID
        elif command[:1] == ["inspect"]:
            output = json.dumps([self.container])
        elif command[:2] == ["network", "inspect"]:
            output = json.dumps([self.network])
        elif "exec" in command and "python3" in command:
            output = json.dumps(self.runtime)
        elif command[:1] == ["exec"]:
            output = "running"
        elif command[:1] == ["restart"]:
            self.container["State"]["StartedAt"] = "restarted-" + str(len(self.calls))
        elif command[:2] == ["network", "rm"]:
            self.network = None
        elif command[:1] == ["rm"]:
            self.container = None
        return output

    @staticmethod
    def labels(command):
        return dict(command[index + 1].split("=", 1) for index, value in enumerate(command) if value == "--label")


@pytest.fixture
def clone(tmp_path):
    runner = FakeDocker()
    value = MailClone(PROFILES["debian12"], tmp_path / "private", runner=runner)
    value.create()
    return value, runner


def test_clone_has_no_published_ports_and_pins_the_inspected_image_id(clone):
    value, runner = clone
    argv = next(argv for argv, _kwargs in runner.calls if argv[1:2] == ["run"])
    assert not {"-p", "-P", "--publish", "--publish-all", "--network=host"}.intersection(argv)
    assert IMAGE in argv
    assert value.container_id == CID
    assert "vmlab-a" not in argv and "vmlab-b" not in argv


@pytest.mark.parametrize("changed", ["id", "label", "hostname", "network", "image", "ports", "actual_ports"])
def test_cleanup_refuses_a_foreign_or_changed_container_without_rm(clone, changed):
    value, runner = clone
    if changed == "id":
        runner.container["Id"] = "4" * 64
    if changed == "label":
        runner.container["Config"]["Labels"] = {}
    if changed == "hostname":
        runner.container["Config"]["Hostname"] = "vmlab-a"
    if changed == "network":
        runner.container["NetworkSettings"]["Networks"] = {}
    if changed == "image":
        runner.container["Image"] = "sha256:" + "4" * 64
    if changed == "ports":
        runner.container["HostConfig"]["PortBindings"] = {"25/tcp": [{"HostPort": "25"}]}
    if changed == "actual_ports":
        runner.container["HostConfig"] = {}
        runner.container["NetworkSettings"]["Ports"] = {"25/tcp": [{"HostIp": "0.0.0.0", "HostPort": "2525"}]}
    before = len(runner.calls)
    with pytest.raises(MailLabError):
        value.cleanup()
    assert not any(argv[1:2] == ["rm"] for argv, _ in runner.calls[before:])


@pytest.mark.parametrize("action", ["setup", "inspect_node", "reconcile_submitters"])
def test_playbook_accepts_a_receipt_bound_to_the_current_hostname_and_operation(clone, action):
    value, _runner = clone
    assert value.playbook(action) == {"configured": True, "profile": "debian12-dovecot23"}


@pytest.mark.parametrize("changed", ["envelope_hostname", "payload_hostname", "boolean_version"])
def test_playbook_refuses_an_otherwise_valid_foreign_or_boolean_version_receipt(clone, changed):
    value, runner = clone
    if changed == "envelope_hostname":
        runner.receipt_override["node_hostname"] = "foreign.mail-lab.praho.test"
    if changed == "payload_hostname":
        runner.payload_override["node_hostname"] = "foreign.mail-lab.praho.test"
    if changed == "boolean_version":
        runner.receipt_override["version"] = True
    with pytest.raises(MailLabError, match="Production playbook did not prove"):
        value.playbook("setup")


@pytest.mark.parametrize("secret_fields", [False, True])
def test_refused_playbook_keeps_only_bounded_public_failure_metadata(clone, secret_fields):
    value, runner = clone
    runner.payload_override = {
        "error": SECRET if secret_fields else "mail_unrelated_configuration_changed",
        "stage": SECRET if secret_fields else "secure_configuration",
        "credentials": SECRET,
    }
    with pytest.raises(MailLabError):
        value.playbook("setup")
    path = value.artifacts / "receipt-setup.json"
    metadata = json.loads(path.read_text())
    assert metadata["code"] == ("unknown" if secret_fields else "mail_unrelated_configuration_changed")
    assert metadata["stage"] == ("unknown" if secret_fields else "secure_configuration")
    assert metadata["envelope_bound"] is True
    assert SECRET not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600


def test_certificate_reconciliation_uses_the_same_operation_and_checks_typed_proof(clone):
    value, runner = clone
    identity = uuid4()
    result = value.playbook("reconcile_node_certificate", operation_id=identity)
    assert result["outcome"] == "unchanged"
    assert result["certificate_sha256"] == "b" * 64
    call = next(argv for argv, _kwargs in runner.calls if Path(argv[0]).name == "ansible-playbook")
    assert json.loads(call[call.index("--extra-vars") + 1])["mail_operation_id"] == str(identity)


@pytest.mark.parametrize("identity", [False, 0, ""])
def test_explicit_invalid_operation_identity_refuses_before_any_docker_or_ansible_call(clone, identity):
    value, runner = clone
    before = len(runner.calls)
    with pytest.raises(MailLabError):
        value.playbook("reconcile_node_certificate", operation_id=identity)
    assert runner.calls[before:] == []


@pytest.mark.parametrize(
    "changes",
    [
        {"certificate_sha256": "unknown"},
        {"outcome": "guessed"},
        {"not_after": "2000-01-01T00:00:00+00:00"},
        {"pending_code": "private unknown detail"},
    ],
)
def test_certificate_reconciliation_refuses_unproven_native_certificate_fields(clone, changes):
    value, runner = clone
    runner.payload_override.update(changes)
    with pytest.raises(MailLabError):
        value.playbook("reconcile_node_certificate", operation_id=uuid4())


def test_repeated_valid_renewal_fixture_preserves_the_prior_fake_ca(monkeypatch, tmp_path):
    actual_path = Path

    def local_path(*parts):
        path = actual_path(*parts)
        return tmp_path / str(path).lstrip("/") if path.is_absolute() else path

    directory = tmp_path / ("a" * 32)
    directory.mkdir()
    material = _certificate("node.mail-lab.praho.test")
    for relative, content in {
        "etc/praho-mail/node.pem": material["pem"],
        "etc/praho-mail/node.key": "fixture",
        "var/lib/praho/mail/node.json": "{}",
        "etc/webmin/miniserv.pem": material["pem"],
    }.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    trust = tmp_path / "usr/local/share/ca-certificates"
    trust.mkdir(parents=True)
    monkeypatch.setattr(node_checks, "Path", local_path)
    monkeypatch.setattr(node_checks, "command", lambda *_args, **_kwargs: "")
    for _ in range(2):
        node_checks.certificate_candidate(
            {"case": "valid", "material": _certificate("node.mail-lab.praho.test")}, directory
        )
    assert len(list(trust.glob("*.crt"))) == 2


def test_owned_cleanup_uses_recorded_ids_and_refuses_other_network_endpoints(clone):
    value, runner = clone
    runner.network["Containers"] = {"foreign-container": {}}
    with pytest.raises(MailLabError):
        value.cleanup()
    assert not any(argv[1:3] == ["network", "rm"] for argv, _ in runner.calls)


def test_failed_run_retains_owned_clone_by_default_but_explicit_cleanup_is_possible(clone):
    value, runner = clone
    value.finish(success=False)
    assert runner.container is not None and runner.network is not None
    assert (value.artifacts / "retained.json").is_file()
    value.finish(success=False, cleanup_failure=True)
    assert runner.container is None and runner.network is None
    assert ["docker", "rm", "--force", CID] in [argv for argv, _ in runner.calls]
    assert ["docker", "network", "rm", NID] in [argv for argv, _ in runner.calls]


def test_optional_dns_affects_only_new_container_arguments(tmp_path):
    runner = FakeDocker()
    value = MailClone(PROFILES["debian12"], tmp_path / "private", runner=runner, dns="192.168.65.7")
    value.create()
    command = next(argv for argv, _ in runner.calls if argv[1:2] == ["run"])
    assert command[command.index("--dns") + 1] == "192.168.65.7"
    assert not any("resolv.conf" in str(argv) for argv, _ in runner.calls)


def test_subprocess_secret_never_escapes_via_exception_or_timeout_traceback(clone):
    value, runner = clone
    for error in (
        subprocess.CalledProcessError(1, ["native", "--pass", SECRET], stderr=SECRET),
        subprocess.TimeoutExpired(["native", "--pass", SECRET], 1, stderr=SECRET),
    ):
        runner.fail = error
        with pytest.raises(MailLabError) as failure:
            value.check_profile()
        assert SECRET not in "".join(traceback.format_exception(failure.value))


def test_wrong_runtime_profile_is_refused_before_fixture_mutation(clone):
    value, runner = clone
    runner.runtime["os_id"] = "ubuntu"
    with pytest.raises(MailLabError):
        value.check_profile()
    assert not any('"action": "prepare"' in (kwargs.get("input") or "") for _argv, kwargs in runner.calls)


def test_a_foreign_network_label_is_refused_before_removing_the_container(clone):
    value, runner = clone
    runner.network["Labels"] = {}
    before = len(runner.calls)
    with pytest.raises(MailLabError):
        value.cleanup()
    assert not any(argv[1:2] == ["rm"] or argv[1:3] == ["network", "rm"] for argv, _ in runner.calls[before:])


def test_preexisting_customer_domains_are_refused_before_fixture_mutation(clone):
    value, runner = clone
    runner.runtime["domain_count"] = 1
    with pytest.raises(MailLabError):
        value.check_profile()
    assert not any('"action": "prepare"' in (kwargs.get("input") or "") for _argv, kwargs in runner.calls)


def test_node_dispatcher_drops_native_secret_tracebacks(monkeypatch, tmp_path, capsys):
    run_id = "a" * 32
    private = tmp_path / run_id
    private.mkdir(mode=0o700)
    actual_path = Path
    called = []

    def local_path(*parts):
        if parts[0] == "/var/lib/praho-mail-lab":
            return private
        return actual_path(*parts)

    def fail(_request, _directory):
        called.append(True)
        raise subprocess.CalledProcessError(1, ["native", "--pass", SECRET], stderr=SECRET)

    monkeypatch.setattr(node_checks, "Path", local_path)
    monkeypatch.setattr(node_checks, "__file__", str(private / "node_checks.py"))
    monkeypatch.setattr(node_checks.os, "geteuid", lambda: 0)
    monkeypatch.setattr(node_checks, "profile", fail)
    monkeypatch.setattr(node_checks.sys, "stdin", io.StringIO(json.dumps({"run_id": run_id, "action": "profile"})))
    assert node_checks.main() == 1
    assert called == [True]
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err
    assert json.loads(captured.out)["code"] == "mail_lab_node_check_failed"


def test_generated_certificate_satisfies_the_production_seven_day_preflight():
    material = _certificate("node-test.mail-lab.praho.test")
    certificate_pem = "-----BEGIN CERTIFICATE-----" + material["pem"].split("-----BEGIN CERTIFICATE-----", 1)[1]
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
    ca = x509.load_pem_x509_certificate(material["ca"].encode())
    key = serialization.load_pem_private_key(material["pem"].encode(), password=None)
    assert certificate.not_valid_after_utc > datetime.now(UTC) + timedelta(days=7)
    assert certificate.issuer == ca.subject
    assert certificate.public_key().public_numbers() == key.public_key().public_numbers()
    assert ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
    assert certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName
    ) == ["node-test.mail-lab.praho.test"]


def test_a_recovered_certificate_is_typed_proof(clone):
    value, runner = clone
    runner.payload_override.update(outcome="recovered", pending_code="")
    assert value.playbook("reconcile_node_certificate", operation_id=uuid4())["outcome"] == "recovered"


def test_a_bundle_upgrade_receipt_is_bound_and_typed_without_live_listeners(clone):
    value, runner = clone
    runner.payload_override.update(
        outcome="upgraded", bundle_sha256="c" * 64, configured=False, default_mail_off=False, public_ports=[]
    )
    result = value.playbook("upgrade_bundle", operation_id=uuid4())
    assert result == {"profile": "debian12-dovecot23", "outcome": "upgraded", "bundle_sha256": "c" * 64}
    for changes in ({"outcome": "replaced"}, {"bundle_sha256": "not a digest"}, {"node_hostname": "foreign.test"}):
        runner.payload_override.update(changes)
        with pytest.raises(MailLabError):
            value.playbook("upgrade_bundle", operation_id=uuid4())
        runner.payload_override.update(outcome="upgraded", bundle_sha256="c" * 64, node_hostname=value.hostname)


def test_a_previous_commit_playbook_source_is_the_one_run(clone, tmp_path):
    value, runner = clone
    source = tmp_path / "previous/virtualmin_mail.yml"
    source.parent.mkdir()
    source.write_text("---\n")
    value.playbook("setup", source=source)
    call = next(argv for argv, _kwargs in runner.calls if Path(argv[0]).name == "ansible-playbook")
    assert str(source) in call and str(PLAYBOOK) not in call
    for unsafe in (tmp_path / "previous/other.yml", tmp_path / "missing/virtualmin_mail.yml"):
        with pytest.raises(MailLabError):
            value.playbook("setup", source=unsafe)


def test_an_interrupted_playbook_must_end_without_any_receipt(clone):
    value, runner = clone
    runner.ansible_result = ("worker killed", 2)
    value.playbook_interrupted("reconcile_node_certificate", operation_id=uuid4())
    runner.ansible_result = None
    with pytest.raises(MailLabError):
        value.playbook_interrupted("reconcile_node_certificate", operation_id=uuid4())


def test_a_bare_restart_proves_a_new_start_without_requiring_ready_mail(clone):
    value, runner = clone
    value.restart()
    assert any(argv[1:2] == ["restart"] for argv, _ in runner.calls)
    assert not any('"action": "boot_state"' in (kwargs.get("input") or "") for _argv, kwargs in runner.calls)


def test_public_codes_and_stages_cover_every_native_code_and_stage():
    files = PLAYBOOK.parent / "files"
    specification = importlib.util.spec_from_file_location("mail_lab_public_codes", files / "praho-mail.py")
    native = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(native)
    assert native.PUBLIC_ERRORS == _PUBLIC_CODES
    sources = "".join((files / name).read_text() for name in ("praho-mail.py", "praho_mail_setup.py"))
    assert set(re.findall(r'stage = "([a-z_]+)"', sources)) <= _PUBLIC_STAGES
