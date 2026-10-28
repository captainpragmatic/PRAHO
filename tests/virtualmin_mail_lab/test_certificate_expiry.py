"""Expired node certificate recovery on an owned disposable clone, through the production playbook."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests.virtualmin_mail_lab.harness import PLAYBOOK, REPO, MailClone, MailLabError, _private_json

CHECKS = Path(__file__).with_name("expiry_checks.py")
GUARD = "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /usr/lib/praho/mail/praho-mail-boot.py ; "
# The last helper bundle before this change (bd0d9651 = aefee9f0); it is in PREDECESSOR_BUNDLES.
PREVIOUS_BUNDLE = "bd0d9651"


def protocol() -> Any:
    specification = importlib.util.spec_from_file_location(
        "mail_lab_setup_protocol", PLAYBOOK.parent / "files/praho_mail_setup.py"
    )
    if specification is None or specification.loader is None:
        raise MailLabError("Mail setup protocol is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def expiry(clone: MailClone, action: str, **values: Any) -> dict[str, Any]:
    """Run one fixed in-clone expiry check; only its bounded JSON facts return to the host."""
    clone._owned()
    target = clone.directory + "/expiry_checks.py"
    clone._docker(["cp", str(CHECKS), clone.container_id + ":" + target])
    clone._docker(["exec", clone.container_id, "chmod", "0600", target])
    result = clone._docker(
        ["exec", "-i", clone.container_id, "python3", target],
        payload=json.dumps({"action": action, "run_id": clone.run_id, "hostname": clone.hostname, **values}),
        timeout=600,
        required=False,
    )
    try:
        facts = json.loads(result.stdout)
        if not isinstance(facts, dict) or facts.get("ok") is not True:
            raise ValueError
    except (ValueError, TypeError):
        raise MailLabError("A fixed expiry check failed; private clone journal retained") from None
    clone.facts.append({"stage": "expiry_" + action, "ok": True})
    _private_json(clone.artifacts / ("expiry-" + action + ".json"), facts)
    return facts


def expired_material(hostname: str) -> dict[str, str]:
    """A strict, correctly named leaf under a fresh clone-only CA, expired one day ago."""
    now = datetime.now(UTC)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable PRAHO expired-leaf test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(issuer)
        .issuer_name(issuer)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=60))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)
        .sign(issuer_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now - timedelta(days=1))
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
        "leaf": leaf.public_bytes(serialization.Encoding.PEM).decode(),
        "key": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    }


def assert_pinned_topology(clone: MailClone, facts: dict[str, Any]) -> None:
    """The installed units' loaded state equals the production topology table for this profile."""
    assert facts["toplevel_dropins"] == {key: [] for key in facts["toplevel_dropins"]}
    for unit in protocol().UNIT_TOPOLOGY[clone.profile.native_profile]:
        shown = facts["units"][unit["unit"]]
        assert (
            shown["LoadState"],
            shown["Type"],
            shown["UnitFileState"],
            shown["FragmentPath"],
            shown["DropInPaths"],
            shown["NeedDaemonReload"],
            (shown["ActiveState"], shown["SubState"]),
        ) == (
            "loaded",
            unit["type"],
            unit["file_state"],
            unit["fragment"],
            unit["dropin"],
            "no",
            unit["started"],
        )
        assert shown["ExecStartPre"].startswith(GUARD)
        assert shown["ExecStartPre"].count("{") == 1


def expire_and_renew(clone: MailClone) -> None:
    """Forge an expired installed leaf, prove a real restart is refused, stop mail, then renew in Webmin."""
    expiry(clone, "forge_expired", material=expired_material(clone.hostname))
    clone.certificate_candidate("valid")


def recovered(clone: MailClone, operation_id: Any) -> dict[str, Any]:
    result = clone.playbook("reconcile_node_certificate", operation_id=operation_id)
    assert result["outcome"] == "recovered"
    clone.node("certificate_replaced")  # all four frontends serve the exact new leaf; journal is ready
    return result


@pytest.mark.mail_node
def test_an_expired_stopped_node_recovers_resumes_after_owner_death_and_after_restart(mail_clone: MailClone) -> None:
    mail_clone.prepare()
    mail_clone.playbook("setup")
    assert_pinned_topology(mail_clone, expiry(mail_clone, "topology"))

    first = uuid4()
    expire_and_renew(mail_clone)
    recovered(mail_clone, first)
    timing = expiry(mail_clone, "start_timing")
    # Each start ran the guard under a live permit; the worker refuses to start below this margin.
    assert all(0 < seconds < protocol().GUARD_START_SECONDS for seconds in timing["guard_start_seconds"].values())
    mail_clone.node("preserved")
    mail_clone.node("denied")

    # The owner dies right after the guard admitted its first unit.
    killed = uuid4()
    expire_and_renew(mail_clone)
    expiry(mail_clone, "arm_kill", trigger="first_start")
    mail_clone.playbook_interrupted("reconcile_node_certificate", operation_id=killed)
    owner = expiry(mail_clone, "owner_killed")
    recovered(mail_clone, killed)

    # The container restarts mid-sequence: the lock, the owner and the live fence are all gone.
    restarted = uuid4()
    expire_and_renew(mail_clone)
    expiry(mail_clone, "arm_kill", trigger="starting")
    mail_clone.playbook_interrupted("reconcile_node_certificate", operation_id=restarted)
    mail_clone.restart()
    expiry(mail_clone, "after_restart")
    recovered(mail_clone, restarted)

    # A completed delivery replays as verification only.
    assert mail_clone.playbook("reconcile_node_certificate", operation_id=first)["outcome"] == "unchanged"
    mail_clone.node("preserved")
    mail_clone.node("denied")
    print(
        json.dumps(
            {
                "profile": mail_clone.profile.key,
                "guard_start_seconds": timing["guard_start_seconds"],
                "owner_death": {key: owner[key] for key in ("admitted_daemon", "later_start_refused")},
            }
        )
    )


def previous_playbook(directory: Path) -> Path:
    """Extract the previous commit's playbook, helpers and templates into a private directory."""
    relative = PLAYBOOK.parent.relative_to(REPO)
    git = shutil.which("git")
    if git is None:
        raise MailLabError("git is required to extract the previous bundle")
    archive = subprocess.run(  # noqa: S603 -- fixed test-owned argv
        [
            git,
            "-C",
            str(REPO),
            "archive",
            PREVIOUS_BUNDLE,
            str(relative / "virtualmin_mail.yml"),
            str(relative / "files"),
            str(relative / "templates/mail"),
        ],
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout
    directory.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        bundle.extractall(directory, filter="data")
    return directory / relative / "virtualmin_mail.yml"


@pytest.mark.mail_node
def test_a_previous_bundle_upgrades_in_place_on_an_expired_stopped_node_then_recovers(
    mail_clone: MailClone,
) -> None:
    source = previous_playbook(mail_clone.artifacts / "previous")
    mail_clone.prepare()
    mail_clone.playbook("setup", source=source)
    expire_and_renew(mail_clone)
    before = expiry(mail_clone, "installed_bundle")
    upgrade = uuid4()
    assert mail_clone.playbook("upgrade_bundle", operation_id=upgrade)["outcome"] == "upgraded"
    after = expiry(mail_clone, "installed_bundle")
    current = {
        "/usr/lib/praho/mail/" + name: hashlib.sha256((PLAYBOOK.parent / "files" / name).read_bytes()).hexdigest()
        for name in protocol().NATIVE_FILES
    }
    assert {path: after["digests"][path] for path in current} == current
    assert before["digests"] != after["digests"] and after["journal_status"] == "ready"
    assert mail_clone.playbook("upgrade_bundle", operation_id=uuid4())["outcome"] == "unchanged"
    recovered(mail_clone, uuid4())
    mail_clone.node("preserved")
