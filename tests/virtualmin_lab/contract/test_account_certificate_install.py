"""Lab test: virtualmin_install_account_cert.yml, run through PRAHO's AnsibleService on the lab node.

The playbook receives the certificate, the chain and the key as variables, installs them with
`virtualmin install-cert`, and must leave no key material behind whether the install worked or not. The sandbox
domain's name is an account-name shape (eight letters, then the zone), so it passes the playbook's input check.

Written before its first lab run: the install itself is proven by the success of the playbook and by what is
left on the node afterwards; checking which certificate the domain then serves belongs to the lab run that
proves P1.10 end to end.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from apps.infrastructure.ansible_service import AnsibleService
from tests.virtualmin_lab.contract.harness import SANDBOX_DOMAIN, Lab

CONTAINER = "vmlab-b"
PLAYBOOK = "virtualmin_install_account_cert.yml"
INSTALL_TIMEOUT = 300


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pem_key(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def _self_signed(key: ec.EllipticCurvePrivateKey, name: str) -> str:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _leftovers(lab: Lab) -> list[str]:
    listing = lab.exec_on(CONTAINER, "sh", "-c", "ls -d /run/praho-cert-* 2>/dev/null; true")
    return listing.split()


def _run(lab: Lab, key_pem: str, certificate_pem: str) -> tuple[bool, str]:
    variables = {
        "account_name": SANDBOX_DOMAIN,
        "certificate_pem": certificate_pem,
        "chain_pem": "",
        "private_key_pem": key_pem,
    }
    result = AnsibleService().run_playbook(
        lab.server.node_deployment, PLAYBOOK, variables, timeout_seconds=INSTALL_TIMEOUT
    )
    assert result.is_ok(), result.unwrap_err() if result.is_err() else ""
    outcome = result.unwrap()
    return bool(outcome.success), str(outcome.stdout)


def test_a_matching_certificate_installs_and_leaves_no_key_material(lab: Lab) -> None:
    key = _key()
    certificate = _self_signed(key, SANDBOX_DOMAIN)

    installed, output = _run(lab, _pem_key(key), certificate)

    assert installed, output[-2000:]
    assert _leftovers(lab) == []
    assert "BEGIN PRIVATE KEY" not in output
    # The node's own word on what it now serves is what PRAHO checks before recording the install.
    reported = re.search(r"INSTALLED_FINGERPRINT=([0-9A-Fa-f:]+)", output)
    assert reported is not None, output[-2000:]
    sent = x509.load_pem_x509_certificate(certificate.encode()).fingerprint(hashes.SHA256()).hex()
    assert reported.group(1).replace(":", "").lower() == sent


def test_a_certificate_that_does_not_match_its_key_fails_and_still_leaves_nothing(lab: Lab) -> None:
    key, other = _key(), _key()

    installed, output = _run(lab, _pem_key(other), _self_signed(key, SANDBOX_DOMAIN))

    assert not installed
    assert _leftovers(lab) == []
    assert "BEGIN PRIVATE KEY" not in output
