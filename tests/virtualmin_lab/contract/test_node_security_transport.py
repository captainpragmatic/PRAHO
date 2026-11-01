"""Real enrolled SSH inspection and durable API re-enrollment stay separate from port recovery."""

from __future__ import annotations

import base64
import json
import re

from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.virtualmin_security import connection_identity
from tests.virtualmin_lab.contract.harness import Lab
from tests.virtualmin_lab.contract.test_web_only_security import harden_webmin


def test_security_read_playbook_returns_identity_bound_native_evidence(lab: Lab) -> None:
    identity = connection_identity(lab.server)
    result = AnsibleService().run_server_playbook(
        lab.server, "virtualmin_security_read.yml", {"security_identity": identity}, timeout_seconds=120
    )
    assert result.is_ok(), "Enrolled security inspection transport failed"
    assert result.unwrap().success, "Native security inspection failed"
    matches = re.findall(r"PRAHO_SECURITY_INSPECTION=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    assert len(matches) == 1
    evidence = json.loads(base64.b64decode(matches[0], validate=True))
    assert evidence["identity"] == identity
    assert evidence["versions"] == {"webmin": "2.670", "virtualmin": "8.3.0"}
    assert evidence["schema"] == 1
    assert evidence["listeners"] and evidence["principals"] and evidence["firewall"]
    password = lab.server.get_api_password()
    if password and password in json.dumps(evidence):
        raise AssertionError("Native inspection exposed the durable API password")
    healthy = lab.gateway.test_connection()
    assert healthy.is_ok() and healthy.unwrap()["healthy"] is True


def test_enrollment_playbook_proves_the_same_durable_api_and_ssh_pinned_certificate(lab: Lab) -> None:
    password = lab.server.get_api_password()
    assert password and lab.server.api_username != "root"
    try:
        result = AnsibleService().run_playbook(
            lab.server.node_deployment,
            "virtualmin_security_enroll.yml",
            {"security_hardening_approved": True, "praho_api_user": lab.server.api_username, "praho_api_password": password},
            timeout_seconds=180,
        )
        assert result.is_ok(), "Dedicated API enrollment transport failed"
        assert result.unwrap().success, "Native dedicated API enrollment failed"
        certificates = re.findall(r"PRAHO_PANEL_CERT=([0-9a-f]{64})", result.unwrap().stdout)
        assert certificates == [lab.server.ssl_cert_fingerprint]
        if password in result.unwrap().stdout or password in result.unwrap().stderr:
            raise AssertionError("Native enrollment exposed its private credential")
        connected = lab.gateway.test_connection()
        assert connected.is_ok() and connected.unwrap()["healthy"] is True
    finally:
        harden_webmin(lab)
