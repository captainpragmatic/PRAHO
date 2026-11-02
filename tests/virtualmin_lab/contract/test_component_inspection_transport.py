"""The production read-only component playbook runs on a managed node's already enrolled SSH identity."""

import base64
import json
import re

from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.component_migration_manifest import ComponentManifest
from apps.provisioning.virtualmin_gateway import listing_attribute
from apps.provisioning.virtualmin_security import connection_identity
from tests.virtualmin_lab.contract.harness import SANDBOX_DOMAIN, SANDBOX_USER, Lab


def test_native_component_playbook_returns_bound_scope_over_existing_ssh(lab: Lab) -> None:
    domain_id = str(listing_attribute(lab.domain_values(SANDBOX_DOMAIN), "ID"))
    request = {
        "server_uuid": str(lab.server.pk),
        "connection_identity": connection_identity(lab.server),
        "domain_id": domain_id,
        "domain": SANDBOX_DOMAIN,
        "owner": SANDBOX_USER,
        "paths": [{"relative": "public_html", "purpose": "application"}],
        "databases": [],
    }
    result = AnsibleService().run_server_playbook(
        lab.server,
        "virtualmin_component.yml",
        {"component_action": "inspect", "component_request": request},
        timeout_seconds=180,
    )
    assert result.is_ok(), result
    assert result.unwrap().success, "The native component inspection playbook did not complete"
    encoded = re.findall(r"PRAHO_COMPONENT_INSPECTION=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
    assert len(encoded) == 1
    manifest = ComponentManifest.parse(json.loads(base64.b64decode(encoded[0], validate=True)))
    assert manifest.as_json()["source"]["domain_id"] == domain_id
    assert manifest.as_json()["source"]["connection_identity"] == connection_identity(lab.server)
    assert manifest.selected_paths == ("public_html",)
