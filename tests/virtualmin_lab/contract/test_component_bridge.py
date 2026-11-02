"""Execute the narrow component bridge playbook through enrolled managed SSH.

Controller admission and publication ordering have database contracts. This test
qualifies the executable playbook itself, including private helper retirement.
"""

import base64
import json
import re
import subprocess
from pathlib import Path
from uuid import uuid4

from django.conf import settings

from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.management.commands._virtualmin_lab import container_address
from tests.virtualmin_lab.contract.harness import SANDBOX_DOMAIN, Lab


def test_native_component_bridge_playbook_prepares_and_retires_exact_source(lab: Lab) -> None:
    # Explicit disposable-lab preparation, as required by the production source
    # preview. The bridge must never implicitly prepare an imported source.
    default = Path(settings.BASE_DIR) / "infrastructure/ansible/playbooks/files/praho-default-site.conf"
    lab.exec("install", "-d", "-m", "0755", "/var/www/praho-default")
    subprocess.run(  # noqa: S603 -- literal owned lab container and repository's public configuration asset
        ["docker", "cp", str(default), lab.node.container + ":/etc/apache2/conf-enabled/praho-default-site.conf"],  # noqa: S607
        check=True,
        capture_output=True,
        timeout=30,
    )
    lab.exec("chown", "root:root", "/etc/apache2/conf-enabled/praho-default-site.conf")
    lab.exec("chmod", "0644", "/etc/apache2/conf-enabled/praho-default-site.conf")
    lab.exec("apache2ctl", "configtest")
    lab.exec("apache2ctl", "graceful")
    identity = str(uuid4())
    deployment = lab.server.node_deployment
    runner = AnsibleService()
    values = {
        "bridge_id": identity,
        "bridge_domain": SANDBOX_DOMAIN,
        "bridge_account_name": "",
        "bridge_source_ipv4": container_address(lab.node.container),
        "bridge_target_ipv4": "192.0.2.20",
        "bridge_certificate_min_seconds": 3600,
        "component_bridge_operation": {"operation_id": identity, "worker_token": str(uuid4())},
    }

    def step(action):
        result = runner.run_playbook(
            deployment,
            "virtualmin_component_bridge.yml",
            {**values, "component_bridge_action": action},
            timeout_seconds=180,
        )
        assert result.is_ok(), result
        assert result.unwrap().success, result.unwrap().stdout
        encoded = re.findall(r"BRIDGE_RESULT=([A-Za-z0-9+/=]+)", result.unwrap().stdout)
        assert len(encoded) == 1
        receipt = json.loads(base64.b64decode(encoded[0], validate=True))
        assert receipt["identity"] == identity and receipt["action"] == action
        assert "PRIVATE KEY" not in json.dumps(receipt)
        return receipt["payload"]

    try:
        manifest = step("prepare")
        assert manifest["domain"] == SANDBOX_DOMAIN
        assert manifest["identity"] == identity
        assert manifest["source"] == values["bridge_source_ipv4"]
        assert manifest["target"] == values["bridge_target_ipv4"]
        assert any(row["name"] == SANDBOX_DOMAIN and row["port"] == 80 for row in manifest["vhosts"])
        # Preparation never publishes the reverse proxy or enables any domain.
        lab.exec("test", "!", "-e", "/etc/apache2/conf-enabled/praho-migration-" + identity + ".conf")
    finally:
        step("remove")
        lab.exec("test", "!", "-e", "/var/lib/praho/bridges/" + identity + "/source.json")
        lab.exec("test", "!", "-e", "/etc/apache2/conf-enabled/praho-migration-" + identity + ".conf")
