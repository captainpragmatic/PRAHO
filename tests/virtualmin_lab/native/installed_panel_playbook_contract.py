"""Shared installed-panel contracts; these do not certify Ubuntu installation."""

from pathlib import Path

import yaml

PLAYBOOKS = Path(__file__).resolve().parents[3] / "services/platform/infrastructure/ansible/playbooks"


def assert_shared_api_user_tasks() -> None:
    shared_name = "virtualmin_api_user_tasks.yml"
    importers = ("virtualmin.yml", "virtualmin_security_enroll.yml")
    imports = {
        name: [
            index
            for index, task in enumerate(yaml.safe_load((PLAYBOOKS / name).read_text())[0]["tasks"])
            if task.get("ansible.builtin.import_tasks") == shared_name
        ]
        for name in importers
    }
    assert imports.keys() == {"virtualmin.yml", "virtualmin_security_enroll.yml"}
    assert sum(len(indices) for indices in imports.values()) == 2
    assert all(len(indices) == 1 for indices in imports.values())
    # Last-importer canary: a missing enrollment include must never pass vacuously.
    assert len(imports["virtualmin_security_enroll.yml"]) == 1
    install = yaml.safe_load((PLAYBOOKS / "virtualmin.yml").read_text())[0]["tasks"]
    position = imports["virtualmin.yml"][0]
    assert install[position - 1]["name"] == "Require every PRAHO feature to be enabled"
    assert install[position + 1]["name"] == "Create PRAHO tracking file"

    shared = yaml.safe_load((PLAYBOOKS / shared_name).read_text())
    assert len(shared) == 3
    assert [task["name"] for task in shared] == [
        "Install the PRAHO API user helper",
        "Refuse an empty node admin allowlist",
        "Create or update the PRAHO API user",
    ]
    assert shared[0]["ansible.builtin.copy"] == {
        "src": "files/praho-webmin-api-user.pl",
        "dest": "/usr/local/sbin/praho-webmin-api-user",
        "owner": "root",
        "group": "root",
        "mode": "0700",
    }
    assert "node_admin_allowed_cidrs | length > 0" in shared[1]["ansible.builtin.assert"]["that"]
    command = shared[2]["ansible.builtin.command"]
    assert command["stdin"] == "{{ praho_api_password }}"
    assert "praho_api_password" not in command["argv"]
    assert "node_admin_allowed_cidrs" in command["argv"]
    assert shared[2]["no_log"] is True
    assert all(task["when"] == "praho_api_user is defined and praho_api_password is defined" for task in shared)

    enroll = yaml.safe_load((PLAYBOOKS / "virtualmin_security_enroll.yml").read_text())[0]["tasks"]
    guard = enroll[0]
    assert guard["no_log"] is True
    assert guard["ansible.builtin.assert"]["that"] == [
        "security_hardening_approved | default(false) | bool",
        "praho_api_user != 'root'",
        "praho_api_password | length >= 16",
        "node_admin_allowed_cidrs | length > 0",
    ]
    assert imports["virtualmin_security_enroll.yml"][0] > 0
    assert enroll[-1]["ansible.builtin.debug"]["msg"] == "{{ panel_certificate.stdout }}"
