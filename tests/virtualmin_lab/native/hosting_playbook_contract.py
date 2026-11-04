"""Controller contracts for the playbooks reached by the owned native workflows.

The integration census invokes these controls through its normal Make target. Only
the Ansible network/process boundary is replaced. These checks do not execute a
playbook or prove native Ubuntu quotas, mail suppression or provider deployment.
The separate manifest-bound native gates remain required.
"""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
from unittest.mock import ANY, patch

import yaml

REPO = Path(__file__).resolve().parents[3]
PLAYBOOKS = REPO / "services/platform/infrastructure/ansible/playbooks"

# Independent expected routes, not values derived from the production dispatcher.
HOSTING_ROUTES = (
    ("quota", "probe", "virtualmin_quota.yml", "PRAHO_QUOTA_RESULT", 150),
    ("quota", "apply", "virtualmin_quota.yml", "PRAHO_QUOTA_RESULT", 420),
    ("quota", "fence", "virtualmin_quota.yml", "PRAHO_QUOTA_RESULT", 90),
    ("node", "inspect", "virtualmin_hosting_read.yml", "PRAHO_HOSTING_RESULT", 180),
    ("node", "handover", "virtualmin_hosting_policy.yml", "PRAHO_HOSTING_RESULT", 180),
    ("node", "fence", "virtualmin_hosting_policy.yml", "PRAHO_HOSTING_RESULT", 180),
    ("node", "quota_policy", "virtualmin_hosting_policy.yml", "PRAHO_HOSTING_RESULT", 180),
    ("node", "quota_fence", "virtualmin_hosting_policy.yml", "PRAHO_HOSTING_RESULT", 180),
    ("node", "requalify", "virtualmin_hosting_policy.yml", "PRAHO_HOSTING_RESULT", 180),
    ("node", "requalify_fence", "virtualmin_hosting_policy.yml", "PRAHO_HOSTING_RESULT", 180),
    ("helper", "prepare", "virtualmin_hosting_prepare.yml", "PRAHO_HOSTING_RESULT", 180),
    ("helper", "fence", "virtualmin_hosting_prepare.yml", "PRAHO_HOSTING_RESULT", 180),
)


def assert_hosting_route(family: str, action: str, playbook: str, marker: str, timeout: int) -> None:
    from apps.common.types import Ok  # noqa: PLC0415 -- Django is initialized by the integration runner.
    from apps.infrastructure.ansible_service import AnsibleResult, AnsibleService  # noqa: PLC0415
    from apps.provisioning import hosting_node_transport  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415

    server = VirtualminServer(name="Controller contract only", hostname="controller-contract.invalid")
    request = {"token": "controller-boundary-only", "domain": "contract.invalid", "identity": {"uid": 12345}}
    observed = {"token": request["token"], "boundary": "controller-only"}
    encoded = base64.b64encode(json.dumps(observed).encode()).decode()
    result = Ok(AnsibleResult(True, playbook, f"{marker}={encoded}", "", 0))
    runner, prefix = {
        "quota": (hosting_node_transport.run_quota_operation, "quota"),
        "node": (hosting_node_transport.run_node_operation, "hosting"),
        "helper": (hosting_node_transport.run_helper_operation, "hosting"),
    }[family]
    with patch.object(AnsibleService, "run_server_playbook", autospec=True, return_value=result) as boundary:
        assert runner(server, action, request) == observed
        boundary.assert_called_once_with(
            ANY, server, playbook, {f"{prefix}_action": action, f"{prefix}_request": request}, timeout_seconds=timeout
        )
    assert (PLAYBOOKS / playbook).is_file()


def assert_installed_hosting_helpers() -> None:
    from apps.provisioning.hosting_node_bundle import helper_bundle  # noqa: PLC0415 -- Use the actual release bundle.

    # This is an imported task list, not a separately invokable play. Assert its
    # actual deployment include and installation loop instead of calling it one.
    deployment = yaml.safe_load((PLAYBOOKS / "virtualmin.yml").read_text())
    includes = [
        task
        for task in deployment[0]["tasks"]
        if task.get("ansible.builtin.import_tasks") == "virtualmin_hosting_tasks.yml"
    ]
    assert len(includes) == 1
    tasks = yaml.safe_load((PLAYBOOKS / "virtualmin_hosting_tasks.yml").read_text())
    copies = [task for task in tasks if "ansible.builtin.copy" in task]
    assert len(copies) == 1
    copy = copies[0]["ansible.builtin.copy"]
    assert copy == {
        "src": "files/{{ item }}",
        "dest": "/usr/local/lib/praho/{{ item }}",
        "owner": "root",
        "group": "root",
        "mode": "0700",
    }
    expected = {
        "praho_quota.py",
        "praho_quota_native.py",
        "praho-quota-metadata.pl",
        "praho_usage.py",
        "praho_hosting_node.py",
        "praho-notification-policy.pl",
    }
    assert len(copies[0]["loop"]) == 6
    assert set(copies[0]["loop"]) == expected
    bundle = helper_bundle()
    assert set(bundle["files"]) == expected
    for name, encoded in bundle["files"].items():
        assert base64.b64decode(encoded, validate=True) == (PLAYBOOKS / "files" / name).read_bytes()
    installer = ast.parse((PLAYBOOKS / "files/praho_hosting_prepare.py").read_text())
    file_sets = [
        ast.literal_eval(node.value.args[0])
        for node in installer.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "FILES" for target in node.targets)
        and isinstance(node.value, ast.Call)
    ]
    assert file_sets == [expected]
