"""Read the effective native role through its static task includes."""

import re
from pathlib import Path

import yaml

INVALID_CADDY_SITE = "\n:443 {\n    invalid_native_fixture_directive\n}\n"


def failed_ansible_task(output: str) -> str:
    failure = re.search(r"(?m)^(?:fatal|failed): \[", output)
    assert failure is not None, "Expected an actual Ansible task failure"
    tasks = re.findall(r"TASK \[(.*?)\]", output[: failure.start()])
    assert tasks, "Expected a named task before the Ansible failure"
    return tasks[-1]


def native_tasks(path: Path) -> list[dict]:
    tasks = []
    for task in yaml.safe_load(path.read_text()):
        include = task.get("ansible.builtin.include_tasks", task.get("include_tasks"))
        if isinstance(include, str) and (path.parent / include).is_file():
            tasks.append(task)
            tasks.extend(native_tasks(path.parent / include))
        else:
            tasks.append(task)
    return tasks
