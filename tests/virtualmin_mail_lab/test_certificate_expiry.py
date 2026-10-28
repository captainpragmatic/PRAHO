"""Expired node certificate recovery on an owned disposable clone, through the production playbook."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from tests.virtualmin_mail_lab.harness import PLAYBOOK, MailClone, MailLabError, _private_json

CHECKS = Path(__file__).with_name("expiry_checks.py")
GUARD = "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /usr/lib/praho/mail/praho-mail-boot.py ; "


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


@pytest.mark.mail_node
def test_installed_unit_topology_is_the_pinned_profile_table(mail_clone: MailClone) -> None:
    mail_clone.prepare()
    mail_clone.playbook("setup")
    facts = expiry(mail_clone, "topology")
    assert_pinned_topology(mail_clone, facts)
    print(json.dumps({"profile": mail_clone.profile.key, "ready_guard_seconds": facts["guard_seconds"]}))
