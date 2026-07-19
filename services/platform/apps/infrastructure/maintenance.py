"""Semantic maintenance actions mapped to repository-owned playbooks."""

from __future__ import annotations

from collections.abc import Iterable

MAINTENANCE_ACTION_PLAYBOOKS: dict[str, dict[str, str]] = {
    "security": {
        "virtualmin": "virtualmin_harden.yml",
        "blesta": "blesta_harden.yml",
    },
}


def resolve_maintenance_playbooks(panel_type: str, actions: Iterable[str]) -> list[str]:
    """Resolve semantic action IDs to fixed panel-aware playbook filenames."""
    resolved: list[str] = []
    for action in actions:
        panel_playbooks = MAINTENANCE_ACTION_PLAYBOOKS.get(action)
        if panel_playbooks is None:
            raise ValueError(f"Unsupported maintenance action: {action}")
        playbook = panel_playbooks.get(panel_type)
        if playbook is None:
            raise ValueError(f"Maintenance action '{action}' is unsupported for panel '{panel_type}'")
        resolved.append(playbook)
    return resolved
