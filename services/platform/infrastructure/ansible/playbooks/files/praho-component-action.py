#!/usr/bin/env python3
"""Bounded source actions; private native context and credentials never leave the node."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_REQUEST_BYTES = 256 * 1024
MAX_CHANGED_PARTS = 32
SOURCE_ACTIONS = frozenset(
    {
        "source_hold",
        "source_verify",
        "source_export",
        "source_release",
        "source_commit",
        "source_route",
        "source_retire",
        "source_retire_artifacts",
    }
)
TARGET_ACTIONS = frozenset(
    {
        "target_prepare",
        "target_restore",
        "target_verify",
        "target_seal",
        "target_activate",
        "target_billing_hold",
        "target_policy",
        "target_remove",
        "target_retire_artifacts",
        "target_retire_unprepared_archive",
    }
)


def _module(filename: str, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    if spec is None or spec.loader is None:
        raise ValueError("The native source component action is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def perform_retirement(payload: dict[str, Any]) -> dict[str, Any]:
    retirement = _module("praho-component-retire.py", "component_action_retirement")
    artifacts = payload["action"] == "source_retire_artifacts"
    callback = retirement.cleanup_released_export if artifacts else retirement.retire_source
    receipt = callback(payload["request"], payload["operation_id"], payload["authority_digest"])
    if receipt != {
        "phase": "released_export_retired" if artifacts else "retired",
        "operation_id": payload["operation_id"],
        "source_domain_id": payload["request"]["domain_id"],
    }:
        raise ValueError("Source retirement did not prove its exact retained native identity")
    return {
        "operation_id": payload["operation_id"],
        "action": payload["action"],
        "phase": "artifacts_retired" if artifacts else "retired",
    }


def perform(payload: dict[str, Any]) -> dict[str, Any]:
    action = payload.get("action")
    if action in TARGET_ACTIONS:
        return perform_target(payload)
    if action not in SOURCE_ACTIONS:
        raise ValueError("An explicit qualified source component action is required")
    if action in {"source_retire", "source_retire_artifacts"}:
        return perform_retirement(payload)
    source_module = _module("praho-component-native-source.py", "component_action_native_source")
    source = source_module.NativeSource(payload["request"], payload["operation_id"], payload["authority_digest"])
    if action == "source_route":
        routing = _module("praho-component-routing.py", "component_action_routing")
        result = routing.route_source(source, payload["network"])
        return {"operation_id": source.operation, "action": action, "phase": "routed", "routing": result["mode"]}
    if action == "source_commit":
        with source.coordinator.journal.locked():
            committed = source.coordinator._state()["phase"] == "committed"
        if committed:
            source.coordinator.commit(
                archive_sha256=payload["archive_sha256"], target_receipt_sha256=payload["target_receipt_sha256"]
            )
            return {"operation_id": source.operation, "action": action, "phase": "committed"}
    if action == "source_hold":
        source.coordinator.apply()
    elif action == "source_verify":
        source.coordinator.verify()
    elif action == "source_release":
        source.coordinator.release()
    else:
        exporter = _module("praho-component-source-export.py", "component_action_export")
        receipt = exporter.export_source(source)
        if action == "source_export":
            return {"operation_id": source.operation, "action": action, "phase": "held", "export": receipt}
        if receipt["sha256"] != payload.get("archive_sha256"):
            raise ValueError("Source commit does not match its immutable selected archive")
        source.coordinator.commit(
            archive_sha256=receipt["sha256"], target_receipt_sha256=payload["target_receipt_sha256"]
        )
    return {
        "operation_id": source.operation,
        "action": action,
        "phase": "released" if action == "source_release" else "committed" if action == "source_commit" else "held",
    }


def perform_target(payload: dict[str, Any]) -> dict[str, Any]:
    target_module = _module("praho-component-target.py", "component_action_native_target")
    manifest = payload["request"]
    if target_module.archives.source.authority_digest(manifest) != payload["authority_digest"]:
        raise ValueError("Target component action changed its approved source authority")
    target = target_module.TargetCoordinator(
        manifest,
        payload["operation_id"],
        payload["target_identity"],
        payload["archive_sha256"],
        payload["creation_params"],
    )
    action = payload["action"]
    if action == "target_prepare":
        receipt = target.prepare()
    elif action == "target_restore":
        receipt = target.restore()
    elif action == "target_verify":
        receipt = target.verify()
    elif action == "target_seal":
        receipt = target.seal(payload["target_receipt_sha256"])
    elif action == "target_policy":
        receipt = target.reconcile_policy(enabled=payload["enabled"])
    elif action == "target_billing_hold":
        receipt = target.record_billing_hold(payload["billing_hold"])
    elif action == "target_retire_artifacts":
        receipt = target.retire_artifacts()
    elif action == "target_retire_unprepared_archive":
        receipt = target.retire_unprepared_archive()
    elif action == "target_remove":
        receipt = target.remove()
    else:
        receipt = target.activate(
            payload["target_receipt_sha256"], enabled=payload["enabled"], billing_hold=payload.get("billing_hold")
        )
    return {**receipt, "action": action}


RETIREMENT_STEPS = frozenset({"web", "database", "paths", "files", "cron", "ingress", "export"})
_SAFE_REASON = re.compile(r"[A-Za-z0-9 _.,;()'/-]{1,200}")


def failure_receipt(error: BaseException) -> dict[str, Any]:
    """What a failed action may tell Platform past no_log: the type, the authored reason, retirement facts.

    Only the message's own prefix is kept; text interpolated after ": " (helper stderr, paths) never leaves.
    """
    receipt: dict[str, Any] = {"type": type(error).__name__[:64]}
    reason = str(error).split(": ", 1)[0]
    if _SAFE_REASON.fullmatch(reason):
        receipt["reason"] = reason
    step = getattr(error, "retirement_step", None)
    if step in RETIREMENT_STEPS:
        receipt["step"] = step
    changed = getattr(error, "retained_changed", None)
    if (
        isinstance(changed, list)
        and len(changed) <= MAX_CHANGED_PARTS
        and all(isinstance(name, str) and name.isidentifier() for name in changed)
    ):
        receipt["changed"] = changed
    return receipt


if __name__ == "__main__":
    encoded = sys.stdin.read(MAX_REQUEST_BYTES + 1)
    if len(encoded.encode()) > MAX_REQUEST_BYTES:
        raise ValueError("Source component request exceeds its bound")
    value = json.loads(encoded)
    if not isinstance(value, dict):
        raise ValueError("An exact source component action is required")
    try:
        result = perform(value)
    except Exception as error:
        # The playbook's rescue returns this last line; the traceback stays on the node.
        print(json.dumps({"failure": failure_receipt(error)}, sort_keys=True, separators=(",", ":")))
        raise
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False))
