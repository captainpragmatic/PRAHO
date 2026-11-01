#!/usr/bin/env python3
"""Durable ordering and compensation for independently receipted source holds."""

from __future__ import annotations

import importlib.util
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

ORDER = ("web", "cron", "database", "paths")
POLICY = "component-source-v1"
HISTORY_POLICY = "component-source-operation-v1"


class Fence(Protocol):
    def apply(self) -> None: ...
    def verify(self) -> None: ...
    def release(self) -> None: ...


def _journals() -> Any:
    spec = importlib.util.spec_from_file_location(
        "component_source_receipts", Path(__file__).with_name("praho-component-journal.py")
    )
    if spec is None or spec.loader is None:
        raise ValueError("Native component operation receipts are unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SourceCoordinator:
    def __init__(  # noqa: PLR0913 -- exact authority plus independent native operations and retained-service proof
        self,
        domain_id: str,
        operation_id: str,
        authority_digest: str,
        *,
        preflight: Callable[[], dict[str, Any]],
        build: Callable[[dict[str, Any]], dict[str, Fence]],
        retained: Callable[[dict[str, Any]], str],
        state_dir: Path = Path("/var/lib/praho/component-sources"),
        boot_id: str | None = None,
    ) -> None:
        self.preflight, self.build, self.retained = preflight, build, retained
        self.journal = _journals().ComponentJournal(
            state_dir,
            domain_id,
            {
                "operation_id": operation_id,
                "scope_digest": authority_digest,
                "boot_id": boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            },
        )

    def _operation_history(self, identity: dict[str, str]) -> Any:
        return _journals().ComponentJournal(
            self.journal.directory / "operations" / identity["operation_id"], identity["domain_id"], identity
        )

    def _history_state(self, journal: Any) -> dict[str, Any] | None:
        if journal.directory.is_symlink():
            raise ValueError("The source operation history has an unqualified private namespace")
        if journal.directory.exists():
            if journal.directory.resolve() != journal.directory:
                raise ValueError("The source operation history has an unqualified private namespace")
            journal._private(journal.directory.lstat(), directory=True)
            if any(
                path.name not in {journal.path.name, journal.path.with_suffix(".lock").name}
                for path in journal.directory.iterdir()
            ):
                raise ValueError("The source operation UUID has unknown or previously seen history")
        state: dict[str, Any] | None = journal.read()
        if state is None:
            if journal.directory.exists():
                raise ValueError("The source operation history is missing after an uncertain intent")
            return None
        journal.assert_owned(state)
        if state.get("policy") != HISTORY_POLICY or state.get("phase") not in {"current", "retired"}:
            raise ValueError("The source operation history is unrecognized")
        return state

    def _assert_history(self, state: dict[str, Any]) -> None:
        if state.get("operation_history") not in {None, HISTORY_POLICY}:
            raise ValueError("The source operation references unknown history")
        history = self._history_state(self._operation_history(self.journal.identity))
        if history is None and state.get("operation_history") == HISTORY_POLICY:
            raise ValueError("The source operation has lost its durable identity history")
        if history is not None and history["phase"] == "retired" and state.get("phase") != "released":
            raise ValueError("A retired source operation history cannot authorize native holds")

    def _record_history(self, journal: Any, phase: str) -> None:
        with journal.locked():
            previous = journal.read()
            if previous is not None:
                journal.assert_owned(previous)
                if previous.get("policy") != HISTORY_POLICY or previous.get("phase") not in {"current", "retired"}:
                    raise ValueError("The source operation history is unrecognized")
                if previous["phase"] == "retired" and phase != "retired":
                    raise ValueError("A previously seen source UUID cannot be fenced again")
                previous["phase"] = phase
                journal.write(previous)
            else:
                journal.create({"policy": HISTORY_POLICY, "phase": phase})

    def _retire_previous(self, state: dict[str, Any]) -> None:
        if (
            state.get("policy") != POLICY
            or state.get("domain_id") != self.journal.identity["domain_id"]
            or state.get("phase") != "released"
            or state.get("applied") != []
            or state.get("pending") is not None
            or not isinstance(state.get("context"), dict)
        ):
            raise ValueError("Another source operation has unresolved native ownership")
        if state.get("export_retirement") != "retired":
            raise ValueError("Retire the previous source export artifacts before replacing its ownership receipt")
        identity = {key: state[key] for key in ("domain_id", "operation_id", "scope_digest", "boot_id")}
        history = self._operation_history(identity)
        previous = self._history_state(history)
        if state.get("operation_history") not in {None, HISTORY_POLICY} or (
            state.get("operation_history") == HISTORY_POLICY and previous is None
        ):
            raise ValueError("The previous source operation has missing or unknown history")
        # Persist the old UUID tombstone BEFORE its domain parent is overwritten.
        # No native credential, selected data or archived context enters history.
        self._record_history(history, "retired")

    def _state(self) -> dict[str, Any]:
        state: dict[str, Any] | None = self.journal.read()
        if state is None:
            raise ValueError("Source component operation has no durable ownership receipt")
        self.journal.assert_owned(state)
        self._assert_history(state)
        applied = state.get("applied")
        if (
            state.get("policy") != POLICY
            or state.get("phase")
            not in {"fencing", "held", "compensating", "released", "committed", "retiring", "retired"}
            or not isinstance(applied, list)
            or applied != list(ORDER[: len(applied)])
            or len(applied) > len(ORDER)
            or state.get("pending") not in {None, *ORDER}
            or not isinstance(state.get("context"), dict)
        ):
            raise ValueError("Source component operation receipt is incomplete or unrecognized")
        if state["phase"] in {"held", "committed", "retiring", "retired"} and (
            applied != list(ORDER) or state["pending"] is not None
        ):
            raise ValueError("Source component operation lacks a complete held receipt")
        if state["phase"] == "released" and (applied or state["pending"] is not None):
            raise ValueError("Source component compensation has incomplete native receipts")
        if state["pending"] is not None and (len(applied) == len(ORDER) or state["pending"] != ORDER[len(applied)]):
            raise ValueError("Source component operation has an unrecognized native mutation intent")
        return state

    def _steps(self, state: dict[str, Any]) -> dict[str, Fence]:
        context = state["context"]
        if not context.get("retained_digest") or self.retained(context) != context["retained_digest"]:
            raise ValueError("Retained services or source authentication changed; inspect before proceeding")
        steps = self.build(context)
        if set(steps) != set(ORDER):
            raise ValueError("Every independent native component hold is required")
        return steps

    def _verify(self, state: dict[str, Any]) -> None:
        steps = self._steps(state)
        for name in ORDER:
            steps[name].verify()
        self._steps(state)

    def apply(self) -> None:
        with self.journal.locked():
            state = self.journal.read()
            history = self._operation_history(self.journal.identity)
            seen = self._history_state(history)
            if seen is not None and (
                state is None or state.get("operation_id") != self.journal.identity["operation_id"]
            ):
                raise ValueError("A previously seen source UUID cannot replace later native operation history")
            if state is not None and state.get("operation_id") != self.journal.identity["operation_id"]:
                self._retire_previous(state)
                state = None
            if state is None:
                context = self.preflight()
                if not isinstance(context, dict) or not context.get("retained_digest"):
                    raise ValueError("Fresh exact source authority and retained-service evidence are required")
                self._record_history(history, "current")
                state = self.journal.create(
                    {
                        "policy": POLICY,
                        "phase": "fencing",
                        "context": context,
                        "applied": [],
                        "pending": None,
                        "operation_history": HISTORY_POLICY,
                    }
                )
            state = self._state()
            if state["phase"] in {"fencing", "held"} and state.get("operation_history") is None:
                self._record_history(history, "current")
                state["operation_history"] = HISTORY_POLICY
                self.journal.write(state)
            if state["phase"] == "held":
                self._verify(state)
                return
            if state["phase"] != "fencing":
                raise ValueError("A compensating, released or committed source cannot be fenced again")
            steps = self._steps(state)
            for name in state["applied"]:
                steps[name].verify()
            for name in ORDER[len(state["applied"]) :]:
                self._steps(state)
                state["pending"] = name
                self.journal.write(state)
                steps[name].apply()
                steps[name].verify()
                state["applied"].append(name)
                state["pending"] = None
                self.journal.write(state)
            self._verify(state)
            state["phase"] = "held"
            self.journal.write(state)

    def verify(self) -> None:
        with self.journal.locked():
            state = self._state()
            if state["phase"] != "held":
                raise ValueError("Only a completely held source may authorize component export")
            self._verify(state)

    def commit(self, *, archive_sha256: str, target_receipt_sha256: str) -> None:
        """Seal source compensation after the worker's durable forward-commit decision."""
        receipt = {"archive_sha256": archive_sha256, "target_receipt_sha256": target_receipt_sha256}
        if any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in receipt.values()
        ):
            raise ValueError("Exact exported archive and held-target receipt digests are required")
        with self.journal.locked():
            state = self._state()
            if state["phase"] == "committed" and state.get("commit") == receipt:
                return
            if state["phase"] != "held":
                raise ValueError("A source commit requires the same complete held operation")
            self._verify(state)
            state.update(phase="committed", commit=receipt)
            self.journal.write(state)

    def release(self) -> None:
        with self.journal.locked():
            state = self._state()
            if state["phase"] == "released":
                return
            if state["phase"] in {"committed", "retiring", "retired"}:
                raise ValueError("Committed website source cannot be reopened by compensation")
            steps = self._steps(state)
            state["phase"] = "compensating"
            self.journal.write(state)
            # A lost response may follow a real native mutation. Only that child's
            # exact ownership receipt may reconcile it; absence is not permission.
            if state["pending"] is not None:
                steps[state["pending"]].release()
                state["pending"] = None
                self.journal.write(state)
            while state["applied"]:
                self._steps(state)
                steps[state["applied"][-1]].release()
                state["applied"].pop()
                self.journal.write(state)
            self._steps(state)
            state["phase"] = "released"
            self.journal.write(state)
