"""A stand-in for the node's database write hold gateway, with the interface 7A's gateway exposes (brief refinements)."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from uuid import UUID

from apps.common.types import Err, Ok

# The gateway's own types, so the stand-in can't drift from the interface it stands in for.
from apps.provisioning.database_hold_gateway import HoldIdentity, HoldReceipt, HoldRefusal
from apps.provisioning.virtualmin_models import VirtualminServer

HELD_DIGEST = "5e" * 32  # the node reports a bare sha256 hex digest


@dataclass
class FakeNode:
    """Scripted answers per action; records every call in order."""

    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    # held | sessions | lost_response (applied, answer lost) | undelivered (never applied) | refused
    # | busy (lock_busy) | barrier (barrier_active): the node applies nothing and the next request may get through
    hold_answer: str = "held"
    release_answer: str = "released"  # released | uncertain
    verify_answer: str = "held"  # held | sessions | drift
    fenced: set[UUID] = field(default_factory=set)
    journal: dict[int, UUID] = field(default_factory=dict)  # generation -> token the node holds it for
    reachable: bool = True  # False: every call's answer is lost

    def module(self) -> SimpleNamespace:
        def guarded(call: Any) -> Any:
            def run(identity: HoldIdentity, **kwargs: Any) -> Any:
                # As the real gateway: an unknown server raises before anything is run.
                VirtualminServer.objects.get(pk=identity.server_id)
                if not self.reachable:
                    self.calls.append((call.__name__, {"identity": identity, **kwargs}))
                    return Err(HoldRefusal("uncertain", "the node response was lost"))
                return call(identity, **kwargs)

            return run

        return SimpleNamespace(
            HoldIdentity=HoldIdentity,
            hold=guarded(self.hold),
            release=guarded(self.release),
            verify=guarded(self.verify),
            fence=guarded(self.fence),
            probe=guarded(self.probe),
        )

    def hold(self, identity: HoldIdentity, *, token: UUID, generation: int) -> Any:
        self.calls.append(("hold", {"identity": identity, "token": token, "generation": generation}))
        transient = {"undelivered": "uncertain", "busy": "lock_busy", "barrier": "barrier_active"}
        if self.hold_answer in transient:
            code, self.hold_answer = transient[self.hold_answer], "held"  # the next request gets through
            return Err(HoldRefusal(code, code))
        if self.hold_answer == "refused":
            return Err(HoldRefusal("shared_username", "shared_username principal shop"))
        if self.journal.get(generation, token) != token:
            return Err(HoldRefusal("generation_conflict", "generation_conflict"))
        self.journal[generation] = token
        if self.hold_answer == "lost_response":
            return Err(HoldRefusal("uncertain", "no response"))
        sessions = (41,) if self.hold_answer == "sessions" else ()
        phase = "holding" if sessions else "held"
        return Ok(HoldReceipt("hold", identity, token, generation, phase, HELD_DIGEST, sessions, ()))

    def release(self, identity: HoldIdentity, *, generation: int) -> Any:
        self.calls.append(("release", {"identity": identity, "generation": generation}))
        if self.release_answer == "uncertain":
            return Err(HoldRefusal("uncertain", "no response"))
        token = self.journal.pop(generation, None)  # idempotent: nothing to release is released
        return Ok(HoldReceipt("release", identity, token, generation, "released", None, (), ()))

    def verify(self, identity: HoldIdentity, *, generation: int) -> Any:
        self.calls.append(("verify", {"identity": identity, "generation": generation}))
        if generation not in self.journal:
            return Ok(HoldReceipt("verify", identity, None, generation, "verified", None, (), ("not_held",)))
        sessions = (41,) if self.verify_answer == "sessions" else ()
        drift = ("grant ALL re-added",) if self.verify_answer == "drift" else ()
        phase = "holding" if sessions else "verified"
        token = self.journal[generation]
        return Ok(HoldReceipt("verify", identity, token, generation, phase, HELD_DIGEST, sessions, drift))

    def fence(self, identity: HoldIdentity, *, token: UUID) -> Any:
        self.calls.append(("fence", {"identity": identity, "token": token}))
        self.fenced.add(token)
        return Ok(HoldReceipt("fence", identity, token, max(self.journal, default=0), "fenced", None, (), ()))

    def probe(self, identity: HoldIdentity, *, token: UUID, generation: int) -> Any:
        self.calls.append(("probe", {"identity": identity, "token": token, "generation": generation}))
        return Ok(HoldReceipt("probe", identity, token, generation, "probed", None, (), ()))

    def actions(self) -> list[str]:
        return [name for name, _ in self.calls]
