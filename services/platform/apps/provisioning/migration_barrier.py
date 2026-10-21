"""The migration's write barrier on a node (ADR-0061 Phase 2, plan amendment E2).

`run_barrier` runs `virtualmin_write_barrier.yml` once and returns the node's one result line, cross-
checked against the run that asked for it. Every outcome that is not conclusive is UNKNOWN: the
migration treats it as "the node may have changed" and compensates, never as success.

The record (`BarrierRecord`) is what the barrier found before the fence: the crontab's hashes (the
crontab itself stays on the node), each name's enabled state, the databases and the accounts on them.
It is persisted on the migration row before the fence goes up and is the only input of a release.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any

from apps.common.types import Err, Ok, Result, Retriability

from .virtualmin_models import VirtualminServer

BARRIER_PLAYBOOK = "virtualmin_write_barrier.yml"
BARRIER_LOCK_WAIT_SECONDS = 60
BARRIER_DRAIN_WAIT_SECONDS = 60
BARRIER_TIMEOUT_SECONDS = 600
BARRIER_ACTIONS = frozenset({"record", "apply", "verify", "release", "idle"})
BARRIER_OUTCOMES = frozenset({"ok", "refused", "failed", "busy"})

_RESULT_RE = re.compile(r"BARRIER_RESULT=([A-Za-z0-9+/=]+)")
_TOKEN_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_DOMAIN_ID_RE = re.compile(r"^[0-9]{1,30}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9._@-]{1,80}$")
_ACCOUNT_HOST_RE = re.compile(r"^[A-Za-z0-9.%_:-]{1,255}$")
_DATABASE_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[A-Za-z0-9_:.@%-]{1,200}$")


@dataclass(frozen=True)
class BarrierAccount:
    user: str
    host: str
    locked: bool  # Its lock state before the barrier: a release puts back exactly this
    plugin: str
    auth_sha: str  # A digest of the stored credential, never the credential
    grants_sha: str


@dataclass(frozen=True)
class BarrierRecord:
    has_crontab: bool
    crontab_sha: str
    active_sha: str  # The crontab's active lines: what a release and the target are verified against
    enabled: tuple[tuple[str, bool], ...]  # The domain, then each sub-server
    databases: tuple[str, ...]
    accounts: tuple[BarrierAccount, ...]

    def as_state(self) -> dict[str, Any]:
        """The JSON persisted in `VirtualminMigration.barrier_state["record"]`."""
        return {
            "has_crontab": self.has_crontab,
            "crontab_sha": self.crontab_sha,
            "active_sha": self.active_sha,
            "enabled": [{"name": name, "enabled": on} for name, on in self.enabled],
            "databases": list(self.databases),
            "accounts": [account.__dict__ for account in self.accounts],
        }

    @classmethod
    def from_state(cls, state: Any) -> Result[BarrierRecord, str]:
        """The record, from the node's payload or from the row; anything malformed is refused."""
        try:
            record = cls(
                has_crontab=state["has_crontab"] is True,
                crontab_sha=str(state["crontab_sha"]),
                active_sha=str(state["active_sha"]),
                enabled=tuple((str(item["name"]), item["enabled"] is True) for item in state["enabled"]),
                databases=tuple(str(db) for db in state["databases"]),
                accounts=tuple(
                    BarrierAccount(
                        user=str(item["user"]),
                        host=str(item["host"]),
                        locked=item["locked"] is True,
                        plugin=str(item["plugin"]),
                        auth_sha=str(item["auth_sha"]),
                        grants_sha=str(item["grants_sha"]),
                    )
                    for item in state["accounts"]
                ),
            )
        except (KeyError, TypeError):
            return Err("The barrier record is incomplete", retriability=Retriability.NOT_RETRIABLE)
        valid = (
            _SHA_RE.match(record.crontab_sha)
            and _SHA_RE.match(record.active_sha)
            and record.enabled
            and all(_NAME_RE.match(name) for name, _ in record.enabled)
            and all(_DATABASE_RE.match(db) for db in record.databases)
            and all(
                _ACCOUNT_RE.match(a.user)
                and _ACCOUNT_HOST_RE.match(a.host)
                and _SHA_RE.match(a.auth_sha)
                and _SHA_RE.match(a.grants_sha)
                for a in record.accounts
            )
        )
        if not valid:
            return Err("The barrier record holds a value the node cannot take", retriability=Retriability.NOT_RETRIABLE)
        return Ok(record)

    def accounts_lines(self) -> str:
        """The accounts as the script reads them: base64 of "user<TAB>host<TAB>locked" lines."""
        lines = "".join(f"{a.user}\t{a.host}\t{int(a.locked)}\n" for a in self.accounts)
        return base64.b64encode(lines.encode()).decode()

    def enabled_lines(self) -> str:
        lines = "".join(f"{name}\t{int(on)}\n" for name, on in self.enabled)
        return base64.b64encode(lines.encode()).decode()


@dataclass(frozen=True)
class BarrierStep:
    outcome: str
    reason: str
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.outcome == "ok"


def _uncertain(message: str) -> Err[str]:
    return Err(f"Barrier result unusable: {message}", retriability=Retriability.UNKNOWN)


def parse_barrier_result(  # noqa: PLR0911  # One exit per way a result line can be unusable
    stdout: str, *, token: str, domain_id: str, action: str
) -> Result[BarrierStep, str]:
    """Parse and cross-check the single result line; anything else is uncertain."""
    encoded = set(_RESULT_RE.findall(stdout))
    if len(encoded) != 1:
        return _uncertain(f"expected exactly one result line, found {len(encoded)}")
    try:
        payload = json.loads(base64.b64decode(encoded.pop(), validate=True))
    except (ValueError, binascii.Error):
        return _uncertain("not decodable")
    if not isinstance(payload, dict):
        return _uncertain("not an object")
    if (payload.get("token"), payload.get("domain_id"), payload.get("action")) != (token, domain_id, action):
        return _uncertain("it names a different run")
    outcome, reason = str(payload.get("outcome", "")), str(payload.get("reason", ""))
    if outcome not in BARRIER_OUTCOMES:
        return _uncertain(f"unknown outcome {outcome!r}")
    if not _REASON_RE.match(reason):
        return _uncertain("malformed reason")
    return Ok(BarrierStep(outcome=outcome, reason=reason, payload=payload))


def barrier_variables(  # noqa: PLR0913  # One value per input the playbook validates
    action: str,
    *,
    domain: str,
    domain_id: str,
    token: str,
    previous_token: str = "",
    record: BarrierRecord | None = None,
    killed_at: int = 0,
) -> Result[dict[str, Any], str]:
    """The playbook's variables; anything the node would refuse is refused here first."""
    if (
        action not in BARRIER_ACTIONS
        or not _NAME_RE.match(domain)
        or not _DOMAIN_ID_RE.match(domain_id)
        or not _TOKEN_RE.match(token)
        or (previous_token and not _TOKEN_RE.match(previous_token))
        or killed_at < 0
    ):
        return Err("The barrier inputs are not acceptable to the node", retriability=Retriability.NOT_RETRIABLE)
    if action in {"apply", "verify", "release"} and record is None:
        return Err(f"A barrier {action} needs the record", retriability=Retriability.NOT_RETRIABLE)
    variables: dict[str, Any] = {
        "barrier_action": action,
        "barrier_domain": domain,
        "barrier_domain_id": domain_id,
        "barrier_token": token,
        "barrier_previous_token": previous_token,
        "barrier_lock_wait_seconds": BARRIER_LOCK_WAIT_SECONDS,
        "barrier_drain_wait_seconds": BARRIER_DRAIN_WAIT_SECONDS,
        "barrier_killed_at": str(killed_at),
    }
    if record is not None:
        variables.update(
            barrier_accounts=record.accounts_lines(),
            barrier_enabled=record.enabled_lines(),
            barrier_has_crontab="1" if record.has_crontab else "0",
            barrier_crontab_active_sha=record.active_sha,
        )
    return Ok(variables)


def run_barrier(server: VirtualminServer, variables: dict[str, Any]) -> Result[BarrierStep, str]:
    """Run the barrier playbook once; every non-conclusive outcome is UNKNOWN."""
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # Circular

    deployment = getattr(server, "node_deployment", None)
    if deployment is None:
        return Err(
            f"Server {server.hostname} is manually registered (no managed node_deployment); no barrier is possible",
            retriability=Retriability.NOT_RETRIABLE,
        )
    result = AnsibleService().run_playbook(
        deployment, BARRIER_PLAYBOOK, variables, timeout_seconds=BARRIER_TIMEOUT_SECONDS
    )
    if result.is_err():
        return Err(f"Barrier step could not run: {result.unwrap_err()}", retriability=Retriability.UNKNOWN)
    run = result.unwrap()
    if not run.success:
        return Err(
            f"Barrier playbook failed or timed out (rc={run.return_code}); node state is uncertain",
            retriability=Retriability.UNKNOWN,
        )
    return parse_barrier_result(
        run.stdout,
        token=str(variables["barrier_token"]),
        domain_id=str(variables["barrier_domain_id"]),
        action=str(variables["barrier_action"]),
    )
