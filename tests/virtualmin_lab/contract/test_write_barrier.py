"""Lab test: virtualmin_write_barrier.yml, run through PRAHO's own barrier call on the lab node (ADR-0061 P2.4).

On a domain created the way PRAHO creates one (the default features, its database included), the
barrier records the domain, closes it (disabled, its owner's jobs commented, its database accounts
locked), holds on a later check, and a release puts back exactly what was recorded: the domain
enabled again, the jobs active again with the same hash, the accounts unlocked.
"""

from __future__ import annotations

from collections.abc import Iterator
from uuid import uuid4

import pytest

from apps.provisioning.migration_barrier import BarrierRecord, BarrierStep, barrier_variables, run_barrier
from tests.virtualmin_lab.contract.harness import Lab, assert_accepted

DOMAIN = "contractbarrier.praho.test"
JOB = "*/5 * * * * /bin/true"


@pytest.fixture
def barrier_domain(lab: Lab) -> Iterator[tuple[str, str]]:
    """The domain id and its owner, on a domain this test alone uses; removed afterwards."""
    lab.remove_domain(DOMAIN)
    created = lab.quiet("create-domain", {"domain": DOMAIN, "pass": "Contract-barrier-1", "default-features": ""})
    assert_accepted(created)
    try:
        domain_id = lab.exec("virtualmin", "list-domains", "--domain", DOMAIN, "--id-only").strip()
        owner = lab.exec("virtualmin", "list-domains", "--domain", DOMAIN, "--user-only").strip()
        lab.exec("sh", "-c", f"echo '{JOB}' | crontab -u '{owner}' -")
        yield domain_id, owner
    finally:
        lab.remove_domain(DOMAIN)


def _step(  # noqa: PLR0913  # One value per barrier input
    lab: Lab, action: str, domain_id: str, token: str, *, record: BarrierRecord | None = None, killed_at: int = 0
) -> BarrierStep:
    variables = barrier_variables(
        action, domain=DOMAIN, domain_id=domain_id, token=token, record=record, killed_at=killed_at
    ).unwrap()
    result = run_barrier(lab.server, variables)
    assert result.is_ok(), result.unwrap_err() if result.is_err() else ""
    return result.unwrap()


def _disabled(lab: Lab) -> bool:
    return DOMAIN in lab.exec("virtualmin", "list-domains", "--disabled", "--name-only").split()


def _active_jobs(lab: Lab, owner: str) -> list[str]:
    listing = lab.exec("sh", "-c", f"crontab -u '{owner}' -l 2>/dev/null || true")
    return [line for line in listing.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_the_barrier_closes_the_domain_and_a_release_puts_back_what_was_recorded(
    lab: Lab, barrier_domain: tuple[str, str]
) -> None:
    domain_id, owner = barrier_domain
    token = str(uuid4())

    recorded = _step(lab, "record", domain_id, token)
    assert recorded.ok, recorded.reason
    record = BarrierRecord.from_state(recorded.payload).unwrap()
    assert record.accounts, "the domain's database accounts are recorded"

    applied = _step(lab, "apply", domain_id, token, record=record)
    assert applied.ok, applied.reason
    held = _step(lab, "verify", domain_id, token, record=record, killed_at=int(applied.payload["killed_at"]))
    assert held.ok, held.reason
    assert _disabled(lab)
    assert _active_jobs(lab, owner) == [], "the owner's jobs are commented under the barrier"

    released = _step(lab, "release", domain_id, token, record=record)
    assert released.ok, released.reason
    assert not _disabled(lab)
    assert _active_jobs(lab, owner) == [JOB]
