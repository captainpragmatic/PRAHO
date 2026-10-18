"""The parameters of every disable-domain and enable-domain PRAHO sends (ADR-0061 P1.5).

A customer's account name is a sub-server of its domain. Virtualmin changes a sub-server's state
with its parent only when asked (`subservers`); without it, a suspended customer's account name
keeps serving the customer's site. Every call site builds its parameters here, and a test fails on
any that builds them by hand.
"""

from __future__ import annotations

DOMAIN_STATE_PROGRAMS = frozenset({"disable-domain", "enable-domain"})


def domain_state_params(domain: str) -> dict[str, str]:
    """Disable or enable `domain` together with every sub-server under it, its account name included."""
    return {"domain": domain, "subservers": ""}
