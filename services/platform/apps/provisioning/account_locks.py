"""Lock a Virtualmin account row, then read its owner.

PostgreSQL docs, "Transaction Isolation" (Read Committed): when SELECT ... FOR UPDATE finds a row
changed by a concurrent transaction, it waits, then re-checks only the newest version of the row it
locks. Rows joined in the same statement keep the values of the statement's starting snapshot. So
the account is locked without joins, and what callers need from related rows is read in a later
statement, once the lock is held.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .service_models import Service
from .virtualmin_models import VirtualminAccount


@dataclass(frozen=True)
class LockedAccount:
    """A locked account row and its owner, read after the lock."""

    account: VirtualminAccount
    customer_id: int


def lock_account(account_id: Any) -> LockedAccount | None:
    """Lock the account join-free and read its owning customer after the lock. Call inside a transaction."""
    account = VirtualminAccount.objects.select_for_update(of=("self",), no_key=True).filter(pk=account_id).first()
    if account is None:
        return None
    customer_id = Service.objects.filter(pk=account.service_id).values_list("customer_id", flat=True).get()
    return LockedAccount(account, customer_id)
