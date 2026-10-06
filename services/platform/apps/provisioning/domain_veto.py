"""The domain half of a hosting account's enabled state (#566, ADR-0051).

Hosting is enabled exactly when the Service is active and no domain bound to it is in
``Domain.HOSTING_DISABLING_STATUSES``. The provisioning reconciler is the single writer of
that state; this module answers the domain question for it, its divergence sweep and the
lifecycle-job retries, so all of them read the same predicate.

The match: a ``ServiceDomain`` binding to the account's service AND
``Domain.name == VirtualminAccount.domain``. A domain bound under another name (an add-on
or a parked domain) does not hold the account's own hosting off.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.db.models import Exists, OuterRef, QuerySet

from apps.provisioning.relationship_models import ServiceDomain

if TYPE_CHECKING:
    from apps.provisioning.virtualmin_models import VirtualminAccount


def _blocking_links() -> QuerySet[ServiceDomain]:
    from apps.domains.models import Domain  # noqa: PLC0415  # ADR-0007: cross-app import at call time

    return ServiceDomain.objects.filter(domain__status__in=Domain.HOSTING_DISABLING_STATUSES)


def blocking_domain_status(account: VirtualminAccount) -> str | None:
    """The status of a bound domain holding the account's hosting off, or None."""
    status: str | None = (
        _blocking_links()
        .filter(service_id=account.service_id, domain__name=account.domain)
        .order_by("domain__status")
        .values_list("domain__status", flat=True)
        .first()
    )
    return status


def domain_disables_hosting(account: VirtualminAccount) -> bool:
    """True when a domain bound to the account's service currently disables hosting."""
    return blocking_domain_status(account) is not None


def _held_off() -> Exists:
    return Exists(_blocking_links().filter(service_id=OuterRef("service_id"), domain__name=OuterRef("domain")))


def exclude_domain_disabled(accounts: QuerySet[VirtualminAccount]) -> QuerySet[VirtualminAccount]:
    """Drop accounts held off by their domain, so sweeps do not re-queue them forever."""
    return accounts.exclude(_held_off())


def only_domain_disabled(accounts: QuerySet[VirtualminAccount]) -> QuerySet[VirtualminAccount]:
    """Keep only accounts held off by their domain: the same match, so the two sets partition."""
    return accounts.filter(_held_off())
