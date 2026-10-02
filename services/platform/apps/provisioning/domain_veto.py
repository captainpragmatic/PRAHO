"""Domain-status veto on re-enabling a hosting account (#566, ADR-0051).

Two writers decide whether a Virtualmin account is enabled: the Service reconciler and
the domain status sync. The reconciler reads ``Service.status`` alone, so it used to
re-enable an account the domain path had just disabled for an expired domain. Until
ADR-0051 settles single ownership, paths that only read the Service must not re-enable
an account whose linked domain is in a hosting-disabling status.

The match mirrors the domain path exactly: a ``ServiceDomain`` binding to the account's
service AND ``Domain.name == VirtualminAccount.domain``. A same-name domain row that is not
bound to the service could never have suspended the account, so it does not block it.
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


def domain_disables_hosting(account: VirtualminAccount) -> bool:
    """True when a domain bound to the account's service currently disables hosting."""
    return _blocking_links().filter(service_id=account.service_id, domain__name=account.domain).exists()


def exclude_domain_disabled(accounts: QuerySet[VirtualminAccount]) -> QuerySet[VirtualminAccount]:
    """Drop accounts held off by their domain, so sweeps do not re-queue them forever."""
    return accounts.exclude(
        Exists(_blocking_links().filter(service_id=OuterRef("service_id"), domain__name=OuterRef("domain")))
    )
