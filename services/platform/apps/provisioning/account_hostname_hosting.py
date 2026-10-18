"""What a customer and staff are told about an account's name (ADR-0061 P1.11, P1.12, P1.13).

A name is told only once it is live: the feature is on, its records are applied at the provider
and an unexpired certificate for it is installed on the node DNS points at. Nothing here names a
node or an address. Every record the customer is asked to set points at the account name, so a
move never makes what they set stale (ADR-0061 section 2).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import account_hostname_config as config
from .account_hostname_models import AccountHostname

if TYPE_CHECKING:
    from .service_models import Service
    from .virtualmin_models import VirtualminAccount

# Phase 1 offers the external-DNS paths only (ADR-0061 section 2, paths 2 and 3); our own
# nameservers (path 1) arrive with the customer zones.
EXTERNAL_DNS = "external_dns"


def records_published(hostname: AccountHostname) -> bool:
    """Whether every record PRAHO meant for the name is applied as meant, the A record among them."""
    records = hostname.records or {}
    if "A" not in records:
        return False
    return all(entry.get("applied") and entry.get("applied") == entry.get("intended") for entry in records.values())


def live_account_name(account: VirtualminAccount) -> AccountHostname | None:
    """The account's name when it can be used now, else None."""
    from .account_name_certificates import certificate_installed_on  # noqa: PLC0415  # Deferred: imports acme

    if not config.account_hostnames_enabled():
        return None
    hostname = AccountHostname.objects.filter(account=account, retired_at__isnull=True).first()
    if hostname is None or hostname.target_server_id is None or not records_published(hostname):
        return None
    if not certificate_installed_on(hostname, hostname.target_server_id):
        return None
    return hostname


def dns_instructions(domain: str, account_name: str) -> list[dict[str, str]]:
    """The records a customer on external DNS sets: `www` as a CNAME and the apex as an ALIAS.

    A provider without ALIAS or CNAME flattening redirects the apex to `www` instead (the Portal
    says so); a raw node address is never offered.
    """
    return [
        {"type": "CNAME", "name": f"www.{domain}", "value": account_name},
        {"type": "ALIAS", "name": domain, "value": account_name},
    ]


def hosting_summary(service: Service) -> dict[str, Any] | None:
    """The customer's view of their hosting's name, or None until it is live (or with no account)."""
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415  # Circular

    account = VirtualminAccount.objects.filter(service=service).first()
    if account is None:
        return None
    hostname = live_account_name(account)
    if hostname is None:
        return None
    return {
        "account_name": hostname.fqdn,
        "path": EXTERNAL_DNS,
        "records": dns_instructions(account.domain, hostname.fqdn),
    }
