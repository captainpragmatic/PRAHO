"""What a customer and staff are told about an account's name (ADR-0061 P1.11, P1.12, P1.13).

A name is told only once it is live: the feature is on, its records are applied at the provider
and an unexpired certificate for it is installed on the node DNS points at. Nothing here names a
node or an address. Every record the customer is asked to set points at the account name, so a
move never makes what they set stale (ADR-0061 section 2).
"""

from __future__ import annotations

import logging
from datetime import datetime
from functools import partial
from typing import TYPE_CHECKING, Any
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from . import account_hostname_config as config
from .account_hostname_models import AccountHostname
from .account_locks import lock_account
from .service_models import Service

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminAccount

logger = logging.getLogger(__name__)

ACTIVATION_TEMPLATE = "account_name_live"

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


def announce_when_live(hostname: AccountHostname) -> bool:
    """Tell the customer, once, that their hosting name is live (P1.12). True when a message was claimed.

    The claim (`activation_notified_at`) is taken under the row lock after everything is checked
    again there, and the message is sent only once that claim commits, so two syncs never send two.
    A suspended account, a name not live yet or a customer without an address is not told.

    Runs after publication commits. It locks the account, whose row a suspension writes, and then
    the name: the order ownership writers use (hosted_zone_ownership), so the two never deadlock.
    """
    account_id = AccountHostname.objects.filter(pk=hostname.pk).values_list("account_id", flat=True).first()
    if account_id is None:
        return False
    with transaction.atomic():
        locked = lock_account(account_id)
        row = (
            AccountHostname.objects.select_for_update(of=("self",))
            .filter(pk=hostname.pk, account_id=account_id, retired_at__isnull=True, activation_notified_at__isnull=True)
            .first()
        )
        if row is None or locked is None:
            return False
        account = locked.account
        if account.status != "active" or live_account_name(account) is None:
            return False
        address = Service.objects.filter(pk=account.service_id).values_list("customer__primary_email", flat=True).get()
        if not address:
            return False
        claimed = timezone.now()
        row.activation_notified_at = claimed
        row.save(update_fields=["activation_notified_at", "updated_at"])
        transaction.on_commit(partial(_send_activation, row.pk, claimed), robust=True)
    return True


def _send_activation(hostname_pk: UUID, claimed: datetime) -> None:
    """Send the activation message; a send that fails gives the claim back for the next sync."""
    from apps.customers.services import get_customer_locale  # noqa: PLC0415  # Cross-app (ADR-0007)
    from apps.notifications.services import EmailService  # noqa: PLC0415  # Cross-app (ADR-0007)

    row = AccountHostname.objects.select_related("account__service__customer").get(pk=hostname_pk)
    account = row.account
    if account is None:
        return
    if account.status != "active":
        # Suspended after the claim committed: say nothing, and give the claim back so the
        # customer is told once the account is active again.
        AccountHostname.objects.filter(pk=hostname_pk, activation_notified_at=claimed).update(
            activation_notified_at=None
        )
        logger.info("⚠️ [AccountName] %s not announced: account is %s", row.fqdn, account.status)
        return
    customer = account.service.customer
    www, apex = dns_instructions(account.domain, row.fqdn)
    result = EmailService.send_template_email(
        template_key=ACTIVATION_TEMPLATE,
        recipient=customer.primary_email,
        context={
            "customer_name": customer.get_display_name(),
            "domain": account.domain,
            "account_name": row.fqdn,
            "www_record": f"{www['type']} {www['name']} -> {www['value']}",
            "apex_record": f"{apex['type']} {apex['name']} -> {apex['value']}",
        },
        locale=get_customer_locale(customer),
        customer=customer,
        async_send=False,  # Already in a task
    )
    if result.success:
        logger.info("✅ [AccountName] Customer told %s is live", row.fqdn)
        return
    AccountHostname.objects.filter(pk=hostname_pk, activation_notified_at=claimed).update(activation_notified_at=None)
    logger.warning("⚠️ [AccountName] Activation message for %s not sent, retried later: %s", row.fqdn, result.error)


def staff_account_name(account: VirtualminAccount) -> dict[str, Any] | None:
    """What staff see on the account page: the name, where it points, its records and its certificate (P1.13)."""
    from .account_hostname_models import AccountNameCertificate, AccountNameCertificateInstall  # noqa: PLC0415

    hostname = (
        AccountHostname.objects.select_related("target_server").filter(account=account, retired_at__isnull=True).first()
    )
    if hostname is None:
        return None
    certificate = AccountNameCertificate.objects.filter(hostname=hostname).first()
    installs = AccountNameCertificateInstall.objects.filter(hostname=hostname).select_related("server")
    return {
        "fqdn": hostname.fqdn,
        "target_server": hostname.target_server,
        "records": [
            {"type": record_type, "intended": entry.get("intended", ""), "applied": entry.get("applied", "")}
            for record_type, entry in sorted((hostname.records or {}).items())
        ],
        "published": records_published(hostname),
        "live": live_account_name(account) is not None,
        "last_reconciled_at": hostname.last_reconciled_at,
        "activation_notified_at": hostname.activation_notified_at,
        "certificate": certificate,
        "installs": list(installs),
        "enabled": config.account_hostnames_enabled(),
    }
