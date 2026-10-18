"""Account names: the node side and the DNS side (ADR-0061 P1.4).

An account name `<label>.<zone>` is a Virtualmin sub-server of the customer's domain, its web root
linked to the customer's (P1.15), its certificate its own (P1.10). PRAHO publishes A and AAAA
records for it in the account zone, pointing at `AccountHostname.target_server`.

- `ensure_node_account_name` makes one node serve the name: ownership read from the node's full
  listing, the sub-server created if absent, its state set BEFORE its content, the web root linked
  (only once the zone's Public Suffix List entry has shipped), the current certificate installed.
- `remove_node_account_name` deletes the name's sub-server only, after the same ownership check.
- `sync_account_hostname` converges the DNS records to `target_server`, publishing only a name
  whose certificate is installed there, after proving the token reads the configured zone.
- `retire_account_hostname` deletes the records and retires the row; its label is never reused.

Nothing here runs while `dns.account_hostnames_enabled` is off.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Any

from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result, Retriability, retriability_of

from . import account_hostname_config as config
from .account_hostname_models import AccountHostname
from .account_name_node import link_account_name_web_root
from .virtualmin_domain_state import domain_state_params
from .virtualmin_gateway import (
    TOP_LEVEL_SERVER,
    VirtualminConfig,
    VirtualminGateway,
    explicit_rejection,
    listing_attribute,
)
from .virtualmin_models import VirtualminAccount, VirtualminServer

logger = logging.getLogger(__name__)

DNS_PROVIDER = "cloudflare"
SUB_SERVER = "Sub-server"
_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_LABEL_LENGTH = 8
_LABEL_ATTEMPTS = 20
SYNCABLE_STATUSES = frozenset({"active", "suspended"})


@dataclass(frozen=True)
class EnsureOutcome:
    created: bool
    enabled: bool
    linked: bool
    certificate_installed: bool


def owner_tag(hostname: AccountHostname) -> str:
    """The tag PRAHO's records for this name carry; only records bearing it are ever changed."""
    return f"praho:account-name:{hostname.pk}"


# ----------------------------------------------------------------------------- certificates
# P1.10 owns issuance and installation. Until it is wired in, nothing counts as ready, so no name
# is ever published or announced without a certificate.


def certificate_ready_on(hostname: AccountHostname, server: VirtualminServer) -> bool:
    """Whether an unexpired certificate for the name is installed on `server`."""
    return False


def install_certificate(hostname: AccountHostname, server: VirtualminServer) -> Result[bool, str]:
    """Install the name's current certificate on `server`; Ok(False) when there is none yet."""
    return Ok(False)


# ----------------------------------------------------------------------------- rows


class AccountNameRetiredError(Exception):
    """The account's name was retired (the account was terminated); an account has one name, ever."""


def allocate_account_hostname(account: VirtualminAccount) -> AccountHostname:
    """The account's live name, created with a fresh random label when it has none.

    An account has one name for its whole life (a one-to-one row, kept when retired so its label is
    never reused). Asking again for a terminated account's name is refused, not retried.
    """
    existing = AccountHostname.objects.filter(account=account).first()
    if existing is not None:
        if existing.retired_at is not None:
            raise AccountNameRetiredError(f"The account name {existing.fqdn} was retired")
        return existing
    zone = config.account_zone()
    for _ in range(_LABEL_ATTEMPTS):
        label = "".join(secrets.choice(_LABEL_ALPHABET) for _ in range(_LABEL_LENGTH))
        try:
            with transaction.atomic():
                return AccountHostname.objects.create(label=label, zone=zone, account=account)
        except IntegrityError:
            continue  # A label is never reused, retired ones included: draw again
    raise RuntimeError("Could not draw an unused account-name label")


# ----------------------------------------------------------------------------- node side


def _gateway(server: VirtualminServer) -> VirtualminGateway:
    return VirtualminGateway(VirtualminConfig(server=server))


def _rows(gateway: VirtualminGateway) -> Result[dict[str, dict[str, str]], str]:
    listing = gateway.list_domains_with_owners()
    if listing.is_err():
        return Err(f"Domain listing failed: {listing.unwrap_err()}", retriability=retriability_of(listing))
    return Ok({row["domain"]: row for row in listing.unwrap()})


def _ownership_refusal(rows: dict[str, dict[str, str]], account: VirtualminAccount, name: str) -> str | None:
    """Why this node's rows do not let PRAHO act on the name for this account, or None."""
    parent = rows.get(account.domain)
    if parent is None or parent.get("type") != TOP_LEVEL_SERVER:
        return f"{account.domain} is not a top-level server on this node"
    if parent.get("username") != account.virtualmin_username:
        return f"{account.domain} is not owned by {account.virtualmin_username} on this node"
    child = rows.get(name)
    if child is None:
        return None
    if child.get("type") != SUB_SERVER or child.get("parent_domain") != account.domain:
        return f"{name} exists on this node and is not a sub-server of {account.domain}"
    if child.get("username") != account.virtualmin_username:
        return f"{name} is owned by another user on this node"
    return None


def _program(gateway: VirtualminGateway, program: str, params: dict[str, Any]) -> Result[None, str]:
    """One call whose success must be explicit; a rejection is definite, anything else ambiguous."""
    result = gateway.call(program, params)
    if result.is_err():
        return Err(f"{program} failed: {result.unwrap_err()}", retriability=retriability_of(result))
    response = result.unwrap()
    if response.success:
        return Ok(None)
    rejection = explicit_rejection(response.raw_response)
    if rejection is not None:
        return Err(f"{program} rejected: {rejection}", retriability=Retriability.NOT_RETRIABLE)
    return Err(f"Ambiguous {program}", retriability=Retriability.UNKNOWN)


def _name_state(gateway: VirtualminGateway, name: str) -> Result[dict[str, Any], str]:
    state = gateway.get_domain_state(name)
    if state.is_err():
        return Err(f"State of {name} unreadable: {state.unwrap_err()}", retriability=retriability_of(state))
    return Ok(state.unwrap())


def _home(gateway: VirtualminGateway, name: str) -> Result[str, str]:
    result = gateway.call("list-domains", {"domain": name, "multiline": ""})
    if result.is_err() or not result.unwrap().success:
        return Err(f"Home of {name} unreadable", retriability=Retriability.UNKNOWN)
    for item in result.unwrap().data.get("data") or []:
        if isinstance(item, dict) and item.get("name") == name:
            home = listing_attribute(item.get("values") or {}, "Home directory")
            if home:
                return Ok(home)
    return Err(f"Home of {name} unreadable", retriability=Retriability.UNKNOWN)


def _set_state(gateway: VirtualminGateway, name: str, *, enabled: bool) -> Result[None, str]:
    """Bring the name's sub-server to the wanted state and verify it from the node."""
    state = _name_state(gateway, name)
    if state.is_err():
        return Err(state.unwrap_err(), retriability=retriability_of(state))
    if state.unwrap().get("enabled") is not enabled:
        changed = _program(gateway, "enable-domain" if enabled else "disable-domain", domain_state_params(name))
        if changed.is_err():
            return changed
        state = _name_state(gateway, name)
        if state.is_err():
            return Err(state.unwrap_err(), retriability=retriability_of(state))
        if state.unwrap().get("enabled") is not enabled:
            return Err(f"{name} did not reach the wanted state", retriability=Retriability.UNKNOWN)
    return Ok(None)


def _create_name(gateway: VirtualminGateway, account: VirtualminAccount, name: str) -> Result[None, str]:
    """Create the name as a sub-server of the account's domain, then read it back as this account's."""
    create = _program(
        gateway,
        "create-domain",
        {"domain": name, "parent": account.domain, "dir": "", "web": "", "ssl": "", "desc": "PRAHO account name"},
    )
    if create.is_err():
        return create
    rows = _rows(gateway)  # Read again: the name must now be this account's own sub-server
    if rows.is_err():
        return Err(rows.unwrap_err(), retriability=retriability_of(rows))
    refusal = _ownership_refusal(rows.unwrap(), account, name)
    if refusal is not None or name not in rows.unwrap():
        return Err(f"After create: {refusal or 'the name is missing'}", retriability=Retriability.UNKNOWN)
    return Ok(None)


def _link_when_shipped(
    gateway: VirtualminGateway, server: VirtualminServer, account: VirtualminAccount, name: str
) -> Result[bool, str]:
    """Link the web root, only once the zone is a public suffix in shipped browsers (ADR-0061 §1)."""
    if not config.account_zone_psl_shipped():
        return Ok(False)
    home = _home(gateway, name)
    if home.is_err():
        return Err(home.unwrap_err(), retriability=retriability_of(home))
    link = link_account_name_web_root(server, home=home.unwrap(), customer_user=account.virtualmin_username)
    if link.is_err():
        return Err(link.unwrap_err(), retriability=retriability_of(link))
    return Ok(True)


def ensure_node_account_name(  # noqa: PLR0911  # One exit per step that can refuse or stay ambiguous
    account: VirtualminAccount, server: VirtualminServer, *, enabled: bool
) -> Result[EnsureOutcome, str]:
    """Make `server` serve the account's name: owned, in the wanted state, linked, certified. Idempotent.

    `enabled` is False for a suspended account and for a migration target not yet activated: a
    child created under a disabled customer domain starts enabled (lab S10), so its state is set
    and verified before its content is linked.
    """
    hostname = AccountHostname.objects.filter(account=account, retired_at__isnull=True).first()
    if hostname is None:
        return Err("The account has no live account name", retriability=Retriability.NOT_RETRIABLE)
    name = hostname.fqdn
    gateway = _gateway(server)

    rows = _rows(gateway)
    if rows.is_err():
        return Err(rows.unwrap_err(), retriability=retriability_of(rows))
    refusal = _ownership_refusal(rows.unwrap(), account, name)
    if refusal is not None:
        return Err(f"Refused: {refusal}", retriability=Retriability.NOT_RETRIABLE)

    created = name not in rows.unwrap()
    if created:
        create = _create_name(gateway, account, name)
        if create.is_err():
            return Err(create.unwrap_err(), retriability=retriability_of(create))

    state = _set_state(gateway, name, enabled=enabled)
    if state.is_err():
        return Err(state.unwrap_err(), retriability=retriability_of(state))

    linked = _link_when_shipped(gateway, server, account, name)
    if linked.is_err():
        return Err(linked.unwrap_err(), retriability=retriability_of(linked))

    certificate = install_certificate(hostname, server)
    if certificate.is_err():
        return Err(certificate.unwrap_err(), retriability=retriability_of(certificate))
    return Ok(
        EnsureOutcome(
            created=created, enabled=enabled, linked=linked.unwrap(), certificate_installed=certificate.unwrap()
        )
    )


def remove_node_account_name(account: VirtualminAccount, server: VirtualminServer) -> Result[bool, str]:
    """Delete the name's sub-server on `server` (never the customer's domain); Ok(False) when absent.

    The ownership check is read immediately before the call. Deleting the sub-server removes its own
    home and never follows the web-root link (lab S7b).
    """
    hostname = AccountHostname.objects.filter(account=account).order_by("-created_at").first()
    if hostname is None:
        return Ok(False)
    name = hostname.fqdn
    gateway = _gateway(server)
    rows = _rows(gateway)
    if rows.is_err():
        return Err(rows.unwrap_err(), retriability=retriability_of(rows))
    if name not in rows.unwrap():
        return Ok(False)
    refusal = _ownership_refusal(rows.unwrap(), account, name)
    if refusal is not None:
        return Err(f"Refused: {refusal}", retriability=Retriability.NOT_RETRIABLE)
    deleted = _program(gateway, "delete-domain", {"domain": name})
    if deleted.is_err():
        return Err(deleted.unwrap_err(), retriability=retriability_of(deleted))
    return Ok(True)


# ----------------------------------------------------------------------------- DNS side


def _dns_gateway() -> Any:
    from apps.infrastructure.dns_gateway import (  # noqa: PLC0415  # Deferred: infrastructure imports provisioning
        get_dns_gateway,
    )

    return get_dns_gateway(DNS_PROVIDER, config.account_zone_api_token())


def _syncable(hostname: AccountHostname) -> str | None:
    """Why the name is not published now, or None when it may be."""
    account = hostname.account
    if account is None or hostname.retired_at is not None:
        return "retired"
    if account.status not in SYNCABLE_STATUSES or account.provisioned_at is None:
        return "account_not_ready"
    server = hostname.target_server
    if server is None or not server.ipv4_address:
        return "no_target_address"
    if not certificate_ready_on(hostname, server):
        return "certificate_not_ready"
    return None


def _prove_zone(gateway: Any, zone_id: str, zone: str) -> Result[None, str]:
    """The token is proven where it is used: it reads this zone id, and the id is this zone."""
    name = gateway.get_zone_name(zone_id)
    if name.is_err():
        return Err(f"Account zone unreadable with the token: {name.unwrap_err()}", retriability=retriability_of(name))
    if str(name.unwrap()).strip(".").lower() != zone:
        return Err("The account zone id is not the account zone", retriability=Retriability.NOT_RETRIABLE)
    return Ok(None)


def sync_account_hostname(hostname: AccountHostname) -> Result[str, str]:
    """Converge the name's A and AAAA records to its target server. Ok(reason) says what was done."""
    if not config.account_hostnames_enabled():
        return Ok("disabled")
    reason = _syncable(hostname)
    if reason is not None:
        return Ok(f"skipped:{reason}")
    server = hostname.target_server
    ipv4 = server.ipv4_address if server is not None else None
    if server is None or not ipv4:
        return Ok("skipped:no_target_address")
    zone_id = config.account_zone_id()
    gateway = _dns_gateway()

    proven = _prove_zone(gateway, zone_id, hostname.zone)
    if proven.is_err():
        return Err(proven.unwrap_err(), retriability=retriability_of(proven))

    from apps.infrastructure.dns_gateway import DnsRecordSpec  # noqa: PLC0415  # Deferred: see _dns_gateway

    ttl = config.account_record_ttl_seconds()
    specs = [DnsRecordSpec(record_type="A", name=hostname.fqdn, content=ipv4, owner_tag=owner_tag(hostname), ttl=ttl)]
    if server.ipv6_address:
        specs.append(
            DnsRecordSpec(
                record_type="AAAA",
                name=hostname.fqdn,
                content=server.ipv6_address,
                owner_tag=owner_tag(hostname),
                ttl=ttl,
            )
        )
    # The intent first: a crash after the provider call still leaves what was meant on record.
    intended = {spec.record_type: {"intended": spec.content, "ttl": spec.ttl} for spec in specs}
    AccountHostname.objects.filter(pk=hostname.pk).update(records=intended, updated_at=timezone.now())

    outcome = gateway.reconcile_records(zone_id, specs, owner_tag(hostname))
    applied = {
        record.record_type: {**intended.get(record.record_type, {}), "applied": record.content, "id": record.record_id}
        for record in outcome.applied
    }
    AccountHostname.objects.filter(pk=hostname.pk).update(
        records={**intended, **applied},
        last_reconciled_at=timezone.now() if outcome.error is None else hostname.last_reconciled_at,
        updated_at=timezone.now(),
    )
    if outcome.error is not None:
        return Err(f"DNS reconcile failed: {outcome.error}", retriability=outcome.retriability)
    return Ok("published")


def retire_account_hostname(hostname: AccountHostname) -> Result[None, str]:
    """Delete the name's records and retire it. The label stays taken for ever."""
    if hostname.retired_at is not None:
        return Ok(None)
    if config.account_hostnames_enabled() or hostname.records:
        deleted = _dns_gateway().delete_owned_records(config.account_zone_id(), owner_tag(hostname))
        if deleted.is_err():
            return Err(f"Record removal failed: {deleted.unwrap_err()}", retriability=retriability_of(deleted))
    # A save, not a queryset update: the retirement is audited by the row's own signals.
    hostname.retired_at = timezone.now()
    hostname.records = {}
    hostname.save(update_fields=["retired_at", "records", "updated_at"])
    return Ok(None)
