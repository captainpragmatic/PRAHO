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
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from uuid import UUID

    from apps.infrastructure.dns_gateway import DnsRecordSpec

logger = logging.getLogger(__name__)

DNS_PROVIDER = "cloudflare"
SUB_SERVER = "Sub-server"
_LABEL_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_LABEL_LENGTH = 8
_LABEL_ATTEMPTS = 20
SYNCABLE_STATUSES = frozenset({"active", "suspended"})
# The cutover lowers the name's TTL for the move and the bridge (ADR-0061 P2.3). The provider's
# reported TTL on every owned record is what proves the change is live; the wait is bounded, and a
# name that never confirms is rolled back rather than moved on stale routing.
TTL_LOWER_DEADLINE = timedelta(minutes=30)


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
# P1.10 (account_name_certificates) owns issuance and installation. A name is published and
# announced only once an unexpired certificate for it is installed on the node DNS points at.


def certificate_ready_on(hostname: AccountHostname, server: VirtualminServer) -> bool:
    """Whether an unexpired certificate for the name is installed on `server`."""
    from .account_name_certificates import certificate_installed_on  # noqa: PLC0415  # Deferred: imports acme

    return certificate_installed_on(hostname, server.pk)


def install_certificate(hostname: AccountHostname, server: VirtualminServer) -> Result[bool, str]:
    """Order the name's certificate if it needs one and install it on `server`; Ok(False) when not yet.

    An issuance that is deferred, out of budget, failed or not configured leaves the name unready
    and unpublished, and the sweep tries again; that is not an error of this node. A certificate in
    hand that did not install is.
    """
    from .account_name_certificates import (  # noqa: PLC0415  # Deferred: imports acme
        IssuanceStatus,
        ensure_certificate_on_node,
    )

    result = ensure_certificate_on_node(hostname, server)
    if result.ready:
        return Ok(True)
    issued = result.issuance is not None and result.issuance.status in {
        IssuanceStatus.ISSUED,
        IssuanceStatus.ALREADY_VALID,
    }
    if issued:
        return Err(
            f"Certificate not installed on {server.hostname}: {result.detail}", retriability=Retriability.UNKNOWN
        )
    logger.info("⏳ [AccountName] Certificate for %s not ready yet: %s", hostname.fqdn, result.detail)
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
    return _create_name_row(account, config.account_zone())


def _create_name_row(account: VirtualminAccount, zone: str) -> AccountHostname:
    """Insert the account's name with a fresh label; the row another caller created meanwhile wins."""
    for _ in range(_LABEL_ATTEMPTS):
        label = "".join(secrets.choice(_LABEL_ALPHABET) for _ in range(_LABEL_LENGTH))
        try:
            with transaction.atomic():
                return AccountHostname.objects.create(label=label, zone=zone, account=account)
        except IntegrityError:
            # Either the label is taken (never reused, retired ones included: draw again) or the
            # account got its name from a concurrent allocation, which is then the answer.
            existing = AccountHostname.objects.filter(account=account).first()
            if existing is not None:
                if existing.retired_at is not None:
                    raise AccountNameRetiredError(f"The account name {existing.fqdn} was retired") from None
                return existing
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


def ensure_node_account_name(
    account: VirtualminAccount, server: VirtualminServer, *, enabled: bool, operation_owner: bool = False
) -> Result[EnsureOutcome, str]:
    """Make `server` serve the account's name: owned, in the wanted state, linked, certified. Idempotent.

    `enabled` is False for a suspended account and for a migration target not yet activated: a
    child created under a disabled customer domain starts enabled (lab S10), so its state is set
    and verified before its content is linked.

    One node step runs per name at a time (`account_name_lease`). A caller that does not own an
    operation on the account (the create task, the sweep) changes the node only while it holds the
    account's row lock, the one migration admission takes, and only when no migration, backup,
    restore or delete owns the account; the wanted state is then read again under that lock. A
    migration or restore, which is the account's operation, passes `operation_owner=True`.
    """
    from .account_name_lease import node_lease  # noqa: PLC0415  # Deferred: keeps the module import light

    hostname = AccountHostname.objects.filter(account=account, retired_at__isnull=True).first()
    if hostname is None:
        return Err("The account has no live account name", retriability=Retriability.NOT_RETRIABLE)
    with node_lease(hostname) as token:
        if token is None:
            return Err(f"Another node step for {hostname.fqdn} is running", retriability=Retriability.UNKNOWN)
        return _ensure_held(hostname, account, server, enabled=enabled, operation_owner=operation_owner)


def _ensure_held(
    hostname: AccountHostname,
    account: VirtualminAccount,
    server: VirtualminServer,
    *,
    enabled: bool,
    operation_owner: bool,
) -> Result[EnsureOutcome, str]:
    gateway = _gateway(server)
    preflight = _preflight(gateway, hostname, account, server)
    if preflight.is_err():
        return Err(preflight.unwrap_err(), retriability=retriability_of(preflight))
    if operation_owner:
        placed = _place_name(gateway, hostname, account, enabled=enabled, rows=preflight.unwrap())
    else:
        with transaction.atomic():
            locked = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=account.pk)
            refusal = _admission_refusal(locked)
            if refusal is not None:
                return refusal
            # Read again under the lock: the account and the node may have moved since the preflight.
            wanted = enabled and locked.status == "active"
            placed = _place_name(gateway, hostname, locked, enabled=wanted, rows=None)
    if placed.is_err():
        return Err(placed.unwrap_err(), retriability=retriability_of(placed))
    created, now_enabled = placed.unwrap()

    name = hostname.fqdn
    linked = _link_when_shipped(gateway, server, account, name)
    if linked.is_err():
        return Err(linked.unwrap_err(), retriability=retriability_of(linked))

    certificate = install_certificate(hostname, server)
    if certificate.is_err():
        return Err(certificate.unwrap_err(), retriability=retriability_of(certificate))
    return Ok(
        EnsureOutcome(
            created=created, enabled=now_enabled, linked=linked.unwrap(), certificate_installed=certificate.unwrap()
        )
    )


def _preflight(
    gateway: VirtualminGateway, hostname: AccountHostname, account: VirtualminAccount, server: VirtualminServer
) -> Result[dict[str, dict[str, str]], str]:
    """The node's rows, refused when the name belongs to anything else, and old evidence dropped.

    A fresh sub-server serves Virtualmin's self-signed certificate, so an install recorded for an
    earlier copy (a rolled-back migration, a restore from nothing, a return to a former node) must not
    count. It is dropped before any create, outside the account lock, so a create that succeeds on the
    node and is never answered cannot leave the old evidence in place.
    """
    from .account_name_certificates import forget_installation  # noqa: PLC0415  # Deferred: imports acme

    rows = _rows(gateway)
    if rows.is_err():
        return Err(rows.unwrap_err(), retriability=retriability_of(rows))
    refusal = _ownership_refusal(rows.unwrap(), account, hostname.fqdn)
    if refusal is not None:
        return Err(f"Refused: {refusal}", retriability=Retriability.NOT_RETRIABLE)
    if hostname.fqdn not in rows.unwrap():
        forget_installation(hostname, server)
    return Ok(rows.unwrap())


def _admission_refusal(account: VirtualminAccount) -> Err[str] | None:
    """None when a caller owning no operation may change the node now; the refusal otherwise."""
    from .virtualmin_migration_models import account_has_active_operation  # noqa: PLC0415  # Circular

    if account_has_active_operation(account, allow_waiting_mail=True):
        return Err("An operation owns the account; its name is left to the sweep", retriability=Retriability.UNKNOWN)
    if account.status not in SYNCABLE_STATUSES:
        return Err(f"The account is {account.status}", retriability=Retriability.NOT_RETRIABLE)
    return None


def _place_name(
    gateway: VirtualminGateway,
    hostname: AccountHostname,
    account: VirtualminAccount,
    *,
    enabled: bool,
    rows: dict[str, dict[str, str]] | None,
) -> Result[tuple[bool, bool], str]:
    """The name's sub-server owned and in the wanted state: (created, enabled). `rows=None` reads them."""
    name = hostname.fqdn
    if rows is None:
        listed = _rows(gateway)
        if listed.is_err():
            return Err(listed.unwrap_err(), retriability=retriability_of(listed))
        rows = listed.unwrap()
        refusal = _ownership_refusal(rows, account, name)
        if refusal is not None:
            return Err(f"Refused: {refusal}", retriability=Retriability.NOT_RETRIABLE)

    created = name not in rows
    if created:
        create = _create_name(gateway, account, name)
        if create.is_err():
            return Err(create.unwrap_err(), retriability=retriability_of(create))

    state = _set_state(gateway, name, enabled=enabled)
    if state.is_err():
        return Err(state.unwrap_err(), retriability=retriability_of(state))
    return Ok((created, enabled))


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


def lock_for_publication(pk: UUID, *, skip_locked: bool = False) -> AccountHostname | None:
    """The name's row, locked for a change to its records and read afresh. Call inside `atomic()`.

    Every publisher of the name's A and AAAA records (sync, withdraw, retire, and the cutover's
    commit) changes the provider only while holding this lock, deciding on what the row says under
    it, so a caller holding an older copy never publishes a node the name has left nor a name retired
    meanwhile (ADR-0061 Phase 2, invariant 3). The certificate's challenge TXT records are not
    routing and stay under the order's own claim. Nothing takes the account's lock while holding this
    one: the cutover's commit takes the account's first.

    The row is locked first and read with its relations after: on PostgreSQL a locking query that
    waited re-reads only the locked row, so a join in it would pair the new `target_server_id` with
    the server row seen before the wait, which reads as no target at all.
    """
    # Non-key updates are still serialized; FK KEY SHARE checks may complete
    # while another account writer waits for this publication transaction.
    locked = AccountHostname.objects.select_for_update(no_key=True, skip_locked=skip_locked).filter(pk=pk)
    if not list(locked.values_list("pk", flat=True)):
        return None
    return AccountHostname.objects.select_related("account", "account__server", "target_server").get(pk=pk)


def sync_account_hostname(hostname: AccountHostname, *, skip_locked: bool = False) -> Result[str, str]:
    from .managed_dns_service import publication_intents  # noqa: PLC0415  # Commit customer creation intents before RPC

    if not config.account_hostnames_enabled():
        return Ok("disabled")
    with publication_intents(hostname.pk, skip_locked=skip_locked) as prepared:
        if prepared.is_err():
            return Err(prepared.unwrap_err(), retriability=retriability_of(prepared))
        return _sync_account_hostname(hostname, skip_locked=skip_locked, create_permits=prepared.unwrap())


def _sync_account_hostname(
    hostname: AccountHostname, *, skip_locked: bool, create_permits: dict[str, str]
) -> Result[str, str]:
    """Converge the name's A and AAAA records to its target server. Ok(reason) says what was done.

    Only the row's id is used: everything is decided again under the name's lock. `skip_locked`
    (the sweep) passes over a name being published instead of waiting for it.
    """
    if not config.account_hostnames_enabled():
        return Ok("disabled")
    # Twice under the lock. The intent is committed first, alone, so a worker killed during the
    # provider call still leaves the name marked as published, and so withdrawn or retired later.
    planned = _publication_step(hostname.pk, skip_locked=skip_locked)
    if planned is not None:
        return planned
    zone_id = config.account_zone_id()
    gateway = _dns_gateway()
    proven = _prove_zone(gateway, zone_id, hostname.zone)  # A read: outside the lock, to keep it short
    if proven.is_err():
        return Err(proven.unwrap_err(), retriability=retriability_of(proven))
    return _publish(hostname.pk, gateway, zone_id, create_permits=create_permits)


def _publication_step(pk: UUID, *, skip_locked: bool) -> Result[str, str] | None:
    """Record the intent under the lock, or say why nothing is published (None: go on to publish)."""
    with transaction.atomic():
        hostname = lock_for_publication(pk, skip_locked=skip_locked)
        if hostname is None:
            return Ok("skipped:busy" if skip_locked else "skipped:retired")
        decided = _decide(hostname)
        if decided is None:
            _store_intent(hostname, _specs(hostname))
        return decided


def _decide(hostname: AccountHostname) -> Result[str, str] | None:
    """On the locked row: withdraw, skip with a reason, or None when the name is to be published."""
    reason = _syncable(hostname)
    if reason == "certificate_not_ready" and hostname.records:
        return _withdraw(hostname)
    if reason is not None:
        return Ok(f"skipped:{reason}")
    return None


def _specs(hostname: AccountHostname, *, ttl: int | Mapping[str, int] | None = None) -> list[DnsRecordSpec]:
    from apps.infrastructure.dns_gateway import DnsRecordSpec  # noqa: PLC0415  # Deferred: see _dns_gateway

    server = hostname.target_server
    if server is None or not server.ipv4_address:  # _syncable refused these; kept for the type
        return []

    def _ttl(record_type: str) -> int:
        if ttl is None:
            # A routine sync during a cutover must not undo the lowering; only the restore raises it.
            return (
                config.account_cutover_ttl_seconds()
                if hostname.previous_ttl is not None
                else config.account_record_ttl_seconds()
            )
        if isinstance(ttl, Mapping):
            return int(ttl.get(record_type, config.account_record_ttl_seconds()))
        return ttl

    tag = owner_tag(hostname)
    specs = [
        DnsRecordSpec(record_type="A", name=hostname.fqdn, content=server.ipv4_address, owner_tag=tag, ttl=_ttl("A"))
    ]
    if server.ipv6_address:
        specs.append(
            DnsRecordSpec(
                record_type="AAAA", name=hostname.fqdn, content=server.ipv6_address, owner_tag=tag, ttl=_ttl("AAAA")
            )
        )
    return specs


def _merged(previous: Mapping[str, Any], intended: Mapping[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    """Each intended record keeps what was learned about it while its content is unchanged.

    A record whose content changes starts again, and a type no longer intended is dropped: the
    provider deletes it, and an entry left behind would read as published.
    """
    merged: dict[str, dict[str, object]] = {}
    for record_type, entry in intended.items():
        before = previous.get(record_type) or {}
        kept = before if before.get("intended") == entry.get("intended") else {}
        merged[record_type] = {**kept, **entry}
        if "previous_ttl" in before:
            # The TTL to restore belongs to the name, not to the content that happened to be live then.
            merged[record_type]["previous_ttl"] = before["previous_ttl"]
    return merged


def _store_intent(hostname: AccountHostname, specs: list[DnsRecordSpec]) -> dict[str, dict[str, object]]:
    intended: dict[str, dict[str, object]] = {
        spec.record_type: {"intended": spec.content, "ttl": spec.ttl} for spec in specs
    }
    merged = _merged(hostname.records or {}, intended)
    AccountHostname.objects.filter(pk=hostname.pk).update(records=merged, updated_at=timezone.now())
    hostname.records = merged
    return merged


def _publish(
    pk: UUID,
    gateway: Any,
    zone_id: str,
    *,
    ttl: int | Mapping[str, int] | None = None,
    create_permits: dict[str, str] | None = None,
) -> Result[str, str]:
    """The provider call, under the lock, for what the row says now: a commit since may have moved it."""
    with transaction.atomic():
        hostname = lock_for_publication(pk)
        if hostname is None:
            return Ok("skipped:retired")
        decided = _decide(hostname)
        if decided is not None:
            return decided
        specs = _specs(hostname, ttl=ttl)
        intended = _store_intent(hostname, specs)
        outcome = gateway.reconcile_records(zone_id, specs, owner_tag(hostname))
        # An Err from here commits what was stored, on purpose: a partial apply is still what exists.
        published = _record_outcome(gateway, zone_id, hostname, intended, outcome)
        if published.is_err():
            return published
        from .managed_dns_service import TtlMode, sync_managed_locked  # noqa: PLC0415  # Deferred customer-zone seam

        mode: TtlMode = "restore" if isinstance(ttl, Mapping) else "lower" if ttl is not None else "current"
        managed = sync_managed_locked(hostname, mode=mode, create_permits=create_permits)
        return published if managed.is_ok() else Err(managed.unwrap_err(), retriability=retriability_of(managed))


def _withdraw(hostname: AccountHostname) -> Result[str, str]:
    """A published name whose certificate is gone stops being published, and is due again at every sweep.

    Publishing means only a name with an unexpired certificate installed on its node is in DNS; a name
    that lost it would send customers to a node that cannot serve it. Called under the name's lock.
    """
    from .managed_dns_service import withdraw_managed_locked  # noqa: PLC0415  # Deferred customer-zone seam

    managed = withdraw_managed_locked(hostname)
    if managed.is_err():
        return Err(managed.unwrap_err(), retriability=retriability_of(managed))
    deleted = _dns_gateway().delete_owned_records(config.account_zone_id(), owner_tag(hostname))
    if deleted.is_err():
        return Err(f"Record withdrawal failed: {deleted.unwrap_err()}", retriability=retriability_of(deleted))
    AccountHostname.objects.filter(pk=hostname.pk, retired_at__isnull=True).update(
        records={}, last_reconciled_at=None, updated_at=timezone.now()
    )
    logger.warning("⚠️ [AccountName] %s withdrawn from DNS: no valid certificate on its node", hostname.fqdn)
    return Ok("withdrawn")


def withdraw_drained_node(server: VirtualminServer) -> Result[None, str]:
    """Withdraw non-live names before node retirement, preserving labels for recovery."""
    names = AccountHostname.objects.filter(target_server=server, retired_at__isnull=True).values_list(
        "pk", "account_id"
    )
    for hostname_id, account_id in list(names):
        with transaction.atomic():
            account = (
                VirtualminAccount.objects.select_for_update(no_key=True).filter(pk=account_id).first()
                if account_id
                else None
            )
            hostname = lock_for_publication(hostname_id)
            if hostname is None or hostname.target_server_id != server.pk:
                continue
            if account is not None and account.status in SYNCABLE_STATUSES:
                return Err("A live account still has a hostname on this node")
            if hostname.records:
                withdrawn = _withdraw(hostname)
                if withdrawn.is_err():
                    return Err(withdrawn.unwrap_err(), retriability=retriability_of(withdrawn))
            AccountHostname.objects.filter(pk=hostname.pk).update(target_server=None, updated_at=timezone.now())
    return Ok(None)


def _record_outcome(
    gateway: Any,
    zone_id: str,
    hostname: AccountHostname,
    intended: Mapping[str, dict[str, object]],
    outcome: Any,
) -> Result[str, str]:
    """Store what the provider applied; a name retired meanwhile has its records deleted again."""
    applied = {
        record.record_type: {
            **intended.get(record.record_type, {}),
            "applied": record.content,
            "applied_ttl": record.ttl,
            "id": record.record_id,
        }
        for record in outcome.applied
    }
    kept = AccountHostname.objects.filter(pk=hostname.pk, retired_at__isnull=True).update(
        records={**intended, **applied},
        last_reconciled_at=timezone.now() if outcome.error is None else hostname.last_reconciled_at,
        updated_at=timezone.now(),
    )
    if kept == 0:
        # Retired while this sync talked to the provider: the retire's delete may have run before the
        # records came back, so they are deleted again and the retired row is left as it is.
        gateway.delete_owned_records(zone_id, owner_tag(hostname))
        return Ok("retired")
    if outcome.error is not None:
        return Err(f"DNS reconcile failed: {outcome.error}", retriability=outcome.retriability)
    from .account_hostname_hosting import announce_when_live  # noqa: PLC0415  # Deferred: imports acme

    announce_when_live(hostname)
    return Ok("published")


def _effective_ttl(hostname: AccountHostname) -> int:
    """The TTL the name currently runs on, from what the provider reported or what was asked for."""
    for entry in (hostname.records or {}).values():
        for key in ("applied_ttl", "ttl"):
            value = entry.get(key)
            if isinstance(value, int):
                return value
    return config.account_record_ttl_seconds()


def ttl_is(hostname: AccountHostname, ttl: int | Mapping[str, int]) -> bool:
    """Every owned record the provider reports carries the TTL asked for, record type by record type."""
    records = hostname.records or {}
    if not records:
        return False
    for record_type, entry in records.items():
        expected = int(ttl.get(record_type, -1)) if isinstance(ttl, Mapping) else ttl
        if entry.get("applied_ttl") != expected:
            return False
    return True


def ttl_is_lowered(hostname: AccountHostname, *, ttl: int | None = None) -> bool:
    """Every owned record the provider reports carries the lower TTL; one holdout is not converged."""
    threshold = config.account_cutover_ttl_seconds() if ttl is None else ttl
    from .managed_dns_service import ttls_confirmed_locked  # noqa: PLC0415  # Deferred customer-zone seam

    with transaction.atomic():
        locked = lock_for_publication(hostname.pk)
        return bool(locked and ttl_is(locked, threshold) and ttls_confirmed_locked(locked))


def _previous_ttls(hostname: AccountHostname) -> dict[str, int]:
    """The TTL to restore for each record type, from what was recorded when the lowering began."""
    fallback = hostname.previous_ttl or config.account_record_ttl_seconds()
    return {
        record_type: int(entry.get("previous_ttl") or fallback)
        for record_type, entry in (hostname.records or {}).items()
    }


def _begin_lowering(hostname: AccountHostname, create_permits: dict[str, str]) -> Result[bool, str]:
    """Record the TTL each record had, once, under the name's lock. False when nothing is published."""
    now = timezone.now()
    with transaction.atomic():
        locked = lock_for_publication(hostname.pk)
        if locked is None or locked.retired_at is not None or not locked.records:
            return Ok(False)
        from .managed_dns_service import begin_lowering_locked  # noqa: PLC0415  # Deferred customer-zone seam

        managed = begin_lowering_locked(locked, epoch=locked.ttl_lowered_at or now, create_permits=create_permits)
        if managed.is_err():
            return Err(managed.unwrap_err(), retriability=retriability_of(managed))
        records = locked.records
        for entry in records.values():
            if "previous_ttl" not in entry:
                entry["previous_ttl"] = (
                    entry.get("applied_ttl") or entry.get("ttl") or config.account_record_ttl_seconds()
                )
        fields: dict[str, object] = {"records": records}
        # Keep the longest original TTL even if a record type is removed during the move.
        fields["previous_ttl"] = max(
            locked.previous_ttl or 0,
            managed.unwrap(),
            *(int(entry["previous_ttl"]) for entry in records.values()),
        )
        if locked.ttl_lowered_at is None:
            fields["ttl_lowered_at"] = now
        AccountHostname.objects.filter(pk=locked.pk).update(updated_at=now, **fields)
        return Ok(True)


def _apply_ttl(
    hostname: AccountHostname, ttl: int | Mapping[str, int], *, create_permits: dict[str, str]
) -> Result[str, str]:
    """Publish the name's records with `ttl`, proving the zone first; says whether that landed."""
    zone_id = config.account_zone_id()
    gateway = _dns_gateway()
    proven = _prove_zone(gateway, zone_id, hostname.zone)
    if proven.is_err():
        return Err(proven.unwrap_err(), retriability=retriability_of(proven))
    published = _publish(hostname.pk, gateway, zone_id, ttl=ttl, create_permits=create_permits)
    if published.is_err():
        return published
    state = published.unwrap()
    if state != "published":
        return Err(f"Account name cannot set its TTL: {state}", retriability=Retriability.NOT_RETRIABLE)
    return Ok("published")


def lower_account_hostname_ttl(hostname: AccountHostname) -> Result[str, str]:
    from .managed_dns_service import publication_intents  # noqa: PLC0415  # Commit customer creation intents before RPC

    if not config.account_hostnames_enabled():
        return Ok("disabled")
    with publication_intents(hostname.pk, mode="lower") as prepared:
        if prepared.is_err():
            return Err(prepared.unwrap_err(), retriability=retriability_of(prepared))
        return _lower_account_hostname_ttl(hostname, prepared.unwrap())


def _lower_account_hostname_ttl(hostname: AccountHostname, create_permits: dict[str, str]) -> Result[str, str]:
    """Lower every owned record's TTL, then wait one maximum previous TTL after confirmation.

    `waiting` covers provider propagation and the old answers still held by caches. The provider
    deadline applies before confirmation; a legitimately longer old TTL is allowed to expire.
    """
    if not config.account_hostnames_enabled():
        return Ok("disabled")
    begun = _begin_lowering(hostname, create_permits)
    if begun.is_err():
        return Err(begun.unwrap_err(), retriability=retriability_of(begun))
    if not begun.unwrap():
        return Ok("skipped:not_published")
    applied = _apply_ttl(hostname, config.account_cutover_ttl_seconds(), create_permits=create_permits)
    if applied.is_err():
        return applied
    outcome = _lowering_progress(hostname)
    hostname.refresh_from_db()
    return outcome


def _lowering_progress(hostname: AccountHostname) -> Result[str, str]:
    """Confirm the provider's result and the cache deadline on the current, locked record set."""
    with transaction.atomic():
        locked = lock_for_publication(hostname.pk)
        if locked is None or locked.retired_at is not None:
            return Ok("skipped:retired")
        now = timezone.now()
        if not ttl_is_lowered(locked):
            if locked.ttl_confirmed_at is not None:
                # The provider reports an older TTL again: confirmation and its cache wait restart.
                AccountHostname.objects.filter(pk=locked.pk).update(
                    ttl_confirmed_at=None, ttl_lowered_at=now, updated_at=now
                )
            elif locked.ttl_lowered_at is not None and now >= locked.ttl_lowered_at + TTL_LOWER_DEADLINE:
                return Err(
                    "The provider did not confirm the lower TTL in time", retriability=Retriability.NOT_RETRIABLE
                )
            return Ok("waiting")
        confirmed = locked.ttl_confirmed_at
        if confirmed is None:
            confirmed = now
            AccountHostname.objects.filter(pk=locked.pk).update(ttl_confirmed_at=confirmed, updated_at=now)
        previous_ttl = locked.previous_ttl or max(_previous_ttls(locked).values())
        return Ok("converged" if now >= confirmed + timedelta(seconds=previous_ttl) else "waiting")


def restore_account_hostname_ttl(hostname: AccountHostname) -> Result[str, str]:
    from .managed_dns_service import publication_intents  # noqa: PLC0415  # Commit customer creation intents before RPC

    if not config.account_hostnames_enabled():
        return _restore_account_hostname_ttl(hostname, {})
    with publication_intents(hostname.pk, mode="restore") as prepared:
        if prepared.is_err():
            return Err(prepared.unwrap_err(), retriability=retriability_of(prepared))
        return _restore_account_hostname_ttl(hostname, prepared.unwrap())


def _restore_account_hostname_ttl(hostname: AccountHostname, create_permits: dict[str, str]) -> Result[str, str]:
    """Restore and clear evidence under the publication lock, including empty and stale callers."""
    with transaction.atomic():
        locked = lock_for_publication(hostname.pk)
        if locked is None or locked.retired_at is not None:
            return Ok("skipped:retired")
        if locked.previous_ttl is None:
            return Ok("noop")
        if not locked.records:
            from .managed_dns_service import clear_restored_locked  # noqa: PLC0415  # Deferred customer-zone seam

            if not clear_restored_locked(locked):
                return Ok("waiting")
            AccountHostname.objects.filter(pk=locked.pk).update(
                previous_ttl=None, ttl_lowered_at=None, ttl_confirmed_at=None, updated_at=timezone.now()
            )
            return Ok("restored")
        if not config.account_hostnames_enabled():
            return Ok("disabled")
        recorded_ttls = _previous_ttls(locked)
        applied = _apply_ttl(locked, recorded_ttls, create_permits=create_permits)
        return applied if applied.is_err() else _confirm_restored(hostname, recorded_ttls)


def _confirm_restored(hostname: AccountHostname, recorded_ttls: Mapping[str, int]) -> Result[str, str]:
    """Under the name's lock: only clear the evidence when the provider reports the restored TTLs."""
    with transaction.atomic():
        locked = lock_for_publication(hostname.pk)
        if locked is None:
            return Ok("skipped:retired")
        if not ttl_is(locked, recorded_ttls):
            # The provider still reports the lowered value, or a sync raced in: keep the evidence so a
            # retry can finish rather than falsely reporting the restore done.
            return Ok("waiting")
        from .managed_dns_service import clear_restored_locked  # noqa: PLC0415  # Deferred customer-zone seam

        if not clear_restored_locked(locked):
            return Ok("waiting")
        records = locked.records or {}
        for entry in records.values():
            entry.pop("previous_ttl", None)
        AccountHostname.objects.filter(pk=locked.pk).update(
            records=records, previous_ttl=None, ttl_lowered_at=None, ttl_confirmed_at=None, updated_at=timezone.now()
        )
    hostname.refresh_from_db()
    return Ok("restored")


def retire_account_hostname(hostname: AccountHostname) -> Result[None, str]:
    """Delete the name's records and retire it, under the name's lock. The label stays taken for ever."""
    if hostname.retired_at is not None:
        return Ok(None)
    with transaction.atomic():
        locked = lock_for_publication(hostname.pk)
        if locked is None or locked.retired_at is not None:
            return Ok(None)
        from .managed_dns_service import withdraw_managed_locked  # noqa: PLC0415  # Deferred customer-zone seam

        managed = withdraw_managed_locked(locked)
        if managed.is_err():
            return Err(managed.unwrap_err(), retriability=retriability_of(managed))
        if config.account_hostnames_enabled() or locked.records:
            deleted = _dns_gateway().delete_owned_records(config.account_zone_id(), owner_tag(locked))
            if deleted.is_err():
                return Err(f"Record removal failed: {deleted.unwrap_err()}", retriability=retriability_of(deleted))
        # A save of the locked row, not a queryset update: the retirement is audited by its own signals.
        locked.retired_at = timezone.now()
        locked.records = {}
        locked.target_server = None  # A retired name holds no node, so the node can be unregistered
        locked.save(update_fields=["retired_at", "records", "target_server", "updated_at"])
    return Ok(None)
