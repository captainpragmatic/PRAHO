"""A certificate per account name (ADR-0061 P1.10).

Each account name `<label>.<zone>` gets its own certificate, issued on Platform through DNS-01 on the
account zone, so it works before the customer's DNS points anywhere and no DNS token ever reaches a node.

How the state is kept (`AccountNameCertificate`):

* **The material in force** (`current_*`) is apart from **the attempt** (`attempt_*`). A renewal that is
  ordering or failed leaves the current certificate in force; readiness is valid material installed on the
  node, never the attempt state.
* **The budget is durable.** A first issuance takes a reservation under the zone's `AccountNameCertificateBudget`
  row lock, as a rolling seven-day count of non-renewal reservations; renewals take none. The reservation is
  committed before any network call, and an attempt left `ordering` after a crash resumes with the slot it
  already holds, from its stored order URL, instead of ordering (or reserving) twice.
* **Keys live in the vault**, per hostname: the ACME account key under the name, each certificate key under
  the issuance that made it, so a renewal never overwrites the key of the certificate in force.

A renewal overwrites the row's reservation time (the vault identifier of its new key follows from it), so a
renewal inside seven days of the first issuance would drop that issuance from the count; with certificates of
more than 37 days and renewal at 30 days left, that cannot happen.

Resuming is idempotent rather than exclusive: two workers on the same `ordering` row read the same order and
publish the same challenge values, so the worst case is a repeated read, never a second order.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.common.credential_vault import CredentialData, get_credential_vault
from apps.common.transactions import best_effort_atomic
from apps.common.types import Err, Ok, Result
from apps.infrastructure.dns_gateway import DnsProviderGateway, get_dns_gateway

from . import account_hostname_config as config
from .account_hostname_models import (
    AccountHostname,
    AccountNameCertificate,
    AccountNameCertificateBudget,
    AccountNameCertificateInstall,
)
from .acme_client import (
    AcmeClient,
    AcmeError,
    AcmeOrder,
    AcmeOrderFailed,
    AcmeRateLimited,
    LibraryAcmeClient,
)

if TYPE_CHECKING:
    from .virtualmin_models import VirtualminServer

logger = logging.getLogger(__name__)

INSTALL_PLAYBOOK = "virtualmin_install_account_cert.yml"
DNS_PROVIDER = "cloudflare"

ACME_OWNER_PREFIX = "praho:acme:"
BUDGET_WINDOW = timedelta(days=7)
BUDGET_ALERT_PERCENT = 80
RENEW_WITHIN = timedelta(days=30)
# After a rejected order, wait before the next one: Let's Encrypt limits failed validations per name per hour.
FAILED_BACKOFF = timedelta(hours=1)
TRANSIENT_BACKOFF = timedelta(minutes=5)
# Records younger than this may belong to an order whose URL is not saved yet; the sweep leaves them.
SWEEP_MIN_AGE_SECONDS = 1800.0
# Seconds to let the DNS provider publish the challenge values before the server is asked to check them.
DNS_SETTLE_SECONDS = 10.0
INSTALL_TIMEOUT_SECONDS = 300

ACCOUNT_KEY_TYPE = "acme_account_key"
CERT_KEY_TYPE = "acme_certificate_key"
CERT_TYPE = "acme_certificate"
_ACCOUNT_KEY_DAYS = 3650
_CERT_DAYS = 400
_VAULT_REASON = "Account name certificate issuance"
_PEM_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)
_ALERT_TTL_SECONDS = 24 * 3600
_AUDIT_ALERT = "account_name_certificate_alert"


class IssuanceStatus(StrEnum):
    ISSUED = "issued"  # a certificate was ordered and is now in force
    ALREADY_VALID = "already_valid"  # valid material exists; nothing was ordered
    DEFERRED = "deferred"  # try again after `retry_after`; any reservation and order are kept
    BUDGET_EXHAUSTED = "budget_exhausted"  # no new-certificate slot left this week; the name stays unready
    FAILED = "failed"  # the order was rejected
    NOT_CONFIGURED = "not_configured"  # the account zone, its id or its token is missing, or the zone moved
    RETIRED = "retired"  # the name is retired


@dataclass(frozen=True)
class IssuanceOutcome:
    status: IssuanceStatus
    detail: str = ""
    retry_after: datetime | None = None


@dataclass(frozen=True)
class NodeCertificateResult:
    """What `ensure_certificate_on_node` found: whether the name is ready on the node, and why not."""

    ready: bool
    issuance: IssuanceOutcome | None = None
    detail: str = ""


class _Defer(Exception):  # noqa: N818  # Internal control flow: keep the order and try again later
    def __init__(self, seconds: float, detail: str) -> None:
        super().__init__(detail)
        self.seconds = seconds
        self.detail = detail


def build_acme_client(directory_url: str, account_key_pem: str) -> AcmeClient:
    """The ACME client for one account key. Tests replace this with a fake directory."""
    return LibraryAcmeClient(directory_url, account_key_pem)


# =============================================================================
# Readiness (P1.4 calls these)
# =============================================================================


def account_name_ready(hostname: AccountHostname) -> bool:
    """Whether the name's certificate is valid material installed on its intended node.

    The attempt state does not matter: a first issuance still pending, ordering or failed is not ready,
    and a failing renewal does not make a name unready while the certificate on the node is unexpired.
    """
    if hostname.target_server_id is None:
        return False
    return certificate_installed_on(hostname, hostname.target_server_id)


def certificate_installed_on(hostname: AccountHostname, server_id: UUID) -> bool:
    """Whether an unexpired certificate for the name is recorded as installed on that node."""
    return AccountNameCertificateInstall.objects.filter(
        hostname=hostname, server_id=server_id, not_after__gt=timezone.now()
    ).exists()


def record_installation(
    hostname: AccountHostname, server: VirtualminServer, *, certificate_ref: str, not_after: datetime
) -> AccountNameCertificateInstall:
    """Record that this certificate is installed on this node. P1.4 calls it after its own successful install."""
    install, _created = AccountNameCertificateInstall.objects.update_or_create(
        hostname=hostname,
        server=server,
        defaults={"certificate_ref": certificate_ref, "not_after": not_after, "installed_at": timezone.now()},
    )
    return install


def ensure_certificate_on_node(hostname: AccountHostname, server: VirtualminServer) -> NodeCertificateResult:
    """Make sure the name has valid material and that it is installed on ``server``.

    Never orders for a name that already has valid material: it reinstalls the stored certificate. A node
    that already holds the current certificate is left alone.
    """
    issuance = request_certificate(hostname)
    certificate = AccountNameCertificate.objects.filter(hostname=hostname).first()
    if certificate is None or not certificate.has_valid_material():
        return NodeCertificateResult(ready=False, issuance=issuance, detail=issuance.detail or issuance.status.value)
    installed = AccountNameCertificateInstall.objects.filter(
        hostname=hostname,
        server=server,
        certificate_ref=certificate.current_certificate_ref,
        not_after__gt=timezone.now(),
    ).exists()
    if not installed:
        result = install_current_certificate(hostname, server)
        if result.is_err():
            return NodeCertificateResult(ready=False, issuance=issuance, detail=result.unwrap_err())
    ready = AccountNameCertificateInstall.objects.filter(
        hostname=hostname, server=server, not_after__gt=timezone.now()
    ).exists()
    return NodeCertificateResult(
        ready=ready, issuance=issuance, detail="" if ready else "The install was not recorded."
    )


# =============================================================================
# Issuance
# =============================================================================


def order_owner_tag(order_url: str) -> str:
    """The DNS owner tag of an order's challenge records: `praho:acme:<short hash of the order URL>`."""
    return f"{ACME_OWNER_PREFIX}{hashlib.sha256(order_url.encode()).hexdigest()[:16]}"


def request_certificate(hostname: AccountHostname, *, scheduled_renewal: bool = False) -> IssuanceOutcome:
    """Order the name's certificate if it needs one.

    Valid material is never re-ordered, except by the scheduled renewal once it is within 30 days of expiry.
    """
    zone_id, token = config.account_zone_id(), config.account_zone_api_token()
    if not (zone_id and token and config.account_zone() and hostname.zone == config.account_zone()):
        return IssuanceOutcome(IssuanceStatus.NOT_CONFIGURED, "The account zone, its id or its token is not set.")
    certificate, _created = AccountNameCertificate.objects.get_or_create(hostname=hostname)
    # Outside the locked section, so two workers racing to create it cannot fail inside a transaction.
    AccountNameCertificateBudget.objects.get_or_create(zone=hostname.zone)

    claim = _claim_attempt(certificate.pk, scheduled_renewal=scheduled_renewal)
    if isinstance(claim, IssuanceOutcome):
        return claim
    return _run_order(claim)


def _claim_attempt(certificate_id: UUID, *, scheduled_renewal: bool) -> UUID | IssuanceOutcome:
    """Decide, under the row lock, whether to order; take the budget reservation when a new name needs one."""
    now = timezone.now()
    with transaction.atomic():
        certificate = (
            AccountNameCertificate.objects.select_for_update().select_related("hostname").get(pk=certificate_id)
        )
        if certificate.hostname.retired_at is not None:
            return IssuanceOutcome(IssuanceStatus.RETIRED, "The account name is retired.")
        if certificate.has_valid_material() and not (
            scheduled_renewal
            and certificate.current_not_after is not None
            and certificate.current_not_after - now < RENEW_WITHIN
        ):
            return IssuanceOutcome(IssuanceStatus.ALREADY_VALID)
        if certificate.retry_after is not None and certificate.retry_after > now:
            return IssuanceOutcome(IssuanceStatus.DEFERRED, "Waiting out a delay.", retry_after=certificate.retry_after)
        if certificate.attempt_status == AccountNameCertificate.AttemptStatus.ORDERING:
            return certificate.pk  # a crashed or deferred attempt: resume it with the slot it already holds

        renewal = bool(certificate.current_certificate_ref)
        if renewal:
            certificate.attempt_reserved_at = now
        else:
            reserved = _reserve_budget(certificate, now)
            if not reserved:
                return IssuanceOutcome(IssuanceStatus.BUDGET_EXHAUSTED, "No new-certificate slot is left this week.")
        certificate.attempt_is_renewal = renewal
        certificate.attempt_status = AccountNameCertificate.AttemptStatus.ORDERING
        certificate.attempt_order_url = ""
        certificate.retry_after = None
        certificate.save()
    return certificate.pk


def _reserve_budget(certificate: AccountNameCertificate, now: datetime) -> bool:
    """Take one new-certificate slot for ``certificate`` under the zone's budget row lock; False when none is left.

    Called inside the claim transaction, after the certificate row lock and always in that order, so two
    workers can never wait on each other. The count is the rolling seven-day number of non-renewal
    reservations other than this row's own; a failed first attempt that still holds a slot inside the window
    keeps it rather than taking another.
    """
    zone = certificate.hostname.zone
    AccountNameCertificateBudget.objects.select_for_update().get(zone=zone)
    window_start = now - BUDGET_WINDOW
    others = (
        AccountNameCertificate.objects.filter(
            hostname__zone=zone, attempt_is_renewal=False, attempt_reserved_at__gt=window_start
        )
        .exclude(pk=certificate.pk)
        .count()
    )
    limit = config.account_cert_weekly_budget()
    holds_slot = (
        certificate.attempt_reserved_at is not None
        and certificate.attempt_reserved_at > window_start
        and not certificate.attempt_is_renewal
    )
    if holds_slot:
        return True
    if others >= limit:
        _alert(
            zone,
            "exhausted",
            f"The {zone} certificate budget is used up: {others} of {limit} this week.",
            others,
            limit,
        )
        return False
    certificate.attempt_reserved_at = now
    used = others + 1
    if used * 100 >= limit * BUDGET_ALERT_PERCENT:
        _alert(zone, "threshold", f"The {zone} certificate budget is at {used} of {limit} this week.", used, limit)
    return True


def _alert(zone: str, kind: str, description: str, used: int, limit: int) -> None:
    """Flag staff through the audit trail, once a day per zone and kind.

    The write has its own savepoint, so a failed audit write cannot take the reservation's transaction down
    with it, and the day's quiet marker is set only once the alert is written.
    """
    key = f"account-cert-alert:{zone}:{kind}:{timezone.localdate()}"
    if cache.get(key):
        return
    logger.error("🔥 [AccountCert] %s", description)
    budget = AccountNameCertificateBudget.objects.filter(zone=zone).first()
    with best_effort_atomic(logger=logger, scope="AccountCert", message="Certificate budget alert failed"):
        AuditService.log_event(
            AuditEventData(event_type=_AUDIT_ALERT, content_object=budget, description=description),
            AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "operational_event": True,
                    "zone": zone,
                    "used": used,
                    "limit": limit,
                },
            ),
        )
        cache.set(key, 1, _ALERT_TTL_SECONDS)


def _attempt_id(certificate: AccountNameCertificate) -> str:
    """The vault identifier of one issuance's material, fixed by when its attempt reserved its slot."""
    reserved = certificate.attempt_reserved_at
    stamp = reserved.strftime("%Y%m%dT%H%M%S%f") if reserved else "none"
    return f"{certificate.hostname.fqdn}@{stamp}"


def _run_order(certificate_id: UUID) -> IssuanceOutcome:
    """Place or resume the order, publish its challenge values, wait for the certificate and put it in force."""
    certificate = AccountNameCertificate.objects.select_related("hostname").get(pk=certificate_id)
    try:
        fullchain, not_after = _exchange(certificate)
    except (AcmeError, _Defer, _KeyUnavailableError) as exc:
        return _after_exchange_error(certificate_id, exc)

    attempt = _attempt_id(certificate)
    stored = _vault_store(CERT_TYPE, attempt, fullchain, days=_CERT_DAYS)
    if stored.is_err():
        return _defer(certificate_id, None, stored.unwrap_err())
    with transaction.atomic():
        row = AccountNameCertificate.objects.select_for_update().get(pk=certificate_id)
        row.current_certificate_ref = f"{CERT_TYPE}:{attempt}"
        row.current_key_ref = f"{CERT_KEY_TYPE}:{attempt}"
        row.current_not_after = not_after
        row.attempt_status = AccountNameCertificate.AttemptStatus.ISSUED
        row.attempt_order_url = ""
        row.retry_after = None
        row.save()
    logger.info(
        "✅ [AccountCert] Certificate for %s issued, valid until %s", certificate.hostname.fqdn, not_after.date()
    )
    return IssuanceOutcome(IssuanceStatus.ISSUED)


def _after_exchange_error(certificate_id: UUID, exc: Exception) -> IssuanceOutcome:
    """A rejected order ends the attempt; anything else keeps it (and its slot and order) for a later try."""
    if isinstance(exc, AcmeOrderFailed):
        return _fail(certificate_id, str(exc))
    if isinstance(exc, AcmeRateLimited):
        return _defer(certificate_id, exc.retry_after_seconds, f"rate limited: {exc}")
    if isinstance(exc, (AcmeError, _Defer)):
        seconds = exc.retry_after_seconds if isinstance(exc, AcmeError) else exc.seconds
        return _defer(certificate_id, seconds, str(exc))
    return _defer(certificate_id, None, str(exc))


def _exchange(certificate: AccountNameCertificate) -> tuple[str, datetime]:
    """The ACME exchange for one attempt: the full chain and its expiry. Challenge records never outlive it."""
    fqdn = certificate.hostname.fqdn
    attempt = _attempt_id(certificate)
    zone_id = config.account_zone_id()
    gateway = get_dns_gateway(DNS_PROVIDER, config.account_zone_api_token())
    key_pem = _load_or_create_key(CERT_KEY_TYPE, attempt, days=_CERT_DAYS)
    account_key_pem = _load_or_create_key(ACCOUNT_KEY_TYPE, fqdn, days=_ACCOUNT_KEY_DAYS)
    csr_pem = _csr(key_pem, fqdn)
    acme = build_acme_client(config.acme_directory_url(), account_key_pem)
    if certificate.attempt_order_url:
        order = acme.load_order(certificate.attempt_order_url, csr_pem)
    else:
        order = acme.place_order(csr_pem)
        AccountNameCertificate.objects.filter(pk=certificate.pk).update(attempt_order_url=order.url)
    tag = order_owner_tag(order.url)
    try:
        _publish_challenges(gateway, zone_id, order, tag)
        time.sleep(DNS_SETTLE_SECONDS)
        fullchain = acme.complete(order).decode()
        return fullchain, _leaf_not_after(fullchain)
    finally:
        _clean_challenges(gateway, zone_id, tag)


def _publish_challenges(gateway: DnsProviderGateway, zone_id: str, order: AcmeOrder, tag: str) -> None:
    """Publish every challenge value, several per name where the order has several, owned by the order."""
    by_name: dict[str, list[str]] = {}
    for challenge in order.challenges:
        by_name.setdefault(challenge.name, []).append(challenge.value)
    for name, values in by_name.items():
        outcome = gateway.reconcile_txt_values(zone_id, name, values, tag)
        if outcome.error:
            raise _Defer(outcome.retry_after_seconds or TRANSIENT_BACKOFF.total_seconds(), outcome.error)


def _clean_challenges(gateway: DnsProviderGateway, zone_id: str, tag: str) -> None:
    result = gateway.delete_owned_records(zone_id, tag)
    if result.is_err():
        # The sweep reclaims what this leaves behind.
        logger.warning("⚠️ [AccountCert] Challenge cleanup for %s failed: %s", tag, result.unwrap_err())


def _defer(certificate_id: UUID, seconds: float | None, detail: str) -> IssuanceOutcome:
    """Keep the attempt (`ordering`, with its reservation and order) and ask again after a delay."""
    delay = timedelta(seconds=seconds) if seconds else TRANSIENT_BACKOFF
    retry_after = timezone.now() + delay
    AccountNameCertificate.objects.filter(pk=certificate_id).update(retry_after=retry_after)
    logger.warning("⚠️ [AccountCert] Attempt %s deferred until %s: %s", certificate_id, retry_after, detail)
    return IssuanceOutcome(IssuanceStatus.DEFERRED, detail, retry_after=retry_after)


def _fail(certificate_id: UUID, detail: str) -> IssuanceOutcome:
    """End the attempt. The current certificate, if there is one, stays in force."""
    retry_after = timezone.now() + FAILED_BACKOFF
    with transaction.atomic():
        row = AccountNameCertificate.objects.select_for_update().get(pk=certificate_id)
        row.attempt_status = AccountNameCertificate.AttemptStatus.FAILED
        row.attempt_order_url = ""
        row.retry_after = retry_after
        row.save()
    logger.error("🔥 [AccountCert] Order for certificate %s failed: %s", certificate_id, detail)
    return IssuanceOutcome(IssuanceStatus.FAILED, detail, retry_after=retry_after)


# =============================================================================
# Keys, CSR, vault
# =============================================================================


class _KeyUnavailableError(Exception):
    """The vault would not store or return a key."""


def _vault_store(service_type: str, identifier: str, secret: str, *, days: int) -> Result[None, str]:
    stored = get_credential_vault().store_credential(
        CredentialData(
            service_type=service_type,
            service_identifier=identifier,
            username="acme",
            password=secret,
            expires_in_days=days,
            user=None,
            reason=_VAULT_REASON,
        )
    )
    return Err(stored.unwrap_err()) if stored.is_err() else Ok(None)


def vault_secret(ref: str) -> str | None:
    """The secret behind a `<service_type>:<identifier>` vault reference, or None when it cannot be read."""
    service_type, _sep, identifier = ref.partition(":")
    result = get_credential_vault().get_credential(service_type, identifier, user=None, reason=_VAULT_REASON)
    return None if result.is_err() else result.unwrap()[1]


def _load_or_create_key(service_type: str, identifier: str, *, days: int) -> str:
    existing = vault_secret(f"{service_type}:{identifier}")
    if existing:
        return existing
    pem = (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        .decode()
    )
    stored = _vault_store(service_type, identifier, pem, days=days)
    if stored.is_err():
        raise _KeyUnavailableError(f"vault refused a key: {stored.unwrap_err()}")
    return pem


def _csr(key_pem: str, fqdn: str) -> bytes:
    key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise _KeyUnavailableError("the stored certificate key is not an EC key")
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM)


def _leaf_not_after(fullchain_pem: str) -> datetime:
    blocks = _PEM_BLOCK.findall(fullchain_pem)
    if not blocks:
        raise AcmeOrderFailed("the server returned no certificate")
    return x509.load_pem_x509_certificate(blocks[0].encode()).not_valid_after_utc


def split_chain(fullchain_pem: str) -> tuple[str, str]:
    """The leaf certificate and the rest of the chain, each as PEM (the rest may be empty)."""
    blocks = _PEM_BLOCK.findall(fullchain_pem)
    if not blocks:
        return "", ""
    return blocks[0] + "\n", "\n".join(blocks[1:]) + ("\n" if len(blocks) > 1 else "")


# =============================================================================
# Install on a node
# =============================================================================


def install_current_certificate(hostname: AccountHostname, server: VirtualminServer) -> Result[None, str]:
    """Install the certificate in force on ``server`` and record it. The PEMs travel only in the playbook's vars file."""
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # Circular

    certificate = AccountNameCertificate.objects.filter(hostname=hostname).first()
    if certificate is None or not certificate.has_valid_material() or certificate.current_not_after is None:
        return Err("The name has no valid certificate to install.")
    deployment = getattr(server, "node_deployment", None)
    if deployment is None:
        return Err(f"Server {server.hostname} is manually registered (no managed node deployment); cannot install.")
    fullchain = vault_secret(certificate.current_certificate_ref)
    key_pem = vault_secret(certificate.current_key_ref)
    if not fullchain or not key_pem:
        return Err("The certificate or its key could not be read from the vault.")
    leaf, chain = split_chain(fullchain)
    variables: dict[str, Any] = {
        "account_name": hostname.fqdn,
        "certificate_pem": leaf,
        "chain_pem": chain,
        "private_key_pem": key_pem,
    }
    result = AnsibleService().run_playbook(
        deployment, INSTALL_PLAYBOOK, variables, timeout_seconds=INSTALL_TIMEOUT_SECONDS
    )
    if result.is_err():
        return Err(f"Certificate install failed: {result.unwrap_err()}")
    if not result.unwrap().success:
        return Err("The certificate install playbook failed on the node.")
    record_installation(
        hostname, server, certificate_ref=certificate.current_certificate_ref, not_after=certificate.current_not_after
    )
    logger.info("✅ [AccountCert] Certificate for %s installed on %s", hostname.fqdn, server.hostname)
    return Ok(None)


# =============================================================================
# Daily renewal and stale-challenge sweep
# =============================================================================


def renew_due_certificates() -> dict[str, int]:
    """Daily: renew certificates with under 30 days left, resume stalled attempts, reinstall stale installs, sweep DNS.

    Renewals take no budget. A renewed certificate is installed on every node that holds an older one, so it
    does not wait for the next sync.
    """
    counts = {"renewed": 0, "resumed": 0, "deferred": 0, "failed": 0, "installed": 0, "install_failed": 0, "swept": 0}
    now = timezone.now()
    due = AccountNameCertificate.objects.filter(
        hostname__retired_at__isnull=True, current_certificate_ref__gt="", current_not_after__lt=now + RENEW_WITHIN
    ).select_related("hostname")
    for certificate in due:
        _count(counts, request_certificate(certificate.hostname, scheduled_renewal=True), "renewed")
    resumable = AccountNameCertificate.objects.filter(
        hostname__retired_at__isnull=True, attempt_status=AccountNameCertificate.AttemptStatus.ORDERING
    ).select_related("hostname")
    for certificate in resumable:
        _count(counts, request_certificate(certificate.hostname), "resumed")
    _install_stale(counts)
    counts["swept"] = sweep_stale_challenge_records()
    return counts


def _count(counts: dict[str, int], outcome: IssuanceOutcome, issued_key: str) -> None:
    if outcome.status is IssuanceStatus.ISSUED:
        counts[issued_key] += 1
    elif outcome.status is IssuanceStatus.DEFERRED:
        counts["deferred"] += 1
    elif outcome.status in {IssuanceStatus.FAILED, IssuanceStatus.BUDGET_EXHAUSTED}:
        counts["failed"] += 1


def _install_stale(counts: dict[str, int]) -> None:
    """Reinstall the certificate in force wherever a node still holds an older one.

    Only nodes that already have an install record are touched. The first install on a name's intended node
    belongs to `ensure_certificate_on_node`, which the hostname service calls after the node's sub-server
    exists; running it from here would install ahead of that and fail every day until then.
    """
    installs = AccountNameCertificateInstall.objects.filter(
        hostname__retired_at__isnull=True, hostname__certificate__isnull=False
    ).select_related("hostname__certificate", "server")
    for install in installs:
        certificate = install.hostname.certificate
        if not certificate.has_valid_material() or install.certificate_ref == certificate.current_certificate_ref:
            continue
        if install_current_certificate(install.hostname, install.server).is_ok():
            counts["installed"] += 1
        else:
            counts["install_failed"] += 1


def sweep_stale_challenge_records() -> int:
    """Delete challenge TXT records that no running order owns: what a crash between publishing and cleanup left."""
    zone_id, token = config.account_zone_id(), config.account_zone_api_token()
    if not (zone_id and token):
        return 0
    live = frozenset(
        order_owner_tag(url)
        for url in AccountNameCertificate.objects.filter(
            attempt_status=AccountNameCertificate.AttemptStatus.ORDERING, attempt_order_url__gt=""
        ).values_list("attempt_order_url", flat=True)
    )
    gateway = get_dns_gateway(DNS_PROVIDER, token)
    result = gateway.sweep_owned_records(
        zone_id, ACME_OWNER_PREFIX, keep_owner_tags=live, min_age_seconds=SWEEP_MIN_AGE_SECONDS
    )
    if result.is_err():
        logger.warning("⚠️ [AccountCert] Challenge sweep failed: %s", result.unwrap_err())
        return 0
    return len(result.unwrap())
