"""Bounded native mail observations. Worker-only node calls never enable a customer domain."""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from apps.common.types import Err, Ok, Result, Retriability, retriability_of

if TYPE_CHECKING:
    from apps.infrastructure.ansible_service import AnsibleService

    from .virtualmin_models import VirtualminAccount, VirtualminServer

MAIL_PLAYBOOK = "virtualmin_mail.yml"
MAIL_PROFILE = "debian12-dovecot23"
MAIL_PROFILES = frozenset({MAIL_PROFILE, "ubuntu2604-dovecot24"})
MAIL_INSPECT_TIMEOUT_SECONDS = 120
MAIL_SETUP_TIMEOUT_SECONDS = 900
MAIL_CERTIFICATE_TIMEOUT_SECONDS = 900
MAIL_BUNDLE_TIMEOUT_SECONDS = 300
MAX_MAIL_USERS = 1000
MAX_RESERVED_ACCOUNT_ZONES = 64
MAX_MAIL_ALIASES = 2000
MAX_ALIAS_TARGETS = 16
MAX_RECEIPT_BYTES = 256 * 1024
MIN_PRINTABLE_CODEPOINT = 32
MIN_HOSTNAME_LABELS = 2
MIN_OWNED_UID = 1000
MAX_OWNED_UID = 2**31
MIN_DKIM_RSA_BITS = 2048
MAIL_SERVICES = frozenset({"imap", "pop3", "submission", "smtp"})
PUBLIC_MAIL_PORTS = frozenset({25, 465, 993, 995})
_RESULT = re.compile(r"MAIL_RESULT=([A-Za-z0-9+/=]+)")
_SAFE_ERRORS = frozenset(
    {
        "mail_profile_unsupported",
        "mail_unmanaged_mta",
        "mail_queue_uncertain",
        "mail_node_identity_mismatch",
        "mail_domain_identity_mismatch",
        "mail_custom_configuration_refused",
        "mail_setup_incomplete",
        "mail_native_inspection_failed",
        "mail_operation_busy",
        "mail_firewall_unavailable",
        "mail_node_certificate_unproven",
        "mail_setup_review_required",
        "mail_unrelated_configuration_changed",
        "mail_node_operation_in_progress",
        "mail_node_services_unavailable",
        "mail_node_bundle_upgrade_required",
        "mail_node_bundle_incompatible",
    }
)
_PERMANENT_ERRORS = frozenset(
    {
        "mail_profile_unsupported",
        "mail_unmanaged_mta",
        "mail_node_identity_mismatch",
        "mail_domain_identity_mismatch",
        "mail_setup_review_required",
        "mail_unrelated_configuration_changed",
        "mail_node_bundle_upgrade_required",
        "mail_node_bundle_incompatible",
    }
)
# The node refuses these before any write; the caller replays its own persisted operation id.
_RETRIABLE_ERRORS = frozenset({"mail_node_operation_in_progress", "mail_node_services_unavailable"})
# An unproven candidate is refused before staging only at these (action, stage) points.
_CANDIDATE_STAGES = frozenset({("setup", "node_certificate"), ("reconcile_node_certificate", "certificate_candidate")})


@dataclass(frozen=True)
class MailNodeObservation:
    node_hostname: str
    profile: str
    configured: bool
    default_mail_off: bool
    public_ports: tuple[int, ...]


@dataclass(frozen=True)
class MailNodeCertificateObservation:
    node_hostname: str
    profile: str
    configured: bool
    default_mail_off: bool
    public_ports: tuple[int, ...]
    outcome: Literal["unchanged", "replaced", "retained_previous", "recovered"]
    certificate_sha256: str
    not_after: datetime
    pending_code: str


@dataclass(frozen=True)
class MailNodeBundleObservation:
    node_hostname: str
    profile: str
    outcome: Literal["upgraded", "unchanged"]
    bundle_sha256: str


@dataclass(frozen=True)
class MailSubmitterObservation:
    node_hostname: str
    profile: str
    configured: bool
    default_mail_off: bool
    maps_sha256: str


@dataclass(frozen=True)
class MailUserObservation:
    login: str
    email: str
    uid: int
    enabled: bool


@dataclass(frozen=True)
class MailAliasObservation:
    address: str
    targets: tuple[str, ...]


@dataclass(frozen=True)
class MailDkimObservation:
    selector: str
    record_name: str
    record_value: str


@dataclass(frozen=True)
class MailCertificateObservation:
    service: str
    hostname: str
    sha256: str
    not_after: datetime


@dataclass(frozen=True)
class MailDomainObservation:
    node_hostname: str
    domain: str
    domain_id: str
    owner: str
    owner_uid: int
    mail_enabled: bool
    users: tuple[MailUserObservation, ...]
    aliases: tuple[MailAliasObservation, ...]
    dkim: MailDkimObservation | None
    certificates: tuple[MailCertificateObservation, ...]
    ready: bool


def _runner() -> AnsibleService:
    from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415  # ADR-0007

    return AnsibleService()


def _object(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("object required")
    return cast(dict[str, Any], value)


def _text(value: object, maximum: int = 253) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or value != value.strip()
        or any(ord(c) < MIN_PRINTABLE_CODEPOINT for c in value)
    ):
        raise ValueError("invalid bounded text")
    return value


def _hostname(value: object) -> str:
    name = _text(value).lower().rstrip(".")
    labels = name.split(".")
    if len(labels) < MIN_HOSTNAME_LABELS or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
    ):
        raise ValueError("invalid hostname")
    return name


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError("boolean required")
    return value


def _uid(value: object) -> int:
    if type(value) is not int or not MIN_OWNED_UID <= value < MAX_OWNED_UID:
        raise ValueError("invalid owned Unix identity")
    return value


def _login(value: object) -> str:
    login = _text(value, 128)
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}", login) or login == "root":
        raise ValueError("invalid native login")
    return login


def _address(value: object, *, domain: str | None = None, catchall: bool = False) -> str:
    address = _text(value, 254)
    if address.count("@") != 1:
        raise ValueError("invalid email")
    local, raw_domain = address.split("@")
    if not (catchall and not local) and not re.fullmatch(r"[A-Za-z0-9_.+%=-]{1,64}", local):
        raise ValueError("unsupported native address")
    owner = _hostname(raw_domain)
    if domain is not None and owner != domain:
        raise ValueError("foreign email domain")
    return local + "@" + owner


def _rows(value: object, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError("invalid inventory")
    return value


def _profile(payload: dict[str, Any]) -> None:
    if payload.get("profile") not in MAIL_PROFILES:
        raise ValueError("mail_profile_unsupported")


def _read_receipt(stdout: str, identity: str, action: str, hostname: str) -> Result[dict[str, Any], str]:
    try:
        if len(stdout) > 2 * MAX_RECEIPT_BYTES:
            raise ValueError("oversized receipt")
        encoded = set(_RESULT.findall(stdout))
        if len(encoded) != 1:
            raise ValueError("missing or conflicting receipt")
        wire = base64.b64decode(encoded.pop(), validate=True)
        if len(wire) > MAX_RECEIPT_BYTES:
            raise ValueError("oversized receipt")
        envelope = _object(json.loads(wire))
        if (type(envelope.get("version")), envelope.get("version")) != (int, 1):
            raise ValueError("unsupported receipt")
        if (envelope.get("identity"), envelope.get("action"), envelope.get("node_hostname")) != (
            identity,
            action,
            hostname,
        ):
            raise ValueError("foreign receipt")
        payload = _object(envelope.get("payload"))
        error = payload.get("error")
        if error is not None:
            code = error if error in _SAFE_ERRORS else "mail_native_inspection_failed"
            if code in _RETRIABLE_ERRORS or (
                code == "mail_node_certificate_unproven" and (action, payload.get("stage")) in _CANDIDATE_STAGES
            ):
                return Err(code, retriability=Retriability.RETRIABLE)
            return Err(
                code, retriability=Retriability.NOT_RETRIABLE if code in _PERMANENT_ERRORS else Retriability.UNKNOWN
            )
        if _hostname(payload.get("node_hostname")) != hostname:
            raise ValueError("foreign node")
        _profile(payload)
        return Ok(payload)
    except ValueError as error:
        if str(error) == "mail_profile_unsupported":
            return Err("mail_profile_unsupported", retriability=Retriability.NOT_RETRIABLE)
        return Err("mail_native_result_uncertain", retriability=Retriability.UNKNOWN)
    except (TypeError, KeyError, binascii.Error):
        return Err("mail_native_result_uncertain", retriability=Retriability.UNKNOWN)


def _run(
    server: VirtualminServer, action: str, extra: dict[str, str] | None = None, *, operation_id: UUID | None = None
) -> Result[dict[str, Any], str]:
    deployment = getattr(server, "node_deployment", None)
    if deployment is None:
        return Err("mail_managed_deployment_required", retriability=Retriability.NOT_RETRIABLE)
    try:
        hostname = _hostname(server.hostname)
    except ValueError:
        return Err("mail_node_identity_mismatch", retriability=Retriability.NOT_RETRIABLE)
    identity = str(uuid4() if operation_id is None else operation_id)
    try:
        if str(UUID(identity)) != identity:
            raise ValueError("noncanonical operation")
    except (ValueError, TypeError):
        return Err("mail_native_result_uncertain", retriability=Retriability.NOT_RETRIABLE)
    variables = {
        "mail_operation_id": identity,
        "mail_action": action,
        "mail_expected_node_hostname": hostname,
        **(extra or {}),
    }
    result = _runner().run_playbook(
        deployment,
        MAIL_PLAYBOOK,
        variables,
        timeout_seconds={
            "setup": MAIL_SETUP_TIMEOUT_SECONDS,
            "reconcile_node_certificate": MAIL_CERTIFICATE_TIMEOUT_SECONDS,
            "upgrade_bundle": MAIL_BUNDLE_TIMEOUT_SECONDS,
        }.get(action, MAIL_INSPECT_TIMEOUT_SECONDS),
    )
    if result.is_err() or not result.unwrap().success:
        return Err("mail_native_execution_failed", retriability=Retriability.UNKNOWN)
    return _read_receipt(result.unwrap().stdout, identity, action, hostname)


def _node_observation(data: dict[str, Any]) -> MailNodeObservation:
    configured, default_off = _boolean(data.get("configured")), _boolean(data.get("default_mail_off"))
    raw_ports = _rows(data.get("public_ports"), len(PUBLIC_MAIL_PORTS))
    if any(type(port) is not int or port not in PUBLIC_MAIL_PORTS for port in raw_ports):
        raise ValueError("unsafe listener")
    ports = tuple(sorted(set(raw_ports)))
    if len(ports) != len(raw_ports) or (configured and (not default_off or set(ports) != PUBLIC_MAIL_PORTS)):
        raise ValueError("unsafe node readiness")
    return MailNodeObservation(_hostname(data["node_hostname"]), _text(data["profile"]), configured, default_off, ports)


def _node(server: VirtualminServer, action: str) -> Result[MailNodeObservation, str]:
    try:
        zones = _mail_zones() if action == "setup" else ()
        extra = {"mail_reserved_account_zones": json.dumps(zones), "mail_account_zone": zones[0]} if zones else {}
    except (ValueError, TypeError):
        return Err("mail_reserved_zones_unproven", retriability=Retriability.NOT_RETRIABLE)
    response = _run(server, action, extra)
    if response.is_err():
        return Err(response.unwrap_err(), retriability=retriability_of(response))
    try:
        observed = _node_observation(response.unwrap())
        if action == "setup" and not observed.configured:
            raise ValueError("incomplete setup")
        return Ok(observed)
    except (ValueError, TypeError, KeyError):
        return Err("mail_native_result_uncertain", retriability=Retriability.UNKNOWN)


def setup_mail_capability(server: VirtualminServer) -> Result[MailNodeObservation, str]:
    """Install only a supported, eligible mail stack; never opt any domain into hosted mail."""
    return _node(server, "setup")


def inspect_mail_node(server: VirtualminServer) -> Result[MailNodeObservation, str]:
    """Observe the supported node profile independently of customer-domain readiness."""
    return _node(server, "inspect_node")


def reconcile_mail_node_certificate(
    server: VirtualminServer, *, operation_id: UUID
) -> Result[MailNodeCertificateObservation, str]:
    """Reconcile or recover only verified node TLS; a completed identity cannot reinstall an old certificate.

    Persist ``operation_id`` before dispatch and replay that same id whenever the result is UNKNOWN.
    """
    response = _run(server, "reconcile_node_certificate", operation_id=operation_id)
    if response.is_err():
        return Err(response.unwrap_err(), retriability=retriability_of(response))
    try:
        data = response.unwrap()
        observed = _node_observation(data)
        outcome = _text(data.get("outcome"), 32)
        digest = _text(data.get("certificate_sha256"), 64)
        expiry = datetime.fromisoformat(_text(data.get("not_after"), 40))
        pending = _text(data.get("pending_code"), 64)
        if not observed.configured or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("unproven node TLS")
        if expiry.tzinfo is None or expiry <= datetime.now(UTC):
            raise ValueError("expired node TLS")
        if (outcome, pending) not in {
            ("unchanged", ""),
            ("replaced", ""),
            ("recovered", ""),
            ("retained_previous", "mail_node_certificate_unproven"),
        }:
            raise ValueError("unproven certificate outcome")
        return Ok(
            MailNodeCertificateObservation(
                observed.node_hostname,
                observed.profile,
                True,
                True,
                observed.public_ports,
                cast(Literal["unchanged", "replaced", "retained_previous", "recovered"], outcome),
                digest,
                expiry.astimezone(UTC),
                pending,
            )
        )
    except (ValueError, TypeError, KeyError):
        return Err("mail_native_result_uncertain", retriability=Retriability.UNKNOWN)


def upgrade_mail_node_bundle(server: VirtualminServer, *, operation_id: UUID) -> Result[MailNodeBundleObservation, str]:
    """Upgrade only the installed native helpers and unit drop-ins of a ready node.

    Persist ``operation_id`` before dispatch and replay that same id whenever the result is UNKNOWN.
    """
    response = _run(server, "upgrade_bundle", operation_id=operation_id)
    if response.is_err():
        return Err(response.unwrap_err(), retriability=retriability_of(response))
    try:
        data = response.unwrap()
        outcome = _text(data.get("outcome"), 16)
        digest = _text(data.get("bundle_sha256"), 64)
        if outcome not in {"upgraded", "unchanged"} or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("unproven bundle outcome")
        return Ok(
            MailNodeBundleObservation(
                _hostname(data["node_hostname"]),
                _text(data["profile"]),
                cast(Literal["upgraded", "unchanged"], outcome),
                digest,
            )
        )
    except (ValueError, TypeError, KeyError):
        return Err("mail_native_result_uncertain", retriability=Retriability.UNKNOWN)


def _mail_zones() -> tuple[str, ...]:
    """Worker-only namespace policy, including retired legacy account connection zones."""
    from .account_hostname_config import account_zone  # noqa: PLC0415  # ADR-0007
    from .account_hostname_models import AccountHostname  # noqa: PLC0415  # ADR-0007

    persisted = AccountHostname.objects.order_by("zone").values_list("zone", flat=True).distinct()
    current = _hostname(account_zone())
    zones = {current}
    zones.update(_hostname(value) for value in persisted[: MAX_RESERVED_ACCOUNT_ZONES + 1])
    if len(zones) > MAX_RESERVED_ACCOUNT_ZONES:
        raise ValueError("reserved zone inventory exceeds bound")
    return (current, *sorted(zones - {current}))


def reconcile_mail_submitters(server: VirtualminServer) -> Result[MailSubmitterObservation, str]:
    """Refresh native UID authority without accepting caller-provided sender identities."""
    try:
        zones = _mail_zones()
    except (ValueError, TypeError):
        return Err("mail_reserved_zones_unproven", retriability=Retriability.NOT_RETRIABLE)
    response = _run(
        server,
        "reconcile_submitters",
        {"mail_reserved_account_zones": json.dumps(zones), "mail_account_zone": zones[0]},
    )
    if response.is_err():
        return Err(response.unwrap_err(), retriability=retriability_of(response))
    try:
        payload = response.unwrap()
        configured, default_off = _boolean(payload.get("configured")), _boolean(payload.get("default_mail_off"))
        digest = _text(payload.get("maps_sha256"), 64)
        if (configured and (not default_off or not re.fullmatch(r"[a-f0-9]{64}", digest))) or (
            not configured and digest
        ):
            raise ValueError("unproven native authority")
        return Ok(
            MailSubmitterObservation(
                _hostname(payload["node_hostname"]), _text(payload["profile"]), configured, default_off, digest
            )
        )
    except (ValueError, TypeError, KeyError):
        return Err("mail_native_result_uncertain", retriability=Retriability.UNKNOWN)


def _users(data: object, domain: str) -> tuple[MailUserObservation, ...]:
    users = []
    for item in _rows(data, MAX_MAIL_USERS):
        row = _object(item)
        users.append(
            MailUserObservation(
                _login(row.get("login")),
                _address(row.get("email"), domain=domain),
                _uid(row.get("uid")),
                _boolean(row.get("enabled")),
            )
        )
    for values in ({user.login for user in users}, {user.email for user in users}, {user.uid for user in users}):
        if len(values) != len(users):
            raise ValueError("conflicting native mailbox identity")
    return tuple(users)


def _aliases(data: object, domain: str) -> tuple[MailAliasObservation, ...]:
    aliases = []
    for item in _rows(data, MAX_MAIL_ALIASES):
        row = _object(item)
        targets = tuple(_address(value) for value in _rows(row.get("targets"), MAX_ALIAS_TARGETS))
        if not targets:
            raise ValueError("alias has no public targets")
        aliases.append(MailAliasObservation(_address(row.get("address"), domain=domain, catchall=True), targets))
    if len({alias.address for alias in aliases}) != len(aliases):
        raise ValueError("duplicate native alias")
    return tuple(aliases)


def _dkim(data: object, domain: str) -> MailDkimObservation | None:
    if data is None:
        return None
    row = _object(data)
    selector = _text(row.get("selector"), 63)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", selector):
        raise ValueError("invalid DKIM selector")
    name = _text(row.get("record_name"))
    if name != selector + "._domainkey." + domain:
        raise ValueError("foreign DKIM record")
    value = _text(row.get("record_value"), 4096)
    prefix = "v=DKIM1; k=rsa; p="
    if not value.startswith(prefix):
        raise ValueError("invalid public DKIM record")
    key = serialization.load_der_public_key(base64.b64decode(value[len(prefix) :], validate=True))
    if not isinstance(key, RSAPublicKey) or key.key_size < MIN_DKIM_RSA_BITS:
        raise ValueError("unsupported DKIM key")
    return MailDkimObservation(selector, name, value)


def _certificates(data: object, account_name: str) -> tuple[MailCertificateObservation, ...]:
    certificates = []
    for item in _rows(data, len(MAIL_SERVICES)):
        row = _object(item)
        service = _text(row.get("service"), 16)
        hostname = _hostname(row.get("hostname"))
        fingerprint = _text(row.get("sha256"), 64)
        expiry = datetime.fromisoformat(_text(row.get("not_after"), 40))
        if service not in MAIL_SERVICES or hostname != account_name or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
            raise ValueError("foreign or invalid certificate")
        if expiry.tzinfo is None:
            raise ValueError("undated certificate")
        certificates.append(MailCertificateObservation(service, hostname, fingerprint, expiry.astimezone(UTC)))
    if len({certificate.service for certificate in certificates}) != len(certificates):
        raise ValueError("duplicate certificate service")
    return tuple(certificates)


def _domain(payload: dict[str, Any], account: VirtualminAccount, account_name: str) -> MailDomainObservation:
    domain, owner = _hostname(payload.get("domain")), _login(payload.get("owner"))
    domain_id = _text(payload.get("domain_id"), 20)
    if (domain, owner) != (_hostname(account.domain), account.virtualmin_username) or not re.fullmatch(
        r"[1-9][0-9]{0,19}", domain_id
    ):
        raise ValueError("foreign domain identity")
    enabled = _boolean(payload.get("mail_enabled"))
    users, aliases = _users(payload.get("users"), domain), _aliases(payload.get("aliases"), domain)
    certificates = _certificates(payload.get("certificates"), account_name)
    ready = (
        _boolean(payload.get("ready"))
        and enabled
        and bool(account_name)
        and any(user.enabled for user in users)
        and {certificate.service for certificate in certificates} == MAIL_SERVICES
        and all(certificate.not_after > datetime.now(UTC) for certificate in certificates)
    )
    return MailDomainObservation(
        _hostname(payload.get("node_hostname")),
        domain,
        domain_id,
        owner,
        _uid(payload.get("owner_uid")),
        enabled,
        users,
        aliases,
        _dkim(payload.get("dkim"), domain),
        certificates,
        ready,
    )


def inspect_mail_domain(account: VirtualminAccount) -> Result[MailDomainObservation, str]:
    """Project bounded public native fields, including a mail-off domain before enrollment."""
    try:
        domain, owner = _hostname(account.domain), _login(account.virtualmin_username)
        hostname = getattr(account, "account_hostname", None)
        account_name = _hostname(hostname.fqdn) if hostname is not None and hostname.retired_at is None else ""
    except (ValueError, AttributeError):
        return Err("mail_domain_identity_mismatch", retriability=Retriability.NOT_RETRIABLE)
    result = _run(
        account.server,
        "inspect_domain",
        {"mail_domain": domain, "mail_expected_owner": owner, "mail_account_hostname": account_name},
    )
    if result.is_err():
        return Err(result.unwrap_err(), retriability=retriability_of(result))
    try:
        return Ok(_domain(result.unwrap(), account, account_name))
    except (ValueError, TypeError, KeyError, binascii.Error):
        return Err("mail_native_result_uncertain", retriability=Retriability.UNKNOWN)
