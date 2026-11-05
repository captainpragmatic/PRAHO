"""Disposable commercial history and a second public deployment under ONE native vault.

This module is never imported by production workers. Initial history is synthetic;
only subsequent public operations and independently verified native evidence count
as acceptance. No method changes the clock or edits an existing commercial period.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dateutil.relativedelta import relativedelta
from django.db import transaction
from django.utils import timezone

from .native_lab import PRIVATE_MODE, NativeAuthority, native_authority, native_driver, native_run_lock, write_private

if TYPE_CHECKING:
    from apps.billing.subscription_models import Subscription
    from apps.products.models import Product
    from apps.provisioning.service_models import Service

    from .models import NodeDeployment

MIN_BOUNDARY_MINUTES = 60
MAX_BOUNDARY_MINUTES = 90


def initialize_commercial_subscription(service: Service, product: Product, boundary: datetime) -> Subscription:
    """Initialize NEW synthetic history, then let the real renewal services settle it.

    Public activate() intentionally resets dates to now. The existing pending→active
    FSM transition is used before the first INSERT instead; no saved period or
    protected state is overwritten. This is fixture construction, not a sale.
    """
    from apps.billing.recurring_billing import fixed_renewal_schedule  # noqa: PLC0415
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.provisioning.service_models import Service  # noqa: PLC0415

    now = timezone.now()
    if timezone.is_naive(boundary) or not now + timedelta(minutes=59) < boundary <= now + timedelta(minutes=90):
        raise ValueError("A new synthetic monthly boundary must be 60-90 minutes ahead")
    with transaction.atomic():
        Customer.all_objects.select_for_update(of=("self",), no_key=True).get(pk=service.customer_id)
        if Subscription.objects.filter(service_id=service.pk).exists():
            raise ValueError("Never rewrite an existing subscription for acceptance setup")
        locked = Service.objects.select_for_update(of=("self",), no_key=True).get(pk=service.pk)
        if locked.customer_id != service.customer_id or product.default_service_plan_id != locked.service_plan_id:
            raise ValueError("The original service owner and exact base product are required")
        initial_end = boundary - relativedelta(months=1)
        proforma_at, charge_at = fixed_renewal_schedule(initial_end)
        subscription = Subscription(
            customer_id=locked.customer_id,
            service=locked,
            product=product,
            currency_id=locked.currency_id,
            quantity=1,
            billing_cycle="monthly",
            unit_price_cents=int(locked.price * 100),
            current_period_start=initial_end - relativedelta(months=1),
            current_period_end=initial_end,
            billing_anchor_day=boundary.day,
            next_billing_date=proforma_at,
            next_proforma_at=proforma_at,
            next_charge_at=charge_at,
            auto_payment_enabled=False,
            meta={"source": "native_acceptance_initial_history", "boundary": boundary.isoformat()},
        )
        subscription._activate_now()
        subscription.save()
        return subscription


def create_commercial_owner(email: str, password: str) -> Any:
    """A NEW fixture owner is compatible with the production UI password policy."""
    from django.contrib.auth.hashers import PBKDF2PasswordHasher  # noqa: PLC0415

    from apps.users.models import User  # noqa: PLC0415

    if User.objects.filter(email=email).exists():
        raise ValueError("Never replace an existing owner's password for acceptance setup")
    hasher = PBKDF2PasswordHasher()
    return User.objects.create(
        email=User.objects.normalize_email(email),
        staff_role="",
        is_staff=False,
        is_superuser=False,
        password=hasher.encode(password, hasher.salt()),
    )


def create_commercial_staff(run: str, password: str) -> Any:
    """Create a NEW staff canary without changing the deployment actor's credentials."""
    from django.contrib.auth.hashers import PBKDF2PasswordHasher  # noqa: PLC0415
    from django.contrib.auth.models import Permission  # noqa: PLC0415
    from django.contrib.contenttypes.models import ContentType  # noqa: PLC0415

    from apps.users.models import User  # noqa: PLC0415

    from .models import NodeDeployment  # noqa: PLC0415

    email = "native-commercial-staff-" + str(UUID(run)) + "@example.invalid"
    if User.objects.filter(email=email).exists():
        raise ValueError("Never replace an existing staff identity, role or password for acceptance")
    hasher = PBKDF2PasswordHasher()
    staff = User.objects.create(
        email=email,
        staff_role="admin",
        is_staff=True,
        is_superuser=False,
        password=hasher.encode(password, hasher.salt()),
    )
    content_type = ContentType.objects.get_for_model(NodeDeployment)
    for code in ("deploy_nodes", "destroy_nodes"):
        permission, _created = Permission.objects.get_or_create(
            content_type=content_type, codename=code, defaults={"name": "Native acceptance " + code.replace("_", " ")}
        )
        staff.user_permissions.add(permission)
    return staff


def _staff_binding(authority: NativeAuthority, primary: NodeDeployment, staff_id: int) -> dict[str, Any]:
    from .native_workflow import _database_identity  # noqa: PLC0415

    return {
        "schema": 1,
        "run": authority.manifest["run"],
        "database": _database_identity(),
        "actor_id": primary.initiated_by_id,
        "user_id": staff_id,
        "email": "native-commercial-staff-" + authority.manifest["run"] + "@example.invalid",
    }


def _admitted_staff(authority: NativeAuthority, primary: NodeDeployment) -> Any:
    from django.contrib.auth.hashers import PBKDF2PasswordHasher  # noqa: PLC0415

    from apps.users.models import User  # noqa: PLC0415

    from .permissions import can_deploy_nodes, can_destroy_nodes  # noqa: PLC0415

    intent = primary.logs.filter(phase="native_acceptance_staff").first()
    if intent is None or type(intent.details.get("user_id")) is not int:
        raise ValueError("Run explicit staff-setup before the commercial clock or peer UI operations")
    expected = _staff_binding(authority, primary, intent.details["user_id"])
    staff = User.objects.filter(pk=expected["user_id"], email=expected["email"]).first()
    password = hashlib.sha256(authority.key + b":commercial-staff-v1").hexdigest()
    if (
        intent.details != expected
        or staff is None
        or staff.staff_role != "admin"
        or not staff.is_staff
        or staff.is_superuser
        or not can_deploy_nodes(staff)
        or not can_destroy_nodes(staff)
        or not staff.password.startswith("pbkdf2_sha256$")
        or not PBKDF2PasswordHasher().verify(password, staff.password)
    ):
        raise ValueError("The admitted staff authority changed; never restore its roles, permissions or password")
    write_private(
        authority.path.parent / (authority.manifest["run"] + ".commercial-staff-login.json"),
        json.dumps({"run": authority.manifest["run"], "email": staff.email, "password": password}, sort_keys=True),
    )
    return staff


def setup_staff_fixture(authority: NativeAuthority) -> Any:
    """Bootstrap only the new staff canary before peer UI work and the billing clock."""
    from .models import NodeDeploymentLog  # noqa: PLC0415

    primary = _primary(authority)
    if primary.logs.filter(phase="native_acceptance_staff").exists():
        return _admitted_staff(authority, primary)
    _inventory(primary)
    password = hashlib.sha256(authority.key + b":commercial-staff-v1").hexdigest()
    with transaction.atomic():
        staff = create_commercial_staff(authority.manifest["run"], password)
        NodeDeploymentLog.objects.create(
            deployment=primary,
            level="INFO",
            phase="native_acceptance_staff",
            message="Admitted a new non-superuser UI fixture before commercial setup",
            details=_staff_binding(authority, primary, staff.pk),
        )
        _admitted_staff(authority, primary)
    return staff


def _primary(authority: NativeAuthority) -> NodeDeployment:
    from .native_fresh_workflow import _completed_provenance, _credentials, _fresh_deployment  # noqa: PLC0415

    token, _dns, zone = _credentials()
    deployment = _fresh_deployment(authority, provider_token=token, zone_id=zone)
    _completed_provenance(deployment, token)
    if (
        authority.manifest.get("phase") != "verified"
        or not deployment.logs.filter(phase="native_fresh_verified").exists()
    ):
        raise ValueError("Complete the primary real fresh-deployment/native proof before acceptance setup")
    if (
        deployment.region.provider_region_id != authority.manifest["location"]
        or deployment.node_size.provider_type_id != authority.manifest["server_type"]
    ):
        raise ValueError("The originally approved primary location or node size changed")
    manifest, _live = native_driver().owned_server(authority.path)
    if str(manifest["server_id"]) != deployment.external_node_id or manifest["ipv4"] != deployment.ipv4_address:
        raise ValueError("The primary exact live provider identity changed")
    return deployment


def _inventory(primary: NodeDeployment, peer: NodeDeployment | None = None) -> None:
    from .models import NodeDeployment  # noqa: PLC0415

    allowed = [primary.pk] + ([peer.pk] if peer is not None else [])
    if NodeDeployment.objects.exclude(pk__in=allowed).exists():
        raise ValueError("The isolated acceptance database contains an unapproved third deployment")


def _peer_values(
    authority: NativeAuthority, primary: NodeDeployment, child: NativeAuthority, peer: NodeDeployment
) -> dict[str, Any]:
    from .deployment_lifecycle import provider_token_fingerprint  # noqa: PLC0415
    from .native_fresh_workflow import _credentials  # noqa: PLC0415
    from .native_workflow import _database_identity  # noqa: PLC0415

    token, _dns, zone = _credentials()
    return {
        "schema": 1,
        "parent_run": authority.manifest["run"],
        "parent_deployment_id": primary.pk,
        "run": child.manifest["run"],
        "deployment_id": peer.pk,
        "database": _database_identity(),
        "creator_fingerprint": provider_token_fingerprint(token),
        "zone_id": zone,
        "actor_id": primary.initiated_by_id,
        "fqdn": peer.fqdn,
        "provider_id": primary.provider_id,
        "region_id": primary.region_id,
        "size_id": primary.node_size_id,
        "expires_at": authority.manifest["expires_at"],
        "public_key_digest": hashlib.sha256(child.public_key.encode()).hexdigest(),
    }


def _read_peer(
    authority: NativeAuthority, path: Path, *, cleanup: bool = False
) -> tuple[NativeAuthority, NodeDeployment]:
    from .models import NodeDeployment  # noqa: PLC0415
    from .native_fresh_workflow import _credentials, _fresh_deployment  # noqa: PLC0415

    path = path.absolute()
    if path == authority.path or path.parent != authority.path.parent:
        raise ValueError("A distinct peer manifest in the original private run directory is required")
    child = native_authority(path, cleanup=cleanup)
    token, _dns, zone = _credentials()
    primary = _fresh_deployment(authority, provider_token=token, zone_id=zone)
    peer = NodeDeployment.objects.filter(correlation_id=UUID(child.manifest["run"])).first()
    if peer is None:
        raise ValueError("The exact pre-create peer intent is missing")
    expected = _peer_values(authority, primary, child, peer)
    intent = peer.logs.filter(phase="native_peer_intent").first()
    if (
        child.manifest.get("origin") != "platform_fresh"
        or child.manifest.get("platform_peer") != expected
        or intent is None
        or intent.details != expected
        or peer.initiated_by_id != primary.initiated_by_id
        or peer.provider_id != primary.provider_id
        or peer.region_id != primary.region_id
        or peer.node_size_id != primary.node_size_id
        or peer.dns_zone != primary.dns_zone
        or child.manifest["expires_at"] != authority.manifest["expires_at"]
    ):
        raise ValueError("The original peer creator, database, key, project, DNS or lifetime changed")
    _inventory(primary, peer)
    return child, peer


def prepare_peer_intent(authority: NativeAuthority, path: Path) -> dict[str, Any]:
    """Bind exactly one child before its first provider operation, retaining the primary vault."""
    from .models import NodeDeployment, NodeDeploymentLog  # noqa: PLC0415
    from .native_workflow import _credential  # noqa: PLC0415

    primary = _primary(authority)
    path = path.absolute()
    if path == authority.path or path.parent != authority.path.parent:
        raise ValueError("Put the distinct peer manifest in the primary private run directory")
    if path.exists() or path.is_symlink():
        _recover_peer_publication(authority, primary, path)
        child, peer = _read_peer(authority, path)
        return _peer_values(authority, primary, child, peer)
    _inventory(primary)
    if timezone.now() + timedelta(hours=2) >= datetime.fromisoformat(authority.manifest["expires_at"]):
        raise ValueError("At least two hours of original authority must remain for a new peer")
    with patch_free_environment(authority):
        native_driver().fresh_intent(path)
    child = native_authority(path)
    child.manifest["expires_at"] = authority.manifest["expires_at"]
    with transaction.atomic():
        _inventory(primary)
        peer = NodeDeployment.objects.create(
            provider=primary.provider,
            region=primary.region,
            node_size=primary.node_size,
            panel_type=primary.panel_type,
            environment=primary.environment,
            node_type=primary.node_type,
            node_number=NodeDeployment.get_next_node_number(
                environment=primary.environment,
                node_type=primary.node_type,
                provider=primary.provider,
                region=primary.region,
            ),
            correlation_id=UUID(child.manifest["run"]),
            dns_zone=primary.dns_zone,
            initiated_by=primary.initiated_by,
            display_name="Native migration peer " + authority.manifest["run"],
            backup_enabled=False,
            backup_storage="platform",
        )
        binding = _peer_values(authority, primary, child, peer)
        NodeDeploymentLog.objects.create(
            deployment=peer,
            level="INFO",
            phase="native_peer_intent",
            message="Approved exact child before any provider create under the original native vault",
            details=binding,
        )
        credential = _credential(
            "ssh",
            "node-" + peer.hostname,
            child.public_key,
            child.key.decode(),
            {
                "native_run": child.manifest["run"],
                "deployment_id": str(peer.pk),
                "purpose": "node_deployment",
            },
        )
        if credential:
            peer.ssh_key_credential_id = credential
            peer.save(update_fields=["ssh_key_credential_id", "updated_at"])
    child.manifest["platform_peer"] = binding
    native_driver().write_manifest(path, child.manifest)
    return binding


def _recover_peer_publication(authority: NativeAuthority, primary: NodeDeployment, path: Path) -> None:
    """A lost local publication may reuse only the committed, never-created intent."""
    from .models import NodeDeployment  # noqa: PLC0415

    child = native_authority(path)
    if child.manifest.get("platform_peer") is not None:
        return
    peer = NodeDeployment.objects.filter(correlation_id=UUID(child.manifest["run"])).first()
    if peer is None:
        raise ValueError("The pre-create peer intent is missing; retain the unbound local key for inspection")
    _inventory(primary, peer)
    expected = _peer_values(authority, primary, child, peer)
    intent = peer.logs.filter(phase="native_peer_intent").first()
    if (
        intent is None
        or intent.details != expected
        or peer.status != "pending"
        or peer.external_node_id
        or peer.server_create_state != "none"
        or peer.operation_token is not None
        or any(child.manifest.get(key) is not None for key in ("server_id", "ssh_key_id", "firewall_id", "ipv4"))
    ):
        raise ValueError("Uncertain or changed peer intent cannot be republished as never-created")
    child.manifest.update(platform_peer=expected, expires_at=authority.manifest["expires_at"])
    native_driver().write_manifest(path, child.manifest)


def patch_free_environment(authority: NativeAuthority) -> Any:
    """Feed only the already approved intent fields to the existing local key generator."""
    from contextlib import contextmanager  # noqa: PLC0415

    @contextmanager
    def approved_environment() -> Any:
        values = {
            "PRAHO_NATIVE_ADMIN_CIDR": authority.manifest["admin_cidr"],
            "PRAHO_NATIVE_LOCATION": authority.manifest["location"],
            "PRAHO_NATIVE_SERVER_TYPE": authority.manifest["server_type"],
        }
        previous = {name: os.environ.get(name) for name in values}
        os.environ.update(values)
        try:
            yield
        finally:
            for name, value in previous.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

    return approved_environment()


def create_peer(authority: NativeAuthority, path: Path) -> None:
    from .deployment_service import NodeDeploymentService  # noqa: PLC0415
    from .models import NodeDeploymentLog  # noqa: PLC0415
    from .native_fresh_workflow import _credentials  # noqa: PLC0415

    _primary(authority)
    _child, peer = _read_peer(authority, path)
    if peer.status == "completed":
        export_peer(authority, path)
        return
    if peer.status != "pending" or peer.external_node_id or peer.server_create_state != "none":
        raise ValueError("Retain the original peer and use public reconciliation/teardown; never create a replacement")
    token, dns, _zone = _credentials()
    result = NodeDeploymentService().deploy_node(
        peer, {"api_token": token}, cloudflare_api_token=dns, user=peer.initiated_by
    )
    if result.is_err():
        raise ValueError("Public peer deployment refused or failed: " + result.unwrap_err())
    completed, report = result.unwrap(), result.unwrap().validation_report
    NodeDeploymentLog.objects.create(
        deployment=peer,
        level="INFO",
        phase="native_fresh_result",
        message="Actual peer public deployment result",
        details={
            "source": "NodeDeploymentService.deploy_node",
            "stages": completed.stages_completed,
            "success": completed.success,
            "validation_passed": report is not None and report.all_passed,
            "validation_checks": [item.check_name for item in report.checks if item.passed] if report else [],
        },
    )
    export_peer(authority, path)


def _peer_live(child: NativeAuthority, peer: NodeDeployment) -> tuple[Any, Any, Any]:
    from apps.common.credential_vault import EncryptedCredential  # noqa: PLC0415

    from .deployment_lifecycle import unique_dns_owner_tag  # noqa: PLC0415
    from .dns_gateway import get_dns_gateway  # noqa: PLC0415
    from .native_fresh_workflow import _approved_dns, _completed_provenance, _credentials  # noqa: PLC0415
    from .native_workflow import require_fixture_dns  # noqa: PLC0415
    from .ssh_key_manager import SSHKeyManager  # noqa: PLC0415

    token, dns, zone = _credentials()
    resources = _completed_provenance(peer, token)
    _approved_dns(peer.dns_zone, dns, zone)
    records = get_dns_gateway("cloudflare", dns).find_records_by_name(zone, peer.fqdn)
    if records.is_err() or not records.unwrap():
        raise ValueError("The peer's current owned DNS is missing")
    rows = records.unwrap()
    if any(
        row.get("comment") != unique_dns_owner_tag(peer.correlation_id)
        or row.get("name") != peer.fqdn
        or row.get("type") not in {"A", "AAAA"}
        for row in rows
    ) or not any(row.get("type") == "A" and row.get("content") == peer.ipv4_address for row in rows):
        raise ValueError("The peer DNS no longer belongs to its actual public deployment")
    require_fixture_dns(peer, str(peer.ipv4_address))
    if not EncryptedCredential.objects.filter(
        pk=peer.ssh_key_credential_id,
        service_type="ssh",
        service_identifier="node-" + peer.hostname,
        is_active=True,
        expires_at__gt=timezone.now(),
        rotation_in_progress=False,
    ).exists():
        raise ValueError("The original enrolled peer credential identity changed")
    original = SSHKeyManager().get_deployment_key(
        peer, user=peer.initiated_by, reason="Export only the approved native peer"
    )
    if (
        original.is_err()
        or original.unwrap().private_key != child.key.decode()
        or original.unwrap().public_key != child.public_key
    ):
        raise ValueError("The original enrolled peer SSH vault identity changed")
    cloud = native_driver().client()
    server, key = (
        cloud.servers.get_by_id(int(resources["server_id"])),
        cloud.ssh_keys.get_by_id(int(resources["ssh_key_id"])),
    )
    expected = {"managed-by": "praho", "praho-deployment": child.manifest["run"]}
    if (
        server is None
        or key is None
        or str(server.id) != resources["server_id"]
        or str(key.id) != resources["ssh_key_id"]
        or server.name != peer.hostname
        or server.public_net.ipv4.ip != peer.ipv4_address
        or key.public_key.strip() != child.public_key
        or any(server.labels.get(name) != value or key.labels.get(name) != value for name, value in expected.items())
    ):
        raise ValueError("The exact live peer provider resource, creator or key changed")
    ownership = {"praho-native-run": child.manifest["run"], "praho-native-owner": native_driver().OWNER}
    if any(
        resource.labels.get(name) not in (None, expected)
        for resource in (server, key)
        for name, expected in ownership.items()
    ):
        raise ValueError("A different native owner already holds this exact peer resource")
    return cloud, server, key


def _write_trust(child: NativeAuthority, peer: NodeDeployment) -> None:
    _key, trust = native_driver().paths(child.path, child.manifest)
    host_keys = peer.ssh_host_keys
    if not host_keys:
        raise ValueError("The peer's original host enrollment is missing")
    value = "".join(
        f"{peer.ipv4_address} {line}\n[{peer.ipv4_address}]:{peer.ssh_port} {line}\n"
        for line in host_keys.splitlines()
        if line.strip()
    )
    descriptor = os.open(trust, os.O_RDWR | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r+") as output:
        info = os.fstat(output.fileno())
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != PRIVATE_MODE or info.st_uid != os.getuid():
            raise ValueError("The original private child host trust is required")
        previous = output.read(native_driver().MAX_MANIFEST + 1)
        if previous and previous != value:
            raise ValueError("The peer's original enrolled host trust changed")
        output.seek(0)
        output.write(value)
        output.truncate()
        output.flush()
        os.fsync(output.fileno())


def export_peer(authority: NativeAuthority, path: Path) -> None:
    _primary(authority)
    child, peer = _read_peer(authority, path)
    phase = child.manifest["phase"]
    if phase not in {"fresh-intent", "prepared", "verified"}:
        raise ValueError("A held or interrupted native peer phase requires its original reconciliation")
    cloud, server, key = _peer_live(child, peer)
    if any(
        child.manifest.get(name) not in (None, expected)
        for name, expected in (
            ("server_id", int(peer.external_node_id)),
            ("ssh_key_id", int(key.id)),
            ("ipv4", peer.ipv4_address),
        )
    ):
        raise ValueError("The exported peer identity was retargeted; never replace its original native proof")
    labels = {"praho-native-run": child.manifest["run"], "praho-native-owner": native_driver().OWNER}
    server.update(labels={**server.labels, **labels})
    cloud.ssh_keys.update(key, labels={**key.labels, **labels})
    _write_trust(child, peer)
    child.manifest.update(
        server_id=int(peer.external_node_id),
        ssh_key_id=int(key.id),
        ipv4=peer.ipv4_address,
        ssh_port=peer.ssh_port,
        host_public_key=peer.ssh_host_keys,
        phase="verified" if phase == "verified" else "prepared",
    )
    native_driver().write_manifest(child.path, child.manifest)


def destroy_peer(authority: NativeAuthority, path: Path) -> None:
    from .cloud_destroy_service import DestroyApproval, approve_destroy, inspect_destroy  # noqa: PLC0415
    from .deployment_service import NodeDeploymentService  # noqa: PLC0415
    from .native_fresh_workflow import _credentials  # noqa: PLC0415

    child, peer = _read_peer(authority, path, cleanup=True)
    token, _dns, _zone = _credentials()
    actor = peer.initiated_by
    if actor is None:
        raise ValueError("The original peer teardown actor is missing")
    if peer.status != "destroyed":
        preview = inspect_destroy(peer, token)
        plan = approve_destroy(
            peer,
            token,
            actor,
            DestroyApproval(
                hostname=peer.hostname,
                digest=preview.digest,
                restore_point_policy="delete",
                reason="Remove only the original disposable native migration peer",
            ),
        )
        result = NodeDeploymentService().destroy_node(peer, {"api_token": token}, user=actor, plan_id=plan.pk)
        if result.is_err() or not result.unwrap():
            raise ValueError("Peer teardown remains uncertain; retain original authority and public ownership records")
        peer.refresh_from_db()
    if peer.status != "destroyed":
        raise ValueError("Public peer teardown has not confirmed absence")
    child.manifest["phase"] = "destroyed"
    native_driver().write_manifest(child.path, child.manifest)


def _new_commercial_rows(authority: NativeAuthority, primary: NodeDeployment, boundary: datetime) -> dict[str, Any]:
    from apps.billing.models import Currency, Subscription  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.products.models import Product, ProductPrice, ProductRelationship  # noqa: PLC0415
    from apps.provisioning.hosting_limit_selectors import prime_current_verification  # noqa: PLC0415
    from apps.provisioning.service_models import Service, ServicePlan  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415
    from apps.users.models import CustomerMembership, User  # noqa: PLC0415

    from .native_workflow import _database_identity  # noqa: PLC0415

    run = str(UUID(authority.manifest["run"]))
    original = Service.objects.select_related("customer", "service_plan", "hosting_limits").get(
        username="nat" + UUID(run).hex[:10],
        customer__name="Native quota acceptance " + run,
        virtualmin_account__server_id=primary.virtualmin_server_id,
    )
    if (
        Customer.all_objects.exclude(pk=original.customer_id).exists()
        or Service.objects.exclude(pk=original.pk).exists()
    ):
        raise ValueError("Refuse unrelated customer/service inventory before synthetic billing setup")
    account = VirtualminAccount.objects.select_related("server__hosting_policy").get(service=original)
    prime_current_verification([original], {original.pk: account})
    if original.__dict__.get("_hosting_current_verified") is not True:
        raise ValueError("The original native service requires an exact current verified account receipt")
    base_disk = original.service_plan.disk_space_gb
    if base_disk is None or base_disk <= 1:
        raise ValueError("The owned foundation fixture requires its finite multi-GiB base allowance")
    if Subscription.objects.filter(service=original).exists():
        raise ValueError("Never initialize over an existing subscription")
    password = hashlib.sha256(authority.key + b":commercial-owner-v1").hexdigest()
    staff = _admitted_staff(authority, primary)
    email = original.customer.primary_email
    if User.objects.filter(email=email).exists():
        raise ValueError("Existing commercial setup lacks its original intent; preserve it for reconciliation")
    with transaction.atomic():
        customer = original.customer
        owner = create_commercial_owner(email, password)
        CustomerMembership.objects.create(customer=customer, user=owner, role="owner", is_active=True)
        currency = Currency.objects.get(code="RON")
        catalog = {}
        base = original.service_plan
        base_price = int(original.price * 100)
        for name, disk, price in (
            ("lower", max(1, base_disk // 2), max(1, base_price // 2)),
            ("base", base_disk, base_price),
            ("higher", base_disk * 2, base_price * 2),
        ):
            plan = (
                base
                if name == "base"
                else ServicePlan.objects.create(
                    name=f"Native {name} {run}",
                    plan_type=base.plan_type,
                    disk_space_gb=disk,
                    bandwidth_gb=base.bandwidth_gb,
                    price_monthly=original.price,
                    **{
                        key: getattr(base, key)
                        for key in ("features", "email_accounts", "databases", "domains", "cpu_cores", "ram_gb")
                    },
                )
            )
            product = Product.objects.create(
                name=plan.name,
                slug=f"native-{name}-{run}",
                product_type="hosting",
                module="virtualmin",
                default_service_plan=plan,
            )
            ProductPrice.objects.create(product=product, currency=currency, monthly_price_cents=price)
            catalog[name] = product
        for source, target in (("lower", "base"), ("base", "higher")):
            ProductRelationship.objects.create(
                source_product=catalog[source], target_product=catalog[target], relationship_type="upgrades_to"
            )
        lanes = {}
        for lane in ("upgrade", "downgrade"):
            name = f"native-{lane}-{UUID(run).hex[:10]}.example.com"
            service = original
            if lane == "downgrade":
                service = Service(
                    customer=customer,
                    currency=currency,
                    service_plan=base,
                    service_name=name,
                    domain=name,
                    username="nd" + UUID(run).hex[:10],
                    price=original.price,
                    auto_renew=True,
                )
                service.activate()
                service.save()
            subscription = initialize_commercial_subscription(service, catalog["base"], boundary)
            lanes[lane] = {"service_id": service.pk, "subscription_id": str(subscription.pk)}
        binding = {
            "schema": 1,
            "run": run,
            "database": _database_identity(),
            "deployment_id": primary.pk,
            "customer_id": customer.pk,
            "owner_id": owner.pk,
            "staff_id": staff.pk,
            "actor_id": primary.initiated_by_id,
            "boundary": boundary.isoformat(),
            "catalog": {name: str(product.pk) for name, product in catalog.items()},
            "lanes": lanes,
        }
        _save_commercial_intent(authority, primary, binding, email, password)
    return binding


def _save_commercial_intent(
    authority: NativeAuthority, primary: NodeDeployment, binding: dict[str, Any], email: str, password: str
) -> None:
    from .models import NodeDeploymentLog  # noqa: PLC0415

    NodeDeploymentLog.objects.create(
        deployment=primary,
        phase="native_commercial_intent",
        level="INFO",
        message="Created only new synthetic initial commercial history",
        details=binding,
    )
    run = authority.manifest["run"]
    write_private(
        authority.path.parent / (run + ".commercial-login.json"),
        json.dumps({"run": run, "email": email, "password": password}, sort_keys=True),
    )


def setup_commercial_fixture(
    authority: NativeAuthority, *, boundary_minutes: int = 75, peer_path: Path | None = None
) -> dict[str, Any]:
    primary = _primary(authority)
    if peer_path is None:
        _inventory(primary)
    else:
        _read_peer(authority, peer_path)
    if type(boundary_minutes) is not int or not MIN_BOUNDARY_MINUTES <= boundary_minutes <= MAX_BOUNDARY_MINUTES:
        raise ValueError("Choose a real boundary 60-90 minutes ahead")
    original = primary.logs.filter(phase="native_commercial_intent").first()
    if original is None:
        boundary = (timezone.now() + timedelta(minutes=boundary_minutes)).replace(microsecond=0)
        if boundary + timedelta(minutes=45) >= datetime.fromisoformat(authority.manifest["expires_at"]):
            raise ValueError("Leave at least 45 minutes after the actual boundary within original authority")
        binding = _new_commercial_rows(authority, primary, boundary)
    else:
        binding = original.details
    _validate_commercial_binding(authority, primary, binding)
    _ensure_native_accounts(primary, binding)
    _settle_initial_cycles(binding)
    authority.manifest["commercial_acceptance"] = binding
    native_driver().write_manifest(authority.path, authority.manifest)
    return binding


def _validate_commercial_binding(authority: NativeAuthority, primary: NodeDeployment, binding: dict[str, Any]) -> None:
    from apps.billing.plan_change_models import PlanChange  # noqa: PLC0415
    from apps.billing.subscription_models import Subscription  # noqa: PLC0415
    from apps.customers.models import Customer  # noqa: PLC0415
    from apps.provisioning.service_models import Service  # noqa: PLC0415
    from apps.users.models import CustomerMembership  # noqa: PLC0415

    from .native_workflow import _database_identity  # noqa: PLC0415

    staff = _admitted_staff(authority, primary)
    if type(binding.get("customer_id")) is not int or type(binding.get("owner_id")) is not int:
        raise ValueError("Exact original customer and owner IDs are required")

    if (
        binding.get("schema") != 1
        or binding.get("staff_id") != staff.pk
        or binding.get("actor_id") != primary.initiated_by_id
        or binding.get("run") != authority.manifest["run"]
        or binding.get("deployment_id") != primary.pk
        or binding.get("database") != _database_identity()
        or set(binding.get("lanes", {})) != {"upgrade", "downgrade"}
        or not CustomerMembership.objects.filter(
            customer_id=binding["customer_id"], user_id=binding["owner_id"], role="owner", is_active=True
        ).exists()
    ):
        raise ValueError("The original commercial intent or owner changed")
    if (
        Customer.all_objects.exclude(pk=binding["customer_id"]).exists()
        or Service.objects.exclude(pk__in=[lane["service_id"] for lane in binding["lanes"].values()]).exists()
        or Subscription.objects.exclude(pk__in=[lane["subscription_id"] for lane in binding["lanes"].values()]).exists()
    ):
        raise ValueError("Refuse unrelated commercial inventory before global renewal preparation")
    for name, lane in binding["lanes"].items():
        subscription = Subscription.objects.select_related("service", "customer", "product").get(
            pk=lane["subscription_id"]
        )
        username = ("nat" if name == "upgrade" else "nd") + UUID(authority.manifest["run"]).hex[:10]
        if (
            subscription.service_id != lane["service_id"]
            or subscription.customer_id != binding["customer_id"]
            or subscription.service is None
            or subscription.service.customer_id != binding["customer_id"]
            or subscription.service.username != username
            or subscription.customer.name != "Native quota acceptance " + authority.manifest["run"]
            or subscription.meta.get("source") != "native_acceptance_initial_history"
            or subscription.meta.get("boundary") != binding["boundary"]
            or str(subscription.product_id) != binding["catalog"]["base"]
        ):
            raise ValueError("The original commercial service, terms or initial history changed")
        if PlanChange.objects.filter(service_id=lane["service_id"]).exists():
            raise ValueError("Commercial acceptance already started; use verification, never rerun initial setup")


def _ensure_native_accounts(primary: NodeDeployment, binding: dict[str, Any]) -> None:
    from apps.provisioning.hosting_limit_selectors import prime_current_verification  # noqa: PLC0415
    from apps.provisioning.service_models import Service  # noqa: PLC0415
    from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415
    from apps.provisioning.virtualmin_service import (  # noqa: PLC0415
        VirtualminAccountCreationData,
        VirtualminProvisioningService,
    )

    server = primary.virtualmin_server
    if server is None:
        raise ValueError("The original registered native server is missing")
    for lane in binding["lanes"].values():
        service = Service.objects.select_related("hosting_limits").get(
            pk=lane["service_id"], customer_id=binding["customer_id"]
        )
        if not VirtualminAccount.objects.filter(service=service).exists():
            created = VirtualminProvisioningService(server).create_virtualmin_account(
                VirtualminAccountCreationData(
                    service=service, domain=service.domain, username=service.username, server=server
                )
            )
            if created.is_err():
                raise ValueError("Public native account creation refused: " + created.unwrap_err())
        service.refresh_from_db()
        account = VirtualminAccount.objects.select_related("server__hosting_policy").get(service=service)
        if (
            account.server_id != server.pk
            or account.domain != service.domain
            or account.virtualmin_username != service.username
        ):
            raise ValueError("The exact owned initial native account changed")
        prime_current_verification([service], {service.pk: account})
        if service.__dict__.get("_hosting_current_verified") is not True:
            raise ValueError("Initial account resources remain unverified; retain the public job for reconciliation")


def _settle_initial_cycles(binding: dict[str, Any]) -> None:
    from apps.billing.models import Subscription  # noqa: PLC0415
    from apps.billing.plan_change_coverage import load_plan_coverage  # noqa: PLC0415
    from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415
    from apps.billing.recurring_billing import RecurringBillingOrchestrator  # noqa: PLC0415

    boundary = datetime.fromisoformat(binding["boundary"])
    cycles = [
        Subscription.objects.get(pk=lane["subscription_id"]).billing_cycles.filter(period_end=boundary).first()
        for lane in binding["lanes"].values()
    ]
    if not any(cycles):
        prepared = RecurringBillingOrchestrator.prepare_due_proformas()
        if prepared["errors"]:
            raise ValueError("Initial real renewal preparation requires review: " + "; ".join(prepared["errors"]))
    elif not all(cycles):
        raise ValueError(
            "Partial initial preparation requires public document reconciliation; do not prepare another period"
        )
    for lane in binding["lanes"].values():
        subscription = Subscription.objects.get(pk=lane["subscription_id"], customer_id=binding["customer_id"])
        cycle = subscription.billing_cycles.get(period_end=datetime.fromisoformat(binding["boundary"]))
        if cycle.invoice_id is None:
            proforma = cycle.proforma
            if proforma is None:
                raise ValueError("The genuine initial renewal document is missing")
            paid = ProformaPaymentService.record_payment_and_convert(
                str(cycle.proforma_id),
                proforma.total_cents,
                "bank",
                reference="Synthetic native acceptance initial history; no real transfer",
            )
            if paid.is_err():
                raise ValueError("Initial synthetic manual settlement refused: " + paid.unwrap_err())
        subscription.refresh_from_db()
        load_plan_coverage(subscription, at=timezone.now())
        cycle.refresh_from_db()
        lane.update(
            initial_cycle_id=str(cycle.pk),
            initial_proforma_id=str(cycle.proforma_id),
            initial_invoice_id=str(cycle.invoice_id),
        )


def verify_acceptance(authority: NativeAuthority, peer_path: Path | None = None) -> None:
    from apps.provisioning.hosting_node_policy import managed_quota_refusal, verify_quota_evidence  # noqa: PLC0415
    from apps.provisioning.hosting_node_tasks import collect_hosting_inspection  # noqa: PLC0415

    from .models import NodeDeploymentLog  # noqa: PLC0415
    from .native_fresh_workflow import verify_fresh_vm  # noqa: PLC0415

    verify_fresh_vm(authority)
    if peer_path is None:
        return
    child, peer = _read_peer(authority, peer_path)
    _peer_live(child, peer)
    native_driver().owned_server(child.path)
    if child.manifest.get("phase") != "verified":
        raise ValueError("Run the actual Ubuntu quota/reboot/update gate on the exact peer first")
    state = json.loads(native_driver().remote(child.path, "/bin/cat /root/praho-native-quota-state.json"))
    if state.get("run") != child.manifest["run"] or any(
        state.get(name) is not True for name in ("initial", "reboot", "packages_updated", "update")
    ):
        raise ValueError("The peer's actual kernel/update controls are incomplete")
    server = peer.virtualmin_server
    if server is None or managed_quota_refusal(server):
        raise ValueError("Explicitly inspect and adopt the exact qualified migration peer first")
    evidence = collect_hosting_inspection(server)
    verify_quota_evidence(evidence["quota"], evidence["identity"])
    NodeDeploymentLog.objects.create(
        deployment=peer,
        level="INFO",
        phase="native_peer_verified",
        message="Both original public deployments and current owned native peer evidence verified",
        details={
            "parent_run": authority.manifest["run"],
            "run": child.manifest["run"],
            "connection_identity": evidence["identity"],
        },
    )


def run_acceptance(path: Path, action: str, *, peer_path: Path | None = None, boundary_minutes: int = 75) -> None:
    cleanup = action == "peer-destroy"
    if os.environ.get("PRAHO_NATIVE_CLEANUP_ONLY") == "1" and not cleanup:
        raise ValueError("Cleanup-only authority cannot create or verify acceptance work")
    authority = native_authority(path, cleanup=cleanup)
    with native_run_lock(authority):
        if action == "staff-setup":
            setup_staff_fixture(authority)
        elif action == "setup":
            setup_commercial_fixture(authority, boundary_minutes=boundary_minutes, peer_path=peer_path)
        elif action == "verify":
            verify_acceptance(authority, peer_path)
        elif peer_path is None:
            raise ValueError("The exact approved peer manifest path is required")
        elif action == "peer-intent":
            prepare_peer_intent(authority, peer_path)
        elif action == "create-peer":
            create_peer(authority, peer_path)
        elif action == "export-peer":
            export_peer(authority, peer_path)
        elif action == "peer-destroy":
            destroy_peer(authority, peer_path)
        else:
            raise ValueError("Unknown native acceptance action")
