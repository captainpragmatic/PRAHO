"""Operator authority and durable source responsibilities for component migrations."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from typing import TYPE_CHECKING
from uuid import uuid4

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.infrastructure.permissions import can_deploy_nodes

from .component_migration_manifest import ComponentManifest
from .component_migration_models import (
    ComponentMigrationApproval,
    ComponentMigrationReview,
    SourceServiceObligation,
    SourceServiceRelease,
)
from .virtualmin_chain import invalidate_chain
from .virtualmin_gateway import is_customer_domain_row, listing_attribute
from .virtualmin_migration_models import VirtualminMigration
from .virtualmin_migration_service import VirtualminMigrationService, list_migration_domains
from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_node_capability import destination_refusal
from .virtualmin_security import connection_identity

if TYPE_CHECKING:
    from apps.users.models import User

MAX_BACKUP_HANDOFF_LENGTH = 2000
COMPONENT_POLICY_VERSION = "component-web-v1"
MAX_COMPONENT_REVIEW_AGE_SECONDS = 900


def _operator(actor: User) -> None:
    if not actor.is_active or not can_deploy_nodes(actor):
        raise PermissionDenied(_("Deployment permission is required for component migration decisions."))


@transaction.atomic
def record_component_review(
    account: VirtualminAccount, target: VirtualminServer, evidence: object, actor: User
) -> ComponentMigrationReview:
    """Store only validated native evidence; inspection never grants destination capability."""
    _operator(actor)
    manifest = ComponentManifest.parse(evidence)
    account = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=account.pk)
    servers = {
        server.pk: server
        for server in VirtualminServer.objects.select_for_update(no_key=True)
        .filter(pk__in=(account.server_id, target.pk))
        .order_by("pk")
    }
    source, target = servers[account.server_id], servers[target.pk]
    source_identity, target_identity = connection_identity(source), connection_identity(target)
    if manifest.as_json()["source"]["connection_identity"] != source_identity:
        raise ValidationError(_("The source connection changed; inspect its component scope again."))
    return ComponentMigrationReview.objects.create(
        account=account,
        source_server=source,
        target_server=target,
        actor=actor,
        policy_version=COMPONENT_POLICY_VERSION,
        source_identity=source_identity,
        target_identity=target_identity,
        digest=manifest.digest,
        authority_digest=manifest.authority_digest,
        manifest=manifest.as_json(),
    )


def _review_scope(
    stored: ComponentMigrationReview, evidence: object
) -> tuple[VirtualminAccount, VirtualminServer, VirtualminServer, ComponentManifest]:
    """Caller holds a transaction; account then ordered server locks serialize admission."""
    account = VirtualminAccount.objects.select_for_update(no_key=True).get(pk=stored.account_id)
    servers = {
        server.pk: server
        for server in VirtualminServer.objects.select_for_update(no_key=True)
        .filter(pk__in=(stored.source_server_id, stored.target_server_id))
        .order_by("pk")
    }
    source, target = servers[stored.source_server_id], servers[stored.target_server_id]
    from apps.infrastructure.node_maintenance_gate import maintenance_refusal  # noqa: PLC0415  # Shared node admission

    for node in (source, target):
        if refusal := maintenance_refusal(node.pk):
            raise ValidationError(refusal)
    latest = ComponentMigrationReview.objects.filter(
        account=account, source_server=source, target_server=target
    ).first()
    age = (timezone.now() - stored.created_at).total_seconds()
    if (
        latest is None
        or latest.pk != stored.pk
        or not 0 <= age <= MAX_COMPONENT_REVIEW_AGE_SECONDS
        or stored.policy_version != COMPONENT_POLICY_VERSION
        or account.server_id != source.pk
        or stored.source_identity != connection_identity(source)
        or stored.target_identity != connection_identity(target)
    ):
        raise ValidationError(
            _("This component preview is stale or superseded; inspect the current source and target again.")
        )
    original, current = ComponentManifest.parse(stored.manifest), ComponentManifest.parse(evidence)
    original.assert_ready()
    current.assert_ready()
    if (
        original.digest != stored.digest
        or original.authority_digest != stored.authority_digest
        or current.authority_digest != stored.authority_digest
    ):
        raise ValidationError(
            _("Component roots, grants, writers or retained dependencies changed; review a new preview.")
        )
    if source.security_state not in {"acknowledged_source_only", "verified_web"}:
        raise ValidationError(_("Acknowledge the source services and responsibilities before component migration."))
    if source.security_operation or target.security_operation or source.status != "active" or target.status != "active":
        raise ValidationError(_("Resolve source and target lifecycle operations before accepting component migration."))
    if target.security_state != "verified_web" or destination_refusal(target) is not None:
        raise ValidationError(_("Component migration requires a currently verified web destination."))
    account.server = source
    return account, source, target, current


@transaction.atomic
def approve_component_review(
    review: ComponentMigrationReview, evidence: object, actor: User, reason: str, backup_responsibility: str
) -> ComponentMigrationApproval:
    _operator(actor)
    if (
        not reason.strip()
        or len(reason) > MAX_BACKUP_HANDOFF_LENGTH
        or not backup_responsibility.strip()
        or len(backup_responsibility) > MAX_BACKUP_HANDOFF_LENGTH
    ):
        raise ValidationError(_("Accept the component impact and independent source backup responsibility explicitly."))
    stored = ComponentMigrationReview.objects.get(pk=review.pk)
    _review_scope(stored, evidence)
    if ComponentMigrationApproval.objects.filter(review=stored).exists():
        raise ValidationError(_("This component preview already has an immutable operator decision."))
    return ComponentMigrationApproval.objects.create(
        review=stored,
        actor=actor,
        reason=reason.strip(),
        backup_responsibility=backup_responsibility.strip(),
    )


def _require_source_history_cleanup(obligation: SourceServiceObligation) -> None:
    for previous in VirtualminMigration.objects.filter(component_source_obligation=obligation).only(
        "status", "barrier_state"
    ):
        state = previous.barrier_state
        if previous.status not in {"failed", "rolled_back", "completed"} or not isinstance(state, dict):
            raise ValidationError(
                _("Resolve the previous source operation history before starting another component move.")
            )
        issued = state.get("component_source_hold_issued", False)
        native_evidence = any(
            key in state
            for key in (
                "component_source_held",
                "component_export",
                "component_source_released",
                "component_source_seal_intent",
                "component_source_sealed",
            )
        )
        if issued is False and not native_evidence:
            continue
        cleanup = state.get("artifact_cleanup")
        if issued is not True or not isinstance(cleanup, dict) or cleanup.get("done") is not True:
            raise ValidationError(
                _(
                    "Finish the previous source operation's private artifact cleanup before starting another component move."
                )
            )


@transaction.atomic
def start_component_migration(
    approval: ComponentMigrationApproval, evidence: object, actor: User, *, enqueue: bool = True
) -> VirtualminMigration:
    """Consume one current decision without touching source services or bootstrapping SSH."""
    _operator(actor)
    approval = ComponentMigrationApproval.objects.select_related("review").get(pk=approval.pk)
    if approval.actor_id != actor.pk:
        raise ValidationError(_("The operator who accepted this preview must start its component migration."))
    account, source, target, manifest = _review_scope(approval.review, evidence)
    try:
        network = {
            "source_ipv4": str(ipaddress.IPv4Address(source.ipv4_address or "")),
            "target_ipv4": str(ipaddress.IPv4Address(target.ipv4_address or "")),
            "source_ipv6": str(ipaddress.IPv6Address(source.ipv6_address)) if source.ipv6_address else "",
            "target_ipv6": str(ipaddress.IPv6Address(target.ipv6_address)) if target.ipv6_address else "",
        }
    except ipaddress.AddressValueError as error:
        raise ValidationError(
            _("Configure the source and target bridge IPv4 addresses before starting this migration.")
        ) from error
    if VirtualminMigration.objects.filter(component_approval=approval).exists():
        raise ValidationError(_("This component approval has already been consumed."))
    engine = VirtualminMigrationService()
    try:
        engine._local_preflight(account, target, component_scope=True)
        hostname = engine._locked_account_name(account, source_id=source.pk)
        target_rows = engine._listing(engine._gateway(target))
        if any(row["domain"] == account.domain for row in target_rows):
            raise ValueError("Domain already exists on target")
        source_rows = engine._listing(engine._gateway(source))
        selected = [row for row in source_rows if row["domain"] == account.domain]
        if (
            len(selected) != 1
            or selected[0]["username"] != account.virtualmin_username
            or not is_customer_domain_row(selected[0])
            or str(listing_attribute(selected[0]["attributes"], "ID")) != manifest.as_json()["source"]["domain_id"]
            or selected[0]["enabled"] is not (account.status == "active")
        ):
            raise ValueError("The current native source domain no longer matches the component preview")
    except ValueError as error:
        raise ValidationError(str(error)) from error
    facts = manifest.as_json()
    obligation = SourceServiceObligation.objects.filter(
        source_server=source, source_domain_id=facts["source"]["domain_id"]
    ).first()
    if obligation is not None and (
        obligation.domain != account.domain
        or obligation.owner != account.virtualmin_username
        or set(obligation.retained_services) != set(facts["retained"]["services"])
        or SourceServiceRelease.objects.filter(obligation=obligation).exists()
    ):
        raise ValidationError(
            _("Resolve the existing retained source identity before starting another component move.")
        )
    if obligation is not None:
        _require_source_history_cleanup(obligation)
    invalidate_chain(account)
    from .hosting_limit_execution import freeze_migration_limits  # noqa: PLC0415 -- Immutable reviewed quota authority.

    hosting_limits = freeze_migration_limits(account)
    migration = VirtualminMigration.objects.create(
        account=account,
        source_server=source,
        target_server=target,
        initiated_by=actor,
        contract=VirtualminMigration.Contract.IMPORTED_WEB,
        component_approval=approval,
        pre_migration_snapshot={
            "domain": account.domain,
            "status": account.status,
            "remote": selected[0],
            "component_manifest": facts,
            "component_network": network,
            "component_account_name": hostname.fqdn if hostname else "",
            "target_limits": {
                "disk_quota_mb": account.effective_disk_quota_mb
                if account.effective_disk_quota_mb is not None
                else account.disk_quota_mb,
                "bandwidth_quota_mb": account.bandwidth_quota_mb,
            },
            "hosting_limits": hosting_limits,
        },
    )
    if obligation is None:
        obligation = SourceServiceObligation.objects.create(
            source_server=source,
            migration=migration,
            source_domain_id=facts["source"]["domain_id"],
            domain=account.domain,
            owner=account.virtualmin_username,
            retained_services=facts["retained"]["services"],
            backup_responsible=actor,
            backup_responsibility=approval.backup_responsibility,
        )
    migration.component_source_obligation = obligation
    migration.save(update_fields=["component_source_obligation", "updated_at"])
    token = uuid4()
    if not migration.acquire_lease(token, engine.lease_ttl):
        raise ValidationError(_("Could not acquire the new component migration lease."))
    engine._audit(migration, "started", actor=actor)
    engine._move(migration, token, "pending", lease_token=None, worker_lease_expires_at=None)
    if enqueue:
        transaction.on_commit(lambda: engine._enqueue(migration.pk))
    return migration


@transaction.atomic
def release_source_obligation(
    obligation: SourceServiceObligation, actor: User, backup_handoff: str
) -> SourceServiceRelease:
    """A drain confirmation or account move cannot substitute for this native proof."""
    if not actor.is_active or not can_deploy_nodes(actor):
        raise PermissionDenied(_("Deployment permission is required to resolve retained source responsibilities."))
    if not backup_handoff.strip() or len(backup_handoff) > MAX_BACKUP_HANDOFF_LENGTH:
        raise ValidationError(_("Describe the resolved source services and independent backup handoff."))
    stored = SourceServiceObligation.objects.get(pk=obligation.pk)
    source = VirtualminServer.objects.select_for_update().get(pk=stored.source_server_id)
    if source.security_operation:
        raise ValidationError(_("Resolve node hardening before releasing retained source responsibilities."))
    if SourceServiceRelease.objects.filter(obligation=stored).exists():
        raise ValidationError(_("The retained source responsibility already has an immutable resolution."))
    identity = connection_identity(source)
    listing = list_migration_domains(VirtualminMigrationService._gateway(source))
    if listing.is_err():
        raise ValidationError(_("A live native source inventory is required to resolve retained source services."))
    rows = listing.unwrap()
    if any(
        row["domain"] == stored.domain
        or row["username"] == stored.owner
        or str(listing_attribute(row["attributes"], "ID")) == stored.source_domain_id
        for row in rows
    ):
        raise ValidationError(_("The retained source domain, identity or owner still has native services."))
    proof = {
        "source_identity": identity,
        "source_domain_id": stored.source_domain_id,
        "domain": stored.domain,
        "owner": stored.owner,
        "native_domain_absent": True,
        "owner_domains_absent": True,
    }
    # Native inventory may take long enough for the operator's role or active
    # status to change. A fresh object also drops Django permission caches.
    actor = type(actor).objects.get(pk=actor.pk)
    _operator(actor)
    return SourceServiceRelease.objects.create(
        obligation=stored,
        actor=actor,
        backup_handoff=backup_handoff.strip(),
        source_identity=identity,
        native_absence_digest=hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest(),
    )
