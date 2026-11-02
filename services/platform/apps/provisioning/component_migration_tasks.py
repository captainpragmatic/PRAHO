"""Bounded native inspection and fresh operator decisions outside HTTP requests."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils.translation import gettext as _

from apps.infrastructure.permissions import can_deploy_nodes

from .component_migration_inspection import collect_source_components
from .component_migration_manifest import ComponentManifest
from .component_migration_models import ComponentMigrationReview, SourceServiceObligation
from .component_migration_service import (
    approve_component_review,
    record_component_review,
    release_source_obligation,
    start_component_migration,
)
from .virtualmin_gateway import listing_attribute
from .virtualmin_migration_service import VirtualminMigrationService
from .virtualmin_models import VirtualminAccount, VirtualminServer
from .virtualmin_node_capability import destination_refusal

if TYPE_CHECKING:
    from apps.users.models import User


def _operator(actor_id: str) -> User:
    from apps.users.models import User  # noqa: PLC0415 -- cross-app actor boundary

    actor = User.objects.get(pk=actor_id)
    if not actor.is_active or not actor.is_staff_user or not can_deploy_nodes(actor):
        raise PermissionDenied(_("An active staff operator with deployment permission is required."))
    return actor


def _inspect(account: VirtualminAccount, target: VirtualminServer, selection: dict[str, object]) -> ComponentManifest:
    source = account.server
    if (
        source.pk == target.pk
        or source.security_state not in {"acknowledged_source_only", "verified_web"}
        or source.status != "active"
        or source.security_operation
        or target.security_operation
        or target.status != "active"
        or target.security_state != "verified_web"
        or destination_refusal(target) is not None
    ):
        raise ValidationError(
            _("Resolve source acknowledgment, node operations and current destination verification before inspection.")
        )
    rows = VirtualminMigrationService._listing(VirtualminMigrationService._gateway(source))
    domains = [
        row for row in rows if row["domain"] == account.domain and row["username"] == account.virtualmin_username
    ]
    if len(domains) != 1:
        raise ValidationError(_("The current native source domain or owner is missing or ambiguous."))
    manifest = collect_source_components(
        source,
        {
            **selection,
            "domain_id": str(listing_attribute(domains[0]["attributes"], "ID")),
            "domain": account.domain,
            "owner": account.virtualmin_username,
        },
    )
    expected_paths = cast("list[dict[str, str]]", selection.get("paths", []))
    expected_databases = cast("list[str]", selection.get("databases", []))
    actual_paths = [{"relative": row["relative"], "purpose": row["purpose"]} for row in manifest.as_json()["paths"]]
    if sorted((row["relative"], row["purpose"]) for row in actual_paths) != sorted(
        (row["relative"], row["purpose"]) for row in expected_paths
    ) or sorted(manifest.selected_databases) != sorted(expected_databases):
        raise ValidationError(
            _("Native inspection returned different selected paths or databases. Inspect the intended scope again.")
        )
    return manifest


def inspect_component_migration(
    account_id: str, target_id: str, actor_id: str, selection: dict[str, object]
) -> dict[str, str]:
    _operator(actor_id)
    account = VirtualminAccount.objects.select_related("server").get(pk=account_id)
    target = VirtualminServer.objects.get(pk=target_id)
    try:
        manifest = _inspect(account, target, selection)
        review = record_component_review(account, target, manifest.as_json(), _operator(actor_id))
    except (ValidationError, ValueError) as error:
        return {
            "outcome": "needs_review",
            "message": "; ".join(error.messages) if isinstance(error, ValidationError) else str(error),
        }
    return {"outcome": "reviewed", "review_id": str(review.pk)}


def accept_component_migration(
    account_id: str, review_id: str, actor_id: str, reason: str, backup_responsibility: str
) -> dict[str, str]:
    actor = _operator(actor_id)
    review = ComponentMigrationReview.objects.select_related("account__server", "target_server").get(
        pk=review_id, account_id=UUID(account_id)
    )
    scope = ComponentManifest.parse(review.manifest)
    selection: dict[str, object] = {
        "paths": [{"relative": path["relative"], "purpose": path["purpose"]} for path in scope.as_json()["paths"]],
        "databases": list(scope.selected_databases),
    }
    try:
        manifest = _inspect(review.account, review.target_server, selection)
        actor = _operator(actor_id)
        with transaction.atomic():
            approval = approve_component_review(review, manifest.as_json(), actor, reason, backup_responsibility)
            migration = start_component_migration(approval, manifest.as_json(), actor)
    except (ValidationError, ValueError) as error:
        return {
            "outcome": "needs_review",
            "message": "; ".join(error.messages) if isinstance(error, ValidationError) else str(error),
        }
    return {"outcome": "started", "migration_id": str(migration.pk)}


def release_component_source(account_id: str, obligation_id: str, actor_id: str, backup_handoff: str) -> dict[str, str]:
    actor = _operator(actor_id)
    obligation = SourceServiceObligation.objects.get(pk=obligation_id, migration__account_id=UUID(account_id))
    try:
        release = release_source_obligation(obligation, actor, backup_handoff)
    except (ValidationError, ValueError) as error:
        return {
            "outcome": "needs_review",
            "message": "; ".join(error.messages) if isinstance(error, ValidationError) else str(error),
        }
    return {"outcome": "released", "obligation_id": str(release.obligation_id)}
