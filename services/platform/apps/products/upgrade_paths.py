"""Serialized staff configuration of forward upgrades and their reverse downgrade paths."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import router, transaction
from django.utils.translation import gettext_lazy as _

from apps.audit.services import AuditService
from apps.common.decorators import is_administrator

from .models import Product, ProductRelationship

if TYPE_CHECKING:
    from typing import Literal

    from apps.users.models import User

UPGRADE_RELATIONSHIP = "upgrades_to"


def _locked_catalog(actor: User, using: str) -> tuple[User, dict[UUID, Product]]:
    from apps.users.models import User  # noqa: PLC0415 -- Recheck the current catalog actor after initialization.

    current_actor = User.objects.using(using).get(pk=actor.pk)
    if not current_actor.is_active or not is_administrator(current_actor):
        raise PermissionDenied(_("Only administrators can change the product catalog."))
    # All existing products, including unrelated endpoints, serialize graph edits.
    # Locking only a pair permits two disjoint edits to jointly create a cycle.
    # New products have no edges until this service. NO KEY UPDATE permits other
    # transactions' ordinary FK references while keeping graph writers ordered.
    products = {
        product.pk: product
        for product in Product.objects.using(using).select_for_update(of=("self",), no_key=True).order_by("pk")
    }
    return current_actor, products


def _edge_values(edge: ProductRelationship) -> dict[str, object]:
    return {
        "source_product_id": str(edge.source_product_id),
        "target_product_id": str(edge.target_product_id),
        "relationship_type": edge.relationship_type,
        "is_active": edge.is_active,
        "sort_order": edge.sort_order,
    }


def _audit(
    edge: ProductRelationship,
    actor: User,
    action: Literal["create", "update", "delete"],
    old_values: dict[str, object],
) -> None:
    descriptions = {
        "create": _("Hosting upgrade path created."),
        "update": _("Hosting upgrade path updated."),
        "delete": _("Hosting upgrade path removed."),
    }
    AuditService.log_simple_event(
        action,
        user=actor,
        content_object=edge,
        description=str(descriptions[action]),
        old_values=old_values,
        new_values={} if action == "delete" else _edge_values(edge),
        metadata={"relationship_type": UPGRADE_RELATIONSHIP},
    )


def _validate_direction(*, source_id: UUID, target_id: UUID, edge_id: UUID | None, is_active: bool, using: str) -> None:
    if source_id == target_id:
        raise ValidationError(_("A product cannot upgrade to itself."))
    edges = ProductRelationship.objects.using(using).filter(relationship_type=UPGRADE_RELATIONSHIP)
    if edge_id is not None:
        edges = edges.exclude(pk=edge_id)
    if edges.filter(source_product_id=source_id, target_product_id=target_id).exists():
        raise ValidationError(_("This upgrade path already exists. Edit the existing link instead."))
    if not is_active:
        return
    adjacency: dict[UUID, set[UUID]] = {}
    for source, target in edges.filter(is_active=True).values_list("source_product_id", "target_product_id"):
        adjacency.setdefault(source, set()).add(target)
    if source_id in adjacency.get(target_id, set()):
        raise ValidationError(_("An active upgrade path already exists in the opposite direction."))
    pending, visited = [target_id], set()
    while pending:
        candidate = pending.pop()
        if candidate == source_id:
            raise ValidationError(_("This upgrade path would create a cycle."))
        if candidate not in visited:
            visited.add(candidate)
            pending.extend(adjacency.get(candidate, set()) - visited)


def save_upgrade_path(  # noqa: PLR0913 -- Explicit source, target and existing edge identity.
    *,
    actor: User,
    source_product_id: UUID,
    target_product_id: UUID,
    relationship_id: UUID | None = None,
    is_active: bool = True,
    sort_order: int = 0,
) -> ProductRelationship:
    """The graph curates direction; checkout separately validates price and compatibility."""
    if type(is_active) is not bool or type(sort_order) is not int or not 0 <= sort_order <= 2**31 - 1:
        raise ValidationError(_("Choose a valid active state and non-negative display order."))
    using = router.db_for_write(ProductRelationship)
    with transaction.atomic(using=using):
        current_actor, products = _locked_catalog(actor, using)
        if source_product_id not in products:
            raise Product.DoesNotExist
        if target_product_id not in products:
            raise ValidationError(_("Select an existing target product."))
        edge = None
        if relationship_id is not None:
            edge = (
                ProductRelationship.objects.using(using)
                .select_for_update(of=("self",))
                .get(pk=relationship_id, source_product_id=source_product_id, relationship_type=UPGRADE_RELATIONSHIP)
            )
        _validate_direction(
            source_id=source_product_id,
            target_id=target_product_id,
            edge_id=relationship_id,
            is_active=is_active,
            using=using,
        )
        old_values = _edge_values(edge) if edge is not None else {}
        created = edge is None
        if edge is None:
            edge = ProductRelationship(source_product_id=source_product_id, relationship_type=UPGRADE_RELATIONSHIP)
        edge.target_product_id, edge.is_active, edge.sort_order = target_product_id, is_active, sort_order
        edge.save(using=using)
        _audit(edge, current_actor, "create" if created else "update", old_values)
        return edge


def ensure_upgrade_path(
    *, actor: User, source_product_id: UUID, target_product_id: UUID
) -> tuple[ProductRelationship, bool]:
    """Idempotent dev seed: preserve an existing link's active/order/config fields."""
    using = router.db_for_write(ProductRelationship)
    with transaction.atomic(using=using):
        _locked_catalog(actor, using)
        existing = (
            ProductRelationship.objects.using(using)
            .filter(
                source_product_id=source_product_id,
                target_product_id=target_product_id,
                relationship_type=UPGRADE_RELATIONSHIP,
            )
            .first()
        )
        if existing is not None:
            return existing, False
        return save_upgrade_path(
            actor=actor, source_product_id=source_product_id, target_product_id=target_product_id
        ), True


def remove_upgrade_path(*, actor: User, source_product_id: UUID, relationship_id: UUID) -> None:
    using = router.db_for_write(ProductRelationship)
    with transaction.atomic(using=using):
        current_actor, _products = _locked_catalog(actor, using)
        edge = (
            ProductRelationship.objects.using(using)
            .select_for_update(of=("self",))
            .get(pk=relationship_id, source_product_id=source_product_id, relationship_type=UPGRADE_RELATIONSHIP)
        )
        _audit(edge, current_actor, "delete", _edge_values(edge))
        edge.delete(using=using)
