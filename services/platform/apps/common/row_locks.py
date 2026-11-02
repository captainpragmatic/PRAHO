"""Fresh relationship reads after root-only row locking inside an existing transaction."""

from __future__ import annotations

from django.db import connections, transaction
from django.db.models import Model, QuerySet, Subquery
from django.db.models.expressions import BaseExpression, OuterRef, RawSQL, ResolvedOuterRef
from django.db.models.sql.query import Query
from django.db.models.sql.where import ExtraWhere, WhereNode


def _unsupported_expression(expression: object) -> bool:
    if isinstance(expression, (OuterRef, ResolvedOuterRef, RawSQL, ExtraWhere)):
        return True
    if isinstance(expression, WhereNode):
        return any(_unsupported_expression(child) for child in expression.children)
    if isinstance(expression, Query):
        return bool(expression.external_aliases) or _unsupported_expression(expression.where)
    if isinstance(expression, BaseExpression):
        return any(_unsupported_expression(child) for child in expression.get_source_expressions())
    return False


def lock_many_and_load[ModelT: Model](
    queryset: QuerySet[ModelT], *, no_key: bool = False, nowait: bool = False, skip_locked: bool = False
) -> list[ModelT]:
    """Lock roots in PK order, then reload eligible locked roots with fresh relations.

    Two statements for nonempty results, plus requested prefetches. An empty
    locked set needs only the lock statement. Related data is fresh at reload;
    callers must explicitly lock relationships that must stay stable until commit.
    """
    query = queryset.query
    if (
        query.select_for_update or query.is_sliced or not query.default_cols
        or query.distinct or query.annotations or query.group_by or query.combinator
        or query.extra or query.extra_tables or query.extra_order_by or _unsupported_expression(query.where)
    ):
        raise ValueError("Row lock helpers require an unlocked, unsliced, unprojected model queryset without aggregation")
    if nowait and skip_locked:
        raise ValueError("nowait and skip_locked are mutually exclusive")

    # select_for_update marks its clone for write routing without executing it.
    # Resolve once so neither statement can drift to a read replica.
    alias = queryset.select_for_update(of=("self",)).db
    if not connections[alias].in_atomic_block:
        raise transaction.TransactionManagementError("Row lock helpers require an atomic transaction on the write database")
    source = queryset.using(alias).all()
    candidates = source.order_by().values("pk")
    roots = (
        queryset.model._base_manager.using(alias)  # Source filters remain in the candidate subquery.
        .filter(pk__in=Subquery(candidates))
        .order_by("pk")
        .select_for_update(of=("self",), no_key=no_key, nowait=nowait, skip_locked=skip_locked)
    )
    locked_pks = list(roots.values_list("pk", flat=True))
    # Reapply every eligibility/tenant predicate against a new statement snapshot.
    # In particular, a FK retargeted while waiting must use its new joined row.
    return list(source.filter(pk__in=locked_pks))


def lock_one_and_load[ModelT: Model](
    queryset: QuerySet[ModelT], *, no_key: bool = False, nowait: bool = False, skip_locked: bool = False
) -> ModelT:
    """The single-object variant preserves get()'s model-specific exceptions."""
    rows = lock_many_and_load(queryset, no_key=no_key, nowait=nowait, skip_locked=skip_locked)
    if not rows:
        # Django adds these exceptions to each concrete model class.
        raise queryset.model.DoesNotExist(f"{queryset.model.__name__} matching query does not exist.")  # type: ignore[attr-defined]
    if len(rows) != 1:
        raise queryset.model.MultipleObjectsReturned(f"get() returned more than one {queryset.model.__name__}: {len(rows)}")  # type: ignore[attr-defined]
    return rows[0]
