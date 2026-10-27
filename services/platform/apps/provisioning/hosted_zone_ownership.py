"""Serialize hosting ownership changes against DNS publication without moving customer zones.

Ownership writers take Account rows, then AccountHostname rows, then Service rows, all in
primary-key order. Publishers already hold the name. The final Service lock also excludes
new FK links; a changed account inventory causes a retry rather than locking a new Account
after a Name. Unchanged identity fields are omitted from incidental full saves.
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Iterable, Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, ClassVar, Literal, TypeVar, cast

from django.core.exceptions import ValidationError
from django.db import models, router, transaction
from django.utils.translation import gettext_lazy as _

if TYPE_CHECKING:
    from .service_models import Service
    from .virtualmin_models import VirtualminAccount

OwnedModel = TypeVar("OwnedModel", bound=models.Model)
OwnershipKind = Literal["service", "account"]
_MISSING = object()
_SAVE_POSITIONAL = ("force_insert", "force_update", "using", "update_fields")
_SAVE_FIELD_INTENT = "_dns_save_field_intent"


def save_field_intent(instance: models.Model, fallback: Collection[str] | None) -> Collection[str] | None:
    """Signal consumers observe the caller's write intent, before ownership SQL filtering."""
    return cast("Collection[str] | None", instance.__dict__.get(_SAVE_FIELD_INTENT, fallback))


def _save_with_field_intent(
    instance: models.Model,
    save: Callable[..., None],
    kwargs: dict[str, Any],
    intent: Collection[str] | None,
) -> None:
    previous = instance.__dict__.get(_SAVE_FIELD_INTENT, _MISSING)
    instance.__dict__[_SAVE_FIELD_INTENT] = intent
    try:
        save(**kwargs)
    finally:
        if previous is _MISSING:
            instance.__dict__.pop(_SAVE_FIELD_INTENT, None)
        else:
            instance.__dict__[_SAVE_FIELD_INTENT] = previous


def _field(kind: OwnershipKind) -> str:
    return "customer" if kind == "service" else "service"


def _snapshot_key(kind: OwnershipKind) -> str:
    return "_dns_loaded_" + _field(kind) + "_id"


def remember_ownership(instance: models.Model, kind: OwnershipKind) -> None:
    attribute = _field(kind) + "_id"
    if attribute in instance.__dict__:
        instance.__dict__[_snapshot_key(kind)] = instance.__dict__[attribute]


def _identity(value: Any) -> int:
    if isinstance(value, models.Model):
        value = value.pk
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise ValidationError(_("Hosting ownership changes require a concrete saved identity."))
    try:
        identifier = int(value)
    except (ValueError, TypeError) as error:
        raise ValidationError(_("Invalid hosting ownership identity.")) from error
    if identifier <= 0:
        raise ValidationError(_("Invalid hosting ownership identity."))
    return identifier


def _stale() -> ValidationError:
    return ValidationError(
        _("Hosting ownership changed while this edit was waiting. Reload and review the current owner.")
    )


def _accounts(using: str) -> models.QuerySet[Any]:
    from .virtualmin_models import VirtualminAccount  # noqa: PLC0415  # Models import this fence.

    return VirtualminAccount.objects.using(using)


def _services(using: str) -> models.QuerySet[Any]:
    from .service_models import Service  # noqa: PLC0415  # Models import this fence.

    return Service.objects.using(using)


def _lock_account_names(account_ids: Iterable[Any], using: str) -> dict[Any, int]:
    from .account_hostname_models import AccountHostname  # noqa: PLC0415  # Models import this fence.

    identifiers = tuple(account_ids)
    # Publication can finish deferred FK checks against the Account while holding its Name.
    # NO KEY UPDATE still excludes account changes but permits those KEY SHARE checks, so
    # the publisher can commit and release the Name this ownership writer is waiting for.
    locked = dict(
        _accounts(using)
        .filter(pk__in=identifiers)
        .order_by("pk")
        .select_for_update(of=("self",), no_key=True)
        .values_list("pk", "service_id")
    )
    list(
        AccountHostname.objects.using(using)
        .filter(account_id__in=locked)
        .order_by("pk")
        .select_for_update(of=("self",))
        .values_list("pk", flat=True)
    )
    return locked


def _lock_services(identifiers: Iterable[int], using: str) -> dict[int, int]:
    return dict(
        _services(using)
        .filter(pk__in=tuple(identifiers))
        .order_by("pk")
        .select_for_update(of=("self",))
        .values_list("pk", "customer_id")
    )


@contextmanager
def fence_service_ownership(expected: dict[Any, int], *, using: str) -> Iterator[None]:
    with transaction.atomic(using=using):
        accounts = dict(_accounts(using).filter(service_id__in=expected).values_list("pk", "service_id"))
        locked = _lock_account_names(accounts, using)
        current = _lock_services(expected, using)
        fresh_accounts = dict(_accounts(using).filter(service_id__in=expected).values_list("pk", "service_id"))
        if current != expected or locked != accounts or fresh_accounts != accounts:
            raise _stale()
        yield


@contextmanager
def fence_account_ownership(expected: dict[Any, int], desired: Iterable[int], *, using: str) -> Iterator[None]:
    with transaction.atomic(using=using):
        service_ids = set(expected.values()) | set(desired)
        owners = dict(_services(using).filter(pk__in=service_ids).values_list("pk", "customer_id"))
        locked = _lock_account_names(expected, using)
        current_owners = _lock_services(service_ids, using)
        if locked != expected or owners != current_owners or set(current_owners) != service_ids:
            raise _stale()
        yield


def _fence(kind: OwnershipKind, expected: dict[Any, int], desired: Iterable[int], using: str) -> Any:
    return (
        fence_service_ownership(expected, using=using)
        if kind == "service"
        else fence_account_ownership(expected, desired, using=using)
    )


def save_with_ownership(
    instance: models.Model,
    kind: OwnershipKind,
    save: Callable[..., None],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> None:
    kwargs = dict(kwargs)
    if len(args) > len(_SAVE_POSITIONAL):
        raise TypeError("Model.save() accepts at most four positional arguments.")
    for key, value in zip(_SAVE_POSITIONAL, args, strict=False):
        if key in kwargs:
            raise TypeError(f"save() received {key} twice")
        kwargs[key] = value
    field = _field(kind)
    attribute = field + "_id"
    fields = kwargs.get("update_fields")
    if fields is not None:
        fields = set(fields)
        kwargs["update_fields"] = fields
    intent = fields
    desired = instance.__dict__.get(attribute, _MISSING)
    if (fields is not None and not {field, attribute}.intersection(fields)) or desired is _MISSING:
        _save_with_field_intent(instance, save, kwargs, intent)
        return
    loaded = instance.__dict__.get(_snapshot_key(kind), _MISSING)
    if not instance._state.adding and desired == loaded:
        # A full form/monitoring save must never write a cached ownership FK back to the DB.
        if fields is None:
            fields = {
                item.name
                for item in instance._meta.concrete_fields
                if not item.primary_key and item.attname not in instance.get_deferred_fields()
            }
        kwargs["update_fields"] = fields - {field, attribute}
        _save_with_field_intent(instance, save, kwargs, intent)
        return
    using = kwargs.get("using") or router.db_for_write(type(instance), instance=instance)
    source = _services(using) if kind == "service" else _accounts(using)
    current = (
        source.filter(pk=instance.pk).values_list(attribute, flat=True).first() if instance.pk is not None else None
    )
    if current is None:
        _save_with_field_intent(instance, save, kwargs, intent)
        remember_ownership(instance, kind)
        return
    expected = current if loaded is _MISSING else loaded
    with _fence(kind, {instance.pk: expected}, (_identity(desired),), using):
        _save_with_field_intent(instance, save, kwargs, intent)
    remember_ownership(instance, kind)


class _OwnershipQuerySet(models.QuerySet[OwnedModel]):
    ownership_kind: ClassVar[OwnershipKind]

    def update(self, **kwargs: Any) -> int:
        field = _field(self.ownership_kind)
        key = field if field in kwargs else field + "_id"
        if key not in kwargs:
            return super().update(**kwargs)
        if field in kwargs and field + "_id" in kwargs:
            raise ValidationError(_("Specify hosting ownership once."))
        self._for_write = True
        desired = _identity(kwargs[key])
        expected = dict(self.values_list("pk", field + "_id"))
        if not expected:
            return 0
        with _fence(self.ownership_kind, expected, (desired,), self.db):
            # Only the frozen selection was locked; a newly matching row is never swept into this update.
            rows: models.QuerySet[Any] = models.QuerySet(model=self.model, using=self.db).filter(pk__in=expected)
            return rows.update(**{**kwargs, key: desired})

    def bulk_update(self, objs: Iterable[Any], fields: Iterable[str], batch_size: int | None = None) -> int:
        objects, selected_fields = tuple(objs), tuple(fields)
        field = _field(self.ownership_kind)
        if not {field, field + "_id"}.intersection(selected_fields):
            return super().bulk_update(objects, selected_fields, batch_size=batch_size)
        self._for_write = True
        current = dict(self.filter(pk__in=[obj.pk for obj in objects]).values_list("pk", field + "_id"))
        chosen = [obj for obj in objects if obj.pk in current]
        expected = {obj.pk: obj.__dict__.get(_snapshot_key(self.ownership_kind), current[obj.pk]) for obj in chosen}
        desired = [_identity(getattr(obj, field + "_id")) for obj in chosen]
        with _fence(self.ownership_kind, expected, desired, self.db):
            rows: models.QuerySet[Any] = models.QuerySet(model=self.model, using=self.db).filter(pk__in=expected)
            count = rows.bulk_update(chosen, selected_fields, batch_size=batch_size)
        for obj in chosen:
            remember_ownership(obj, self.ownership_kind)
        return count


class ServiceOwnershipQuerySet(_OwnershipQuerySet["Service"]):
    model: type[Service]
    ownership_kind = "service"


class AccountOwnershipQuerySet(_OwnershipQuerySet["VirtualminAccount"]):
    model: type[VirtualminAccount]
    ownership_kind = "account"
