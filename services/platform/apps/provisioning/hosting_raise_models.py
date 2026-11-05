"""Persistent overlay identity; accepted terms remain in immutable applications."""

from __future__ import annotations

from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _


class HostingRaiseQuerySet(models.QuerySet["ServiceHostingRaise"]):
    def update(self, **kwargs: Any) -> int:
        from .hosting_raise_service import raise_write_allowed  # noqa: PLC0415 -- Service owns overlay writes.

        if not raise_write_allowed():
            raise ValidationError(_("Use the reviewed hosting raise service to change temporary resources."))
        return super().update(**kwargs)

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError(_("Temporary hosting raises must be reviewed individually."))

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[ServiceHostingRaise]:
        raise ValidationError(_("Temporary hosting raises must be reviewed individually."))

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Temporary hosting raise identity and history cannot be reset."))


class ServiceHostingRaise(models.Model):
    service = models.OneToOneField(
        "provisioning.Service", primary_key=True, on_delete=models.CASCADE, related_name="hosting_raise"
    )
    revision = models.PositiveBigIntegerField(default=1)
    owner_id = models.PositiveBigIntegerField()
    extra_mib = models.PositiveIntegerField()
    first_granted_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=12, choices=[(value, value) for value in ("active", "expired", "revoked")])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = HostingRaiseQuerySet.as_manager()

    class Meta:
        db_table = "provisioning_service_hosting_raise"
        db_table_comment = "Persistent monotonic temporary disk overlay identity, including after expiry."
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.CheckConstraint(condition=models.Q(revision__gte=1), name="hosting_raise_revision_positive"),
            models.CheckConstraint(
                condition=models.Q(expires_at__gt=models.F("first_granted_at")), name="hosting_raise_expiry_after_grant"
            ),
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        from .hosting_raise_service import raise_write_allowed  # noqa: PLC0415 -- Service owns overlay writes.

        if not raise_write_allowed():
            raise ValidationError(_("Use the reviewed hosting raise service to change temporary resources."))
        super().save(*args, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError(_("Temporary hosting raise identity and history cannot be reset."))
