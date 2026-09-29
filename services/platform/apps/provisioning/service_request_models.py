"""Service change requests reviewed privately inside support tickets."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any, ClassVar

from django.db import models
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransitionMixin, FSMField, transition

SERVICE_REQUEST_NOTE_LIMIT = 4000


class ServiceRequest(ConcurrentTransitionMixin, models.Model):
    class Action(models.TextChoices):
        UPGRADE = "upgrade_request", _("Upgrade request")
        DOWNGRADE = "downgrade_request", _("Downgrade request")
        SUSPEND = "suspend_request", _("Suspension request")
        CANCEL = "cancel_request", _("Cancellation request")

    class Status(models.TextChoices):
        PENDING = "pending", _("Pending review")
        APPROVED = "approved", _("Approved; awaiting manual completion")
        REJECTED = "rejected", _("Rejected")
        COMPLETED = "completed", _("Completed")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ticket = models.OneToOneField("tickets.Ticket", on_delete=models.CASCADE, related_name="service_request")
    customer = models.ForeignKey("customers.Customer", on_delete=models.PROTECT, editable=False)
    service = models.ForeignKey("provisioning.Service", on_delete=models.PROTECT, editable=False)
    requested_by = models.ForeignKey(
        "users.User", on_delete=models.PROTECT, related_name="service_requests", editable=False
    )
    submission_id = models.UUIDField(editable=False)
    action = models.CharField(max_length=24, choices=Action.choices, editable=False)
    reason = models.TextField(max_length=SERVICE_REQUEST_NOTE_LIMIT, blank=True, editable=False)
    status = FSMField(max_length=16, choices=Status.choices, default=Status.PENDING, protected=True)
    reviewed_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="reviewed_service_requests"
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    last_decision_note = models.TextField(max_length=SERVICE_REQUEST_NOTE_LIMIT, blank=True, editable=False)
    last_decision_from_status = models.CharField(max_length=16, blank=True, editable=False)
    completed_by = models.ForeignKey(
        "users.User", on_delete=models.SET_NULL, null=True, blank=True, related_name="completed_service_requests"
    )
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=["customer", "requested_by", "submission_id"], name="unique_customer_service_submission"
            ),
            models.CheckConstraint(
                condition=models.Q(status__in=["pending", "approved", "rejected", "completed"]),
                name="service_request_valid_status",
            ),
            models.CheckConstraint(
                condition=models.Q(
                    action__in=["upgrade_request", "downgrade_request", "suspend_request", "cancel_request"]
                ),
                name="service_request_valid_action",
            ),
        ]

    @transition(field=status, source=Status.PENDING, target=Status.APPROVED)
    def approve(self) -> None:
        """Record approval; execution remains a separate staff operation."""

    @transition(field=status, source=[Status.PENDING, Status.APPROVED], target=Status.REJECTED)
    def reject(self) -> None:
        """Decline the request, including one previously approved."""

    @transition(field=status, source=Status.APPROVED, target=Status.COMPLETED)
    def complete(self) -> None:
        """Record that staff has carried out and verified the change."""

    def refresh_from_db(
        self,
        using: str | None = None,
        fields: Iterable[str] | None = None,
        from_queryset: models.QuerySet[ServiceRequest] | None = None,
    ) -> None:
        saved: dict[str, Any] = {}
        if (fields is None or "status" in fields) and "status" in self.__dict__:
            saved["status"] = self.__dict__.pop("status")
        try:
            super().refresh_from_db(using=using, fields=fields, from_queryset=from_queryset)
        except Exception:
            self.__dict__.update(saved)
            raise
