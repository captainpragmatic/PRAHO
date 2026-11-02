"""Revision-aware policy persistence under the same server gate as window admission."""

from __future__ import annotations

from datetime import time
from typing import TYPE_CHECKING, TypedDict
from uuid import UUID

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from apps.audit.services import AuditContext, AuditEventData, AuditService
from apps.infrastructure.node_maintenance_models import NodeMaintenancePolicy, NodeMaintenanceWindow
from apps.infrastructure.node_maintenance_service import require_maintenance_operator

if TYPE_CHECKING:
    from apps.users.models import User


class PolicyValues(TypedDict):
    timezone: str
    weekdays: list[int]
    starts_time: time
    ends_time: time
    max_defer_minutes: int


def save_maintenance_policy(
    node_id: UUID, *, actor: User, values: PolicyValues, expected_revision: int | None
) -> NodeMaintenancePolicy:
    """The posted revision is evidence of review; the freshly locked row owns authority."""
    from apps.provisioning.virtualmin_models import VirtualminServer  # noqa: PLC0415  # Cross-app server gate.

    require_maintenance_operator(actor)
    with transaction.atomic():
        try:
            node = VirtualminServer.objects.select_for_update(of=("self",)).get(pk=node_id)
        except VirtualminServer.DoesNotExist as error:
            raise ValidationError(
                _("The server is no longer registered. Reload before changing its policy.")
            ) from error
        policy = NodeMaintenancePolicy.objects.select_for_update(of=("self",)).filter(node=node).first()
        if (policy is not None and expected_revision != policy.revision) or (
            policy is None and expected_revision not in (None, 0)
        ):
            raise ValidationError(_("This maintenance policy changed. Reload and review the current revision."))
        if NodeMaintenanceWindow.objects.filter(node=node, status__in=("scheduled", "running", "overran")).exists():
            raise ValidationError(_("Cancel or finish the applicable window before changing its scheduling policy."))
        if policy is None:
            policy = NodeMaintenancePolicy(node=node)
        else:
            policy.revision += 1
        policy.timezone = values["timezone"]
        policy.weekdays = values["weekdays"]
        policy.starts_time = values["starts_time"]
        policy.ends_time = values["ends_time"]
        policy.max_defer_minutes = values["max_defer_minutes"]
        policy.updated_by = actor
        policy.full_clean()
        policy.save()
        AuditService.log_event(
            AuditEventData(
                event_type="node_window_policy",
                content_object=policy,
                new_values={
                    "revision": policy.revision,
                    "timezone": policy.timezone,
                    "weekdays": policy.weekdays,
                    "starts_time": policy.starts_time.isoformat(),
                    "ends_time": policy.ends_time.isoformat(),
                    "max_defer_minutes": policy.max_defer_minutes,
                },
                description="Operator configured the permitted maintenance intervals.",
            ),
            AuditContext(user=actor, actor_type="user"),
        )
        return policy
