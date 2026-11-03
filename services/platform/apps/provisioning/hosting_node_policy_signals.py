"""Audit reviewed native policy decisions without exposing node evidence."""

from typing import Any

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.audit.services import AuditService
from apps.audit.switches import audit_signals_disabled

from .hosting_node_policy_models import NodeHostingExecution, NodeHostingPolicy, NodeHostingReview


@receiver(post_save, sender=NodeHostingPolicy)
@receiver(post_save, sender=NodeHostingReview)
@receiver(post_save, sender=NodeHostingExecution)
def audit_node_hosting_policy(sender: type, instance: Any, created: bool, **kwargs: Any) -> None:
    if not audit_signals_disabled():
        values = {
            name: str(getattr(instance, name))
            for name in (
                "server_id",
                "policy_version",
                "revision",
                "quota_adopted",
                "notification_owner",
                "operation",
                "digest",
                "action",
                "actor_id",
                "reason",
                "authority",
                "status",
                "review_id",
                "verification_id",
            )
            if hasattr(instance, name)
        }
        AuditService.log_simple_event(
            "create" if created else "update",
            content_object=instance,
            description="Native hosting policy review or ownership changed",
            new_values=values,
        )
