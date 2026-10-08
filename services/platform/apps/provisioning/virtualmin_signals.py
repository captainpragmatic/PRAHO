"""
Virtualmin-specific signals for PRAHO Platform
Comprehensive Virtualmin account and provisioning job lifecycle management.

Includes:
- Virtualmin account lifecycle events (creation, updates, deletion)
- Virtualmin provisioning job status tracking
- Security event logging for Virtualmin operations
- Cross-app notification helpers for provisioning completion
"""

import logging
from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
)
from apps.common.transactions import best_effort_atomic, swallow_application_errors

from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

logger = logging.getLogger(__name__)


# ===============================================================================
# VIRTUALMIN INTEGRATION SIGNALS
# ===============================================================================


def _log_optional_virtualmin_event(
    event_data: Callable[[], AuditEventData], *, context: Callable[[], AuditContext]
) -> None:
    # Build the payload inside the savepoint too: it may load server/account relations.
    with best_effort_atomic(logger=logger, scope="Virtualmin", message="Virtualmin audit failed"):
        AuditService.log_event(event_data(), context=context())


@receiver(post_save, sender=VirtualminAccount)
def audit_virtualmin_account_changes(
    sender: type[VirtualminAccount], instance: VirtualminAccount, created: bool, **kwargs: Any
) -> None:
    """
    Audit all Virtualmin account lifecycle events for GDPR compliance.

    Logs:
    - Account creation/modification/deletion
    - Status changes (active, suspended, disabled)
    - Server assignments and migrations
    - Customer relationship changes
    """
    # Check if audit signals are disabled (for testing)
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return

    with swallow_application_errors(
        logger=logger, scope="provisioning", message="audit_virtualmin_account_changes failed"
    ):
        if created:
            # Log account creation
            _log_optional_virtualmin_event(
                lambda: AuditEventData(
                    event_type="virtualmin_account_created",
                    content_object=instance,
                    new_values={
                        "domain": instance.domain,
                        "server": str(instance.server.hostname) if instance.server else None,
                        "status": instance.status,
                        "customer_id": str(instance.praho_customer_id) if instance.praho_customer_id else None,
                        "service_id": str(instance.service_id),
                    },
                    description=f"Virtualmin account created for domain {instance.domain}",
                ),
                context=lambda: AuditContext(
                    actor_type="system",
                    metadata={
                        "source_app": "provisioning",
                        "compliance_event": True,
                        "provisioning_action": True,
                        "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                        "requires_gdpr_logging": True,
                    },
                ),
            )

            logger.info(f"✅ [ProvisioningAudit] Created Virtualmin account for {instance.domain}")

        else:
            # Log account updates
            update_fields = kwargs.get("update_fields")

            if update_fields:
                if "status" in update_fields:
                    # Status change is critical for compliance
                    _log_optional_virtualmin_event(
                        lambda: AuditEventData(
                            event_type="virtualmin_account_status_changed",
                            content_object=instance,
                            new_values={"status": instance.status},
                            description=f"Virtualmin account status changed to {instance.status} for {instance.domain}",
                        ),
                        context=lambda: AuditContext(
                            actor_type="system",
                            metadata={
                                "source_app": "provisioning",
                                "compliance_event": True,
                                "provisioning_action": True,
                                "status_change": True,
                                "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                            },
                        ),
                    )

                if "server" in update_fields:
                    # Server migration
                    _log_optional_virtualmin_event(
                        lambda: AuditEventData(
                            event_type="virtualmin_account_server_migrated",
                            content_object=instance,
                            new_values={"server": str(instance.server.hostname) if instance.server else None},
                            description=f"Virtualmin account migrated to server {instance.server.hostname if instance.server else 'None'} for {instance.domain}",
                        ),
                        context=lambda: AuditContext(
                            user=None,
                            actor_type="system",
                            metadata={
                                "source_app": "provisioning",
                                "compliance_event": True,
                                "provisioning_action": True,
                                "server_migration": True,
                                "requires_infrastructure_review": True,
                            },
                        ),
                    )
            else:
                # General update
                _log_optional_virtualmin_event(
                    lambda: AuditEventData(
                        event_type="virtualmin_account_updated",
                        content_object=instance,
                        description=f"Virtualmin account updated for {instance.domain}",
                    ),
                    context=lambda: AuditContext(
                        user=None,
                        actor_type="system",
                        metadata={
                            "source_app": "provisioning",
                            "compliance_event": True,
                            "provisioning_action": True,
                            "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                        },
                    ),
                )


@receiver(pre_delete, sender=VirtualminAccount)
def audit_virtualmin_account_deletion(
    sender: type[VirtualminAccount], instance: VirtualminAccount, **kwargs: Any
) -> None:
    """
    Audit Virtualmin account deletion for GDPR compliance.

    Critical for maintaining immutable audit trails of account lifecycle.
    """
    # Check if audit signals are disabled (for testing)
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return

    with swallow_application_errors(
        logger=logger, scope="provisioning", message="audit_virtualmin_account_deletion failed"
    ):
        _log_optional_virtualmin_event(
            lambda: AuditEventData(
                event_type="virtualmin_account_deleted",
                content_object=instance,
                old_values={
                    "domain": instance.domain,
                    "server": str(instance.server.hostname) if instance.server else None,
                    "status": instance.status,
                    "customer_id": str(instance.praho_customer_id) if instance.praho_customer_id else None,
                    "service_id": str(instance.service_id),
                },
                description=f"Virtualmin account deleted for domain {instance.domain}",
            ),
            context=lambda: AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "compliance_event": True,
                    "provisioning_action": True,
                    "account_termination": True,
                    "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                    "requires_gdpr_logging": True,
                    "data_retention_trigger": True,
                },
            ),
        )

        logger.info(f"🗑️ [ProvisioningAudit] Deleted Virtualmin account for {instance.domain}")


def audit_job_status_transition(
    job: VirtualminProvisioningJob, *, actor_type: str = "system", user: Any = None
) -> None:
    """Emit the job status-change audit event for CAS transitions.

    Token-fenced backup/restore transitions use queryset.update(), which fires
    no post_save signal — call sites invoke this so ADR-0016 coverage holds and
    every terminal outcome (incl. takeovers and operator resolutions) is on the
    immutable trail.
    """
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return
    AuditService.log_event(
        AuditEventData(
            event_type=f"virtualmin_provisioning_job_{job.status}",
            content_object=job,
            new_values={
                "status": job.status,
                "status_message": job.status_message or None,
                "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            },
            description=f"Virtualmin provisioning job {job.status}: {job.operation} for "
            f"{job.account.domain if job.account else 'unknown'}",
        ),
        context=AuditContext(
            actor_type=actor_type,
            user=user,
            metadata={
                "source_app": "provisioning",
                "operational_event": True,
                "provisioning_job": True,
                "job_status_change": True,
                "correlation_id": job.correlation_id,
                "virtualmin_server": str(job.server.hostname) if job.server else None,
                "requires_monitoring_alert": job.status in ("failed", "attention"),
            },
        ),
    )


@receiver(post_save, sender=VirtualminProvisioningJob)
def audit_virtualmin_provisioning_jobs(
    sender: type[VirtualminProvisioningJob], instance: VirtualminProvisioningJob, created: bool, **kwargs: Any
) -> None:
    """
    Audit Virtualmin provisioning job lifecycle for operational tracking.

    Logs job creation, status changes, and completion for monitoring and debugging.
    """
    # Check if audit signals are disabled (for testing)
    if getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
        return

    with swallow_application_errors(
        logger=logger, scope="provisioning", message="audit_virtualmin_provisioning_jobs failed"
    ):
        if created:
            # Log job creation
            _log_optional_virtualmin_event(
                lambda: AuditEventData(
                    event_type="virtualmin_provisioning_job_created",
                    content_object=instance,
                    new_values={
                        "operation": instance.operation,
                        "status": instance.status,
                        "correlation_id": instance.correlation_id,
                        "account_domain": instance.account.domain if instance.account else None,
                        "server": str(instance.server.hostname) if instance.server else None,
                    },
                    description=f"Virtualmin provisioning job created: {instance.operation} for {instance.account.domain if instance.account else 'unknown'}",
                ),
                context=lambda: AuditContext(
                    actor_type="system",
                    metadata={
                        "source_app": "provisioning",
                        "operational_event": True,
                        "provisioning_job": True,
                        "correlation_id": instance.correlation_id,
                        "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                    },
                ),
            )
        else:
            # Log job status changes
            update_fields = kwargs.get("update_fields")

            if update_fields and "status" in update_fields:
                # Job status change
                event_action = f"virtualmin_provisioning_job_{instance.status}"

                _log_optional_virtualmin_event(
                    lambda: AuditEventData(
                        event_type=event_action,
                        content_object=instance,
                        new_values={
                            "status": instance.status,
                            "status_message": instance.status_message if instance.status_message else None,
                            "completed_at": instance.completed_at.isoformat() if instance.completed_at else None,
                        },
                        description=f"Virtualmin provisioning job {instance.status}: {instance.operation} for {instance.account.domain if instance.account else 'unknown'}",
                    ),
                    context=lambda: AuditContext(
                        actor_type="system",
                        metadata={
                            "source_app": "provisioning",
                            "operational_event": True,
                            "provisioning_job": True,
                            "job_status_change": True,
                            "correlation_id": instance.correlation_id,
                            "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                            "requires_monitoring_alert": instance.status == "failed",
                        },
                    ),
                )
