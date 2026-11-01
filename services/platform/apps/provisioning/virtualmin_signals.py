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

from django.db.models.signals import post_save, pre_delete, pre_save
from django.dispatch import receiver

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
)
from apps.audit.switches import audit_signals_disabled
from apps.common.transactions import best_effort_atomic, swallow_application_errors

from .component_migration_models import (
    ComponentMigrationApproval,
    ComponentMigrationReview,
    SourceServiceObligation,
    SourceServiceRelease,
)
from .hosted_zone_ownership import save_field_intent
from .virtualmin_migration_models import MigrationBridge
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from .virtualmin_security_models import NodeSecurityDecision, NodeSecurityExecution, NodeSecurityReview

logger = logging.getLogger(__name__)


@receiver(post_save, sender=ComponentMigrationReview)
def audit_component_inspection(
    sender: type[ComponentMigrationReview], instance: ComponentMigrationReview, created: bool, **kwargs: Any
) -> None:
    if created and not audit_signals_disabled():
        AuditService.log_event(
            AuditEventData(
                event_type="security_scan_detected",
                severity="low",
                content_object=instance,
                description="Recorded native website component scope and retained service dependencies",
                new_values={
                    "account_id": str(instance.account_id),
                    "digest": instance.digest,
                    "authority_digest": instance.authority_digest,
                    "policy_version": instance.policy_version,
                },
            ),
            context=AuditContext(user=instance.actor, metadata={"source_app": "provisioning"}),
        )


@receiver(post_save, sender=ComponentMigrationApproval)
def audit_component_approval(
    sender: type[ComponentMigrationApproval], instance: ComponentMigrationApproval, created: bool, **kwargs: Any
) -> None:
    if created and not audit_signals_disabled():
        AuditService.log_event(
            AuditEventData(
                event_type="configuration_changed",
                content_object=instance,
                description="Accepted website component impact and independent retained source backup responsibility",
                new_values={"review_id": str(instance.review_id), "authority_digest": instance.review.authority_digest},
            ),
            context=AuditContext(user=instance.actor, metadata={"source_app": "provisioning"}),
        )


@receiver(post_save, sender=SourceServiceRelease)
def audit_source_responsibility_release(
    sender: type[SourceServiceRelease], instance: SourceServiceRelease, created: bool, **kwargs: Any
) -> None:
    if created and not audit_signals_disabled():
        AuditService.log_event(
            AuditEventData(
                event_type="configuration_changed",
                content_object=instance,
                description="Resolved retained source services after native absence and independent backup handoff",
                new_values={
                    "obligation_id": str(instance.obligation_id),
                    "native_absence_digest": instance.native_absence_digest,
                    "source_identity": instance.source_identity,
                },
            ),
            context=AuditContext(user=instance.actor, metadata={"source_app": "provisioning"}),
        )


@receiver(post_save, sender=SourceServiceObligation)
def audit_retained_source_services(
    sender: type[SourceServiceObligation], instance: SourceServiceObligation, created: bool, **kwargs: Any
) -> None:
    if created and not audit_signals_disabled():
        AuditService.log_event(
            AuditEventData(
                event_type="configuration_changed",
                content_object=instance,
                description="Operator accepted independent backup responsibility for retained source services",
                new_values={
                    "source_server_id": str(instance.source_server_id),
                    "source_domain_id": instance.source_domain_id,
                    "migration_id": str(instance.migration_id),
                    "retained_services": instance.retained_services,
                },
            ),
            context=AuditContext(user=instance.backup_responsible, metadata={"source_app": "provisioning"}),
        )


@receiver(post_save, sender=NodeSecurityReview)
def audit_node_security_review(
    sender: type[NodeSecurityReview], instance: NodeSecurityReview, created: bool, **kwargs: Any
) -> None:
    """Audit only the evidence reference, never copy a remote payload into audit storage."""
    if created and not audit_signals_disabled():
        AuditService.log_event(
            AuditEventData(
                event_type="security_scan_detected",
                severity="low",  # Recording evidence is not a detected incident.
                content_object=instance,
                description="Node security inspection recorded",
                new_values={
                    "server_id": str(instance.server_id),
                    "digest": instance.digest,
                    "policy_version": instance.policy_version,
                },
            ),
            context=AuditContext(actor_type="system", metadata={"source_app": "provisioning"}),
        )


@receiver(post_save, sender=NodeSecurityDecision)
def audit_node_security_decision(
    sender: type[NodeSecurityDecision], instance: NodeSecurityDecision, created: bool, **kwargs: Any
) -> None:
    """A source acknowledgment is an operator action, never a verification result."""
    if created and not audit_signals_disabled():
        AuditService.log_event(
            AuditEventData(
                event_type="configuration_changed",
                content_object=instance,
                description="Operator recorded a node security decision",
                new_values={"review_id": str(instance.review_id), "action": instance.action},
            ),
            context=AuditContext(user=instance.actor, metadata={"source_app": "provisioning"}),
        )


@receiver(pre_save, sender=NodeSecurityExecution)
def remember_security_execution_status(
    sender: type[NodeSecurityExecution], instance: NodeSecurityExecution, **kwargs: Any
) -> None:
    instance.__dict__["_previous_security_status"] = (
        sender.objects.filter(pk=instance.pk).values_list("status", flat=True).first()
        if not instance._state.adding
        else None
    )


@receiver(post_save, sender=NodeSecurityExecution)
def audit_security_execution(
    sender: type[NodeSecurityExecution], instance: NodeSecurityExecution, created: bool, **kwargs: Any
) -> None:
    if audit_signals_disabled() or (
        not created and instance.__dict__.get("_previous_security_status") == instance.status
    ):
        return
    verified_review = instance.verification
    AuditService.log_event(
        AuditEventData(
            event_type="configuration_changed",
            content_object=instance,
            description="Node hardening execution state changed",
            new_values={
                "server_id": str(instance.server_uuid),
                "status": instance.status,
                "decision_id": str(instance.decision_id),
                "verification_id": str(instance.verification_id),
            },
        ),
        context=AuditContext(
            user=verified_review.decision.actor if verified_review is not None else instance.decision.actor,
            metadata={"source_app": "provisioning"},
        ),
    )


# ===============================================================================
# VIRTUALMIN INTEGRATION SIGNALS
# ===============================================================================


@receiver(pre_save, sender=MigrationBridge)
def remember_bridge_status(sender: type[MigrationBridge], instance: MigrationBridge, **kwargs: Any) -> None:
    instance.__dict__["_previous_bridge_status"] = (
        sender.objects.filter(pk=instance.pk).values_list("status", flat=True).first()
        if not instance._state.adding
        else None
    )


@receiver(post_save, sender=MigrationBridge)
def audit_bridge_lifecycle(
    sender: type[MigrationBridge], instance: MigrationBridge, created: bool, **kwargs: Any
) -> None:
    """A bridge outlives its cutover; evidence and lease updates are not business transitions."""
    if audit_signals_disabled() or (
        not created and instance.__dict__.get("_previous_bridge_status") == instance.status
    ):
        return
    action = {
        "pending": "virtualmin_bridge_pending",
        "active": "virtualmin_bridge_active",
        "removing_source": "virtualmin_bridge_removing_source",
        "torn_down": "virtualmin_bridge_torn_down",
        "failed": "virtualmin_bridge_failed",
    }[instance.status]
    _log_optional_virtualmin_event(
        lambda: AuditEventData(
            event_type=action,
            content_object=instance,
            description=f"Migration bridge {instance.pk}: {instance.status}",
            new_values={"status": instance.status, "migration_id": str(instance.migration_id)},
        ),
        context=lambda: AuditContext(actor_type="system", metadata={"source_app": "provisioning"}),
    )


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
    if audit_signals_disabled():
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
            update_fields = save_field_intent(instance, kwargs.get("update_fields"))

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
    if audit_signals_disabled():
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
    if audit_signals_disabled():
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
    if audit_signals_disabled():
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
