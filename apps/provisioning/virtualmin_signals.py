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
from typing import Any

from django.conf import settings
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
)
from apps.common.validators import log_security_event

from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob

logger = logging.getLogger(__name__)


# ===============================================================================
# VIRTUALMIN INTEGRATION SIGNALS
# ===============================================================================


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

    try:
        if created:
            # Log account creation
            AuditService.log_event(
                AuditEventData(
                    event_type="virtualmin_account_created",
                    content_object=instance,
                    new_values={
                        "domain": instance.domain,
                        "server": str(instance.server.hostname) if instance.server else None,
                        "status": instance.status,
                        "customer_id": str(instance.praho_customer_id) if instance.praho_customer_id else None,
                        "service_id": str(instance.praho_service_id) if instance.praho_service_id else None,
                    },
                    description=f"Virtualmin account created for domain {instance.domain}",
                ),
                context=AuditContext(
                    actor_type="system", 
                    metadata={
                        "source_app": "provisioning",
                        "compliance_event": True,
                        "provisioning_action": True,
                        "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                        "requires_gdpr_logging": True,
                    }
                ),
            )
            
            logger.info(f"✅ [ProvisioningAudit] Created Virtualmin account for {instance.domain}")
            
        else:
            # Log account updates
            update_fields = kwargs.get("update_fields")
            
            if update_fields:
                if "status" in update_fields:
                    # Status change is critical for compliance
                    AuditService.log_event(
                        AuditEventData(
                            event_type="virtualmin_account_status_changed",
                            content_object=instance,
                            new_values={"status": instance.status},
                            description=f"Virtualmin account status changed to {instance.status} for {instance.domain}",
                        ),
                        context=AuditContext(
                            actor_type="system", 
                            metadata={
                                "source_app": "provisioning",
                                "compliance_event": True,
                                "provisioning_action": True,
                                "status_change": True,
                                "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                            }
                        ),
                    )
                
                if "server" in update_fields:
                    # Server migration
                    AuditService.log_event(
                        AuditEventData(
                            action="virtualmin_account_server_migrated",
                            user=None,
                            content_object=instance,
                            new_values={"server": str(instance.server.hostname) if instance.server else None},
                            description=f"Virtualmin account migrated to server {instance.server.hostname if instance.server else 'None'} for {instance.domain}",
                            metadata={
                                "compliance_event": True,
                                "provisioning_action": True,
                                "server_migration": True,
                                "requires_infrastructure_review": True,
                            },
                            context=AuditContext(actor_type="system", metadata={"source_app": "provisioning"}),
                        )
                    )
            else:
                # General update
                AuditService.log_event(
                    AuditEventData(
                        action="virtualmin_account_updated",
                        user=None,
                        content_object=instance,
                        description=f"Virtualmin account updated for {instance.domain}",
                        metadata={
                            "compliance_event": True,
                            "provisioning_action": True,
                            "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                        },
                        context=AuditContext(actor_type="system", metadata={"source_app": "provisioning"}),
                    )
                )

    except Exception as e:
        logger.error(f"🔥 [ProvisioningAudit] Failed to audit Virtualmin account changes: {e}")


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

    try:
        AuditService.log_event(
            AuditEventData(
                event_type="virtualmin_account_deleted",
                content_object=instance,
                old_values={
                    "domain": instance.domain,
                    "server": str(instance.server.hostname) if instance.server else None,
                    "status": instance.status,
                    "customer_id": str(instance.praho_customer_id) if instance.praho_customer_id else None,
                    "service_id": str(instance.praho_service_id) if instance.praho_service_id else None,
                },
                description=f"Virtualmin account deleted for domain {instance.domain}",
            ),
            context=AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "compliance_event": True,
                    "provisioning_action": True,
                    "account_termination": True,
                    "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                    "requires_gdpr_logging": True,
                    "data_retention_trigger": True,
                }
            ),
        )
        
        logger.info(f"🗑️ [ProvisioningAudit] Deleted Virtualmin account for {instance.domain}")
        
    except Exception as e:
        logger.error(f"🔥 [ProvisioningAudit] Failed to audit Virtualmin account deletion: {e}")


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

    try:
        if created:
            # Log job creation
            AuditService.log_event(
                AuditEventData(
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
                context=AuditContext(
                    actor_type="system",
                    metadata={
                        "source_app": "provisioning",
                        "operational_event": True,
                        "provisioning_job": True,
                        "correlation_id": instance.correlation_id,
                        "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                    }
                ),
            )
        else:
            # Log job status changes
            update_fields = kwargs.get("update_fields")
            
            if update_fields and "status" in update_fields:
                # Job status change
                event_action = f"virtualmin_provisioning_job_{instance.status}"
                
                AuditService.log_event(
                    AuditEventData(
                        event_type=event_action,
                        content_object=instance,
                        new_values={
                            "status": instance.status,
                            "status_message": instance.status_message if instance.status_message else None,
                            "completed_at": instance.completed_at.isoformat() if instance.completed_at else None,
                        },
                        description=f"Virtualmin provisioning job {instance.status}: {instance.operation} for {instance.account.domain if instance.account else 'unknown'}",
                    ),
                    context=AuditContext(
                        actor_type="system",
                        metadata={
                            "source_app": "provisioning",
                            "operational_event": True,
                            "provisioning_job": True,
                            "job_status_change": True,
                            "correlation_id": instance.correlation_id,
                            "virtualmin_server": str(instance.server.hostname) if instance.server else None,
                            "requires_monitoring_alert": instance.status == "failed",
                        }
                    ),
                )

    except Exception as e:
        logger.error(f"🔥 [ProvisioningAudit] Failed to audit Virtualmin provisioning job: {e}")


# ===============================================================================
# VIRTUALMIN HELPER FUNCTIONS
# ===============================================================================


def log_virtualmin_security_event(event_type: str, details: dict[str, Any], ip_address: str | None = None) -> None:
    """
    Log security events related to Virtualmin operations.
    
    Used by services for logging authentication failures, suspicious activity, etc.
    """
    try:
        log_security_event(
            event_type,
            {
                **details,
                "source_app": "provisioning",
                "virtualmin_integration": True,
                "timestamp": timezone.now().isoformat(),
            },
            ip_address,
        )
        
        logger.warning(f"🔒 [VirtualminSecurity] {event_type}: {details}")
        
    except Exception as e:
        logger.error(f"🔥 [VirtualminSecurity] Failed to log security event: {e}")


def notify_provisioning_completion(account: VirtualminAccount, success: bool, details: dict[str, Any] | None = None) -> None:
    """
    Helper function to notify other apps of provisioning completion.
    
    Can be used by provisioning services to trigger cross-app workflows.
    """
    try:
        # Log completion for audit trail
        AuditService.log_event(
            AuditEventData(
                event_type="virtualmin_provisioning_completed",
                content_object=account,
                new_values={
                    "success": success,
                    "domain": account.domain,
                    "server": str(account.server.hostname) if account.server else None,
                    "details": details or {},
                },
                description=f"Virtualmin provisioning {'completed successfully' if success else 'failed'} for {account.domain}",
            ),
            context=AuditContext(
                actor_type="system",
                metadata={
                    "source_app": "provisioning",
                    "provisioning_completion": True,
                    "cross_app_notification": True,
                    "virtualmin_server": str(account.server.hostname) if account.server else None,
                    "success": success,
                }
            ),
        )
        
        # TODO: Add hooks for other apps (billing notifications, customer communications, etc.)
        # This can be extended to trigger:
        # - Welcome emails with control panel credentials
        # - Billing activation notifications
        # - Customer dashboard updates
        
        logger.info(f"🔔 [ProvisioningNotification] Notified provisioning completion for {account.domain}: {'success' if success else 'failure'}")
        
    except Exception as e:
        logger.error(f"🔥 [ProvisioningNotification] Failed to notify provisioning completion: {e}")
