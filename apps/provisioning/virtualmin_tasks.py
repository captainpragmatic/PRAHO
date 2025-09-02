"""
Virtualmin Celery Tasks - PRAHO Platform
Asynchronous provisioning tasks for Virtualmin operations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from celery import shared_task  # type: ignore[import-untyped]
from django.core.cache import cache
from django.db import models
from django.utils import timezone

from apps.provisioning.models import Service

from .virtualmin_models import (
    VirtualminAccount,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from .virtualmin_service import (
    VirtualminProvisioningService,
    VirtualminServerManagementService,
)

logger = logging.getLogger(__name__)

# Task configuration
TASK_RETRY_DELAY = 300  # 5 minutes
TASK_MAX_RETRIES = 3
TASK_SOFT_TIME_LIMIT = 600  # 10 minutes
TASK_TIME_LIMIT = 900  # 15 minutes


@dataclass
class VirtualminProvisioningConfig:
    """Configuration for Virtualmin provisioning task."""
    service_id: str
    domain: str
    username: str | None = None
    password: str | None = None
    template: str = "Default"
    server_id: str | None = None


@shared_task(
    bind=True,
    max_retries=TASK_MAX_RETRIES,
    default_retry_delay=TASK_RETRY_DELAY,
    soft_time_limit=TASK_SOFT_TIME_LIMIT,
    time_limit=TASK_TIME_LIMIT,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_jitter=True
)
def provision_virtualmin_account(
    self: Any,
    service_id: str,
    domain: str,
    username: str | None = None,
    password: str | None = None,
    template: str = "Default",
    server_id: str | None = None
) -> dict[str, Any]:
    """
    Async task to provision Virtualmin account.
    
    Args:
        service_id: PRAHO service UUID
        domain: Primary domain name
        username: Virtualmin username (auto-generated if None)
        password: Account password (auto-generated if None)
        template: Virtualmin template name
        server_id: Target server UUID (auto-selected if None)
        
    Returns:
        Dictionary with provisioning result
        
    Raises:
        Exception: On provisioning failure (triggers retry)
    """
    task_id = self.request.id
    correlation_id = f"provision_{task_id}"
    
    logger.info(
        f"🔄 [VirtualminTask] Starting provisioning for domain {domain} "
        f"(service: {service_id}, correlation: {correlation_id})"
    )
    
    try:
        # Get service
        try:
            service = Service.objects.get(id=service_id)
        except Service.DoesNotExist:
            error_msg = f"Service {service_id} not found"
            logger.error(f"❌ [VirtualminTask] {error_msg}")
            return {"success": False, "error": error_msg}
            
        # Get server if specified
        server = None
        if server_id:
            try:
                server = VirtualminServer.objects.get(id=server_id)
            except VirtualminServer.DoesNotExist:
                error_msg = f"Server {server_id} not found"
                logger.error(f"❌ [VirtualminTask] {error_msg}")
                return {"success": False, "error": error_msg}
                
        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(server)
        
        # Execute provisioning
        result = provisioning_service.create_virtualmin_account(
            service=service,
            domain=domain,
            username=username,
            password=password,
            template=template,
            server=server
        )
        
        if result.is_ok():
            account = result.unwrap()
            success_data = {
                "success": True,
                "account_id": str(account.id),
                "domain": account.domain,
                "server": account.server.hostname,
                "status": account.status
            }
            
            logger.info(
                f"✅ [VirtualminTask] Provisioned {domain} successfully "
                f"(account: {account.id}, server: {account.server.hostname})"
            )
            
            return success_data
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Provisioning failed for {domain}: {error_msg}")
            
            # Check if this is a retryable error
            if self.request.retries < self.max_retries and _is_retryable_error(error_msg):
                    logger.warning(
                        f"🔄 [VirtualminTask] Retrying provision {domain} "
                        f"(attempt {self.request.retries + 1}/{self.max_retries})"
                    )
                    raise Exception(error_msg)  # Trigger retry
                    
            return {"success": False, "error": error_msg}
            
    except Exception as e:
        error_msg = str(e)
        logger.exception(f"💥 [VirtualminTask] Unexpected error provisioning {domain}: {e}")
        
        # Don't retry on the final attempt
        if self.request.retries >= self.max_retries:
            return {"success": False, "error": error_msg}
            
        # Re-raise to trigger retry
        raise


@shared_task(
    bind=True,
    max_retries=TASK_MAX_RETRIES,
    default_retry_delay=TASK_RETRY_DELAY,
    soft_time_limit=300,  # 5 minutes for suspension
    time_limit=600
)
def suspend_virtualmin_account(self: Any, account_id: str, reason: str = "") -> dict[str, Any]:
    """
    Async task to suspend Virtualmin account.
    
    Args:
        account_id: VirtualminAccount UUID
        reason: Suspension reason
        
    Returns:
        Dictionary with suspension result
    """
    task_id = self.request.id
    
    logger.info(f"🔄 [VirtualminTask] Suspending account {account_id} (task: {task_id})")
    
    try:
        # Get account
        try:
            account = VirtualminAccount.objects.get(id=account_id)
        except VirtualminAccount.DoesNotExist:
            error_msg = f"Account {account_id} not found"
            logger.error(f"❌ [VirtualminTask] {error_msg}")
            return {"success": False, "error": error_msg}
            
        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(account.server)
        
        # Execute suspension
        result = provisioning_service.suspend_account(account, reason)
        
        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Suspended {account.domain} successfully")
            return {
                "success": True,
                "account_id": str(account.id),
                "domain": account.domain,
                "reason": reason
            }
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Suspension failed for {account.domain}: {error_msg}")
            
            if self.request.retries < self.max_retries and _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry
                
            return {"success": False, "error": error_msg}
            
    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error suspending account {account_id}: {e}")
        
        if self.request.retries >= self.max_retries:
            return {"success": False, "error": str(e)}
            
        raise


@shared_task(
    bind=True,
    max_retries=TASK_MAX_RETRIES,
    default_retry_delay=TASK_RETRY_DELAY,
    soft_time_limit=300,
    time_limit=600
)
def unsuspend_virtualmin_account(self: Any, account_id: str) -> dict[str, Any]:
    """
    Async task to unsuspend Virtualmin account.
    
    Args:
        account_id: VirtualminAccount UUID
        
    Returns:
        Dictionary with unsuspension result
    """
    task_id = self.request.id
    
    logger.info(f"🔄 [VirtualminTask] Unsuspending account {account_id} (task: {task_id})")
    
    try:
        # Get account
        try:
            account = VirtualminAccount.objects.get(id=account_id)
        except VirtualminAccount.DoesNotExist:
            error_msg = f"Account {account_id} not found"
            logger.error(f"❌ [VirtualminTask] {error_msg}")
            return {"success": False, "error": error_msg}
            
        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(account.server)
        
        # Execute unsuspension
        result = provisioning_service.unsuspend_account(account)
        
        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Unsuspended {account.domain} successfully")
            return {
                "success": True,
                "account_id": str(account.id),
                "domain": account.domain
            }
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Unsuspension failed for {account.domain}: {error_msg}")
            
            if self.request.retries < self.max_retries and _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry
                
            return {"success": False, "error": error_msg}
            
    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error unsuspending account {account_id}: {e}")
        
        if self.request.retries >= self.max_retries:
            return {"success": False, "error": str(e)}
            
        raise


@shared_task(
    bind=True,
    max_retries=TASK_MAX_RETRIES,
    default_retry_delay=TASK_RETRY_DELAY,
    soft_time_limit=600,  # 10 minutes for deletion
    time_limit=900
)
def delete_virtualmin_account(self: Any, account_id: str) -> dict[str, Any]:
    """
    Async task to delete Virtualmin account.
    
    Args:
        account_id: VirtualminAccount UUID
        
    Returns:
        Dictionary with deletion result
    """
    task_id = self.request.id
    
    logger.info(f"🔄 [VirtualminTask] Deleting account {account_id} (task: {task_id})")
    
    try:
        # Get account
        try:
            account = VirtualminAccount.objects.get(id=account_id)
        except VirtualminAccount.DoesNotExist:
            error_msg = f"Account {account_id} not found"
            logger.error(f"❌ [VirtualminTask] {error_msg}")
            return {"success": False, "error": error_msg}
            
        domain = account.domain  # Store for logging after deletion
        
        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(account.server)
        
        # Execute deletion
        result = provisioning_service.delete_account(account)
        
        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Deleted {domain} successfully")
            return {
                "success": True,
                "account_id": str(account.id),
                "domain": domain
            }
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Deletion failed for {domain}: {error_msg}")
            
            if self.request.retries < self.max_retries and _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry
                
            return {"success": False, "error": error_msg}
            
    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error deleting account {account_id}: {e}")
        
        if self.request.retries >= self.max_retries:
            return {"success": False, "error": str(e)}
            
        raise


@shared_task(
    bind=True,
    soft_time_limit=1800,  # 30 minutes for health checks
    time_limit=2400
)
def health_check_virtualmin_servers(self: Any) -> dict[str, Any]:
    """
    Periodic task to health check all Virtualmin servers.
    
    Returns:
        Dictionary with health check results
    """
    task_id = self.request.id
    
    logger.info(f"🔄 [VirtualminTask] Starting server health checks (task: {task_id})")
    
    try:
        # Prevent concurrent health checks
        lock_key = "virtualmin_health_check_lock"
        if cache.get(lock_key):
            logger.info("⏭️ [VirtualminTask] Health check already running, skipping")
            return {"success": True, "message": "Already running"}
            
        # Set lock for 30 minutes
        cache.set(lock_key, True, 1800)
        
        try:
            servers = VirtualminServer.objects.filter(status="active")
            results = {
                "total_servers": servers.count(),
                "healthy_servers": 0,
                "unhealthy_servers": 0,
                "servers": []
            }
            
            management_service = VirtualminServerManagementService()
            
            for server in servers:
                logger.info(f"🏥 [VirtualminTask] Health checking {server.hostname}")
                
                health_result = management_service.health_check_server(server)
                
                server_result = {
                    "hostname": server.hostname,
                    "healthy": health_result.is_ok(),
                    "last_check": timezone.now().isoformat()
                }
                
                if health_result.is_ok():
                    results["healthy_servers"] += 1
                    server_result["data"] = health_result.unwrap()
                else:
                    results["unhealthy_servers"] += 1
                    server_result["error"] = health_result.unwrap_err()
                    
                results["servers"].append(server_result)
                
            logger.info(
                f"✅ [VirtualminTask] Health check completed: "
                f"{results['healthy_servers']}/{results['total_servers']} healthy"
            )
            
            return {"success": True, "results": results}
            
        finally:
            # Always release lock
            cache.delete(lock_key)
            
    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error in health check: {e}")
        return {"success": False, "error": str(e)}


@shared_task(
    bind=True,
    soft_time_limit=3600,  # 1 hour for statistics update
    time_limit=4800
)
def update_virtualmin_server_statistics(self: Any) -> dict[str, Any]:
    """
    Periodic task to update server statistics from Virtualmin.
    
    Returns:
        Dictionary with statistics update results
    """
    task_id = self.request.id
    
    logger.info(f"🔄 [VirtualminTask] Updating server statistics (task: {task_id})")
    
    try:
        # Prevent concurrent statistics updates
        lock_key = "virtualmin_stats_update_lock"
        if cache.get(lock_key):
            logger.info("⏭️ [VirtualminTask] Statistics update already running, skipping")
            return {"success": True, "message": "Already running"}
            
        # Set lock for 1 hour
        cache.set(lock_key, True, 3600)
        
        try:
            servers = VirtualminServer.objects.filter(status="active")
            results = {
                "total_servers": servers.count(),
                "updated_servers": 0,
                "failed_servers": 0,
                "servers": []
            }
            
            management_service = VirtualminServerManagementService()
            
            for server in servers:
                logger.info(f"📊 [VirtualminTask] Updating statistics for {server.hostname}")
                
                stats_result = management_service.update_server_statistics(server)
                
                server_result = {
                    "hostname": server.hostname,
                    "updated": stats_result.is_ok(),
                    "last_update": timezone.now().isoformat()
                }
                
                if stats_result.is_ok():
                    results["updated_servers"] += 1
                    server_result["statistics"] = stats_result.unwrap()
                else:
                    results["failed_servers"] += 1
                    server_result["error"] = stats_result.unwrap_err()
                    
                results["servers"].append(server_result)
                
            logger.info(
                f"✅ [VirtualminTask] Statistics update completed: "
                f"{results['updated_servers']}/{results['total_servers']} updated"
            )
            
            return {"success": True, "results": results}
            
        finally:
            # Always release lock
            cache.delete(lock_key)
            
    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error updating statistics: {e}")
        return {"success": False, "error": str(e)}


@shared_task(
    bind=True,
    max_retries=1,  # Limited retries for job processing
    default_retry_delay=60
)
def process_failed_virtualmin_jobs(self: Any) -> dict[str, Any]:
    """
    Process failed Virtualmin jobs that can be retried.
    
    Returns:
        Dictionary with job processing results
    """
    task_id = self.request.id
    
    logger.info(f"🔄 [VirtualminTask] Processing failed jobs (task: {task_id})")
    
    try:
        # Get failed jobs that can be retried
        now = timezone.now()
        retryable_jobs = VirtualminProvisioningJob.objects.filter(
            status="failed",
            retry_count__lt=models.F('max_retries'),
            next_retry_at__lte=now
        ).select_related('server', 'account')
        
        results = {
            "total_jobs": retryable_jobs.count(),
            "retried_jobs": 0,
            "skipped_jobs": 0,
            "jobs": []
        }
        
        for job in retryable_jobs[:50]:  # Limit to 50 jobs per run
            try:
                # Schedule job for retry
                job.schedule_retry()
                
                # Trigger appropriate task based on operation
                if job.operation == "create_domain" and job.account:
                    provision_virtualmin_account.delay(
                        str(job.account.service.id),
                        job.account.domain,
                        job.account.virtualmin_username,
                        server_id=str(job.server.id)
                    )
                elif job.operation == "suspend_domain" and job.account:
                    suspend_virtualmin_account.delay(
                        str(job.account.id),
                        job.parameters.get("reason", "")
                    )
                elif job.operation == "unsuspend_domain" and job.account:
                    unsuspend_virtualmin_account.delay(str(job.account.id))
                elif job.operation == "delete_domain" and job.account:
                    delete_virtualmin_account.delay(str(job.account.id))
                    
                results["retried_jobs"] += 1
                results["jobs"].append({
                    "job_id": str(job.id),
                    "operation": job.operation,
                    "status": "retried"
                })
                
                logger.info(
                    f"🔄 [VirtualminTask] Retried job {job.id} ({job.operation})"
                )
                
            except Exception as e:
                results["skipped_jobs"] += 1
                results["jobs"].append({
                    "job_id": str(job.id),
                    "operation": job.operation,
                    "status": "skipped",
                    "error": str(e)
                })
                
                logger.warning(
                    f"⚠️ [VirtualminTask] Failed to retry job {job.id}: {e}"
                )
                
        logger.info(
            f"✅ [VirtualminTask] Job processing completed: "
            f"{results['retried_jobs']} retried, {results['skipped_jobs']} skipped"
        )
        
        return {"success": True, "results": results}
        
    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error processing failed jobs: {e}")
        return {"success": False, "error": str(e)}


def _is_retryable_error(error_message: str) -> bool:
    """
    Determine if an error is retryable.
    
    Args:
        error_message: Error message to analyze
        
    Returns:
        True if error should be retried
    """
    retryable_patterns = [
        "connection timeout",
        "connection error",
        "server error",
        "timeout",
        "temporarily unavailable",
        "service unavailable",
        "rate limit",
        "network error",
        "dns error"
    ]
    
    error_lower = error_message.lower()
    return any(pattern in error_lower for pattern in retryable_patterns)


# Celery beat schedule for periodic tasks
# Add to settings.py:
"""
CELERY_BEAT_SCHEDULE = {
    'virtualmin-health-check': {
        'task': 'apps.provisioning.virtualmin_tasks.health_check_virtualmin_servers',
        'schedule': crontab(minute=0),  # Every hour
    },
    'virtualmin-update-statistics': {
        'task': 'apps.provisioning.virtualmin_tasks.update_virtualmin_server_statistics',
        'schedule': crontab(minute=30, hour='*/6'),  # Every 6 hours
    },
    'virtualmin-process-failed-jobs': {
        'task': 'apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs',
        'schedule': crontab(minute='*/15'),  # Every 15 minutes
    },
}
"""
