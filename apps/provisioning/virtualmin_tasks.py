"""
Virtualmin Django-Q2 Tasks - PRAHO Platform
Asynchronous provisioning tasks for Virtualmin operations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, TypedDict

from django.core.cache import cache
from django.db import models
from django.utils import timezone
from django_q.models import Schedule as ScheduleModel
from django_q.tasks import async_task, schedule

from apps.provisioning.models import Service

from .virtualmin_models import (
    VirtualminAccount,
    VirtualminProvisioningJob,
    VirtualminServer,
)
from .virtualmin_service import (
    VirtualminAccountCreationData,
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


class VirtualminProvisioningParams(TypedDict, total=False):
    """Parameters for Virtualmin account provisioning"""

    service_id: str
    domain: str
    username: str | None
    password: str | None
    template: str
    server_id: str | None


def provision_virtualmin_account(params: VirtualminProvisioningParams) -> dict[str, Any]:
    """
    Sync task to provision Virtualmin account.

    Args:
        params: VirtualminProvisioningParams containing all provisioning parameters

    Returns:
        Dictionary with provisioning result

    Raises:
        Exception: On provisioning failure (triggers retry)
    """
    service_id = params["service_id"]
    domain = params["domain"]
    correlation_id = f"provision_{service_id}_{domain}"

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
        server_id = params.get("server_id")
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
        creation_data = VirtualminAccountCreationData(
            service=service,
            domain=domain,
            username=params.get("username"),
            password=params.get("password"),
            template=params.get("template", "Default"),
            server=server,
        )
        result = provisioning_service.create_virtualmin_account(creation_data)

        if result.is_ok():
            account = result.unwrap()
            success_data = {
                "success": True,
                "account_id": str(account.id),
                "domain": account.domain,
                "server": account.server.hostname,
                "status": account.status,
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
            if _is_retryable_error(error_msg):
                logger.warning(f"🔄 [VirtualminTask] Retryable error for {domain}")
                raise Exception(error_msg)  # Trigger retry in django-q2

            return {"success": False, "error": error_msg}

    except Exception as e:
        error_msg = str(e)
        logger.exception(f"💥 [VirtualminTask] Unexpected error provisioning {domain}: {e}")

        # Re-raise to trigger retry
        raise


def suspend_virtualmin_account(account_id: str, reason: str = "") -> dict[str, Any]:
    """
    Sync task to suspend Virtualmin account.

    Args:
        account_id: VirtualminAccount UUID
        reason: Suspension reason

    Returns:
        Dictionary with suspension result
    """
    logger.info(f"🔄 [VirtualminTask] Suspending account {account_id}")

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
            return {"success": True, "account_id": str(account.id), "domain": account.domain, "reason": reason}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Suspension failed for {account.domain}: {error_msg}")

            if _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry

            return {"success": False, "error": error_msg}

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error suspending account {account_id}: {e}")
        raise


def unsuspend_virtualmin_account(account_id: str) -> dict[str, Any]:
    """
    Sync task to unsuspend Virtualmin account.

    Args:
        account_id: VirtualminAccount UUID

    Returns:
        Dictionary with unsuspension result
    """
    logger.info(f"🔄 [VirtualminTask] Unsuspending account {account_id}")

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
            return {"success": True, "account_id": str(account.id), "domain": account.domain}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Unsuspension failed for {account.domain}: {error_msg}")

            if _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry

            return {"success": False, "error": error_msg}

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error unsuspending account {account_id}: {e}")
        raise


def delete_virtualmin_account(account_id: str) -> dict[str, Any]:
    """
    Sync task to delete Virtualmin account.

    Args:
        account_id: VirtualminAccount UUID

    Returns:
        Dictionary with deletion result
    """
    logger.info(f"🔄 [VirtualminTask] Deleting account {account_id}")

    try:
        # Get account
        try:
            account = VirtualminAccount.objects.get(id=account_id)
        except VirtualminAccount.DoesNotExist:
            error_msg = f"Account {account_id} not found"
            logger.error(f"❌ [VirtualminTask] {error_msg}")
            return {"success": False, "error": error_msg}

        # Note: Protection check is handled in the service layer
        domain = account.domain  # Store for logging after deletion

        # Create provisioning service
        provisioning_service = VirtualminProvisioningService(account.server)

        # Execute deletion
        result = provisioning_service.delete_account(account)

        if result.is_ok():
            logger.info(f"✅ [VirtualminTask] Deleted {domain} successfully")
            return {"success": True, "account_id": str(account.id), "domain": domain}
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [VirtualminTask] Deletion failed for {domain}: {error_msg}")

            if _is_retryable_error(error_msg):
                raise Exception(error_msg)  # Trigger retry

            return {"success": False, "error": error_msg}

    except Exception as e:
        logger.exception(f"💥 [VirtualminTask] Error deleting account {account_id}: {e}")
        raise


def health_check_virtualmin_servers() -> dict[str, Any]:
    """
    Periodic task to health check all Virtualmin servers.

    Returns:
        Dictionary with health check results
    """
    logger.info("🔄 [VirtualminTask] Starting server health checks")

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
            results: dict[str, Any] = {
                "total_servers": servers.count(),
                "healthy_servers": 0,
                "unhealthy_servers": 0,
                "servers": [],
            }

            management_service = VirtualminServerManagementService()

            for server in servers:
                logger.info(f"🏥 [VirtualminTask] Health checking {server.hostname}")

                health_result = management_service.health_check_server(server)

                server_result = {
                    "hostname": server.hostname,
                    "healthy": health_result.is_ok(),
                    "last_check": timezone.now().isoformat(),
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


def update_virtualmin_server_statistics() -> dict[str, Any]:
    """
    Periodic task to update server statistics from Virtualmin.

    Returns:
        Dictionary with statistics update results
    """
    logger.info("🔄 [VirtualminTask] Updating server statistics")

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
            results: dict[str, Any] = {
                "total_servers": servers.count(),
                "updated_servers": 0,
                "failed_servers": 0,
                "servers": [],
            }

            management_service = VirtualminServerManagementService()

            for server in servers:
                logger.info(f"📊 [VirtualminTask] Updating statistics for {server.hostname}")

                stats_result = management_service.update_server_statistics(server)

                server_result = {
                    "hostname": server.hostname,
                    "updated": stats_result.is_ok(),
                    "last_update": timezone.now().isoformat(),
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


def process_failed_virtualmin_jobs() -> dict[str, Any]:
    """
    Process failed Virtualmin jobs that can be retried.

    Returns:
        Dictionary with job processing results
    """
    logger.info("🔄 [VirtualminTask] Processing failed jobs")

    try:
        # Get failed jobs that can be retried
        now = timezone.now()
        retryable_jobs = VirtualminProvisioningJob.objects.filter(
            status="failed", retry_count__lt=models.F("max_retries"), next_retry_at__lte=now
        ).select_related("server", "account")

        results: dict[str, Any] = {
            "total_jobs": retryable_jobs.count(),
            "retried_jobs": 0,
            "skipped_jobs": 0,
            "jobs": [],
        }

        for job in retryable_jobs[:50]:  # Limit to 50 jobs per run
            try:
                # Schedule job for retry
                job.schedule_retry()

                # Trigger appropriate task based on operation
                if job.operation == "create_domain" and job.account:
                    async_task(
                        "apps.provisioning.virtualmin_tasks.provision_virtualmin_account",
                        str(job.account.service.id),
                        job.account.domain,
                        job.account.virtualmin_username,
                        server_id=str(job.server.id),
                        timeout=TASK_TIME_LIMIT,
                    )
                elif job.operation == "suspend_domain" and job.account:
                    async_task(
                        "apps.provisioning.virtualmin_tasks.suspend_virtualmin_account",
                        str(job.account.id),
                        job.parameters.get("reason", ""),
                        timeout=TASK_TIME_LIMIT,
                    )
                elif job.operation == "unsuspend_domain" and job.account:
                    async_task(
                        "apps.provisioning.virtualmin_tasks.unsuspend_virtualmin_account",
                        str(job.account.id),
                        timeout=TASK_TIME_LIMIT,
                    )
                elif job.operation == "delete_domain" and job.account:
                    async_task(
                        "apps.provisioning.virtualmin_tasks.delete_virtualmin_account",
                        str(job.account.id),
                        timeout=TASK_TIME_LIMIT,
                    )

                results["retried_jobs"] += 1
                results["jobs"].append({"job_id": str(job.id), "operation": job.operation, "status": "retried"})

                logger.info(f"🔄 [VirtualminTask] Retried job {job.id} ({job.operation})")

            except Exception as e:
                results["skipped_jobs"] += 1
                results["jobs"].append(
                    {"job_id": str(job.id), "operation": job.operation, "status": "skipped", "error": str(e)}
                )

                logger.warning(f"⚠️ [VirtualminTask] Failed to retry job {job.id}: {e}")

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
        "dns error",
    ]

    error_lower = error_message.lower()
    return any(pattern in error_lower for pattern in retryable_patterns)


# ===============================================================================
# TASK QUEUE WRAPPER FUNCTIONS
# ===============================================================================


def provision_virtualmin_account_async(params: VirtualminProvisioningParams) -> str:
    """Queue Virtualmin account provisioning task."""
    return async_task(
        "apps.provisioning.virtualmin_tasks.provision_virtualmin_account", params, timeout=TASK_TIME_LIMIT
    )


def suspend_virtualmin_account_async(account_id: str, reason: str = "") -> str:
    """Queue Virtualmin account suspension task."""
    return async_task(
        "apps.provisioning.virtualmin_tasks.suspend_virtualmin_account",
        account_id,
        reason,
        timeout=TASK_SOFT_TIME_LIMIT,
    )


def unsuspend_virtualmin_account_async(account_id: str) -> str:
    """Queue Virtualmin account unsuspension task."""
    return async_task(
        "apps.provisioning.virtualmin_tasks.unsuspend_virtualmin_account", account_id, timeout=TASK_SOFT_TIME_LIMIT
    )


def delete_virtualmin_account_async(account_id: str) -> str:
    """Queue Virtualmin account deletion task."""
    return async_task(
        "apps.provisioning.virtualmin_tasks.delete_virtualmin_account", account_id, timeout=TASK_TIME_LIMIT
    )


# ===============================================================================
# SCHEDULED TASKS SETUP
# ===============================================================================


def setup_virtualmin_scheduled_tasks() -> dict[str, str]:
    """Set up all Virtualmin scheduled tasks."""
    tasks_created = {}

    # Check for existing tasks first
    existing_tasks = list(
        ScheduleModel.objects.filter(
            name__in=["virtualmin-health-check", "virtualmin-statistics", "virtualmin-retry-failed-jobs"]
        ).values_list("name", flat=True)
    )

    # Health check every hour
    if "virtualmin-health-check" not in existing_tasks:
        schedule(
            "apps.provisioning.virtualmin_tasks.health_check_virtualmin_servers",
            schedule_type="H",
            name="virtualmin-health-check",
            cluster="praho-cluster",
        )
        tasks_created["health_check"] = "created"
    else:
        tasks_created["health_check"] = "already_exists"

    # Statistics update every 6 hours
    if "virtualmin-statistics" not in existing_tasks:
        schedule(
            "apps.provisioning.virtualmin_tasks.update_virtualmin_server_statistics",
            schedule_type="C",
            cron="0 */6 * * *",
            name="virtualmin-statistics",
            cluster="praho-cluster",
        )
        tasks_created["statistics"] = "created"
    else:
        tasks_created["statistics"] = "already_exists"

    # Process failed jobs every 15 minutes
    if "virtualmin-retry-failed-jobs" not in existing_tasks:
        schedule(
            "apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs",
            schedule_type="I",
            minutes=15,
            name="virtualmin-retry-failed-jobs",
            cluster="praho-cluster",
        )
        tasks_created["retry_jobs"] = "created"
    else:
        tasks_created["retry_jobs"] = "already_exists"

    logger.info(f"✅ [VirtualminTask] Scheduled tasks setup: {tasks_created}")
    return tasks_created
