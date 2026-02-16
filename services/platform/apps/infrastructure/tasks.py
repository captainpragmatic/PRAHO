"""
Infrastructure Async Tasks

Django-Q2 tasks for background processing of node deployments.
These tasks are queued and executed asynchronously by Q cluster workers.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.deployment_service import DeploymentResult, get_deployment_service
from apps.infrastructure.validation_service import NodeValidationReport, get_validation_service
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


def deploy_node_task(
    deployment_id: int,
    credentials: dict[str, str],
    cloudflare_api_token: str | None = None,
    user_id: int | None = None,
) -> dict:
    """
    Async task to deploy a node.

    This task is queued via Django-Q2 and executes the complete
    deployment pipeline in the background.

    Args:
        deployment_id: ID of the NodeDeployment to deploy
        credentials: Provider credentials dict (e.g., {"api_token": "xxx"})
        cloudflare_api_token: Cloudflare API token (optional)
        user_id: ID of the user initiating the deployment

    Returns:
        dict with deployment result information
    """
    from apps.infrastructure.models import NodeDeployment
    from apps.users.models import User

    logger.info(f"[Task:deploy_node] Starting deployment for deployment_id={deployment_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:deploy_node] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    service = get_deployment_service()
    result = service.deploy_node(
        deployment=deployment,
        credentials=credentials,
        cloudflare_api_token=cloudflare_api_token,
        user=user,
    )

    if result.is_err():
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "error": result.unwrap_err(),
        }

    deploy_result = result.unwrap()
    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deploy_result.hostname,
        "stages_completed": deploy_result.stages_completed,
        "virtualmin_server_id": deploy_result.virtualmin_server_id,
        "duration_seconds": deploy_result.duration_seconds,
    }


def destroy_node_task(
    deployment_id: int,
    credentials: dict[str, str],
    cloudflare_api_token: str | None = None,
    user_id: int | None = None,
) -> dict:
    """
    Async task to destroy a node.

    Args:
        deployment_id: ID of the NodeDeployment to destroy
        credentials: Provider credentials dict
        cloudflare_api_token: Cloudflare API token
        user_id: ID of the user initiating the destruction

    Returns:
        dict with destruction result information
    """
    from apps.infrastructure.models import NodeDeployment
    from apps.users.models import User

    logger.info(f"[Task:destroy_node] Starting destruction for deployment_id={deployment_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:destroy_node] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    service = get_deployment_service()
    result = service.destroy_node(
        deployment=deployment,
        credentials=credentials,
        cloudflare_api_token=cloudflare_api_token,
        user=user,
    )

    if result.is_err():
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "error": result.unwrap_err(),
        }

    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deployment.hostname,
        "destroyed_at": timezone.now().isoformat(),
    }


def retry_deployment_task(
    deployment_id: int,
    credentials: dict[str, str],
    cloudflare_api_token: str | None = None,
    user_id: int | None = None,
) -> dict:
    """
    Async task to retry a failed deployment.

    Args:
        deployment_id: ID of the failed NodeDeployment to retry
        credentials: Provider credentials dict
        cloudflare_api_token: Cloudflare API token
        user_id: ID of the user initiating the retry

    Returns:
        dict with retry result information
    """
    from apps.infrastructure.models import NodeDeployment
    from apps.users.models import User

    logger.info(f"[Task:retry_deployment] Retrying deployment_id={deployment_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:retry_deployment] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    service = get_deployment_service()
    result = service.retry_deployment(
        deployment=deployment,
        credentials=credentials,
        cloudflare_api_token=cloudflare_api_token,
        user=user,
    )

    if result.is_err():
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "retry_count": deployment.retry_count,
            "error": result.unwrap_err(),
        }

    deploy_result = result.unwrap()
    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deploy_result.hostname,
        "retry_count": deployment.retry_count,
        "stages_completed": deploy_result.stages_completed,
        "duration_seconds": deploy_result.duration_seconds,
    }


def validate_node_task(deployment_id: int) -> dict:
    """
    Async task to validate a deployed node.

    Runs health checks against a deployed node and updates
    its validation status.

    Args:
        deployment_id: ID of the NodeDeployment to validate

    Returns:
        dict with validation result information
    """
    from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog

    logger.info(f"[Task:validate_node] Validating deployment_id={deployment_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:validate_node] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    if not deployment.ipv4_address:
        return {
            "success": False,
            "deployment_id": deployment_id,
            "error": "Deployment has no IP address",
        }

    service = get_validation_service()
    result = service.validate_node(deployment)

    if result.is_err():
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "error": result.unwrap_err(),
        }

    report = result.unwrap()

    # Log validation result
    log_level = "INFO" if report.all_passed else "WARNING"
    NodeDeploymentLog.objects.create(
        deployment=deployment,
        level=log_level,
        message=f"Validation: {report.summary}",
        phase="validation",
    )

    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deployment.hostname,
        "all_passed": report.all_passed,
        "summary": report.summary,
        "checks": [
            {
                "name": check.check_name,
                "passed": check.passed,
                "message": check.message,
            }
            for check in report.checks
        ],
    }


def bulk_validate_nodes_task() -> dict:
    """
    Async task to validate all active deployed nodes.

    This can be scheduled to run periodically to monitor
    the health of all infrastructure.

    Returns:
        dict with overall validation summary
    """
    from apps.infrastructure.models import NodeDeployment

    logger.info("[Task:bulk_validate] Starting bulk validation of all nodes")

    deployments = NodeDeployment.objects.filter(
        status="completed",
        ipv4_address__isnull=False,
    )

    results = []
    passed_count = 0
    failed_count = 0

    service = get_validation_service()

    for deployment in deployments:
        try:
            # Quick health check instead of full validation
            is_healthy = service.quick_health_check(deployment)

            results.append(
                {
                    "deployment_id": deployment.id,
                    "hostname": deployment.hostname,
                    "healthy": is_healthy,
                }
            )

            if is_healthy:
                passed_count += 1
            else:
                failed_count += 1
                logger.warning(f"[Task:bulk_validate] Node unhealthy: {deployment.hostname}")

        except Exception as e:
            logger.error(f"[Task:bulk_validate] Error validating {deployment.hostname}: {e}")
            failed_count += 1
            results.append(
                {
                    "deployment_id": deployment.id,
                    "hostname": deployment.hostname,
                    "healthy": False,
                    "error": str(e),
                }
            )

    logger.info(
        f"[Task:bulk_validate] Complete: {passed_count} healthy, {failed_count} unhealthy "
        f"out of {len(results)} nodes"
    )

    return {
        "success": True,
        "total_nodes": len(results),
        "healthy_count": passed_count,
        "unhealthy_count": failed_count,
        "results": results,
    }


def cleanup_failed_deployments_task(max_age_hours: int = 24) -> dict:
    """
    Async task to clean up old failed deployments.

    Removes Terraform state and temporary files for deployments
    that have been failed for longer than max_age_hours.

    Args:
        max_age_hours: Maximum age in hours before cleanup

    Returns:
        dict with cleanup summary
    """
    from datetime import timedelta
    from pathlib import Path

    from apps.infrastructure.models import NodeDeployment

    logger.info(f"[Task:cleanup] Cleaning up failed deployments older than {max_age_hours}h")

    cutoff = timezone.now() - timedelta(hours=max_age_hours)

    failed_deployments = NodeDeployment.objects.filter(
        status="failed",
        updated_at__lt=cutoff,
    )

    cleaned_count = 0
    errors = []

    terraform_base = Path(
        SettingsService.get_setting("node_deployment.terraform_state_path", "/var/lib/praho/terraform")
    )

    for deployment in failed_deployments:
        try:
            deploy_dir = terraform_base / deployment.hostname

            if deploy_dir.exists():
                import shutil

                shutil.rmtree(deploy_dir)
                logger.info(f"[Task:cleanup] Removed Terraform state: {deploy_dir}")

            cleaned_count += 1

        except Exception as e:
            logger.error(f"[Task:cleanup] Error cleaning {deployment.hostname}: {e}")
            errors.append({"hostname": deployment.hostname, "error": str(e)})

    logger.info(f"[Task:cleanup] Cleaned up {cleaned_count} failed deployments")

    return {
        "success": len(errors) == 0,
        "cleaned_count": cleaned_count,
        "errors": errors,
    }


# ===============================================================================
# LIFECYCLE TASKS
# ===============================================================================


def upgrade_node_task(
    deployment_id: int,
    new_size_id: int,
    credentials: dict[str, str],
    user_id: int | None = None,
) -> dict:
    """
    Async task to upgrade a node to a new size.

    Args:
        deployment_id: ID of the NodeDeployment to upgrade
        new_size_id: ID of the new NodeSize
        credentials: Provider credentials dict
        user_id: ID of the user initiating the upgrade

    Returns:
        dict with upgrade result information
    """
    from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog, NodeSize
    from apps.users.models import User

    logger.info(f"[Task:upgrade_node] Upgrading deployment_id={deployment_id} to size_id={new_size_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:upgrade_node] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    try:
        new_size = NodeSize.objects.get(id=new_size_id)
    except NodeSize.DoesNotExist:
        logger.error(f"[Task:upgrade_node] Size {new_size_id} not found")
        return {"success": False, "error": f"Size {new_size_id} not found"}

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    service = get_deployment_service()
    result = service.upgrade_node_size(
        deployment=deployment,
        new_size=new_size,
        credentials=credentials,
        user=user,
    )

    if result.is_err():
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message=f"Upgrade failed: {result.unwrap_err()}",
            phase="upgrade",
        )
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "error": result.unwrap_err(),
        }

    NodeDeploymentLog.objects.create(
        deployment=deployment,
        level="INFO",
        message=f"Upgraded to {new_size.name}",
        phase="upgrade",
    )

    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deployment.hostname,
        "new_size": new_size.name,
        "upgraded_at": timezone.now().isoformat(),
    }


def maintenance_task(
    deployment_id: int,
    playbooks: list[str] | None = None,
    extra_vars: dict | None = None,
    user_id: int | None = None,
) -> dict:
    """
    Async task to run maintenance playbooks on a node.

    Args:
        deployment_id: ID of the NodeDeployment
        playbooks: List of playbook names to run (optional)
        extra_vars: Extra variables for Ansible (optional)
        user_id: ID of the user initiating maintenance

    Returns:
        dict with maintenance result information
    """
    from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog
    from apps.users.models import User

    logger.info(f"[Task:maintenance] Running maintenance on deployment_id={deployment_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:maintenance] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    service = get_deployment_service()
    result = service.run_maintenance(
        deployment=deployment,
        playbooks=playbooks,
        extra_vars=extra_vars,
        user=user,
    )

    if result.is_err():
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message=f"Maintenance failed: {result.unwrap_err()}",
            phase="maintenance",
        )
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "error": result.unwrap_err(),
        }

    ansible_results = result.unwrap()
    playbook_names = playbooks or ["update"]

    NodeDeploymentLog.objects.create(
        deployment=deployment,
        level="INFO",
        message=f"Maintenance completed: {', '.join(playbook_names)}",
        phase="maintenance",
    )

    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deployment.hostname,
        "playbooks_run": playbook_names,
        "results_count": len(ansible_results),
        "completed_at": timezone.now().isoformat(),
    }


def stop_node_task(
    deployment_id: int,
    credentials: dict[str, str],
    user_id: int | None = None,
) -> dict:
    """
    Async task to stop (power off) a node.

    Args:
        deployment_id: ID of the NodeDeployment to stop
        credentials: Provider credentials dict
        user_id: ID of the user initiating the stop

    Returns:
        dict with stop result information
    """
    from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog
    from apps.users.models import User

    logger.info(f"[Task:stop_node] Stopping deployment_id={deployment_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:stop_node] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    service = get_deployment_service()
    result = service.stop_node(
        deployment=deployment,
        credentials=credentials,
        user=user,
    )

    if result.is_err():
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message=f"Stop failed: {result.unwrap_err()}",
            phase="power",
        )
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "error": result.unwrap_err(),
        }

    NodeDeploymentLog.objects.create(
        deployment=deployment,
        level="INFO",
        message="Node powered off",
        phase="power",
    )

    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deployment.hostname,
        "action": "stopped",
        "stopped_at": timezone.now().isoformat(),
    }


def start_node_task(
    deployment_id: int,
    credentials: dict[str, str],
    user_id: int | None = None,
) -> dict:
    """
    Async task to start (power on) a node.

    Args:
        deployment_id: ID of the NodeDeployment to start
        credentials: Provider credentials dict
        user_id: ID of the user initiating the start

    Returns:
        dict with start result information
    """
    from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog
    from apps.users.models import User

    logger.info(f"[Task:start_node] Starting deployment_id={deployment_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:start_node] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    service = get_deployment_service()
    result = service.start_node(
        deployment=deployment,
        credentials=credentials,
        user=user,
    )

    if result.is_err():
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message=f"Start failed: {result.unwrap_err()}",
            phase="power",
        )
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "error": result.unwrap_err(),
        }

    NodeDeploymentLog.objects.create(
        deployment=deployment,
        level="INFO",
        message="Node powered on",
        phase="power",
    )

    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deployment.hostname,
        "action": "started",
        "started_at": timezone.now().isoformat(),
    }


def reboot_node_task(
    deployment_id: int,
    credentials: dict[str, str],
    user_id: int | None = None,
) -> dict:
    """
    Async task to reboot a node.

    Args:
        deployment_id: ID of the NodeDeployment to reboot
        credentials: Provider credentials dict
        user_id: ID of the user initiating the reboot

    Returns:
        dict with reboot result information
    """
    from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog
    from apps.users.models import User

    logger.info(f"[Task:reboot_node] Rebooting deployment_id={deployment_id}")

    try:
        deployment = NodeDeployment.objects.get(id=deployment_id)
    except NodeDeployment.DoesNotExist:
        logger.error(f"[Task:reboot_node] Deployment {deployment_id} not found")
        return {"success": False, "error": f"Deployment {deployment_id} not found"}

    user = None
    if user_id:
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    service = get_deployment_service()
    result = service.reboot_node(
        deployment=deployment,
        credentials=credentials,
        user=user,
    )

    if result.is_err():
        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message=f"Reboot failed: {result.unwrap_err()}",
            phase="power",
        )
        return {
            "success": False,
            "deployment_id": deployment_id,
            "hostname": deployment.hostname,
            "error": result.unwrap_err(),
        }

    NodeDeploymentLog.objects.create(
        deployment=deployment,
        level="INFO",
        message="Node rebooted",
        phase="power",
    )

    return {
        "success": True,
        "deployment_id": deployment_id,
        "hostname": deployment.hostname,
        "action": "rebooted",
        "rebooted_at": timezone.now().isoformat(),
    }


# ===============================================================================
# QUEUE HELPER FUNCTIONS
# ===============================================================================


def queue_deploy_node(
    deployment_id: int,
    credentials: dict[str, str],
    cloudflare_api_token: str | None = None,
    user_id: int | None = None,
) -> str:
    """
    Queue a node deployment task.

    Args:
        deployment_id: ID of the NodeDeployment to deploy
        credentials: Provider credentials dict
        cloudflare_api_token: Cloudflare API token
        user_id: ID of the user initiating the deployment

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.deploy_node_task",
        deployment_id,
        credentials,
        cloudflare_api_token,
        user_id,
        task_name=f"deploy_node_{deployment_id}",
        hook="apps.infrastructure.tasks.deployment_complete_hook",
    )

    logger.info(f"[Queue] Deployment queued: deployment_id={deployment_id}, task_id={task_id}")
    return task_id


def queue_destroy_node(
    deployment_id: int,
    credentials: dict[str, str],
    cloudflare_api_token: str | None = None,
    user_id: int | None = None,
) -> str:
    """
    Queue a node destruction task.

    Args:
        deployment_id: ID of the NodeDeployment to destroy
        credentials: Provider credentials dict
        cloudflare_api_token: Cloudflare API token
        user_id: ID of the user initiating the destruction

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.destroy_node_task",
        deployment_id,
        credentials,
        cloudflare_api_token,
        user_id,
        task_name=f"destroy_node_{deployment_id}",
        hook="apps.infrastructure.tasks.destruction_complete_hook",
    )

    logger.info(f"[Queue] Destruction queued: deployment_id={deployment_id}, task_id={task_id}")
    return task_id


def queue_retry_deployment(
    deployment_id: int,
    credentials: dict[str, str],
    cloudflare_api_token: str | None = None,
    user_id: int | None = None,
) -> str:
    """
    Queue a deployment retry task.

    Args:
        deployment_id: ID of the failed NodeDeployment to retry
        credentials: Provider credentials dict
        cloudflare_api_token: Cloudflare API token
        user_id: ID of the user initiating the retry

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.retry_deployment_task",
        deployment_id,
        credentials,
        cloudflare_api_token,
        user_id,
        task_name=f"retry_deployment_{deployment_id}",
        hook="apps.infrastructure.tasks.deployment_complete_hook",
    )

    logger.info(f"[Queue] Retry queued: deployment_id={deployment_id}, task_id={task_id}")
    return task_id


def queue_upgrade_node(
    deployment_id: int,
    new_size_id: int,
    credentials: dict[str, str],
    user_id: int | None = None,
) -> str:
    """
    Queue a node upgrade task.

    Args:
        deployment_id: ID of the NodeDeployment to upgrade
        new_size_id: ID of the new NodeSize
        credentials: Provider credentials dict
        user_id: ID of the user initiating the upgrade

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.upgrade_node_task",
        deployment_id,
        new_size_id,
        credentials,
        user_id,
        task_name=f"upgrade_node_{deployment_id}",
        hook="apps.infrastructure.tasks.lifecycle_complete_hook",
    )

    logger.info(f"[Queue] Upgrade queued: deployment_id={deployment_id}, task_id={task_id}")
    return task_id


def queue_maintenance(
    deployment_id: int,
    playbooks: list[str] | None = None,
    extra_vars: dict | None = None,
    user_id: int | None = None,
) -> str:
    """
    Queue a maintenance task.

    Args:
        deployment_id: ID of the NodeDeployment
        playbooks: List of playbook names to run
        extra_vars: Extra variables for Ansible
        user_id: ID of the user initiating maintenance

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.maintenance_task",
        deployment_id,
        playbooks,
        extra_vars,
        user_id,
        task_name=f"maintenance_{deployment_id}",
        hook="apps.infrastructure.tasks.lifecycle_complete_hook",
    )

    logger.info(f"[Queue] Maintenance queued: deployment_id={deployment_id}, task_id={task_id}")
    return task_id


def queue_stop_node(
    deployment_id: int,
    credentials: dict[str, str],
    user_id: int | None = None,
) -> str:
    """
    Queue a node stop task.

    Args:
        deployment_id: ID of the NodeDeployment to stop
        credentials: Provider credentials dict
        user_id: ID of the user initiating the stop

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.stop_node_task",
        deployment_id,
        credentials,
        user_id,
        task_name=f"stop_node_{deployment_id}",
        hook="apps.infrastructure.tasks.lifecycle_complete_hook",
    )

    logger.info(f"[Queue] Stop queued: deployment_id={deployment_id}, task_id={task_id}")
    return task_id


def queue_start_node(
    deployment_id: int,
    credentials: dict[str, str],
    user_id: int | None = None,
) -> str:
    """
    Queue a node start task.

    Args:
        deployment_id: ID of the NodeDeployment to start
        credentials: Provider credentials dict
        user_id: ID of the user initiating the start

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.start_node_task",
        deployment_id,
        credentials,
        user_id,
        task_name=f"start_node_{deployment_id}",
        hook="apps.infrastructure.tasks.lifecycle_complete_hook",
    )

    logger.info(f"[Queue] Start queued: deployment_id={deployment_id}, task_id={task_id}")
    return task_id


def queue_reboot_node(
    deployment_id: int,
    credentials: dict[str, str],
    user_id: int | None = None,
) -> str:
    """
    Queue a node reboot task.

    Args:
        deployment_id: ID of the NodeDeployment to reboot
        credentials: Provider credentials dict
        user_id: ID of the user initiating the reboot

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.reboot_node_task",
        deployment_id,
        credentials,
        user_id,
        task_name=f"reboot_node_{deployment_id}",
        hook="apps.infrastructure.tasks.lifecycle_complete_hook",
    )

    logger.info(f"[Queue] Reboot queued: deployment_id={deployment_id}, task_id={task_id}")
    return task_id


# ===============================================================================
# TASK COMPLETION HOOKS
# ===============================================================================


def deployment_complete_hook(task):
    """
    Hook called when a deployment task completes.

    Used for notifications and audit logging.
    """
    from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog

    logger.info(f"[Hook:deployment] Task {task.name} completed: success={task.success}")

    # Parse deployment_id from task name
    if task.result and isinstance(task.result, dict):
        deployment_id = task.result.get("deployment_id")

        if deployment_id:
            try:
                deployment = NodeDeployment.objects.get(id=deployment_id)

                if task.result.get("success"):
                    NodeDeploymentLog.objects.create(
                        deployment=deployment,
                        level="INFO",
                        message=f"Background task completed successfully",
                        phase="complete",
                    )
                else:
                    NodeDeploymentLog.objects.create(
                        deployment=deployment,
                        level="ERROR",
                        message=f"Background task failed: {task.result.get('error', 'Unknown error')}",
                        phase="failed",
                    )

            except NodeDeployment.DoesNotExist:
                pass


def destruction_complete_hook(task):
    """
    Hook called when a destruction task completes.
    """
    logger.info(f"[Hook:destruction] Task {task.name} completed: success={task.success}")

    if task.result and isinstance(task.result, dict):
        if task.result.get("success"):
            hostname = task.result.get("hostname", "unknown")
            logger.info(f"[Hook:destruction] Node {hostname} destroyed successfully")
        else:
            logger.error(f"[Hook:destruction] Destruction failed: {task.result.get('error')}")


def lifecycle_complete_hook(task):
    """
    Hook called when a lifecycle operation task completes.

    Handles: upgrade, maintenance, stop, start, reboot operations.
    """
    logger.info(f"[Hook:lifecycle] Task {task.name} completed: success={task.success}")

    if task.result and isinstance(task.result, dict):
        action = task.result.get("action", "operation")
        hostname = task.result.get("hostname", "unknown")

        if task.result.get("success"):
            logger.info(f"[Hook:lifecycle] {action.title()} completed for {hostname}")
        else:
            logger.error(
                f"[Hook:lifecycle] {action.title()} failed for {hostname}: "
                f"{task.result.get('error', 'Unknown error')}"
            )


# ===============================================================================
# COST TRACKING TASKS
# ===============================================================================


def calculate_daily_costs_task() -> dict:
    """
    Scheduled task to calculate costs for the previous day.

    Should be scheduled to run daily at midnight.

    Returns:
        dict with calculation results
    """
    from datetime import timedelta

    from apps.infrastructure.cost_service import get_cost_tracking_service

    logger.info("[Task:calculate_daily_costs] Starting daily cost calculation")

    now = timezone.now()
    yesterday_start = timezone.make_aware(now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1))
    yesterday_end = timezone.make_aware(
        now.replace(hour=23, minute=59, second=59, microsecond=999999) - timedelta(days=1)
    )

    service = get_cost_tracking_service()
    results = service.calculate_all_deployment_costs(yesterday_start, yesterday_end)

    successful = sum(1 for r in results if r.is_ok())
    failed = sum(1 for r in results if r.is_err())

    # Get summary
    summary = service.get_cost_summary(yesterday_start, yesterday_end)

    logger.info(
        f"[Task:calculate_daily_costs] Completed: {successful} successful, {failed} failed, "
        f"total cost: {summary.total_eur:.2f} EUR"
    )

    return {
        "success": True,
        "date": yesterday_start.date().isoformat(),
        "deployments_processed": successful,
        "deployments_failed": failed,
        "total_cost_eur": str(summary.total_eur),
    }


def calculate_monthly_costs_task(year: int, month: int) -> dict:
    """
    Task to calculate costs for a specific month.

    Args:
        year: Year (e.g., 2025)
        month: Month (1-12)

    Returns:
        dict with calculation results
    """
    from calendar import monthrange
    from datetime import datetime

    from apps.infrastructure.cost_service import get_cost_tracking_service

    logger.info(f"[Task:calculate_monthly_costs] Calculating costs for {year}-{month:02d}")

    _, days_in_month = monthrange(year, month)
    period_start = timezone.make_aware(datetime(year, month, 1))
    period_end = timezone.make_aware(datetime(year, month, days_in_month, 23, 59, 59))

    service = get_cost_tracking_service()
    results = service.calculate_all_deployment_costs(period_start, period_end)

    successful = sum(1 for r in results if r.is_ok())
    failed = sum(1 for r in results if r.is_err())

    summary = service.get_monthly_summary(year, month)

    logger.info(
        f"[Task:calculate_monthly_costs] Completed for {year}-{month:02d}: "
        f"{summary.total_eur:.2f} EUR across {summary.node_count} nodes"
    )

    return {
        "success": True,
        "year": year,
        "month": month,
        "deployments_processed": successful,
        "deployments_failed": failed,
        "total_cost_eur": str(summary.total_eur),
        "compute_cost_eur": str(summary.compute_eur),
        "node_count": summary.node_count,
    }


def generate_cost_report_task(year: int, month: int) -> dict:
    """
    Generate a cost report for a specific month.

    Includes breakdown by deployment, provider, and cost category.

    Args:
        year: Year (e.g., 2025)
        month: Month (1-12)

    Returns:
        dict with cost report data
    """
    from calendar import monthrange
    from datetime import datetime

    from apps.infrastructure.cost_service import get_cost_tracking_service

    logger.info(f"[Task:generate_cost_report] Generating report for {year}-{month:02d}")

    _, days_in_month = monthrange(year, month)
    period_start = timezone.make_aware(datetime(year, month, 1))
    period_end = timezone.make_aware(datetime(year, month, days_in_month, 23, 59, 59))

    service = get_cost_tracking_service()

    # Get summary
    summary = service.get_monthly_summary(year, month)

    # Get breakdown by deployment
    deployment_breakdown = service.get_deployment_breakdown(period_start, period_end)

    # Get breakdown by provider
    provider_breakdown = service.get_provider_breakdown(period_start, period_end)

    report = {
        "success": True,
        "year": year,
        "month": month,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "summary": {
            "total_eur": str(summary.total_eur),
            "compute_eur": str(summary.compute_eur),
            "bandwidth_eur": str(summary.bandwidth_eur),
            "storage_eur": str(summary.storage_eur),
            "node_count": summary.node_count,
        },
        "by_deployment": [
            {
                "hostname": d.hostname,
                "total_cost_eur": str(d.total_cost_eur),
                "monthly_rate_eur": str(d.monthly_rate_eur),
                "uptime_hours": d.uptime_hours,
            }
            for d in deployment_breakdown[:10]  # Top 10
        ],
        "by_provider": {name: str(cost) for name, cost in provider_breakdown.items()},
    }

    logger.info(f"[Task:generate_cost_report] Report generated for {year}-{month:02d}: " f"{summary.total_eur:.2f} EUR")

    return report


def queue_calculate_monthly_costs(year: int, month: int) -> str:
    """
    Queue a monthly cost calculation task.

    Args:
        year: Year (e.g., 2025)
        month: Month (1-12)

    Returns:
        Task ID
    """
    from django_q.tasks import async_task

    task_id = async_task(
        "apps.infrastructure.tasks.calculate_monthly_costs_task",
        year,
        month,
        task_name=f"calculate_monthly_costs_{year}_{month:02d}",
    )

    logger.info(f"[Queue] Monthly cost calculation queued: {year}-{month:02d}, task_id={task_id}")
    return task_id
