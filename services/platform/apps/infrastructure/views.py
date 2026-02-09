"""
Infrastructure Views

Staff interface for managing node deployments, providers, and configurations.
"""

import logging
from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import models
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from apps.common.credential_vault import get_credential_vault
from apps.settings.services import SettingsService

from .audit_service import InfrastructureAuditContext, InfrastructureAuditService
from .forms import (
    CloudProviderForm,
    DeploymentDestroyForm,
    NodeDeploymentForm,
    NodeSizeForm,
)
from .models import (
    CloudProvider,
    NodeDeployment,
    NodeDeploymentLog,
    NodeRegion,
    NodeSize,
    PanelType,
)
from .permissions import (
    can_deploy_nodes,
    can_destroy_nodes,
    can_manage_deployments,
    can_manage_providers,
    can_manage_regions,
    can_manage_sizes,
    can_view_infrastructure,
    require_deploy_permission,
    require_deployment_management,
    require_destroy_permission,
    require_infrastructure_view,
    require_provider_management,
    require_region_management,
    require_size_management,
)
from .tasks import (
    queue_deploy_node,
    queue_destroy_node,
    queue_maintenance,
    queue_reboot_node,
    queue_retry_deployment,
    queue_start_node,
    queue_stop_node,
    queue_upgrade_node,
)

logger = logging.getLogger(__name__)

# Items per page for list views
ITEMS_PER_PAGE = 25


def _get_status_variant(status: str) -> str:
    """Get badge variant for deployment status."""
    return {
        "pending": "secondary",
        "provisioning_node": "info",
        "configuring_dns": "info",
        "running_ansible": "info",
        "validating": "info",
        "registering": "info",
        "completed": "success",
        "failed": "danger",
        "destroying": "warning",
        "destroyed": "secondary",
        "stopped": "secondary",
    }.get(status, "secondary")


def _get_status_icon(status: str) -> str:
    """Get icon for deployment status."""
    return {
        "pending": "clock",
        "provisioning_node": "server",
        "configuring_dns": "globe",
        "running_ansible": "terminal",
        "validating": "check-circle",
        "registering": "user-plus",
        "completed": "check",
        "failed": "x-circle",
        "destroying": "trash-2",
        "destroyed": "archive",
        "stopped": "pause-circle",
    }.get(status, "help-circle")


# ===============================================================================
# DASHBOARD
# ===============================================================================


@login_required
@require_infrastructure_view
def deployment_dashboard(request: HttpRequest) -> HttpResponse:
    """Infrastructure deployment dashboard with overview statistics."""

    # Get deployment statistics
    total_deployments = NodeDeployment.objects.count()
    active_deployments = NodeDeployment.objects.filter(status="completed").count()
    pending_deployments = NodeDeployment.objects.filter(
        status__in=["pending", "provisioning_node", "configuring_dns", "running_ansible", "validating", "registering"]
    ).count()
    failed_deployments = NodeDeployment.objects.filter(status="failed").count()

    # Recent deployments
    recent_deployments = NodeDeployment.objects.select_related(
        "provider", "region", "node_size", "panel_type"
    ).order_by("-created_at")[:5]

    # Provider statistics
    providers = CloudProvider.objects.filter(is_active=True).annotate(
        deployment_count=models.Count("deployments")
    )

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure"},
    ]

    context = {
        "page_title": "Infrastructure Dashboard",
        "breadcrumb_items": breadcrumb_items,
        "total_deployments": total_deployments,
        "active_deployments": active_deployments,
        "pending_deployments": pending_deployments,
        "failed_deployments": failed_deployments,
        "recent_deployments": recent_deployments,
        "providers": providers,
        "deployment_enabled": SettingsService.get_setting("node_deployment.enabled", True),
    }

    return render(request, "infrastructure/dashboard.html", context)


# ===============================================================================
# NODE DEPLOYMENTS
# ===============================================================================


@login_required
@require_infrastructure_view
def deployment_list(request: HttpRequest) -> HttpResponse:
    """List all node deployments with filtering."""

    deployments = NodeDeployment.objects.select_related(
        "provider", "region", "node_size", "panel_type", "initiated_by"
    ).order_by("-created_at")

    # Apply filters
    env_filter = request.GET.get("environment")
    type_filter = request.GET.get("node_type")
    provider_filter = request.GET.get("provider")
    status_filter = request.GET.get("status")
    search_query = request.GET.get("search", "").strip()

    if env_filter:
        deployments = deployments.filter(environment=env_filter)
    if type_filter:
        deployments = deployments.filter(node_type=type_filter)
    if provider_filter:
        deployments = deployments.filter(provider_id=provider_filter)
    if status_filter:
        deployments = deployments.filter(status=status_filter)
    if search_query:
        deployments = deployments.filter(
            models.Q(hostname__icontains=search_query)
            | models.Q(display_name__icontains=search_query)
            | models.Q(ipv4_address__icontains=search_query)
        )

    # Pagination
    paginator = Paginator(deployments, ITEMS_PER_PAGE)
    page_number = request.GET.get("page")
    deployments_page = paginator.get_page(page_number)

    # Prepare table data
    table_data = [
        {
            "id": str(deployment.id),
            "hostname": deployment.hostname,
            "display_name": deployment.display_name,
            "environment": deployment.get_environment_display(),
            "environment_code": deployment.environment,
            "node_type": deployment.get_node_type_display(),
            "node_type_code": deployment.node_type,
            "provider": deployment.provider.name if deployment.provider else "N/A",
            "region": f"{deployment.region.country_code.upper()} / {deployment.region.normalized_code}" if deployment.region else "N/A",
            "status": {
                "text": deployment.get_status_display(),
                "variant": _get_status_variant(deployment.status),
                "icon": _get_status_icon(deployment.status),
            },
            "ipv4": deployment.ipv4_address or "-",
            "created_at": deployment.created_at,
            "detail_url": reverse("infrastructure:deployment_detail", args=[deployment.id]),
        }
        for deployment in deployments_page
    ]

    # Get filter options
    providers = CloudProvider.objects.filter(is_active=True).order_by("name")

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Deployments"},
    ]

    context = {
        "page_title": "Node Deployments",
        "breadcrumb_items": breadcrumb_items,
        "deployments_page": deployments_page,
        "table_data": table_data,
        "filters": {
            "environment": env_filter,
            "node_type": type_filter,
            "provider": provider_filter,
            "status": status_filter,
            "search": search_query,
            "providers": providers,
            "environment_choices": NodeDeployment.ENVIRONMENT_CHOICES,
            "node_type_choices": NodeDeployment.NODE_TYPE_CHOICES,
            "status_choices": NodeDeployment.STATUS_CHOICES,
        },
        "can_create": SettingsService.get_setting("node_deployment.enabled", True),
        "create_url": reverse("infrastructure:deployment_create"),
    }

    return render(request, "infrastructure/deployment_list.html", context)


@login_required
@require_deploy_permission
def deployment_create(request: HttpRequest) -> HttpResponse:
    """Create new node deployment."""

    # Check if deployment is enabled
    if not SettingsService.get_setting("node_deployment.enabled", True):
        messages.error(request, "Node deployment is disabled in settings.")
        return redirect("infrastructure:deployment_list")

    if request.method == "POST":
        form = NodeDeploymentForm(request.POST)
        if form.is_valid():
            deployment = form.save(commit=False)
            deployment.initiated_by = request.user

            # Auto-generate node number
            deployment.node_number = NodeDeployment.get_next_node_number(
                environment=deployment.environment,
                node_type=deployment.node_type,
                provider=deployment.provider,
                region=deployment.region,
            )

            # Generate hostname
            deployment.hostname = deployment.generate_hostname()

            # Set DNS zone from settings
            deployment.dns_zone = SettingsService.get_setting("node_deployment.dns_default_zone", "")

            deployment.save()

            # Get API tokens from credential vault
            api_token = get_credential_vault().get_credential(deployment.provider.credential_identifier)
            cloudflare_token = SettingsService.get_setting("node_deployment.dns_cloudflare_api_token", "")

            if not api_token:
                messages.error(request, f"No API token found for provider {deployment.provider.name}")
                deployment.status = "failed"
                deployment.save()
                return redirect("infrastructure:deployment_detail", pk=deployment.id)

            # Queue deployment task with provider-agnostic credentials
            credentials = {"api_token": api_token}
            task_id = queue_deploy_node(
                deployment_id=deployment.id,
                credentials=credentials,
                cloudflare_api_token=cloudflare_token if cloudflare_token else None,
                user_id=request.user.id,
            )

            messages.success(
                request,
                f"Deployment '{deployment.hostname}' created and queued for provisioning.",
            )
            logger.info(f"[Deployment] Created {deployment.hostname} by {request.user.email}, task_id={task_id}")

            return redirect("infrastructure:deployment_detail", pk=deployment.id)
    else:
        form = NodeDeploymentForm()

    # Get data for JS
    providers = list(CloudProvider.objects.filter(is_active=True).values("id", "name", "code"))
    regions = list(
        NodeRegion.objects.filter(is_active=True)
        .select_related("provider")
        .values("id", "name", "provider_id", "country_code", "normalized_code", "city")
    )
    sizes = list(
        NodeSize.objects.filter(is_active=True)
        .select_related("provider")
        .values(
            "id",
            "name",
            "display_name",
            "provider_id",
            "vcpus",
            "memory_gb",
            "disk_gb",
            "monthly_cost_eur",
            "max_domains",
        )
    )

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Deployments", "url": reverse("infrastructure:deployment_list")},
        {"text": "Create"},
    ]

    context = {
        "page_title": "Deploy New Node",
        "breadcrumb_items": breadcrumb_items,
        "form": form,
        "providers_json": providers,
        "regions_json": regions,
        "sizes_json": sizes,
        "dns_zone": SettingsService.get_setting("node_deployment.dns_default_zone", ""),
        "form_action": reverse("infrastructure:deployment_create"),
        "cancel_url": reverse("infrastructure:deployment_list"),
    }

    return render(request, "infrastructure/deployment_create.html", context)


@login_required
@require_infrastructure_view
def deployment_detail(request: HttpRequest, pk) -> HttpResponse:
    """Deployment detail view with logs and actions."""

    deployment = get_object_or_404(
        NodeDeployment.objects.select_related(
            "provider", "region", "node_size", "panel_type", "initiated_by", "virtualmin_server"
        ),
        id=pk,
    )

    # Get recent logs
    logs = NodeDeploymentLog.objects.filter(deployment=deployment).order_by("-created_at")[:50]

    # Calculate progress percentage
    progress_stages = {
        "pending": 0,
        "provisioning_node": 15,
        "configuring_dns": 35,
        "running_ansible": 55,
        "validating": 80,
        "registering": 90,
        "completed": 100,
        "failed": 0,
        "stopped": 100,
        "destroying": 50,
        "destroyed": 100,
    }
    progress_percentage = progress_stages.get(deployment.status, 0)

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Deployments", "url": reverse("infrastructure:deployment_list")},
        {"text": deployment.hostname},
    ]

    context = {
        "page_title": f"Deployment: {deployment.hostname}",
        "breadcrumb_items": breadcrumb_items,
        "deployment": deployment,
        "logs": logs,
        "progress_percentage": progress_percentage,
        "status_variant": _get_status_variant(deployment.status),
        "status_icon": _get_status_icon(deployment.status),
        "can_retry": deployment.status == "failed",
        "can_destroy": deployment.status in ("completed", "failed", "stopped"),
        "can_manage": can_manage_deployments(request.user),
        "is_in_progress": deployment.status in (
            "pending",
            "provisioning_node",
            "configuring_dns",
            "running_ansible",
            "validating",
            "registering",
        ),
        "fqdn": f"{deployment.hostname}.{deployment.dns_zone}" if deployment.dns_zone else deployment.hostname,
    }

    return render(request, "infrastructure/deployment_detail.html", context)


@login_required
@require_infrastructure_view
def deployment_logs(request: HttpRequest, pk) -> HttpResponse:
    """Full deployment logs view."""

    deployment = get_object_or_404(NodeDeployment, id=pk)
    logs = NodeDeploymentLog.objects.filter(deployment=deployment).order_by("created_at")

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Deployments", "url": reverse("infrastructure:deployment_list")},
        {"text": deployment.hostname, "url": reverse("infrastructure:deployment_detail", args=[deployment.id])},
        {"text": "Logs"},
    ]

    context = {
        "page_title": f"Logs: {deployment.hostname}",
        "breadcrumb_items": breadcrumb_items,
        "deployment": deployment,
        "logs": logs,
    }

    return render(request, "infrastructure/deployment_logs.html", context)


@login_required
@require_deploy_permission
@require_POST
def deployment_retry(request: HttpRequest, pk) -> HttpResponse:
    """Retry a failed deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "failed":
        messages.error(request, "Can only retry failed deployments.")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Get API tokens
    api_token = get_credential_vault().get_credential(deployment.provider.credential_identifier)
    cloudflare_token = SettingsService.get_setting("node_deployment.dns_cloudflare_api_token", "")

    if not api_token:
        messages.error(request, f"No API token found for provider {deployment.provider.name}")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Queue retry task with provider-agnostic credentials
    credentials = {"api_token": api_token}
    task_id = queue_retry_deployment(
        deployment_id=deployment.id,
        credentials=credentials,
        cloudflare_api_token=cloudflare_token if cloudflare_token else None,
        user_id=request.user.id,
    )

    messages.success(request, f"Retry queued for deployment '{deployment.hostname}'.")
    logger.info(f"[Deployment] Retry queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")

    return redirect("infrastructure:deployment_detail", pk=deployment.id)


@login_required
@require_destroy_permission
@require_http_methods(["GET", "POST"])
def deployment_destroy(request: HttpRequest, pk) -> HttpResponse:
    """Destroy a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status not in ("completed", "failed", "stopped"):
        messages.error(request, f"Cannot destroy deployment in status '{deployment.get_status_display()}'.")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    if request.method == "POST":
        form = DeploymentDestroyForm(request.POST, hostname=deployment.hostname)
        if form.is_valid():
            # Get API tokens
            api_token = get_credential_vault().get_credential(deployment.provider.credential_identifier)
            cloudflare_token = SettingsService.get_setting("node_deployment.dns_cloudflare_api_token", "")

            if not api_token:
                messages.error(request, f"No API token found for provider {deployment.provider.name}")
                return redirect("infrastructure:deployment_detail", pk=deployment.id)

            # Queue destroy task with provider-agnostic credentials
            credentials = {"api_token": api_token}
            task_id = queue_destroy_node(
                deployment_id=deployment.id,
                credentials=credentials,
                cloudflare_api_token=cloudflare_token if cloudflare_token else None,
                user_id=request.user.id,
            )

            messages.success(request, f"Destruction queued for deployment '{deployment.hostname}'.")
            logger.info(f"[Deployment] Destroy queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")

            return redirect("infrastructure:deployment_detail", pk=deployment.id)
    else:
        form = DeploymentDestroyForm(hostname=deployment.hostname)

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Deployments", "url": reverse("infrastructure:deployment_list")},
        {"text": deployment.hostname, "url": reverse("infrastructure:deployment_detail", args=[deployment.id])},
        {"text": "Destroy"},
    ]

    context = {
        "page_title": f"Destroy: {deployment.hostname}",
        "breadcrumb_items": breadcrumb_items,
        "deployment": deployment,
        "form": form,
        "form_action": reverse("infrastructure:deployment_destroy", args=[deployment.id]),
        "cancel_url": reverse("infrastructure:deployment_detail", args=[deployment.id]),
    }

    return render(request, "infrastructure/deployment_destroy.html", context)


# ===============================================================================
# LIFECYCLE OPERATIONS
# ===============================================================================


@login_required
@require_deployment_management
@require_http_methods(["GET", "POST"])
def deployment_upgrade(request: HttpRequest, pk) -> HttpResponse:
    """Upgrade a deployment to a new size."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "completed":
        messages.error(request, "Can only upgrade running nodes.")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Get available sizes for this provider (larger than current)
    available_sizes = NodeSize.objects.filter(
        provider=deployment.provider,
        is_active=True,
    ).exclude(id=deployment.node_size_id).order_by("monthly_cost_eur")

    if request.method == "POST":
        new_size_id = request.POST.get("new_size")
        if not new_size_id:
            messages.error(request, "Please select a new size.")
        else:
            try:
                new_size = NodeSize.objects.get(id=new_size_id, provider=deployment.provider)

                # Get API token
                api_token = get_credential_vault().get_credential(deployment.provider.credential_identifier)
                if not api_token:
                    messages.error(request, f"No API token found for provider {deployment.provider.name}")
                    return redirect("infrastructure:deployment_detail", pk=deployment.id)

                # Queue upgrade task with provider-agnostic credentials
                credentials = {"api_token": api_token}
                task_id = queue_upgrade_node(
                    deployment_id=deployment.id,
                    new_size_id=new_size.id,
                    credentials=credentials,
                    user_id=request.user.id,
                )

                messages.success(
                    request,
                    f"Upgrade to '{new_size.name}' queued for '{deployment.hostname}'.",
                )
                logger.info(
                    f"[Deployment] Upgrade queued for {deployment.hostname} to {new_size.name} "
                    f"by {request.user.email}, task_id={task_id}"
                )

                return redirect("infrastructure:deployment_detail", pk=deployment.id)

            except NodeSize.DoesNotExist:
                messages.error(request, "Invalid size selected.")

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Deployments", "url": reverse("infrastructure:deployment_list")},
        {"text": deployment.hostname, "url": reverse("infrastructure:deployment_detail", args=[deployment.id])},
        {"text": "Upgrade"},
    ]

    context = {
        "page_title": f"Upgrade: {deployment.hostname}",
        "breadcrumb_items": breadcrumb_items,
        "deployment": deployment,
        "available_sizes": available_sizes,
        "current_size": deployment.node_size,
        "form_action": reverse("infrastructure:deployment_upgrade", args=[deployment.id]),
        "cancel_url": reverse("infrastructure:deployment_detail", args=[deployment.id]),
    }

    return render(request, "infrastructure/deployment_upgrade.html", context)


@login_required
@require_deployment_management
@require_POST
def deployment_stop(request: HttpRequest, pk) -> HttpResponse:
    """Stop (power off) a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "completed":
        messages.error(request, "Can only stop running nodes.")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Get API token
    api_token = get_credential_vault().get_credential(deployment.provider.credential_identifier)
    if not api_token:
        messages.error(request, f"No API token found for provider {deployment.provider.name}")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Queue stop task with provider-agnostic credentials
    credentials = {"api_token": api_token}
    task_id = queue_stop_node(
        deployment_id=deployment.id,
        credentials=credentials,
        user_id=request.user.id,
    )

    messages.success(request, f"Stop queued for '{deployment.hostname}'.")
    logger.info(f"[Deployment] Stop queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")

    return redirect("infrastructure:deployment_detail", pk=deployment.id)


@login_required
@require_deployment_management
@require_POST
def deployment_start(request: HttpRequest, pk) -> HttpResponse:
    """Start (power on) a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "stopped":
        messages.error(request, "Can only start stopped nodes.")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Get API token
    api_token = get_credential_vault().get_credential(deployment.provider.credential_identifier)
    if not api_token:
        messages.error(request, f"No API token found for provider {deployment.provider.name}")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Queue start task with provider-agnostic credentials
    credentials = {"api_token": api_token}
    task_id = queue_start_node(
        deployment_id=deployment.id,
        credentials=credentials,
        user_id=request.user.id,
    )

    messages.success(request, f"Start queued for '{deployment.hostname}'.")
    logger.info(f"[Deployment] Start queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")

    return redirect("infrastructure:deployment_detail", pk=deployment.id)


@login_required
@require_deployment_management
@require_POST
def deployment_reboot(request: HttpRequest, pk) -> HttpResponse:
    """Reboot a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "completed":
        messages.error(request, "Can only reboot running nodes.")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Get API token
    api_token = get_credential_vault().get_credential(deployment.provider.credential_identifier)
    if not api_token:
        messages.error(request, f"No API token found for provider {deployment.provider.name}")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Queue reboot task with provider-agnostic credentials
    credentials = {"api_token": api_token}
    task_id = queue_reboot_node(
        deployment_id=deployment.id,
        credentials=credentials,
        user_id=request.user.id,
    )

    messages.success(request, f"Reboot queued for '{deployment.hostname}'.")
    logger.info(f"[Deployment] Reboot queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")

    return redirect("infrastructure:deployment_detail", pk=deployment.id)


@login_required
@require_deployment_management
@require_http_methods(["GET", "POST"])
def deployment_maintenance(request: HttpRequest, pk) -> HttpResponse:
    """Run maintenance tasks on a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "completed":
        messages.error(request, "Can only run maintenance on running nodes.")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Available maintenance playbooks
    playbook_options = [
        {"id": "update", "name": "System Update", "description": "Update system packages and security patches"},
        {"id": "security", "name": "Security Hardening", "description": "Apply security hardening configurations"},
        {"id": "ssl_renew", "name": "SSL Certificate Renewal", "description": "Renew SSL certificates via Let's Encrypt"},
        {"id": "backup", "name": "Backup Now", "description": "Trigger immediate backup"},
        {"id": "cleanup", "name": "Disk Cleanup", "description": "Clean up temporary files and logs"},
    ]

    if request.method == "POST":
        selected_playbooks = request.POST.getlist("playbooks")
        if not selected_playbooks:
            messages.error(request, "Please select at least one maintenance task.")
        else:
            # Queue maintenance task
            task_id = queue_maintenance(
                deployment_id=deployment.id,
                playbooks=selected_playbooks,
                user_id=request.user.id,
            )

            playbook_names = ", ".join(selected_playbooks)
            messages.success(
                request,
                f"Maintenance tasks ({playbook_names}) queued for '{deployment.hostname}'.",
            )
            logger.info(
                f"[Deployment] Maintenance queued for {deployment.hostname} "
                f"({playbook_names}) by {request.user.email}, task_id={task_id}"
            )

            return redirect("infrastructure:deployment_detail", pk=deployment.id)

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Deployments", "url": reverse("infrastructure:deployment_list")},
        {"text": deployment.hostname, "url": reverse("infrastructure:deployment_detail", args=[deployment.id])},
        {"text": "Maintenance"},
    ]

    context = {
        "page_title": f"Maintenance: {deployment.hostname}",
        "breadcrumb_items": breadcrumb_items,
        "deployment": deployment,
        "playbook_options": playbook_options,
        "form_action": reverse("infrastructure:deployment_maintenance", args=[deployment.id]),
        "cancel_url": reverse("infrastructure:deployment_detail", args=[deployment.id]),
    }

    return render(request, "infrastructure/deployment_maintenance.html", context)


# ===============================================================================
# HTMX PARTIALS
# ===============================================================================


@login_required
@require_infrastructure_view
@require_GET
def deployment_status_partial(request: HttpRequest, pk) -> HttpResponse:
    """HTMX partial for deployment status updates."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    progress_stages = {
        "pending": 0,
        "provisioning_node": 15,
        "configuring_dns": 35,
        "running_ansible": 55,
        "validating": 80,
        "registering": 90,
        "completed": 100,
        "failed": 0,
        "destroying": 50,
        "destroyed": 100,
    }

    context = {
        "deployment": deployment,
        "progress_percentage": progress_stages.get(deployment.status, 0),
        "status_variant": _get_status_variant(deployment.status),
        "status_icon": _get_status_icon(deployment.status),
        "is_in_progress": deployment.status in (
            "pending",
            "provisioning_node",
            "configuring_dns",
            "running_ansible",
            "validating",
            "registering",
            "destroying",
        ),
    }

    return render(request, "infrastructure/partials/deployment_status.html", context)


@login_required
@require_infrastructure_view
@require_GET
def deployment_logs_partial(request: HttpRequest, pk) -> HttpResponse:
    """HTMX partial for deployment logs."""

    deployment = get_object_or_404(NodeDeployment, id=pk)
    logs = NodeDeploymentLog.objects.filter(deployment=deployment).order_by("-created_at")[:20]

    context = {
        "logs": logs,
    }

    return render(request, "infrastructure/partials/deployment_logs.html", context)


# ===============================================================================
# API ENDPOINTS
# ===============================================================================


@login_required
@require_infrastructure_view
@require_GET
def hostname_preview_api(request: HttpRequest) -> JsonResponse:
    """API endpoint for hostname preview."""

    environment = request.GET.get("environment", "prd")
    node_type = request.GET.get("node_type", "sha")
    provider_id = request.GET.get("provider")
    region_id = request.GET.get("region")

    if not provider_id or not region_id:
        return JsonResponse({"hostname": "---", "error": "Missing provider or region"})

    try:
        provider = CloudProvider.objects.get(id=provider_id)
        region = NodeRegion.objects.get(id=region_id)

        # Get next available number
        next_number = NodeDeployment.get_next_node_number(
            environment=environment,
            node_type=node_type,
            provider=provider,
            region=region,
        )

        hostname = f"{environment}-{node_type}-{provider.code}-{region.country_code}-{region.normalized_code}-{next_number:03d}"
        dns_zone = SettingsService.get_setting("node_deployment.dns_default_zone", "")
        fqdn = f"{hostname}.{dns_zone}" if dns_zone else hostname

        return JsonResponse({
            "hostname": hostname,
            "fqdn": fqdn,
            "next_number": next_number,
        })

    except (CloudProvider.DoesNotExist, NodeRegion.DoesNotExist) as e:
        return JsonResponse({"hostname": "---", "error": str(e)})


# ===============================================================================
# CONFIGURATION: PROVIDERS
# ===============================================================================


@login_required
@require_infrastructure_view
def provider_list(request: HttpRequest) -> HttpResponse:
    """List cloud providers."""

    providers = CloudProvider.objects.annotate(
        deployment_count=models.Count("deployments"),
        region_count=models.Count("regions"),
        size_count=models.Count("sizes"),
    ).order_by("name")

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Providers"},
    ]

    context = {
        "page_title": "Cloud Providers",
        "breadcrumb_items": breadcrumb_items,
        "providers": providers,
        "create_url": reverse("infrastructure:provider_create"),
    }

    return render(request, "infrastructure/provider_list.html", context)


@login_required
@require_provider_management
def provider_create(request: HttpRequest) -> HttpResponse:
    """Create new cloud provider."""

    if request.method == "POST":
        form = CloudProviderForm(request.POST)
        if form.is_valid():
            provider = form.save(commit=False)

            # Store API token in credential vault
            api_token = form.cleaned_data.get("api_token")
            if api_token:
                credential_id = f"cloud_provider_{provider.code}"
                get_credential_vault().store_credential(credential_id, api_token)
                provider.credential_identifier = credential_id

            provider.save()
            messages.success(request, f"Provider '{provider.name}' created successfully.")
            return redirect("infrastructure:provider_list")
    else:
        form = CloudProviderForm()

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Providers", "url": reverse("infrastructure:provider_list")},
        {"text": "Create"},
    ]

    context = {
        "page_title": "Create Provider",
        "breadcrumb_items": breadcrumb_items,
        "form": form,
        "form_action": reverse("infrastructure:provider_create"),
        "cancel_url": reverse("infrastructure:provider_list"),
    }

    return render(request, "infrastructure/provider_form.html", context)


@login_required
@require_provider_management
def provider_edit(request: HttpRequest, pk) -> HttpResponse:
    """Edit cloud provider."""

    provider = get_object_or_404(CloudProvider, id=pk)

    if request.method == "POST":
        form = CloudProviderForm(request.POST, instance=provider)
        if form.is_valid():
            provider = form.save(commit=False)

            # Update API token if provided
            api_token = form.cleaned_data.get("api_token")
            if api_token:
                credential_id = provider.credential_identifier or f"cloud_provider_{provider.code}"
                get_credential_vault().store_credential(credential_id, api_token)
                provider.credential_identifier = credential_id

            provider.save()
            messages.success(request, f"Provider '{provider.name}' updated successfully.")
            return redirect("infrastructure:provider_list")
    else:
        form = CloudProviderForm(instance=provider)

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Providers", "url": reverse("infrastructure:provider_list")},
        {"text": provider.name},
    ]

    context = {
        "page_title": f"Edit Provider: {provider.name}",
        "breadcrumb_items": breadcrumb_items,
        "form": form,
        "provider": provider,
        "form_action": reverse("infrastructure:provider_edit", args=[provider.id]),
        "cancel_url": reverse("infrastructure:provider_list"),
    }

    return render(request, "infrastructure/provider_form.html", context)


# ===============================================================================
# CONFIGURATION: SIZES
# ===============================================================================


@login_required
@require_infrastructure_view
def size_list(request: HttpRequest) -> HttpResponse:
    """List node sizes."""

    sizes = NodeSize.objects.select_related("provider").order_by("provider__name", "sort_order")

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Node Sizes"},
    ]

    context = {
        "page_title": "Node Sizes",
        "breadcrumb_items": breadcrumb_items,
        "sizes": sizes,
        "create_url": reverse("infrastructure:size_create"),
    }

    return render(request, "infrastructure/size_list.html", context)


@login_required
@require_size_management
def size_create(request: HttpRequest) -> HttpResponse:
    """Create new node size."""

    if request.method == "POST":
        form = NodeSizeForm(request.POST)
        if form.is_valid():
            size = form.save()
            messages.success(request, f"Size '{size.name}' created successfully.")
            return redirect("infrastructure:size_list")
    else:
        form = NodeSizeForm()

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Node Sizes", "url": reverse("infrastructure:size_list")},
        {"text": "Create"},
    ]

    context = {
        "page_title": "Create Node Size",
        "breadcrumb_items": breadcrumb_items,
        "form": form,
        "form_action": reverse("infrastructure:size_create"),
        "cancel_url": reverse("infrastructure:size_list"),
    }

    return render(request, "infrastructure/size_form.html", context)


@login_required
@require_size_management
def size_edit(request: HttpRequest, pk) -> HttpResponse:
    """Edit node size."""

    size = get_object_or_404(NodeSize, id=pk)

    if request.method == "POST":
        form = NodeSizeForm(request.POST, instance=size)
        if form.is_valid():
            size = form.save()
            messages.success(request, f"Size '{size.name}' updated successfully.")
            return redirect("infrastructure:size_list")
    else:
        form = NodeSizeForm(instance=size)

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Node Sizes", "url": reverse("infrastructure:size_list")},
        {"text": size.name},
    ]

    context = {
        "page_title": f"Edit Size: {size.name}",
        "breadcrumb_items": breadcrumb_items,
        "form": form,
        "size": size,
        "form_action": reverse("infrastructure:size_edit", args=[size.id]),
        "cancel_url": reverse("infrastructure:size_list"),
    }

    return render(request, "infrastructure/size_form.html", context)


# ===============================================================================
# CONFIGURATION: REGIONS
# ===============================================================================


@login_required
@require_infrastructure_view
def region_list(request: HttpRequest) -> HttpResponse:
    """List node regions."""

    regions = NodeRegion.objects.select_related("provider").order_by("provider__name", "country_code", "name")

    # Group by provider
    providers_with_regions: dict[str, Any] = {}
    for region in regions:
        provider_name = region.provider.name
        if provider_name not in providers_with_regions:
            providers_with_regions[provider_name] = []
        providers_with_regions[provider_name].append(region)

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Regions"},
    ]

    context = {
        "page_title": "Node Regions",
        "breadcrumb_items": breadcrumb_items,
        "providers_with_regions": providers_with_regions,
    }

    return render(request, "infrastructure/region_list.html", context)


@login_required
@require_region_management
@require_POST
def region_toggle(request: HttpRequest, pk) -> HttpResponse:
    """Toggle region active status."""

    region = get_object_or_404(NodeRegion, id=pk)
    region.is_active = not region.is_active
    region.save()

    action = "enabled" if region.is_active else "disabled"
    messages.success(request, f"Region '{region.name}' {action}.")

    if request.headers.get("HX-Request"):
        # Return updated row for HTMX
        return render(request, "infrastructure/partials/region_row.html", {"region": region})

    return redirect("infrastructure:region_list")


# ===============================================================================
# COST TRACKING
# ===============================================================================


@login_required
@require_infrastructure_view
def cost_dashboard(request: HttpRequest) -> HttpResponse:
    """Cost tracking dashboard with summary and trends."""
    from datetime import datetime
    from decimal import Decimal

    from apps.infrastructure.cost_service import get_cost_tracking_service

    service = get_cost_tracking_service()

    # Current month summary
    now = timezone.now()
    current_month_summary = service.get_monthly_summary(now.year, now.month)

    # Previous month for comparison
    if now.month == 1:
        prev_year, prev_month = now.year - 1, 12
    else:
        prev_year, prev_month = now.year, now.month - 1
    prev_month_summary = service.get_monthly_summary(prev_year, prev_month)

    # Calculate month-over-month change
    if prev_month_summary.total_eur > 0:
        mom_change = (
            (current_month_summary.total_eur - prev_month_summary.total_eur)
            / prev_month_summary.total_eur
            * 100
        )
    else:
        mom_change = Decimal("0")

    # Month-to-date summary
    mtd_summary = service.get_current_month_to_date()

    # Projected monthly cost
    days_in_month = 30  # Approximate
    days_elapsed = now.day
    if days_elapsed > 0:
        projected_total = (mtd_summary.total_eur / Decimal(days_elapsed)) * Decimal(days_in_month)
    else:
        projected_total = Decimal("0")

    # Provider breakdown for current month
    month_start = timezone.make_aware(datetime(now.year, now.month, 1))
    provider_breakdown = service.get_provider_breakdown(month_start, now)

    # Top deployments by cost (current month)
    deployment_breakdown = service.get_deployment_breakdown(month_start, now)[:5]

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Costs"},
    ]

    context = {
        "page_title": "Infrastructure Costs",
        "breadcrumb_items": breadcrumb_items,
        "current_month_summary": current_month_summary,
        "prev_month_summary": prev_month_summary,
        "mom_change": mom_change,
        "mtd_summary": mtd_summary,
        "projected_total": projected_total,
        "provider_breakdown": provider_breakdown,
        "top_deployments": deployment_breakdown,
        "current_year": now.year,
        "current_month": now.month,
    }

    return render(request, "infrastructure/cost_dashboard.html", context)


@login_required
@require_infrastructure_view
def cost_history(request: HttpRequest) -> HttpResponse:
    """Monthly cost history view."""
    from calendar import month_name
    from datetime import datetime

    from apps.infrastructure.cost_service import get_cost_tracking_service

    service = get_cost_tracking_service()
    now = timezone.now()

    # Get cost history for last 12 months
    history = []
    for i in range(12):
        if now.month - i > 0:
            year = now.year
            month = now.month - i
        else:
            year = now.year - 1
            month = 12 + (now.month - i)

        summary = service.get_monthly_summary(year, month)
        history.append({
            "year": year,
            "month": month,
            "month_name": month_name[month],
            "summary": summary,
        })

    breadcrumb_items = [
        {"text": "Management", "url": "/dashboard/"},
        {"text": "Infrastructure", "url": reverse("infrastructure:dashboard")},
        {"text": "Costs", "url": reverse("infrastructure:cost_dashboard")},
        {"text": "History"},
    ]

    context = {
        "page_title": "Cost History",
        "breadcrumb_items": breadcrumb_items,
        "history": history,
    }

    return render(request, "infrastructure/cost_history.html", context)


@login_required
@require_infrastructure_view
@require_GET
def cost_api_summary(request: HttpRequest) -> JsonResponse:
    """API endpoint for cost summary data."""
    from apps.infrastructure.cost_service import get_cost_tracking_service

    year = request.GET.get("year")
    month = request.GET.get("month")

    if not year or not month:
        now = timezone.now()
        year = now.year
        month = now.month
    else:
        year = int(year)
        month = int(month)

    service = get_cost_tracking_service()
    summary = service.get_monthly_summary(year, month)

    return JsonResponse({
        "year": year,
        "month": month,
        "total_eur": str(summary.total_eur),
        "compute_eur": str(summary.compute_eur),
        "bandwidth_eur": str(summary.bandwidth_eur),
        "storage_eur": str(summary.storage_eur),
        "node_count": summary.node_count,
    })
