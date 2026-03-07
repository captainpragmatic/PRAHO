"""
Infrastructure Views

Staff interface for managing node deployments, providers, and configurations.
"""

import json
import logging
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast

from django.utils import timezone as tz
from django.utils.dateparse import parse_datetime

if TYPE_CHECKING:
    from apps.users.models import User

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import DatabaseError, models, transaction
from django.db.models import Count, Q
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from apps.infrastructure.audit_service import InfrastructureAuditContext, InfrastructureAuditService
from apps.infrastructure.provider_config import get_provider_sync_fn, get_provider_token, store_provider_token
from apps.settings.services import SettingsService

from .forms import (
    CloudProviderForm,
    DeploymentDestroyForm,
    NodeDeploymentForm,
    NodeSizeForm,
)
from .models import (
    CloudProvider,
    DriftCheck,
    DriftRemediationRequest,
    DriftReport,
    NodeDeployment,
    NodeDeploymentLog,
    NodeRegion,
    NodeSize,
)
from .permissions import (
    can_manage_deployments,
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
    providers = CloudProvider.objects.filter(is_active=True).annotate(deployment_count=models.Count("deployments"))

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
            "region": f"{deployment.region.country_code.upper()} / {deployment.region.normalized_code}"
            if deployment.region
            else "N/A",
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
        messages.error(request, _("Node deployment is disabled in settings."))
        return redirect("infrastructure:deployment_list")

    if request.method == "POST":
        form = NodeDeploymentForm(request.POST)
        if form.is_valid():
            deployment = form.save(commit=False)
            deployment.initiated_by = request.user

            # Atomic block to prevent race conditions on node number assignment
            with transaction.atomic():
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

            # Verify provider token exists before queueing
            token_result = get_provider_token(deployment.provider)
            if token_result.is_err():
                messages.error(request, f"No API token found for provider {deployment.provider.name}")
                deployment.status = "failed"
                deployment.save()
                return redirect("infrastructure:deployment_detail", pk=deployment.id)

            # Queue deployment task — token fetched from vault at execution time (not serialized)
            task_id = queue_deploy_node(
                deployment_id=deployment.id,
                provider_id=deployment.provider.id,
                user_id=request.user.id,
            )

            # Audit: deployment created
            try:
                audit_ctx = InfrastructureAuditContext(user=request.user, request=request)
                InfrastructureAuditService.log_deployment_created(deployment, audit_ctx)
            except (DatabaseError, OSError):
                logger.warning("⚠️ [Audit] Failed to log deployment creation for %s", deployment.hostname, exc_info=True)

            messages.success(
                request,
                f"Deployment '{deployment.hostname}' created and queued for provisioning.",
            )
            logger.info(f"[Deployment] Created {deployment.hostname} by {request.user.email}, task_id={task_id}")  # type: ignore[union-attr]

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
        "providers_json": json.dumps(providers),
        "regions_json": json.dumps(regions),
        "sizes_json": json.dumps(sizes, default=str),
        "dns_zone": SettingsService.get_setting("node_deployment.dns_default_zone", ""),
        "form_action": reverse("infrastructure:deployment_create"),
        "cancel_url": reverse("infrastructure:deployment_list"),
    }

    return render(request, "infrastructure/deployment_create.html", context)


@login_required
@require_infrastructure_view
def deployment_detail(request: HttpRequest, pk: int) -> HttpResponse:
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

    # Pre-compute progress step for template (0-6 range matching 6 stages)
    progress_step = min(progress_percentage // 16, 6)

    context = {
        "page_title": f"Deployment: {deployment.hostname}",
        "breadcrumb_items": breadcrumb_items,
        "deployment": deployment,
        "logs": logs,
        "progress_percentage": progress_percentage,
        "progress_step": progress_step,
        "stages": ["SSH Key", "Provision", "DNS", "Ansible", "Validate", "Register"],
        "status_variant": _get_status_variant(deployment.status),
        "status_icon": _get_status_icon(deployment.status),
        "can_retry": deployment.status == "failed",
        "can_destroy": deployment.status in ("completed", "failed", "stopped"),
        "can_manage": can_manage_deployments(cast("User", request.user)),
        "is_in_progress": deployment.status
        in (
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
def deployment_logs(request: HttpRequest, pk: int) -> HttpResponse:
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
def deployment_retry(request: HttpRequest, pk: int) -> HttpResponse:
    """Retry a failed deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "failed":
        messages.error(request, _("Can only retry failed deployments."))
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Validate token exists before queuing (fail fast)
    token_result = get_provider_token(deployment.provider)

    if token_result.is_err():
        messages.error(request, f"No API token found for provider {deployment.provider.name}")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    task_id = queue_retry_deployment(
        deployment_id=deployment.id,
        provider_id=deployment.provider_id,
        user_id=request.user.id,
    )

    messages.success(request, f"Retry queued for deployment '{deployment.hostname}'.")
    logger.info(f"[Deployment] Retry queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")  # type: ignore[union-attr]

    return redirect("infrastructure:deployment_detail", pk=deployment.id)


@login_required
@require_destroy_permission
@require_http_methods(["GET", "POST"])
def deployment_destroy(request: HttpRequest, pk: int) -> HttpResponse:
    """Destroy a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status not in ("completed", "failed", "stopped"):
        messages.error(request, f"Cannot destroy deployment in status '{deployment.get_status_display()}'.")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    if request.method == "POST":
        form = DeploymentDestroyForm(request.POST, hostname=deployment.hostname)
        if form.is_valid():
            # Validate token exists before queuing (fail fast)
            token_result = get_provider_token(deployment.provider)

            if token_result.is_err():
                messages.error(request, f"No API token found for provider {deployment.provider.name}")
                return redirect("infrastructure:deployment_detail", pk=deployment.id)

            task_id = queue_destroy_node(
                deployment_id=deployment.id,
                provider_id=deployment.provider_id,
                user_id=request.user.id,
            )

            messages.success(request, f"Destruction queued for deployment '{deployment.hostname}'.")
            logger.info(
                f"[Deployment] Destroy queued for {deployment.hostname} by {request.user.email}, task_id={task_id}"  # type: ignore[union-attr]
            )

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
def deployment_upgrade(request: HttpRequest, pk: int) -> HttpResponse:
    """Upgrade a deployment to a new size."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "completed":
        messages.error(request, _("Can only upgrade running nodes."))
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Get available sizes for this provider (larger than current)
    available_sizes = (
        NodeSize.objects.filter(
            provider=deployment.provider,
            is_active=True,
        )
        .exclude(id=deployment.node_size_id)
        .order_by("monthly_cost_eur")
    )

    if request.method == "POST":
        new_size_id = request.POST.get("new_size")
        if not new_size_id:
            messages.error(request, _("Please select a new size."))
        else:
            try:
                new_size = NodeSize.objects.get(id=new_size_id, provider=deployment.provider)

                # Validate token exists before queuing (fail fast)
                token_result = get_provider_token(deployment.provider)
                if token_result.is_err():
                    messages.error(request, f"No API token found for provider {deployment.provider.name}")
                    return redirect("infrastructure:deployment_detail", pk=deployment.id)

                task_id = queue_upgrade_node(
                    deployment_id=deployment.id,
                    new_size_id=new_size.id,
                    provider_id=deployment.provider_id,
                    user_id=request.user.id,
                )

                messages.success(
                    request,
                    f"Upgrade to '{new_size.name}' queued for '{deployment.hostname}'.",
                )
                logger.info(
                    f"[Deployment] Upgrade queued for {deployment.hostname} to {new_size.name} "
                    f"by {request.user.email}, task_id={task_id}"  # type: ignore[union-attr]
                )

                return redirect("infrastructure:deployment_detail", pk=deployment.id)

            except NodeSize.DoesNotExist:
                messages.error(request, _("Invalid size selected."))

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
def deployment_stop(request: HttpRequest, pk: int) -> HttpResponse:
    """Stop (power off) a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "completed":
        messages.error(request, _("Can only stop running nodes."))
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Validate token exists before queuing (fail fast)
    token_result = get_provider_token(deployment.provider)
    if token_result.is_err():
        messages.error(request, f"No API token found for provider {deployment.provider.name}")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    task_id = queue_stop_node(
        deployment_id=deployment.id,
        provider_id=deployment.provider_id,
        user_id=request.user.id,
    )

    messages.success(request, f"Stop queued for '{deployment.hostname}'.")
    logger.info(f"[Deployment] Stop queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")  # type: ignore[union-attr]

    return redirect("infrastructure:deployment_detail", pk=deployment.id)


@login_required
@require_deployment_management
@require_POST
def deployment_start(request: HttpRequest, pk: int) -> HttpResponse:
    """Start (power on) a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "stopped":
        messages.error(request, _("Can only start stopped nodes."))
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Validate token exists before queuing (fail fast)
    token_result = get_provider_token(deployment.provider)
    if token_result.is_err():
        messages.error(request, f"No API token found for provider {deployment.provider.name}")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    task_id = queue_start_node(
        deployment_id=deployment.id,
        provider_id=deployment.provider_id,
        user_id=request.user.id,
    )

    messages.success(request, f"Start queued for '{deployment.hostname}'.")
    logger.info(f"[Deployment] Start queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")  # type: ignore[union-attr]

    return redirect("infrastructure:deployment_detail", pk=deployment.id)


@login_required
@require_deployment_management
@require_POST
def deployment_reboot(request: HttpRequest, pk: int) -> HttpResponse:
    """Reboot a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "completed":
        messages.error(request, _("Can only reboot running nodes."))
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Validate token exists before queuing (fail fast)
    token_result = get_provider_token(deployment.provider)
    if token_result.is_err():
        messages.error(request, f"No API token found for provider {deployment.provider.name}")
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    task_id = queue_reboot_node(
        deployment_id=deployment.id,
        provider_id=deployment.provider_id,
        user_id=request.user.id,
    )

    messages.success(request, f"Reboot queued for '{deployment.hostname}'.")
    logger.info(f"[Deployment] Reboot queued for {deployment.hostname} by {request.user.email}, task_id={task_id}")  # type: ignore[union-attr]

    return redirect("infrastructure:deployment_detail", pk=deployment.id)


@login_required
@require_deployment_management
@require_http_methods(["GET", "POST"])
def deployment_maintenance(request: HttpRequest, pk: int) -> HttpResponse:
    """Run maintenance tasks on a deployment."""

    deployment = get_object_or_404(NodeDeployment, id=pk)

    if deployment.status != "completed":
        messages.error(request, _("Can only run maintenance on running nodes."))
        return redirect("infrastructure:deployment_detail", pk=deployment.id)

    # Available maintenance playbooks
    playbook_options = [
        {"id": "update", "name": "System Update", "description": "Update system packages and security patches"},
        {"id": "security", "name": "Security Hardening", "description": "Apply security hardening configurations"},
        {
            "id": "ssl_renew",
            "name": "SSL Certificate Renewal",
            "description": "Renew SSL certificates via Let's Encrypt",
        },
        {"id": "backup", "name": "Backup Now", "description": "Trigger immediate backup"},
        {"id": "cleanup", "name": "Disk Cleanup", "description": "Clean up temporary files and logs"},
    ]

    if request.method == "POST":
        selected_playbooks = request.POST.getlist("playbooks")
        if not selected_playbooks:
            messages.error(request, _("Please select at least one maintenance task."))
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
                f"({playbook_names}) by {request.user.email}, task_id={task_id}"  # type: ignore[union-attr]
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
def deployment_status_partial(request: HttpRequest, pk: int) -> HttpResponse:
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

    progress_percentage = progress_stages.get(deployment.status, 0)
    # Pre-compute progress step for template (0-6 range matching 6 stages)
    progress_step = min(progress_percentage // 16, 6)

    context = {
        "deployment": deployment,
        "progress_percentage": progress_percentage,
        "progress_step": progress_step,
        "stages": ["SSH Key", "Provision", "DNS", "Ansible", "Validate", "Register"],
        "status_variant": _get_status_variant(deployment.status),
        "status_icon": _get_status_icon(deployment.status),
        "is_in_progress": deployment.status
        in (
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
def deployment_logs_partial(request: HttpRequest, pk: int) -> HttpResponse:
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

        return JsonResponse(
            {
                "hostname": hostname,
                "fqdn": fqdn,
                "next_number": next_number,
            }
        )

    except (CloudProvider.DoesNotExist, NodeRegion.DoesNotExist) as e:
        return JsonResponse({"hostname": "---", "error": str(e)})


@login_required
@require_infrastructure_view
def provider_list(request: HttpRequest) -> HttpResponse:
    """List cloud providers."""

    providers = CloudProvider.objects.annotate(
        deployment_count=models.Count("deployments", distinct=True),
        region_count=models.Count("regions", distinct=True),
        size_count=models.Count("sizes", distinct=True),
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
@require_POST
def sync_providers(request: HttpRequest) -> HttpResponse:
    """Trigger provider catalog sync from APIs (HTMX endpoint)."""
    active_providers = CloudProvider.objects.filter(is_active=True)

    if not active_providers.exists():
        messages.warning(request, _("No active providers configured."))
        return redirect("infrastructure:provider_list")

    for provider in active_providers:
        sync_fn = get_provider_sync_fn(provider.provider_type)
        if not sync_fn:
            continue  # No sync function registered for this provider type

        token_result = get_provider_token(provider)
        if token_result.is_err():
            messages.warning(request, _("No credentials for %(name)s.") % {"name": provider.name})
            continue

        result = sync_fn(token=token_result.unwrap())
        if result.is_err():
            messages.error(
                request,
                _("Sync failed for %(name)s: %(error)s") % {"name": provider.name, "error": result.unwrap_err()},
            )
        else:
            sync_result = result.unwrap()
            messages.success(
                request,
                _("%(name)s sync: %(summary)s") % {"name": provider.name, "summary": sync_result.summary},
            )

    return redirect("infrastructure:provider_list")


@login_required
@require_provider_management
def provider_create(request: HttpRequest) -> HttpResponse:
    """Create new cloud provider."""
    form = CloudProviderForm(request.POST) if request.method == "POST" else CloudProviderForm()

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

    if request.method == "POST" and form.is_valid():
        provider = form.save(commit=False)
        api_token = form.cleaned_data.get("api_token")

        try:
            with transaction.atomic():
                provider.save()
                if api_token:
                    store_result = store_provider_token(provider, api_token, user=request.user)
                    if store_result.is_err():
                        raise ValueError(store_result.unwrap_err())
                    provider.credential_identifier = store_result.unwrap()
                    provider.save(update_fields=["credential_identifier"])
        except ValueError as e:
            messages.error(request, _("Failed to store API token: %(error)s") % {"error": str(e)})
            return render(request, "infrastructure/provider_form.html", context)

        # Audit: provider created
        try:
            audit_ctx = InfrastructureAuditContext(user=request.user, request=request)
            InfrastructureAuditService.log_provider_created(provider, audit_ctx)
        except (DatabaseError, OSError):
            logger.warning("⚠️ [Audit] Failed to log provider creation for %s", provider.name, exc_info=True)

        messages.success(request, f"Provider '{provider.name}' created successfully.")
        return redirect("infrastructure:provider_list")

    return render(request, "infrastructure/provider_form.html", context)


@login_required
@require_provider_management
def provider_edit(request: HttpRequest, pk: int) -> HttpResponse:
    """Edit cloud provider."""
    provider = get_object_or_404(CloudProvider, id=pk)

    if request.method == "POST":
        form = CloudProviderForm(request.POST, instance=provider)
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

    if request.method == "POST" and form.is_valid():
        # Capture old values for audit trail
        old_values = {
            "name": provider.name,
            "code": provider.code,
            "provider_type": provider.provider_type,
            "is_active": provider.is_active,
        }

        provider = form.save(commit=False)
        api_token = form.cleaned_data.get("api_token")

        try:
            with transaction.atomic():
                provider.save()
                if api_token:
                    store_result = store_provider_token(provider, api_token, user=request.user)
                    if store_result.is_err():
                        raise ValueError(store_result.unwrap_err())
                    provider.credential_identifier = store_result.unwrap()
                    provider.save(update_fields=["credential_identifier"])
        except ValueError as e:
            messages.error(request, _("Failed to store API token: %(error)s") % {"error": str(e)})
            return render(request, "infrastructure/provider_form.html", context)

        # Audit: provider updated
        try:
            audit_ctx = InfrastructureAuditContext(user=request.user, request=request)
            InfrastructureAuditService.log_provider_updated(provider, old_values, audit_ctx)
        except (DatabaseError, OSError):
            logger.warning("⚠️ [Audit] Failed to log provider update for %s", provider.name, exc_info=True)

        messages.success(request, f"Provider '{provider.name}' updated successfully.")
        return redirect("infrastructure:provider_list")

    return render(request, "infrastructure/provider_form.html", context)


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
def size_edit(request: HttpRequest, pk: int) -> HttpResponse:
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
def region_toggle(request: HttpRequest, pk: int) -> HttpResponse:
    """Toggle region active status."""

    region = get_object_or_404(NodeRegion, id=pk)
    region.is_active = not region.is_active
    region.save()

    # Audit: region toggled
    try:
        audit_ctx = InfrastructureAuditContext(user=request.user, request=request)
        InfrastructureAuditService.log_region_toggled(region, audit_ctx)
    except (DatabaseError, OSError):
        logger.warning("⚠️ [Audit] Failed to log region toggle for %s", region.name, exc_info=True)

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

    from apps.infrastructure.cost_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_cost_tracking_service,  # Circular: cross-app  # Deferred: avoids circular import
    )

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
            (current_month_summary.total_eur - prev_month_summary.total_eur) / prev_month_summary.total_eur * 100
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
    from calendar import month_name  # noqa: PLC0415  # Deferred: avoids circular import

    from apps.infrastructure.cost_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_cost_tracking_service,  # Circular: cross-app  # Deferred: avoids circular import
    )

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
        history.append(
            {
                "year": year,
                "month": month,
                "month_name": month_name[month],
                "summary": summary,
            }
        )

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
    from apps.infrastructure.cost_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_cost_tracking_service,  # Circular: cross-app  # Deferred: avoids circular import
    )

    year_str = request.GET.get("year")
    month_str = request.GET.get("month")

    if not year_str or not month_str:
        now = timezone.now()
        year = now.year
        month = now.month
    else:
        year = int(year_str)
        month = int(month_str)

    service = get_cost_tracking_service()
    summary = service.get_monthly_summary(year, month)

    return JsonResponse(
        {
            "year": year,
            "month": month,
            "total_eur": str(summary.total_eur),
            "compute_eur": str(summary.compute_eur),
            "bandwidth_eur": str(summary.bandwidth_eur),
            "storage_eur": str(summary.storage_eur),
            "node_count": summary.node_count,
        }
    )


# =============================================================================
# Drift Detection & Remediation Views
# =============================================================================


@login_required
@require_infrastructure_view
@require_GET
def drift_dashboard(request: HttpRequest) -> HttpResponse:
    """Summary of all deployments with drift status."""
    deployments = (
        NodeDeployment.objects.filter(status="completed")
        .select_related("provider", "node_size", "region")
        .annotate(
            unresolved_count=Count("drift_reports", filter=Q(drift_reports__resolved=False), distinct=True),
            pending_remediations=Count(
                "remediation_requests",
                filter=Q(remediation_requests__status="pending_approval"),
                distinct=True,
            ),
        )
    )

    # Prefetch latest drift check per deployment (2 queries instead of N+1)
    latest_check_ids = (
        DriftCheck.objects.filter(deployment__in=deployments)
        .values("deployment_id")
        .annotate(latest_id=models.Max("id"))
        .values_list("latest_id", flat=True)
    )
    latest_checks = {check.deployment_id: check for check in DriftCheck.objects.filter(id__in=latest_check_ids)}

    deployment_data = [
        {
            "deployment": deployment,
            "latest_check": latest_checks.get(deployment.pk),
            "unresolved_count": deployment.unresolved_count,
            "pending_remediations": deployment.pending_remediations,
        }
        for deployment in deployments
    ]

    return render(
        request,
        "infrastructure/drift/dashboard.html",
        {
            "deployment_data": deployment_data,
            "total_unresolved": sum(d["unresolved_count"] for d in deployment_data),
            "total_pending": sum(d["pending_remediations"] for d in deployment_data),
        },
    )


@login_required
@require_infrastructure_view
@require_GET
def drift_deployment_detail(request: HttpRequest, deployment_pk: int) -> HttpResponse:
    """Drift history for a single deployment."""
    deployment = get_object_or_404(NodeDeployment, pk=deployment_pk)

    checks = DriftCheck.objects.filter(deployment=deployment).order_by("-created_at")[:50]
    reports = DriftReport.objects.filter(deployment=deployment).order_by("-created_at")[:100]
    remediations = DriftRemediationRequest.objects.filter(deployment=deployment).order_by("-created_at")[:50]

    return render(
        request,
        "infrastructure/drift/deployment_detail.html",
        {
            "deployment": deployment,
            "checks": checks,
            "reports": reports,
            "remediations": remediations,
        },
    )


@login_required
@require_infrastructure_view
@require_GET
def drift_remediation_list(request: HttpRequest) -> HttpResponse:
    """Pending remediation requests."""
    status_filter = request.GET.get("status", "pending_approval")
    remediations = (
        DriftRemediationRequest.objects.filter(status=status_filter)
        .select_related("deployment", "report", "requested_by")
        .order_by("-created_at")
    )

    paginator = Paginator(remediations, 25)
    page = paginator.get_page(request.GET.get("page"))

    return render(
        request,
        "infrastructure/drift/remediation_list.html",
        {
            "page_obj": page,
            "status_filter": status_filter,
            "status_options": DriftRemediationRequest.STATUS_CHOICES,
        },
    )


def _execute_remediation_async(request_pk: int) -> dict[str, Any]:
    """Async task helper: execute an approved remediation."""
    from apps.infrastructure.drift_remediation import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_drift_remediation_service,  # Circular: cross-app
    )

    req = DriftRemediationRequest.objects.select_related("deployment", "report").get(pk=request_pk)
    service = get_drift_remediation_service()
    result = service.execute_remediation(req)
    if result.is_ok():
        return {"status": "completed"}
    return {"error": result.unwrap_err()}


@login_required
@require_deployment_management
@require_POST
def drift_remediation_approve(request: HttpRequest, pk: int) -> HttpResponse:
    """Approve a remediation request and queue execution asynchronously."""
    from django_q.tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
        async_task,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    user = cast("User", request.user)

    # Validate the request exists and is approvable
    req_obj = get_object_or_404(DriftRemediationRequest, pk=pk)
    if req_obj.status != "pending_approval":
        messages.error(request, _("Cannot approve request in status '%(status)s'.") % {"status": req_obj.status})
        return redirect("infrastructure:drift_remediation_list")

    # Wrap status change + task queueing in one transaction to prevent TOCTOU:
    # if async_task() fails, the status change rolls back too.
    with transaction.atomic():
        req_obj.status = "approved"
        req_obj.approved_by = user
        req_obj.approved_at = timezone.now()
        req_obj.save(update_fields=["status", "approved_by", "approved_at"])

        # Queue the slow execution part (Django-Q2 writes to django_q_task table,
        # so it participates in the same transaction)
        async_task(
            _execute_remediation_async,
            pk,
            task_name=f"remediation_{pk}",
        )

    messages.success(request, _("Remediation approved. Execution queued."))
    return redirect("infrastructure:drift_remediation_list")


@login_required
@require_deployment_management
@require_POST
def drift_remediation_reject(request: HttpRequest, pk: int) -> HttpResponse:
    """Reject a remediation request."""
    from apps.infrastructure.drift_remediation import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_drift_remediation_service,  # Circular: cross-app
    )

    user = cast("User", request.user)
    reason = request.POST.get("reason", "")
    service = get_drift_remediation_service()
    result = service.reject_remediation(pk, user, reason)

    if result.is_ok():
        messages.success(request, _("Remediation rejected."))
    else:
        messages.error(request, str(result.unwrap_err()))

    return redirect("infrastructure:drift_remediation_list")


@login_required
@require_deployment_management
@require_POST
def drift_remediation_schedule(request: HttpRequest, pk: int) -> HttpResponse:
    """Schedule a remediation for a maintenance window."""
    from apps.infrastructure.drift_remediation import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_drift_remediation_service,  # Circular: cross-app
    )

    user = cast("User", request.user)
    scheduled_for_str = request.POST.get("scheduled_for", "")

    if not scheduled_for_str:
        messages.error(request, _("Scheduled time is required."))
        return redirect("infrastructure:drift_remediation_list")

    try:
        scheduled_for = parse_datetime(scheduled_for_str)
        if scheduled_for is None:
            raise ValueError("Could not parse datetime")
        if scheduled_for.tzinfo is None:
            scheduled_for = tz.make_aware(scheduled_for)
    except ValueError:
        messages.error(request, _("Invalid date format."))
        return redirect("infrastructure:drift_remediation_list")

    service = get_drift_remediation_service()
    result = service.schedule_remediation(pk, user, scheduled_for)

    if result.is_ok():
        messages.success(request, _("Remediation scheduled."))
    else:
        messages.error(request, str(result.unwrap_err()))

    return redirect("infrastructure:drift_remediation_list")


@login_required
@require_deployment_management
@require_POST
def drift_remediation_accept(request: HttpRequest, pk: int) -> HttpResponse:
    """Accept drift (update DB to match actual state)."""
    from apps.infrastructure.drift_remediation import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_drift_remediation_service,  # Circular: cross-app
    )

    user = cast("User", request.user)
    service = get_drift_remediation_service()
    result = service.accept_drift(pk, user)

    if result.is_ok():
        messages.success(request, _("Drift accepted. Database updated to match actual state."))
    else:
        messages.error(request, str(result.unwrap_err()))

    return redirect("infrastructure:drift_remediation_list")


def _run_single_drift_scan(deployment_pk: int) -> dict[str, Any]:
    """Async task helper: scan a single deployment for drift."""
    from apps.infrastructure.drift_scanner import (  # noqa: PLC0415  # Deferred: avoids circular import
        get_drift_scanner_service,  # Circular: cross-app  # Deferred: avoids circular import
    )

    deployment = NodeDeployment.objects.get(pk=deployment_pk)
    scanner = get_drift_scanner_service()
    result = scanner.scan_deployment(deployment)
    if result.is_ok():
        return {"findings": len(result.unwrap())}
    return {"error": result.unwrap_err()}


@login_required
@require_deployment_management
@require_POST
def drift_scan_trigger(request: HttpRequest, deployment_pk: int) -> HttpResponse:
    """Manually trigger a drift scan for a deployment."""
    from django_q.tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
        async_task,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    deployment = get_object_or_404(NodeDeployment, pk=deployment_pk)

    # Queue async instead of blocking the request
    async_task(
        _run_single_drift_scan,
        deployment_pk,
        task_name=f"drift_scan_{deployment.hostname}",
    )
    messages.info(request, _("Drift scan queued. Results will appear shortly."))
    return redirect("infrastructure:drift_deployment_detail", deployment_pk=deployment_pk)
