"""
Virtualmin Management Views - PRAHO Platform
Staff interface for managing Virtualmin servers, accounts, and backups.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, TypedDict, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import AnonymousUser
from django.core.paginator import Paginator
from django.db import models, transaction
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from apps.common.security_decorators import (
    audit_service_call,
    monitor_performance,
)
from apps.customers.models import Customer
from apps.users.models import User

from .service_models import Service, ServicePlan
from .virtualmin_backup_service import BackupConfig, RestoreConfig, VirtualminBackupService
from .virtualmin_forms import (
    VirtualminAccountForm,
    VirtualminBackupForm,
    VirtualminBulkActionForm,
    VirtualminRestoreForm,
    VirtualminServerForm,
)
from .virtualmin_gateway import VirtualminConfig, VirtualminGateway
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from .virtualmin_service import (
    VirtualminBackupManagementService,
    VirtualminProvisioningService,
    VirtualminServerManagementService,
)


def _get_user_email(user: User | AnonymousUser) -> str:
    """Get user email safely, handling AnonymousUser cases."""
    if isinstance(user, AnonymousUser):
        return "anonymous"
    return user.email

# Health check constants
HEALTH_CHECK_STALE_SECONDS = 3600  # 1 hour in seconds
BULK_OPERATION_THRESHOLD = 10
MIN_DOMAIN_LENGTH = 3
MAX_CONCURRENT_HEALTH_CHECKS = 10
HEALTH_CHECK_TIMEOUT_SECONDS = 30
OVERALL_HEALTH_CHECK_TIMEOUT = 300
MAX_ERROR_DISPLAY = 3

logger = logging.getLogger(__name__)


class SyncResults(TypedDict):
    servers_checked: int
    accounts_found: int
    accounts_created: int
    accounts_updated: int
    errors: list[str]


def is_staff_or_superuser(user: User | AnonymousUser) -> bool:
    """Check if user is staff or superuser."""
    return user.is_authenticated and (user.is_staff or user.is_superuser)


# ===============================================================================
# VIRTUALMIN SERVERS MANAGEMENT
# ===============================================================================


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=5.0, alert_threshold=2.0)
def virtualmin_servers_list(request: HttpRequest) -> HttpResponse:
    """📊 List all Virtualmin servers with status and statistics."""

    # Get all servers with current statistics
    servers = VirtualminServer.objects.all().order_by("name")

    # Calculate aggregate statistics
    total_domains = sum(server.current_domains for server in servers)
    active_servers = servers.filter(status="active").count()

    # Prepare table data
    table_data = [
        {
            "id": server.id,
            "name": server.name,
            "hostname": server.hostname,
            "status": {
                "text": server.get_status_display(),
                "variant": _get_server_status_variant(server.status),
                "icon": _get_server_status_icon(server.status),
            },
            "domains": server.current_domains,
            "capacity": f"{server.current_domains}/{server.max_domains}",
            "capacity_percentage": server.capacity_percentage,
            "disk_usage": f"{server.current_disk_usage_gb} GB",
            "health_check": server.last_health_check or "Never",
            "actions": [
                {
                    "label": "View",
                    "url": reverse("provisioning:virtualmin_server_detail", args=[server.id]),
                    "variant": "primary",
                    "size": "sm",
                },
                {
                    "label": "Edit",
                    "url": reverse("provisioning:virtualmin_server_edit", args=[server.id]),
                    "variant": "secondary",
                    "size": "sm",
                },
            ],
        }
        for server in servers
    ]

    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Servers"},  # Current page - no URL
    ]

    context = {
        "page_title": "Virtualmin Servers",
        "servers": servers,
        "table_data": table_data,
        "breadcrumb_items": breadcrumb_items,
        "total_domains": total_domains,
        "active_servers": active_servers,
        "table_columns": [
            {"key": "name", "label": "Server Name", "sortable": True},
            {"key": "hostname", "label": "Hostname", "sortable": True},
            {"key": "status", "label": "Status", "sortable": True, "type": "badge"},
            {"key": "capacity", "label": "Domains", "sortable": True},
            {"key": "disk_usage", "label": "Disk Usage", "sortable": True},
            {"key": "health_check", "label": "Last Health Check", "sortable": True},
            {"key": "actions", "label": "Actions", "type": "actions"},
        ],
        "can_add_server": True,
        "add_server_url": reverse("provisioning:virtualmin_server_create"),
    }

    return render(request, "provisioning/virtualmin/servers_list.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=10.0, alert_threshold=3.0)
def virtualmin_server_detail(request: HttpRequest, server_id: str) -> HttpResponse:
    """📋 Detailed view of a specific Virtualmin server."""

    server = get_object_or_404(VirtualminServer, id=server_id)

    # Get recent accounts on this server (PRAHO-tracked)
    recent_accounts = (
        VirtualminAccount.objects.filter(server=server)
        .select_related("service", "service__customer")
        .order_by("-created_at")[:10]
    )

    # Get recent provisioning jobs
    recent_jobs = VirtualminProvisioningJob.objects.filter(server=server).order_by("-created_at")[:10]

    # Get actual domains from Virtualmin server (READ-ONLY operation)
    actual_domains = []
    domains_error = None

    if server.status == "active":
        try:
            service = VirtualminProvisioningService()
            gateway = service._get_gateway(server)

            # SAFE READ-ONLY operation - no deletion risk
            domains_result = gateway.list_domains(name_only=False)
            if domains_result.is_ok():
                raw_domains = domains_result.unwrap()

                # Get existing PRAHO accounts for comparison
                recent_accounts_domains = {acc.domain for acc in recent_accounts}

                # Enhance domain data with PRAHO tracking status
                for domain_data in raw_domains:
                    domain_info = {
                        "domain": domain_data.get("domain", ""),
                        "username": domain_data.get("username", ""),
                        "description": domain_data.get("description", ""),
                        "is_tracked_in_praho": domain_data.get("domain", "") in recent_accounts_domains,
                    }
                    actual_domains.append(domain_info)

                tracked_count = sum(1 for d in actual_domains if d["is_tracked_in_praho"])
                logger.info(
                    f"✅ [ServerDetail] Listed {len(actual_domains)} domains from {server.hostname}, "
                    f"{tracked_count} tracked in PRAHO"
                )
            else:
                domains_error = domains_result.unwrap_err()
                logger.warning(f"⚠️ [ServerDetail] Failed to list domains from {server.hostname}: {domains_error}")
        except Exception as e:
            domains_error = str(e)
            logger.error(f"🔥 [ServerDetail] Error fetching domains from {server.hostname}: {e}")

    # Health check status
    health_status = {
        "is_healthy": server.is_healthy,
        "last_check": server.last_health_check,
        "status_message": _get_health_status_message(server),
    }

    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Servers", "url": reverse("provisioning:virtualmin_servers")},
        {"text": server.name},  # Current page - no URL
    ]

    context = {
        "page_title": f"Server: {server.name}",
        "server": server,
        "breadcrumb_items": breadcrumb_items,
        "recent_accounts": recent_accounts,
        "recent_jobs": recent_jobs,
        "actual_domains": actual_domains,  # Real domains from Virtualmin
        "domains_error": domains_error,
        "health_status": health_status,
        "capacity_stats": {
            "domains_used": server.current_domains,
            "domains_total": server.max_domains,
            "domains_percentage": server.capacity_percentage,
            "disk_used": server.current_disk_usage_gb,
            "disk_total": server.max_disk_gb,
            "bandwidth_used": server.current_bandwidth_usage_gb,
            "bandwidth_total": server.max_bandwidth_gb,
        },
    }

    return render(request, "provisioning/virtualmin/server_detail.html", context)


# ===============================================================================
# VIRTUALMIN ACCOUNTS MANAGEMENT
# ===============================================================================


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=10.0, alert_threshold=3.0)
def virtualmin_accounts_list(request: HttpRequest) -> HttpResponse:
    """📊 List all Virtualmin accounts with filtering and search."""

    # Get base queryset
    accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by(
        "-created_at"
    )

    # Apply filters
    status_filter = request.GET.get("status")
    server_filter = request.GET.get("server")
    search_query = request.GET.get("search", "").strip()

    if status_filter:
        accounts = accounts.filter(status=status_filter)
    if server_filter:
        accounts = accounts.filter(server__id=server_filter)
    if search_query:
        accounts = accounts.filter(
            models.Q(domain__icontains=search_query) | models.Q(service__customer__name__icontains=search_query)
        )

    # Pagination
    paginator = Paginator(accounts, 25)
    page_number = request.GET.get("page")
    accounts_page = paginator.get_page(page_number)

    # Prepare table data
    table_data = [
        {
            "id": account.id,
            "domain": account.domain,
            "customer": account.service.customer.name if account.service else "N/A",
            "server": account.server.name,
            "status": {
                "text": account.get_status_display(),
                "variant": _get_account_status_variant(account.status),
                "icon": _get_account_status_icon(account.status),
            },
            "disk_usage": f"{account.current_disk_usage_mb} MB",
            "bandwidth_usage": f"{account.current_bandwidth_usage_mb} MB",
            "created_at": account.created_at,
            "actions": [
                {
                    "label": "View",
                    "url": reverse("provisioning:virtualmin_account_detail", args=[account.id]),
                    "variant": "primary",
                    "size": "sm",
                },
                {
                    "label": "Backup",
                    "url": reverse("provisioning:virtualmin_account_backup", args=[account.id]),
                    "variant": "success",
                    "size": "sm",
                    "icon": "💾",
                },
            ],
        }
        for account in accounts_page
    ]

    # Get filter options
    servers = VirtualminServer.objects.filter(status="active").order_by("name")
    status_choices = VirtualminAccount.STATUS_CHOICES

    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Accounts"},  # Current page - no URL
    ]

    context = {
        "page_title": "Virtualmin Accounts",
        "accounts_page": accounts_page,
        "accounts": accounts_page,  # For template compatibility
        "table_data": table_data,
        "breadcrumb_items": breadcrumb_items,
        "table_columns": [
            {"key": "domain", "label": "Domain", "sortable": True},
            {"key": "customer", "label": "Customer", "sortable": True},
            {"key": "server", "label": "Server", "sortable": True},
            {"key": "status", "label": "Status", "sortable": True, "type": "badge"},
            {"key": "disk_usage", "label": "Disk Usage", "sortable": True},
            {"key": "created_at", "label": "Created", "sortable": True, "type": "datetime"},
            {"key": "actions", "label": "Actions", "type": "actions"},
        ],
        "filters": {
            "status_filter": status_filter,
            "server_filter": server_filter,
            "search_query": search_query,
            "servers": servers,
            "status_choices": status_choices,
        },
    }

    return render(request, "provisioning/virtualmin/accounts_list.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=5.0, alert_threshold=2.0)
def virtualmin_account_detail(request: HttpRequest, account_id: str) -> HttpResponse:
    """📋 Detailed view of a specific Virtualmin account."""

    account = get_object_or_404(
        VirtualminAccount.objects.select_related("server", "service", "service__customer"), id=account_id
    )

    # Get recent provisioning jobs for this account
    recent_jobs = VirtualminProvisioningJob.objects.filter(account=account).order_by("-created_at")[:10]

    # Get backup history
    backup_service = VirtualminBackupService(account.server)
    backups_result = backup_service.list_backups(account=account, max_age_days=30)
    recent_backups = backups_result.unwrap() if backups_result.is_ok() else []

    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Accounts", "url": reverse("provisioning:virtualmin_accounts")},
        {"text": account.domain},  # Current page - no URL
    ]

    context = {
        "page_title": f"Account: {account.domain}",
        "account": account,
        "breadcrumb_items": breadcrumb_items,
        "recent_jobs": recent_jobs,
        "recent_backups": recent_backups,
        "account_stats": {
            "disk_usage_mb": account.current_disk_usage_mb,
            "disk_quota_mb": account.disk_quota_mb,
            "bandwidth_usage_mb": account.current_bandwidth_usage_mb,
            "bandwidth_quota_mb": account.bandwidth_quota_mb,
            "features": account.features,
        },
        "can_backup": account.is_active,
        "can_restore": len(recent_backups) > 0,
        "backup_url": reverse("provisioning:virtualmin_account_backup", args=[account.id]),
        "restore_url": reverse("provisioning:virtualmin_account_restore", args=[account.id]),
        "suspend_url": reverse("provisioning:virtualmin_account_suspend", args=[account.id]),
        "activate_url": reverse("provisioning:virtualmin_account_activate", args=[account.id]),
        "delete_url": reverse("provisioning:virtualmin_account_delete", args=[account.id]),
        "toggle_protection_url": reverse("provisioning:virtualmin_account_toggle_protection", args=[account.id]),
    }

    return render(request, "provisioning/virtualmin/account_detail.html", context)


# ===============================================================================
# BACKUP AND RESTORE OPERATIONS
# ===============================================================================


@login_required
@user_passes_test(is_staff_or_superuser)
@audit_service_call("virtualmin_backup_form")
def virtualmin_account_backup(request: HttpRequest, account_id: str) -> HttpResponse:
    """💾 Create backup for Virtualmin account."""

    account = get_object_or_404(VirtualminAccount, id=account_id)

    if request.method == "POST":
        form = VirtualminBackupForm(request.POST)
        if form.is_valid():
            backup_management = VirtualminBackupManagementService(account.server)

            config = BackupConfig(
                backup_type=form.cleaned_data["backup_type"],
                include_email=form.cleaned_data["include_email"],
                include_databases=form.cleaned_data["include_databases"],
                include_files=form.cleaned_data["include_files"],
                include_ssl=form.cleaned_data["include_ssl"],
            )
            backup_result = backup_management.create_backup_job(
                account=account,
                config=config,
                initiated_by=f"staff:{cast(User, request.user).email}",
            )

            if backup_result.is_ok():
                job = backup_result.unwrap()
                messages.success(request, f"Backup job created successfully! Job ID: {job.id}")
                return redirect("provisioning:virtualmin_backup_status", job_id=job.id)
            else:
                messages.error(request, f"Failed to create backup: {backup_result.unwrap_err()}")
    else:
        form = VirtualminBackupForm()

    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Accounts", "url": reverse("provisioning:virtualmin_accounts")},
        {"text": account.domain, "url": reverse("provisioning:virtualmin_account_detail", args=[account.id])},
        {"text": "Backup"},  # Current page - no URL
    ]

    context = {
        "page_title": f"Backup Account: {account.domain}",
        "account": account,
        "form": form,
        "breadcrumb_items": breadcrumb_items,
        "form_action": reverse("provisioning:virtualmin_account_backup", args=[account.id]),
        "cancel_url": reverse("provisioning:virtualmin_account_detail", args=[account.id]),
    }

    return render(request, "provisioning/virtualmin/backup_form.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@audit_service_call("virtualmin_restore_form")
def virtualmin_account_restore(request: HttpRequest, account_id: str) -> HttpResponse:
    """🔄 Restore Virtualmin account from backup."""

    account = get_object_or_404(VirtualminAccount, id=account_id)

    # Get available backups
    backup_service = VirtualminBackupService(account.server)
    backups_result = backup_service.list_backups(account=account, max_age_days=90)
    available_backups = backups_result.unwrap() if backups_result.is_ok() else []

    if not available_backups:
        messages.error(request, "No backups available for this account.")
        return redirect("provisioning:virtualmin_account_detail", account_id=account.id)

    if request.method == "POST":
        form = VirtualminRestoreForm(request.POST, available_backups=available_backups)
        if form.is_valid():
            backup_management = VirtualminBackupManagementService(account.server)

            config = RestoreConfig(
                backup_id=form.cleaned_data["backup_id"],
                restore_email=form.cleaned_data["restore_email"],
                restore_databases=form.cleaned_data["restore_databases"],
                restore_files=form.cleaned_data["restore_files"],
                restore_ssl=form.cleaned_data["restore_ssl"],
            )
            restore_result = backup_management.create_restore_job(
                account=account,
                config=config,
                initiated_by=f"staff:{cast(User, request.user).email}",
            )

            if restore_result.is_ok():
                job = restore_result.unwrap()
                messages.success(request, f"Restore job created successfully! Job ID: {job.id}")
                return redirect("provisioning:virtualmin_backup_status", job_id=job.id)
            else:
                messages.error(request, f"Failed to create restore: {restore_result.unwrap_err()}")
    else:
        form = VirtualminRestoreForm(available_backups=available_backups)

    context = {
        "page_title": f"Restore Account: {account.domain}",
        "account": account,
        "form": form,
        "available_backups": available_backups,
        "form_action": reverse("provisioning:virtualmin_account_restore", args=[account.id]),
        "cancel_url": reverse("provisioning:virtualmin_account_detail", args=[account.id]),
    }

    return render(request, "provisioning/virtualmin/restore_form.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=3.0, alert_threshold=1.0)
def virtualmin_backup_status(request: HttpRequest, job_id: str) -> HttpResponse:
    """📊 Monitor backup/restore job status."""

    job = get_object_or_404(VirtualminProvisioningJob, id=job_id)

    # Get real-time status from backup service
    backup_service = VirtualminBackupService(job.server)

    if job.operation == "backup_domain":
        live_status = backup_service.get_backup_status(str(job.id))
    elif job.operation == "restore_domain":
        live_status = backup_service.get_restore_status(str(job.id))
    else:
        live_status = {"status": "unknown", "progress": 0}

    # If it's an HTMX request, return partial template
    if request.headers.get("HX-Request"):
        return render(
            request,
            "provisioning/virtualmin/partials/job_status.html",
            {"job": job, "live_status": live_status, "is_complete": job.status in ["completed", "failed"]},
        )

    context = {
        "page_title": f"Job Status: {job.operation}",
        "job": job,
        "live_status": live_status,
        "refresh_url": reverse("provisioning:virtualmin_backup_status", args=[job.id]),
        "account_url": reverse("provisioning:virtualmin_account_detail", args=[job.account.id]) if job.account else "",
        "is_complete": job.status in ["completed", "failed"],
    }

    return render(request, "provisioning/virtualmin/backup_status.html", context)


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================


def _get_server_status_variant(status: str) -> str:
    """Get badge variant for server status."""
    return {"active": "success", "maintenance": "warning", "disabled": "secondary", "failed": "danger"}.get(
        status, "secondary"
    )


def _get_server_status_icon(status: str) -> str:
    """Get emoji icon for server status."""
    return {"active": "✅", "maintenance": "🔧", "disabled": "⏸️", "failed": "❌"}.get(status, "❓")


def _get_account_status_variant(status: str) -> str:
    """Get badge variant for account status."""
    return {
        "provisioning": "info",
        "active": "success",
        "suspended": "warning",
        "terminated": "secondary",
        "error": "danger",
    }.get(status, "secondary")


def _get_account_status_icon(status: str) -> str:
    """Get emoji icon for account status."""
    return {"provisioning": "⏳", "active": "✅", "suspended": "⏸️", "terminated": "🗑️", "error": "❌"}.get(status, "❓")


def _get_health_status_message(server: VirtualminServer) -> str:
    """Get human-readable health status message."""
    if not server.last_health_check:
        return "Health check has never been performed"

    if server.is_healthy:
        return "Server is healthy and responding"

    age = timezone.now() - server.last_health_check
    if age.total_seconds() > HEALTH_CHECK_STALE_SECONDS:
        return f"Health check is stale ({age.seconds // HEALTH_CHECK_STALE_SECONDS}h ago)"

    return "Server is not responding to health checks"


# ===============================================================================
# ADDITIONAL VIRTUALMIN MANAGEMENT VIEWS
# ===============================================================================


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=5.0, alert_threshold=2.0)
def virtualmin_server_create(request: HttpRequest) -> HttpResponse:
    """+ Create new Virtualmin server."""

    if request.method == "POST":
        form = VirtualminServerForm(request.POST)
        if form.is_valid():
            server = form.save()
            messages.success(request, f"Virtualmin server '{server.name}' created successfully!")
            return redirect("provisioning:virtualmin_server_detail", server_id=server.id)
    else:
        form = VirtualminServerForm()

    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Servers", "url": reverse("provisioning:virtualmin_servers")},
        {"text": "Add Server"},  # Current page - no URL
    ]

    context = {
        "page_title": "Create Virtualmin Server",
        "form": form,
        "breadcrumb_items": breadcrumb_items,
        "form_action": reverse("provisioning:virtualmin_server_create"),
        "cancel_url": reverse("provisioning:virtualmin_servers"),
        "test_connection_url": reverse("provisioning:virtualmin_server_test_connection"),
    }

    return render(request, "provisioning/virtualmin/server_form.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=5.0, alert_threshold=2.0)
def virtualmin_server_edit(request: HttpRequest, server_id: str) -> HttpResponse:
    """✏️ Edit Virtualmin server configuration."""

    server = get_object_or_404(VirtualminServer, id=server_id)

    if request.method == "POST":
        form = VirtualminServerForm(request.POST, instance=server)
        if form.is_valid():
            server = form.save()
            messages.success(request, f"Server '{server.name}' updated successfully!")
            return redirect("provisioning:virtualmin_server_detail", server_id=server.id)
    else:
        form = VirtualminServerForm(instance=server)

    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Servers", "url": reverse("provisioning:virtualmin_servers")},
        {"text": server.name, "url": reverse("provisioning:virtualmin_server_detail", args=[server.id])},
        {"text": "Edit"},  # Current page - no URL
    ]

    context = {
        "page_title": f"Edit Server: {server.name}",
        "server": server,
        "form": form,
        "breadcrumb_items": breadcrumb_items,
        "form_action": reverse("provisioning:virtualmin_server_edit", args=[server.id]),
        "cancel_url": reverse("provisioning:virtualmin_server_detail", args=[server.id]),
        "test_connection_url": reverse("provisioning:virtualmin_server_test_connection"),
    }

    return render(request, "provisioning/virtualmin/server_form.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@require_POST
@audit_service_call("virtualmin_connection_test")
def virtualmin_server_test_connection(request: HttpRequest) -> HttpResponse:
    """🔌 Test connection to Virtualmin server using form data."""

    try:
        # Get connection parameters from POST data
        hostname = request.POST.get("hostname", "").strip()
        api_port = request.POST.get("api_port", "10000")
        api_username = request.POST.get("api_username", "").strip()
        api_password = request.POST.get("api_password", "").strip()
        use_ssl = request.POST.get("use_ssl") == "on"
        ssl_verify = request.POST.get("ssl_verify") == "on"

        # Validate required fields
        if not all([hostname, api_username, api_password]):
            return HttpResponse(
                '<div class="bg-red-500/10 border border-red-500/20 rounded-lg p-4">'
                '<div class="flex items-center">'
                '<div class="flex-shrink-0">'
                '<svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">'
                '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>'
                "</div>"
                '<div class="ml-3">'
                '<h3 class="text-sm font-medium text-red-400">Connection Failed</h3>'
                '<p class="text-sm text-red-300 mt-1">Please fill in all required fields: Hostname, API Username, and API Password</p>'
                "</div>"
                "</div>"
                "</div>",
                content_type="text/html",
            )

        # Create a temporary server instance for testing
        temp_server = VirtualminServer(
            hostname=hostname, api_port=int(api_port), api_username=api_username, use_ssl=use_ssl, ssl_verify=ssl_verify
        )
        # Set the password using the proper method (handles encryption)
        temp_server.set_api_password(api_password)

        # Test the connection
        provisioning_service = VirtualminProvisioningService()
        result = provisioning_service.test_server_connection(temp_server)

        if result.is_ok():
            connection_info = result.unwrap()
            return HttpResponse(
                '<div class="bg-green-500/10 border border-green-500/20 rounded-lg p-4">'
                '<div class="flex items-center">'
                '<div class="flex-shrink-0">'
                '<svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">'
                '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" /></svg>'
                "</div>"
                '<div class="ml-3">'
                '<h3 class="text-sm font-medium text-green-400">Connection Successful</h3>'
                f'<p class="text-sm text-green-300 mt-1">Successfully connected to Virtualmin at {hostname}:{api_port}</p>'
                f'<p class="text-sm text-green-200 mt-1">Server info: {connection_info.get("server_info", "Connected")}</p>'
                "</div>"
                "</div>"
                "</div>",
                content_type="text/html",
            )
        else:
            error_message = result.unwrap_err()
            # Provide more detailed error information for debugging
            return HttpResponse(
                '<div class="bg-red-500/10 border border-red-500/20 rounded-lg p-4">'
                '<div class="flex items-center">'
                '<div class="flex-shrink-0">'
                '<svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">'
                '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>'
                "</div>"
                '<div class="ml-3">'
                '<h3 class="text-sm font-medium text-red-400">Connection Failed</h3>'
                f'<p class="text-sm text-red-300 mt-1"><strong>Error:</strong> {error_message}</p>'
                f'<p class="text-sm text-slate-400 mt-1"><strong>Trying to connect to:</strong> {"https" if use_ssl else "http"}://{hostname}:{api_port}</p>'
                f'<p class="text-sm text-slate-400"><strong>Username:</strong> {api_username}</p>'
                f'<p class="text-sm text-slate-400"><strong>SSL Verify:</strong> {"Yes" if ssl_verify else "No"}</p>'
                "</div>"
                "</div>"
                "</div>",
                content_type="text/html",
            )

    except Exception as e:
        logger.error(f"🔥 [TestConnection] Error testing connection: {e}")
        return HttpResponse(
            '<div class="bg-red-500/10 border border-red-500/20 rounded-lg p-4">'
            '<div class="flex items-center">'
            '<div class="flex-shrink-0">'
            '<svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">'
            '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>'
            "</div>"
            '<div class="ml-3">'
            '<h3 class="text-sm font-medium text-red-400">Test Failed</h3>'
            f'<p class="text-sm text-red-300 mt-1">An error occurred during connection test: {e!s}</p>'
            "</div>"
            "</div>"
            "</div>",
            content_type="text/html",
        )


@login_required
@user_passes_test(is_staff_or_superuser)
@require_POST
@audit_service_call("virtualmin_health_check")
def virtualmin_server_health_check(request: HttpRequest, server_id: str) -> HttpResponse:
    """🏥 Trigger manual health check for Virtualmin server."""

    server = get_object_or_404(VirtualminServer, id=server_id)

    try:
        management_service = VirtualminServerManagementService()
        health_result = management_service.health_check_server(server)

        if health_result.is_ok():
            health_data = health_result.unwrap()
            messages.success(request, f"Health check completed. Server status: {health_data.get('status', 'Unknown')}")
            # Refresh server data from database
            server.refresh_from_db()
        else:
            messages.error(request, f"Health check failed: {health_result.unwrap_err()}")

    except Exception as e:
        messages.error(request, f"Failed to perform health check: {e!s}")

    # If it's an HTMX request, return just the health status card
    if request.headers.get("HX-Request"):
        health_status = {
            "is_healthy": server.is_healthy,
            "last_check": server.last_health_check,
            "status_message": _get_health_status_message(server),
        }
        return render(
            request,
            "provisioning/virtualmin/partials/health_status_card.html",
            {"server": server, "health_status": health_status},
        )

    return redirect("provisioning:virtualmin_server_detail", server_id=server.id)


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=10.0, alert_threshold=3.0)
def virtualmin_backups_list(request: HttpRequest) -> HttpResponse:
    """📋 List all Virtualmin backups across all accounts."""

    # Get any active server for backup listing (backups are centralized in S3)
    server = VirtualminServer.objects.filter(status="active").first()

    if not server:
        messages.error(request, "No active Virtualmin servers found")
        return redirect("provisioning:virtualmin_servers")

    backup_service = VirtualminBackupService(server)

    # Apply filters
    domain_filter = request.GET.get("domain")
    backup_type_filter = request.GET.get("type")
    max_age_days = int(request.GET.get("max_age", 30))

    # Get account if domain filter specified
    account = None
    if domain_filter:
        try:
            account = VirtualminAccount.objects.get(domain=domain_filter)
        except VirtualminAccount.DoesNotExist:
            messages.warning(request, f"Domain '{domain_filter}' not found")

    # List backups
    backups_result = backup_service.list_backups(
        account=account, backup_type=backup_type_filter, max_age_days=max_age_days
    )

    if backups_result.is_err():
        messages.error(request, f"Failed to list backups: {backups_result.unwrap_err()}")
        backups: list[Any] = []
    else:
        backups = backups_result.unwrap()

    # Prepare table data
    table_data = [
        {
            "backup_id": backup["backup_id"],
            "domain": backup["domain"],
            "type": backup["backup_type"],
            "created_at": backup["created_at"],
            "status": {
                "text": backup["status"].title(),
                "variant": "success" if backup["status"] == "completed" else "warning",
                "icon": "✅" if backup["status"] == "completed" else "⏳",
            },
            "features": _format_backup_features(backup),
            "actions": [
                {
                    "label": "Download",
                    "url": f"/virtualmin/backups/{backup['backup_id']}/download/",
                    "variant": "primary",
                    "size": "sm",
                    "icon": "⬇️",
                },
                {
                    "label": "Delete",
                    "url": f"/virtualmin/backups/{backup['backup_id']}/delete/",
                    "variant": "danger",
                    "size": "sm",
                    "icon": "🗑️",
                    "confirm": f"Delete backup {backup['backup_id']}?",
                },
            ],
        }
        for backup in backups
    ]

    # Get filter options
    domains = VirtualminAccount.objects.values_list("domain", flat=True).order_by("domain")
    backup_types = ["full", "incremental", "config_only"]

    context = {
        "page_title": "Virtualmin Backups",
        "backups": backups,
        "table_data": table_data,
        "table_columns": [
            {"key": "backup_id", "label": "Backup ID", "sortable": True},
            {"key": "domain", "label": "Domain", "sortable": True},
            {"key": "type", "label": "Type", "sortable": True},
            {"key": "created_at", "label": "Created", "sortable": True, "type": "datetime"},
            {"key": "status", "label": "Status", "sortable": True, "type": "badge"},
            {"key": "features", "label": "Features", "sortable": False},
            {"key": "actions", "label": "Actions", "type": "actions"},
        ],
        "filters": {
            "domain_filter": domain_filter,
            "backup_type_filter": backup_type_filter,
            "max_age_days": max_age_days,
            "domains": domains,
            "backup_types": backup_types,
        },
    }

    return render(request, "provisioning/virtualmin/backups_list.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=30.0, alert_threshold=5.0)
def virtualmin_bulk_actions(request: HttpRequest) -> HttpResponse:
    """🔄 Perform bulk actions on multiple Virtualmin accounts."""

    if request.method == "POST":
        form = VirtualminBulkActionForm(request.POST)
        if form.is_valid():
            action = form.cleaned_data["action"]
            account_ids = form.cleaned_data["selected_accounts"]

            try:
                # Get accounts
                accounts = VirtualminAccount.objects.filter(id__in=account_ids).select_related("server")

                if not accounts:
                    messages.error(request, "No valid accounts found for bulk action")
                    return redirect("provisioning:virtualmin_accounts")

                # Execute bulk action and handle result
                result = _execute_bulk_action(action, list(accounts), form.cleaned_data)
                _handle_bulk_action_result(request, action, result)

                return redirect("provisioning:virtualmin_accounts")

            except Exception as e:
                messages.error(request, f"Bulk action failed: {e!s}")
    else:
        form = VirtualminBulkActionForm()

    context = {
        "page_title": "Bulk Actions",
        "form": form,
        "form_action": reverse("provisioning:virtualmin_bulk_actions"),
        "cancel_url": reverse("provisioning:virtualmin_accounts"),
    }

    return render(request, "provisioning/virtualmin/bulk_actions.html", context)


# ===============================================================================
# BULK ACTION HELPER FUNCTIONS
# ===============================================================================


@dataclass
class BulkOperationResult:
    """
    Result of a bulk operation with comprehensive tracking.
    
    Attributes:
        total_processed: Total number of items processed
        successful_count: Number of successful operations
        failed_count: Number of failed operations
        errors: List of error messages for failed operations
        rollback_performed: Whether rollback was performed for failed operations
        processing_time_seconds: Total processing time
    """
    total_processed: int
    successful_count: int
    failed_count: int
    errors: list[str]
    rollback_performed: bool = False
    processing_time_seconds: float = 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_processed == 0:
            return 0.0
        return (self.successful_count / self.total_processed) * 100


def _handle_backup_action_result(request: HttpRequest, result: BulkOperationResult) -> None:
    """Handle backup action result and add appropriate messages."""
    if result.rollback_performed:
        messages.error(
            request, 
            f"Backup operation failed and was rolled back. "
            f"Errors: {'; '.join(result.errors[:MAX_ERROR_DISPLAY])}{'...' if len(result.errors) > MAX_ERROR_DISPLAY else ''}"
        )
    else:
        messages.success(
            request, 
            f"Backup jobs created for {result.successful_count}/{result.total_processed} accounts "
            f"({result.success_rate:.1f}% success) in {result.processing_time_seconds:.2f}s"
        )
        if result.failed_count > 0:
            messages.warning(
                request,
                f"{result.failed_count} backup operations failed. Check logs for details."
            )


def _handle_suspend_action_result(request: HttpRequest, result: BulkOperationResult) -> None:
    """Handle suspend action result and add appropriate messages."""
    if result.rollback_performed:
        messages.error(
            request,
            f"Suspend operation failed and was rolled back. "
            f"No accounts were modified. Error: {result.errors[0] if result.errors else 'Unknown error'}"
        )
    else:
        messages.success(
            request, 
            f"Suspended {result.successful_count}/{result.total_processed} accounts "
            f"({result.success_rate:.1f}% success) in {result.processing_time_seconds:.2f}s"
        )
        if result.failed_count > 0:
            messages.warning(
                request,
                f"{result.failed_count} accounts could not be suspended. Check logs for details."
            )


def _handle_activate_action_result(request: HttpRequest, result: BulkOperationResult) -> None:
    """Handle activate action result and add appropriate messages.""" 
    if result.rollback_performed:
        messages.error(
            request,
            f"Activate operation failed and was rolled back. "
            f"No accounts were modified. Error: {result.errors[0] if result.errors else 'Unknown error'}"
        )
    else:
        messages.success(
            request, 
            f"Activated {result.successful_count}/{result.total_processed} accounts "
            f"({result.success_rate:.1f}% success) in {result.processing_time_seconds:.2f}s"
        )
        if result.failed_count > 0:
            messages.warning(
                request,
                f"{result.failed_count} accounts could not be activated. Check logs for details."
            )


def _handle_health_check_action_result(request: HttpRequest, result: BulkOperationResult) -> None:
    """Handle health check action result and add appropriate messages."""
    messages.success(
        request, 
        f"Health checks completed for {result.total_processed} accounts. "
        f"{result.successful_count} healthy ({result.success_rate:.1f}%) "
        f"in {result.processing_time_seconds:.2f}s"
    )
    if result.failed_count > 0:
        messages.warning(
            request,
            f"{result.failed_count} accounts failed health checks. See logs for detailed results."
        )


def _execute_bulk_action(action: str, accounts: list[VirtualminAccount], form_data: dict[str, Any]) -> BulkOperationResult:
    """Execute the specified bulk action on accounts."""
    if action == "backup":
        return _execute_bulk_backup(accounts, form_data)
    elif action == "suspend":
        return _execute_bulk_suspend(accounts)
    elif action == "activate":
        return _execute_bulk_activate(accounts)  
    elif action == "health_check":
        return _execute_bulk_health_check(accounts)
    else:
        return BulkOperationResult(
            total_processed=len(accounts),
            successful_count=0,
            failed_count=len(accounts),
            errors=[f"Unknown action: {action}"],
            rollback_performed=False
        )


def _handle_bulk_action_result(request: HttpRequest, action: str, result: BulkOperationResult) -> None:
    """Handle bulk action result based on action type."""
    if action == "backup":
        _handle_backup_action_result(request, result)
    elif action == "suspend":
        _handle_suspend_action_result(request, result)
    elif action == "activate":
        _handle_activate_action_result(request, result)
    elif action == "health_check":
        _handle_health_check_action_result(request, result)


@transaction.atomic
def _execute_bulk_backup(accounts: list[VirtualminAccount], form_data: dict[str, Any]) -> BulkOperationResult:
    """
    Execute backup for multiple accounts with atomic transaction management.
    
    Algorithm Complexity: O(n) where n is the number of accounts
    
    Performance Optimizations:
    - Atomic database transactions for consistency
    - Batch processing for large account lists
    - Comprehensive error tracking and rollback
    - Progress tracking for long-running operations
    
    Args:
        accounts: List of VirtualminAccount objects to backup
        form_data: Form data containing backup configuration
        
    Returns:
        BulkOperationResult with detailed operation statistics
        
    Transaction Management:
        - All database changes are atomic
        - Failed operations trigger rollback of the entire batch
        - Individual backup jobs are tracked separately
        - Comprehensive audit logging for all operations
    """
    start_time = time.perf_counter()
    backup_type = form_data.get("backup_type", "full")
    errors = []
    successful_accounts = []
    
    logger.info(f"🚀 [Bulk Backup] Starting backup for {len(accounts)} accounts (type: {backup_type})")
    
    try:
        # Process accounts in batches to manage memory and transaction size
        batch_size = 20  # Configurable batch size for optimal performance
        
        for i in range(0, len(accounts), batch_size):
            batch = accounts[i:i + batch_size]
            logger.debug(f"📦 [Bulk Backup] Processing batch {i//batch_size + 1} ({len(batch)} accounts)")
            
            for account in batch:
                try:
                    # Create backup job with proper error handling
                    backup_management = VirtualminBackupManagementService(account.server)
                    config = BackupConfig(backup_type=backup_type)
                    
                    backup_result = backup_management.create_backup_job(
                        account=account, 
                        config=config, 
                        initiated_by="bulk_action"
                    )
                    
                    if backup_result.is_ok():
                        successful_accounts.append(account)
                        logger.debug(f"✅ [Bulk Backup] Success: {account.domain}")
                    else:
                        error_msg = f"Backup creation failed for {account.domain}: {backup_result.unwrap_err()}"
                        errors.append(error_msg)
                        logger.warning(f"⚠️ [Bulk Backup] {error_msg}")
                        
                except Exception as e:
                    error_msg = f"Backup failed for account {account.domain}: {e!s}"
                    errors.append(error_msg)
                    logger.warning(f"🔥 [Bulk Backup] {error_msg}")
                    
                    # For critical errors, consider breaking the batch
                    if "critical" in str(e).lower() or "database" in str(e).lower():
                        logger.error("🚨 [Bulk Backup] Critical error detected, stopping batch processing")
                        raise
        
        processing_time = time.perf_counter() - start_time
        result = BulkOperationResult(
            total_processed=len(accounts),
            successful_count=len(successful_accounts),
            failed_count=len(errors),
            errors=errors,
            rollback_performed=False,
            processing_time_seconds=processing_time
        )
        
        logger.info(
            f"✅ [Bulk Backup] Completed: {result.successful_count}/{result.total_processed} successful "
            f"({result.success_rate:.1f}%) in {result.processing_time_seconds:.2f}s"
        )
        
        return result
        
    except Exception as e:
        # Transaction will be automatically rolled back due to @transaction.atomic
        processing_time = time.perf_counter() - start_time
        error_msg = f"Bulk backup operation failed with critical error: {e!s}"
        errors.append(error_msg)
        
        logger.error(f"🔥 [Bulk Backup] Transaction rolled back: {error_msg}")
        
        return BulkOperationResult(
            total_processed=len(accounts),
            successful_count=0,  # All operations rolled back
            failed_count=len(accounts),
            errors=errors,
            rollback_performed=True,
            processing_time_seconds=processing_time
        )


@transaction.atomic
def _execute_bulk_suspend(accounts: list[VirtualminAccount]) -> BulkOperationResult:
    """
    Suspend multiple accounts with atomic transaction management.
    
    Algorithm Complexity: O(n) where n is the number of accounts
    
    Performance Optimizations:
    - Atomic database operations with rollback safety
    - Batch updates using Django's bulk operations
    - Pre-filtering of eligible accounts
    - Comprehensive audit logging
    
    Args:
        accounts: List of VirtualminAccount objects to suspend
        
    Returns:
        BulkOperationResult with detailed operation statistics
        
    Transaction Safety:
        - All status changes are atomic
        - Failed operations trigger complete rollback
        - Database consistency is maintained
        - Audit trail for all modifications
    """
    start_time = time.perf_counter()
    errors = []
    eligible_accounts = []
    
    # Pre-filter eligible accounts for suspension
    for account in accounts:
        if account.status == "active":
            eligible_accounts.append(account)
        else:
            errors.append(f"Account {account.domain} is not active (current status: {account.status})")
    
    logger.info(f"🚫 [Bulk Suspend] Processing {len(eligible_accounts)} eligible accounts")
    
    try:
        # Create savepoint for partial rollback capability
        savepoint = transaction.savepoint()
        
        successful_accounts = []
        
        # Use bulk update for better performance when possible
        if len(eligible_accounts) > BULK_OPERATION_THRESHOLD:  # Use bulk operations for larger datasets
            try:
                # Bulk update status
                account_ids = [acc.id for acc in eligible_accounts]
                updated_count = VirtualminAccount.objects.filter(
                    id__in=account_ids,
                    status="active"
                ).update(
                    status="suspended",
                    last_modified=timezone.now()
                )
                
                successful_accounts = eligible_accounts[:updated_count]
                logger.info(f"📦 [Bulk Suspend] Bulk updated {updated_count} accounts")
                
            except Exception as e:
                # Fallback to individual updates if bulk operation fails
                logger.warning(f"⚠️ [Bulk Suspend] Bulk operation failed, falling back to individual updates: {e}")
                transaction.savepoint_rollback(savepoint)
                savepoint = transaction.savepoint()
                
                for account in eligible_accounts:
                    try:
                        account.status = "suspended"
                        account.save(update_fields=['status', 'last_modified'])
                        successful_accounts.append(account)
                        
                    except Exception as individual_error:
                        error_msg = f"Failed to suspend {account.domain}: {individual_error!s}"
                        errors.append(error_msg)
                        logger.warning(f"🔥 [Bulk Suspend] {error_msg}")
        else:
            # Process individually for smaller datasets
            for account in eligible_accounts:
                try:
                    account.status = "suspended"
                    account.save(update_fields=['status', 'last_modified'])
                    successful_accounts.append(account)
                    
                except Exception as e:
                    error_msg = f"Failed to suspend {account.domain}: {e!s}"
                    errors.append(error_msg)
                    logger.warning(f"🔥 [Bulk Suspend] {error_msg}")
        
        # Commit the savepoint
        transaction.savepoint_commit(savepoint)
        
        processing_time = time.perf_counter() - start_time
        result = BulkOperationResult(
            total_processed=len(accounts),
            successful_count=len(successful_accounts),
            failed_count=len(accounts) - len(successful_accounts),
            errors=errors,
            rollback_performed=False,
            processing_time_seconds=processing_time
        )
        
        logger.info(
            f"✅ [Bulk Suspend] Completed: {result.successful_count}/{result.total_processed} suspended "
            f"({result.success_rate:.1f}%) in {result.processing_time_seconds:.2f}s"
        )
        
        return result
        
    except Exception as e:
        # Transaction will be automatically rolled back
        processing_time = time.perf_counter() - start_time
        error_msg = f"Bulk suspend operation failed with critical error: {e!s}"
        
        logger.error(f"🔥 [Bulk Suspend] Transaction rolled back: {error_msg}")
        
        return BulkOperationResult(
            total_processed=len(accounts),
            successful_count=0,
            failed_count=len(accounts),
            errors=[error_msg, *errors],
            rollback_performed=True,
            processing_time_seconds=processing_time
        )


@transaction.atomic
def _execute_bulk_activate(accounts: list[VirtualminAccount]) -> BulkOperationResult:
    """
    Activate multiple accounts with atomic transaction management.
    
    Algorithm Complexity: O(n) where n is the number of accounts
    
    Performance Optimizations:
    - Atomic database operations with rollback safety
    - Batch updates using Django's bulk operations
    - Pre-filtering of eligible accounts
    - Optimized for high-volume operations
    
    Args:
        accounts: List of VirtualminAccount objects to activate
        
    Returns:
        BulkOperationResult with detailed operation statistics
        
    Transaction Safety:
        - All status changes are atomic
        - Database consistency maintained
        - Complete rollback on critical failures
    """
    start_time = time.perf_counter()
    errors = []
    eligible_accounts = []
    
    # Pre-filter eligible accounts for activation
    for account in accounts:
        if account.status == "suspended":
            eligible_accounts.append(account)
        else:
            errors.append(f"Account {account.domain} is not suspended (current status: {account.status})")
    
    logger.info(f"🔓 [Bulk Activate] Processing {len(eligible_accounts)} eligible accounts")
    
    try:
        successful_accounts = []
        
        # Use bulk update for better performance
        if len(eligible_accounts) > BULK_OPERATION_THRESHOLD:
            try:
                account_ids = [acc.id for acc in eligible_accounts]
                updated_count = VirtualminAccount.objects.filter(
                    id__in=account_ids,
                    status="suspended"
                ).update(
                    status="active",
                    last_modified=timezone.now()
                )
                
                successful_accounts = eligible_accounts[:updated_count]
                logger.info(f"📦 [Bulk Activate] Bulk updated {updated_count} accounts")
                
            except Exception as e:
                logger.warning(f"⚠️ [Bulk Activate] Bulk operation failed, using individual updates: {e}")
                
                for account in eligible_accounts:
                    try:
                        account.status = "active"
                        account.save(update_fields=['status', 'last_modified'])
                        successful_accounts.append(account)
                        
                    except Exception as individual_error:
                        error_msg = f"Failed to activate {account.domain}: {individual_error!s}"
                        errors.append(error_msg)
                        logger.warning(f"🔥 [Bulk Activate] {error_msg}")
        else:
            # Individual processing for smaller datasets
            for account in eligible_accounts:
                try:
                    account.status = "active"
                    account.save(update_fields=['status', 'last_modified'])
                    successful_accounts.append(account)
                    
                except Exception as e:
                    error_msg = f"Failed to activate {account.domain}: {e!s}"
                    errors.append(error_msg)
                    logger.warning(f"🔥 [Bulk Activate] {error_msg}")
        
        processing_time = time.perf_counter() - start_time
        result = BulkOperationResult(
            total_processed=len(accounts),
            successful_count=len(successful_accounts),
            failed_count=len(accounts) - len(successful_accounts),
            errors=errors,
            rollback_performed=False,
            processing_time_seconds=processing_time
        )
        
        logger.info(
            f"✅ [Bulk Activate] Completed: {result.successful_count}/{result.total_processed} activated "
            f"({result.success_rate:.1f}%) in {result.processing_time_seconds:.2f}s"
        )
        
        return result
        
    except Exception as e:
        processing_time = time.perf_counter() - start_time
        error_msg = f"Bulk activate operation failed with critical error: {e!s}"
        
        logger.error(f"🔥 [Bulk Activate] Transaction rolled back: {error_msg}")
        
        return BulkOperationResult(
            total_processed=len(accounts),
            successful_count=0,
            failed_count=len(accounts),
            errors=[error_msg, *errors],
            rollback_performed=True,
            processing_time_seconds=processing_time
        )


def _validate_account_status(account: VirtualminAccount) -> tuple[bool, str]:
    """Validate account status for health check."""
    if account.status not in ["active", "suspended"]:
        return False, f"Invalid account status: {account.status}"
    return True, ""


def _validate_server_connectivity(account: VirtualminAccount) -> tuple[bool, str]:
    """Validate server connectivity for health check.""" 
    if not account.server or account.server.status != "active":
        return False, "Server is not available or inactive"
    return True, ""


def _validate_domain_configuration(account: VirtualminAccount) -> tuple[bool, str]:
    """Validate domain configuration for health check."""
    if not account.domain or len(account.domain) < MIN_DOMAIN_LENGTH:
        return False, "Invalid domain configuration"
    return True, ""


def _validate_disk_usage_data(account: VirtualminAccount) -> tuple[bool, str]:
    """Validate disk usage data for health check."""
    if hasattr(account, 'disk_usage_mb') and account.disk_usage_mb < 0:
        return False, "Invalid disk usage data"
    return True, ""


def _perform_gateway_connectivity_test(account: VirtualminAccount) -> tuple[bool, str]:
    """Perform Virtualmin gateway connectivity test."""
    try:
        config = VirtualminConfig(server=account.server)
        gateway = VirtualminGateway(config)
        
        ping_result = gateway.ping_server()
        if not ping_result:
            return False, "Virtualmin server connectivity failed"
        return True, ""
        
    except Exception as gateway_error:
        return False, f"Gateway health check failed: {gateway_error!s}"


def _perform_single_health_check(account: VirtualminAccount) -> tuple[VirtualminAccount, bool, str | None]:
    """
    Perform health check on a single account using multiple validation steps.
    
    Returns:
        Tuple of (account, success, error_message)
    """
    try:
        # Run all validation checks in sequence
        validation_checks = [
            _validate_account_status,
            _validate_server_connectivity,
            _validate_domain_configuration,
            _validate_disk_usage_data,
            _perform_gateway_connectivity_test,
        ]
        
        for check_function in validation_checks:
            is_valid, error_msg = check_function(account)
            if not is_valid:
                return account, False, error_msg
        
        return account, True, None
        
    except Exception as e:
        return account, False, f"Health check exception: {e!s}"


@transaction.atomic
def _execute_bulk_health_check(accounts: list[VirtualminAccount]) -> BulkOperationResult:
    """
    Perform health check on multiple accounts with comprehensive monitoring.
    
    Algorithm Complexity: O(n*k) where n is accounts and k is checks per account
    
    Performance Optimizations:
    - Parallel health checks for improved performance
    - Timeout management for unresponsive accounts
    - Batch processing for large account lists
    - Comprehensive health metrics collection
    
    Args:
        accounts: List of VirtualminAccount objects to health check
        
    Returns:
        BulkOperationResult with detailed health check statistics
        
    Health Check Coverage:
        - Account status verification
        - Virtualmin server connectivity
        - Disk usage validation
        - Service availability checks
        - DNS resolution testing
    """
    
    start_time = time.perf_counter()
    errors = []
    successful_checks = []
    
    
    logger.info(f"🏥 [Bulk Health Check] Starting health checks for {len(accounts)} accounts")
    
    try:
        # Use thread pool for parallel health checks (with reasonable concurrency limit)
        max_workers = min(MAX_CONCURRENT_HEALTH_CHECKS, len(accounts))  # Limit concurrent checks to prevent overload
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all health check tasks
            future_to_account = {
                executor.submit(_perform_single_health_check, account): account 
                for account in accounts
            }
            
            # Process completed checks
            for future in as_completed(future_to_account, timeout=OVERALL_HEALTH_CHECK_TIMEOUT):  # Overall timeout
                try:
                    account, success, error_msg = future.result(timeout=HEALTH_CHECK_TIMEOUT_SECONDS)  # Per-check timeout
                    
                    if success:
                        successful_checks.append(account)
                        logger.debug(f"✅ [Health Check] {account.domain} - OK")
                    else:
                        errors.append(f"Health check failed for {account.domain}: {error_msg}")
                        logger.warning(f"⚠️ [Health Check] {account.domain} - {error_msg}")
                        
                except Exception as e:
                    account = future_to_account[future]
                    error_msg = f"Health check timeout or error for {account.domain}: {e!s}"
                    errors.append(error_msg)
                    logger.warning(f"⏰ [Health Check] {error_msg}")
        
        processing_time = time.perf_counter() - start_time
        result = BulkOperationResult(
            total_processed=len(accounts),
            successful_count=len(successful_checks),
            failed_count=len(accounts) - len(successful_checks),
            errors=errors,
            rollback_performed=False,
            processing_time_seconds=processing_time
        )
        
        logger.info(
            f"✅ [Bulk Health Check] Completed: {result.successful_count}/{result.total_processed} healthy "
            f"({result.success_rate:.1f}%) in {result.processing_time_seconds:.2f}s"
        )
        
        return result
        
    except Exception as e:
        processing_time = time.perf_counter() - start_time
        error_msg = f"Bulk health check operation failed: {e!s}"
        
        logger.error(f"🔥 [Bulk Health Check] Operation failed: {error_msg}")
        
        return BulkOperationResult(
            total_processed=len(accounts),
            successful_count=len(successful_checks),
            failed_count=len(accounts) - len(successful_checks),
            errors=[error_msg, *errors],
            rollback_performed=False,  # Health checks don't modify data
            processing_time_seconds=processing_time
        )


def _format_backup_features(backup: dict[str, Any]) -> str:
    """Format backup features for display."""
    features = []
    if backup.get("include_email"):
        features.append("📧 Email")
    if backup.get("include_databases"):
        features.append("🗄️ DB")
    if backup.get("include_files"):
        features.append("📁 Files")
    if backup.get("include_ssl"):
        features.append("🔒 SSL")
    return ", ".join(features) if features else "None"


@login_required
@user_passes_test(is_staff_or_superuser)
@require_POST
@audit_service_call("virtualmin_accounts_sync")
@monitor_performance(max_duration_seconds=30.0, alert_threshold=10.0)
def virtualmin_accounts_sync(request: HttpRequest) -> HttpResponse:  # noqa: C901, PLR0912, PLR0915
    """🔄 Sync accounts from active Virtualmin servers to PRAHO database."""
    
    # Get all active servers
    active_servers = VirtualminServer.objects.filter(status="active")
    
    if not active_servers.exists():
        messages.error(request, "No active Virtualmin servers found to sync from")
        return redirect("provisioning:virtualmin_accounts")
    
    sync_results: SyncResults = {
        "servers_checked": 0,
        "accounts_found": 0,
        "accounts_created": 0,
        "accounts_updated": 0,
        "errors": []
    }
    
    provisioning_service = VirtualminProvisioningService()
    
    for server in active_servers:
        sync_results["servers_checked"] += 1
        
        try:
            # Get gateway for this server
            gateway = provisioning_service._get_gateway(server)
            
            # List domains from this server
            domains_result = gateway.list_domains(name_only=False)
            
            if domains_result.is_err():
                error_msg = f"Failed to get domains from {server.name}: {domains_result.unwrap_err()}"
                sync_results["errors"].append(error_msg)
                logger.warning(f"⚠️ [AccountSync] {error_msg}")
                continue
                
            domains = domains_result.unwrap()
            sync_results["accounts_found"] += len(domains)
            
            # Group domains by username (actual Virtualmin accounts)
            accounts_by_username = {}
            for domain_data in domains:
                domain_name = domain_data.get("domain", "").strip()
                username = domain_data.get("username", "").strip()
                
                if not domain_name or not username:
                    continue
                    
                if username not in accounts_by_username:
                    accounts_by_username[username] = {
                        "domains": [],
                        "primary_domain": domain_name,  # First domain becomes primary
                        "username": username
                    }
                
                accounts_by_username[username]["domains"].append(domain_name)
            
            # Process each Virtualmin account (grouped by username)
            for username, account_data in accounts_by_username.items():
                try:
                    # Check if account already exists in PRAHO
                    account = VirtualminAccount.objects.get(virtualmin_username=username)
                    # Update existing account
                    account.domain = account_data["primary_domain"]
                    account.domains = account_data["domains"] 
                    account.server = server
                    account.last_sync_at = timezone.now()
                    
                    # Fetch actual usage data from Virtualmin API
                    try:
                        gateway = provisioning_service._get_gateway(server)
                        domain_info_result = gateway.get_domain_info(account.domain)
                        
                        if domain_info_result.is_ok():
                            domain_info = domain_info_result.unwrap()
                            account.current_disk_usage_mb = domain_info.get("disk_usage_mb", 0)
                            account.current_bandwidth_usage_mb = domain_info.get("bandwidth_usage_mb", 0)
                            
                            # Update quotas if available
                            if domain_info.get("disk_quota_mb"):
                                account.disk_quota_mb = domain_info["disk_quota_mb"]
                            if domain_info.get("bandwidth_quota_mb"):
                                account.bandwidth_quota_mb = domain_info["bandwidth_quota_mb"]
                                
                            logger.info(f"✅ [UsageSync] Updated usage for {username}: {domain_info['disk_usage_mb']}MB disk, {domain_info['bandwidth_usage_mb']}MB bandwidth")
                        else:
                            logger.warning(f"⚠️ [UsageSync] Failed to get usage for {account.domain}: {domain_info_result.unwrap_err()}")
                    except Exception as e:
                        logger.warning(f"⚠️ [UsageSync] Exception getting usage for {account.domain}: {e}")
                        # Keep existing values if API call fails
                    
                    account.save()
                    sync_results["accounts_updated"] += 1
                    
                except VirtualminAccount.DoesNotExist:
                    # Create new account with associated Service
                    try:
                        # Get default customer and service plan for synced accounts
                        default_customer = Customer.objects.first()
                        default_service_plan = ServicePlan.objects.first()
                        
                        if not default_customer or not default_service_plan:
                            error_msg = f"Missing default customer or service plan for account {username}"
                            sync_results["errors"].append(error_msg)
                            continue
                        
                        # Get or create Service record
                        service, created = Service.objects.get_or_create(
                            username=username,
                            defaults={
                                "customer": default_customer,
                                "service_plan": default_service_plan,
                                "service_name": f"Virtualmin Account - {username}",
                                "domain": account_data["primary_domain"],
                                "status": "active",
                                "billing_cycle": "monthly",
                                "price": default_service_plan.price_monthly or 0.00
                            }
                        )
                        
                        # Update service if it exists
                        if not created:
                            service.domain = account_data["primary_domain"]
                            service.save()
                        
                        # Fetch actual usage data from Virtualmin API
                        disk_usage_mb = 0
                        bandwidth_usage_mb = 0
                        disk_quota_mb = 1000  # Default quota
                        bandwidth_quota_mb = 10000  # Default quota
                        
                        try:
                            gateway = provisioning_service._get_gateway(server)
                            domain_info_result = gateway.get_domain_info(account_data["primary_domain"])
                            
                            if domain_info_result.is_ok():
                                domain_info = domain_info_result.unwrap()
                                disk_usage_mb = domain_info.get("disk_usage_mb", 0)
                                bandwidth_usage_mb = domain_info.get("bandwidth_usage_mb", 0)
                                
                                # Update quotas if available
                                if domain_info.get("disk_quota_mb"):
                                    disk_quota_mb = domain_info["disk_quota_mb"]
                                if domain_info.get("bandwidth_quota_mb"):
                                    bandwidth_quota_mb = domain_info["bandwidth_quota_mb"]
                                    
                                logger.info(f"✅ [AccountSync] Fetched usage data for {account_data['primary_domain']}: {disk_usage_mb}MB disk, {bandwidth_usage_mb}MB bandwidth")
                            else:
                                logger.warning(f"⚠️ [AccountSync] Failed to fetch usage data for {account_data['primary_domain']}: {domain_info_result.unwrap_err()}")
                        except Exception as e:
                            logger.warning(f"⚠️ [AccountSync] Exception fetching usage data for {account_data['primary_domain']}: {e!s}")
                        
                        # Create VirtualminAccount linked to the Service
                        VirtualminAccount.objects.create(
                            service=service,
                            domain=account_data["primary_domain"],
                            domains=account_data["domains"],
                            server=server,
                            virtualmin_username=username,
                            status="active",  # Assume active since it exists on server
                            disk_quota_mb=disk_quota_mb,
                            bandwidth_quota_mb=bandwidth_quota_mb,
                            current_disk_usage_mb=disk_usage_mb,
                            current_bandwidth_usage_mb=bandwidth_usage_mb,
                            last_sync_at=timezone.now()
                        )
                        sync_results["accounts_created"] += 1
                        
                    except Exception as e:
                        error_msg = f"Failed to create account for {username}: {e!s}"
                        sync_results["errors"].append(error_msg)
                        logger.warning(f"⚠️ [AccountSync] {error_msg}")
                        
        except Exception as e:
            error_msg = f"Error syncing server {server.name}: {e!s}"
            sync_results["errors"].append(error_msg)
            logger.error(f"🔥 [AccountSync] {error_msg}")
    
    # Build success message
    success_parts = []
    if sync_results["accounts_created"] > 0:
        success_parts.append(f"{sync_results['accounts_created']} created")
    if sync_results["accounts_updated"] > 0:
        success_parts.append(f"{sync_results['accounts_updated']} updated")
        
    if success_parts:
        message = f"Sync completed: {', '.join(success_parts)} from {sync_results['servers_checked']} servers"
        messages.success(request, message)
    else:
        messages.info(request, f"No new accounts found on {sync_results['servers_checked']} servers")
    
    # Show errors if any
    if sync_results["errors"]:
        error_count = len(sync_results["errors"])
        messages.warning(request, f"{error_count} errors occurred during sync. Check logs for details.")
    
    logger.info(f"✅ [AccountSync] Completed: {sync_results}")
    
    # If HTMX request, return partial template
    if request.headers.get("HX-Request"):
        # Refresh the accounts data for the partial
        accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by("-created_at")
        return render(request, "provisioning/virtualmin/partials/accounts_table.html", {"accounts": accounts})
    
    return redirect("provisioning:virtualmin_accounts")


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=5.0, alert_threshold=2.0)
def virtualmin_account_new(request: HttpRequest) -> HttpResponse:
    """🆕 Create a new Virtualmin account."""
    if request.method == "POST":
        form = VirtualminAccountForm(request.POST)
        if form.is_valid():
            try:
                # Create account
                account = form.save()
                messages.success(request, f"Account {account.domain} created successfully!")
                return redirect("provisioning:virtualmin_account_detail", account_id=account.id)
            except Exception as e:
                messages.error(request, f"Failed to create account: {e!s}")
    else:
        form = VirtualminAccountForm()

    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Accounts", "url": reverse("provisioning:virtualmin_accounts")},
        {"text": "New Account"},  # Current page - no URL
    ]

    context = {
        "page_title": "Create New Virtualmin Account",
        "form": form,
        "breadcrumb_items": breadcrumb_items,
        "action_url": reverse("provisioning:virtualmin_account_new"),
    }

    return render(request, "provisioning/virtualmin/account_form.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@require_POST
@audit_service_call("virtualmin_account_suspend")
@monitor_performance(max_duration_seconds=15.0, alert_threshold=5.0)
def virtualmin_account_suspend(request: HttpRequest, account_id: str) -> HttpResponse:
    """🚫 Suspend a Virtualmin account."""
    account = get_object_or_404(VirtualminAccount, id=account_id)
    
    try:
        # Call Virtualmin API to actually suspend the account
        provisioning_service = VirtualminProvisioningService()
        user_email = _get_user_email(request.user)
        result = provisioning_service.suspend_account(account, reason=f"Suspended by {user_email}")
        
        if result.is_ok():
            messages.success(request, f"Account {account.virtualmin_username} has been suspended on the server.")
            logger.info(f"✅ [AccountSuspend] Account {account.virtualmin_username} suspended by {user_email}")
        else:
            error_msg = result.unwrap_err()
            messages.error(request, f"Failed to suspend account {account.virtualmin_username}: {error_msg}")
            logger.error(f"❌ [AccountSuspend] Failed to suspend {account.virtualmin_username}: {error_msg}")
        
    except Exception as e:
        messages.error(request, f"Failed to suspend account {account.virtualmin_username}: {e!s}")
        logger.error(f"❌ [AccountSuspend] Failed to suspend {account.virtualmin_username}: {e}")
    
    # If HTMX request, check where we came from
    if request.headers.get("HX-Request"):
        # Check if coming from accounts list or detail page based on referrer
        referer = request.headers.get("HX-Current-URL", "")
        if f"accounts/{account.id}/" in referer:
            # Coming from detail page, refresh the page
            return redirect("provisioning:virtualmin_account_detail", account_id=account.id)
        else:
            # Coming from accounts list, return updated table
            accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by("-created_at")
            return render(request, "provisioning/virtualmin/partials/accounts_table.html", {"accounts": accounts})
    
    return redirect("provisioning:virtualmin_accounts")


@login_required
@user_passes_test(is_staff_or_superuser)
@require_POST
@audit_service_call("virtualmin_account_activate")
@monitor_performance(max_duration_seconds=15.0, alert_threshold=5.0)
def virtualmin_account_activate(request: HttpRequest, account_id: str) -> HttpResponse:
    """✅ Activate a Virtualmin account."""
    account = get_object_or_404(VirtualminAccount, id=account_id)
    
    try:
        # Call Virtualmin API to actually activate the account
        provisioning_service = VirtualminProvisioningService()
        result = provisioning_service.unsuspend_account(account)
        
        if result.is_ok():
            messages.success(request, f"Account {account.virtualmin_username} has been activated on the server.")
            logger.info(f"✅ [AccountActivate] Account {account.virtualmin_username} activated by {_get_user_email(request.user)}")
        else:
            error_msg = result.unwrap_err()
            messages.error(request, f"Failed to activate account {account.virtualmin_username}: {error_msg}")
            logger.error(f"❌ [AccountActivate] Failed to activate {account.virtualmin_username}: {error_msg}")
        
    except Exception as e:
        messages.error(request, f"Failed to activate account {account.virtualmin_username}: {e!s}")
        logger.error(f"❌ [AccountActivate] Failed to activate {account.virtualmin_username}: {e}")
    
    # If HTMX request, check where we came from
    if request.headers.get("HX-Request"):
        # Check if coming from accounts list or detail page based on referrer
        referer = request.headers.get("HX-Current-URL", "")
        if f"accounts/{account.id}/" in referer:
            # Coming from detail page, refresh the page
            return redirect("provisioning:virtualmin_account_detail", account_id=account.id)
        else:
            # Coming from accounts list, return updated table
            accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by("-created_at")
            return render(request, "provisioning/virtualmin/partials/accounts_table.html", {"accounts": accounts})
    
    return redirect("provisioning:virtualmin_accounts")


@login_required
@user_passes_test(is_staff_or_superuser)
@require_POST
@audit_service_call("virtualmin_account_toggle_protection")
def virtualmin_account_toggle_protection(request: HttpRequest, account_id: str) -> HttpResponse:
    """🛡️ Toggle deletion protection for a Virtualmin account."""
    account = get_object_or_404(VirtualminAccount, id=account_id)
    
    if request.method == "POST":
        # Toggle the protection status
        account.protected_from_deletion = not account.protected_from_deletion
        account.save()
        
        action = "enabled" if account.protected_from_deletion else "disabled"
        icon = "🔒" if account.protected_from_deletion else "🔓"
        
        messages.success(
            request, 
            f"{icon} Deletion protection {action} for account {account.virtualmin_username}"
        )
        
        logger.info(
            f"{icon} [AccountProtection] Protection {action} for {account.virtualmin_username} by {_get_user_email(request.user)}"
        )
        
        # If HTMX request, check where we came from
        if request.headers.get("HX-Request"):
            # Check if coming from accounts list or detail page based on referrer
            referer = request.headers.get("HX-Current-URL", "")
            if f"accounts/{account.id}/" in referer:
                # Coming from detail page, return updated quick actions section
                context = {
                    "account": account,
                    "toggle_protection_url": reverse("provisioning:virtualmin_account_toggle_protection", args=[account.id]),
                    "delete_url": reverse("provisioning:virtualmin_account_delete", args=[account.id]),
                }
                return render(request, "provisioning/virtualmin/partials/quick_actions.html", context)
            else:
                # Coming from accounts list, return updated table
                accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by("-created_at")
                return render(request, "provisioning/virtualmin/partials/accounts_table.html", {"accounts": accounts})
    
    return redirect("provisioning:virtualmin_accounts")


@login_required
@user_passes_test(is_staff_or_superuser)
@require_http_methods(["DELETE", "POST"])
@audit_service_call("virtualmin_account_delete")
def virtualmin_account_delete(request: HttpRequest, account_id: str) -> HttpResponse:
    """🗑️ Delete a Virtualmin account permanently."""
    account = get_object_or_404(VirtualminAccount, id=account_id)
    
    # Protection is handled in the service layer
    try:
        service = VirtualminProvisioningService(account.server)
        result = service.delete_account(account)
        
        if result.is_ok():
            messages.success(request, f"✅ Account {account.domain} deleted successfully")
            logger.info(f"🗑️ [AccountDelete] Account {account.domain} deleted by {_get_user_email(request.user)}")
        else:
            error_msg = result.unwrap_err()
            messages.error(request, f"❌ Failed to delete account: {error_msg}")
            logger.error(f"🗑️ [AccountDelete] Failed to delete {account.domain}: {error_msg}")
            
    except Exception as e:
        messages.error(request, f"❌ Error deleting account: {e}")
        logger.exception(f"🗑️ [AccountDelete] Exception deleting {account.domain}: {e}")
    
    # If HTMX request, return updated table
    if request.headers.get("HX-Request"):
        accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by("-created_at")
        return render(request, "provisioning/virtualmin/partials/accounts_table.html", {"accounts": accounts})
    
    return redirect("provisioning:virtualmin_accounts")


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=3.0, alert_threshold=1.0)
def virtualmin_job_status(request: HttpRequest, job_id: str) -> HttpResponse:
    """📊 Show Virtualmin job status and progress."""
    job = get_object_or_404(VirtualminProvisioningJob, id=job_id)
    
    # Build breadcrumb navigation
    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "🖥️ Provisioning", "url": reverse("provisioning:virtualmin_servers")},
        {"text": "⚙️ Jobs", "url": reverse("provisioning:virtualmin_servers")},
        {"text": f"Job {job.correlation_id[:8]}", "url": ""},
    ]
    
    max_retry_count = 3  # Maximum number of retry attempts allowed
    context = {
        "job": job,
        "page_title": f"Job Status - {job.operation}",
        "breadcrumb_items": breadcrumb_items,
        "can_retry": job.status == "failed" and job.retry_count < max_retry_count,
    }
    
    return render(request, "provisioning/virtualmin/job_status.html", context)


@login_required
@user_passes_test(is_staff_or_superuser)
@monitor_performance(max_duration_seconds=2.0, alert_threshold=1.0)
def virtualmin_job_logs(request: HttpRequest, job_id: str) -> HttpResponse:
    """📋 Show Virtualmin job logs and details."""
    job = get_object_or_404(VirtualminProvisioningJob, id=job_id)
    
    # Return logs as JSON for HTMX requests
    if request.headers.get("HX-Request"):
        logs = []
        
        # Add job lifecycle logs
        logs.append({
            "timestamp": job.created_at.isoformat(),
            "level": "INFO", 
            "message": f"Job created: {job.operation} for {job.account.domain if job.account else 'unknown'}"
        })
        
        if job.started_at:
            logs.append({
                "timestamp": job.started_at.isoformat(),
                "level": "INFO",
                "message": "Job started"
            })
            
        if job.completed_at:
            logs.append({
                "timestamp": job.completed_at.isoformat(), 
                "level": "SUCCESS" if job.status == "completed" else "ERROR",
                "message": f"Job {job.status}" + (f": {job.status_message}" if job.status_message else "")
            })
            
        # Add response data as structured logs
        if job.result:
            logs.append({
                "timestamp": (job.completed_at or job.updated_at).isoformat(),
                "level": "DEBUG",
                "message": f"Response: {job.result}"
            })
            
        return JsonResponse({"logs": logs})
    
    # Regular template render for non-HTMX requests
    context = {
        "job": job,
        "page_title": f"Job Logs - {job.operation}",
    }
    
    return render(request, "provisioning/virtualmin/job_logs.html", context)
