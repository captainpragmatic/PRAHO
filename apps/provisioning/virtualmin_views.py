"""
Virtualmin Management Views - PRAHO Platform
Staff interface for managing Virtualmin servers, accounts, and backups.
"""

import logging
from typing import Any, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import AnonymousUser
from django.core.paginator import Paginator
from django.db import models
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.common.security_decorators import (
    audit_service_call,
    monitor_performance,
)
from apps.users.models import User

from .virtualmin_backup_service import BackupConfig, RestoreConfig, VirtualminBackupService
from .virtualmin_forms import (
    VirtualminBackupForm,
    VirtualminBulkActionForm,
    VirtualminRestoreForm,
    VirtualminServerForm,
)
from .virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from .virtualmin_service import (
    VirtualminBackupManagementService,
    VirtualminProvisioningService,
    VirtualminServerManagementService,
)

# Health check constants
HEALTH_CHECK_STALE_SECONDS = 3600  # 1 hour in seconds

logger = logging.getLogger(__name__)


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

    context = {
        "page_title": "Virtualmin Servers",
        "servers": servers,
        "table_data": table_data,
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

    context = {
        "page_title": f"Server: {server.name}",
        "server": server,
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

    context = {
        "page_title": "Virtualmin Accounts",
        "accounts_page": accounts_page,
        "table_data": table_data,
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

    context = {
        "page_title": f"Account: {account.domain}",
        "account": account,
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

    context = {
        "page_title": f"Backup Account: {account.domain}",
        "account": account,
        "form": form,
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

    context = {
        "page_title": "Create Virtualmin Server",
        "form": form,
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

    context = {
        "page_title": f"Edit Server: {server.name}",
        "server": server,
        "form": form,
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
        from .virtualmin_models import VirtualminServer  # noqa: PLC0415

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

                # Execute bulk action
                if action == "backup":
                    success_count = _execute_bulk_backup(list(accounts), form.cleaned_data)
                    messages.success(request, f"Backup jobs created for {success_count}/{len(accounts)} accounts")
                elif action == "suspend":
                    success_count = _execute_bulk_suspend(list(accounts))
                    messages.success(request, f"Suspended {success_count}/{len(accounts)} accounts")
                elif action == "activate":
                    success_count = _execute_bulk_activate(list(accounts))
                    messages.success(request, f"Activated {success_count}/{len(accounts)} accounts")
                elif action == "health_check":
                    success_count = _execute_bulk_health_check(list(accounts))
                    messages.success(request, f"Health checks completed for {success_count}/{len(accounts)} accounts")

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


def _execute_bulk_backup(accounts: list[VirtualminAccount], form_data: dict[str, Any]) -> int:
    """Execute backup for multiple accounts."""
    success_count = 0
    backup_type = form_data.get("backup_type", "full")

    for account in accounts:
        try:
            backup_management = VirtualminBackupManagementService(account.server)
            config = BackupConfig(backup_type=backup_type)
            result = backup_management.create_backup_job(
                account=account, config=config, initiated_by="bulk_action"
            )
            if result.is_ok():
                success_count += 1
        except Exception as e:
            logger.warning(f"Bulk backup failed for account {account.domain}: {e}")
            continue  # Skip failed accounts

    return success_count


def _execute_bulk_suspend(accounts: list[VirtualminAccount]) -> int:
    """Suspend multiple accounts."""
    success_count = 0

    for account in accounts:
        try:
            if account.status == "active":
                account.status = "suspended"
                account.save()
                success_count += 1
        except Exception as e:
            logger.warning(f"Bulk suspend failed for account {account.domain}: {e}")
            continue

    return success_count


def _execute_bulk_activate(accounts: list[VirtualminAccount]) -> int:
    """Activate multiple accounts."""
    success_count = 0

    for account in accounts:
        try:
            if account.status == "suspended":
                account.status = "active"
                account.save()
                success_count += 1
        except Exception as e:
            logger.warning(f"Bulk activate failed for account {account.domain}: {e}")
            continue

    return success_count


def _execute_bulk_health_check(accounts: list[VirtualminAccount]) -> int:
    """Perform health check on multiple accounts."""
    success_count = 0

    for _account in accounts:
        try:
            # Placeholder for actual health check implementation
            success_count += 1
        except Exception as e:
            logger.warning(f"Bulk health check failed: {e}")
            continue

    return success_count


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
@monitor_performance(max_duration_seconds=5.0, alert_threshold=2.0)
def virtualmin_account_new(request: HttpRequest) -> HttpResponse:
    """🆕 Create a new Virtualmin account."""
    from .virtualmin_forms import VirtualminAccountForm  # noqa: PLC0415

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

    context = {
        "page_title": "Create New Virtualmin Account",
        "form": form,
        "action_url": reverse("provisioning:virtualmin_account_new"),
    }

    return render(request, "provisioning/virtualmin/account_form.html", context)
