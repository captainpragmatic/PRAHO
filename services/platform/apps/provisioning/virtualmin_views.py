"""
Virtualmin Management Views - PRAHO Platform
Staff interface for managing Virtualmin servers, accounts, and backups.
"""

import logging
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from contextvars import ContextVar
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, TypedDict, cast
from urllib.parse import urlencode
from uuid import UUID

from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import AnonymousUser
from django.core.paginator import Paginator
from django.db import connections, models, transaction
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods, require_POST

from apps.common.decorators import admin_required
from apps.common.security_decorators import (
    audit_service_call,
    monitor_performance,
)
from apps.common.types import Result
from apps.customers.models import Customer
from apps.users.models import User

from .service_models import Service, ServicePlan
from .services import HostingAccountStaffActions
from .virtualmin_backup_service import BackupConfig, RestoreConfig, VirtualminBackupService
from .virtualmin_forms import (
    VirtualminAccountForm,
    VirtualminBackupForm,
    VirtualminBulkActionForm,
    VirtualminBulkFilterForm,
    VirtualminMigrationForm,
    VirtualminRestoreForm,
    VirtualminServerForm,
)
from .virtualmin_gateway import VirtualminConfig, VirtualminGateway
from .virtualmin_migration_models import account_has_active_migration
from .virtualmin_migration_service import VirtualminMigrationService, list_migration_domains
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


# Health check defaults
HEALTH_CHECK_STALE_SECONDS = 3600  # 1 hour in seconds
MIN_DOMAIN_LENGTH = 3
_DEFAULT_MAX_CONCURRENT_HEALTH_CHECKS = 10
# Most accounts the bulk page lists at once: one POST field each, under Django's 1,000-field cap.
BULK_ACCOUNT_LIMIT = 500
_DEFAULT_OVERALL_HEALTH_CHECK_TIMEOUT = 300
_DEFAULT_MAX_ERROR_DISPLAY = 3
_HEALTH_CHECK_DEADLINE: ContextVar[float | None] = ContextVar("virtualmin_health_check_deadline", default=None)


def get_max_concurrent_health_checks() -> int:
    """Get max concurrent health checks from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting(
        "provisioning.max_concurrent_health_checks", _DEFAULT_MAX_CONCURRENT_HEALTH_CHECKS
    )


def get_overall_health_check_timeout() -> int:
    """Get overall health check timeout from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting(
        "provisioning.overall_health_check_timeout", _DEFAULT_OVERALL_HEALTH_CHECK_TIMEOUT
    )


def get_max_error_display() -> int:
    """Get max error display from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("provisioning.max_error_display", _DEFAULT_MAX_ERROR_DISPLAY)


logger = logging.getLogger(__name__)


class SyncResults(TypedDict):
    servers_checked: int
    accounts_found: int
    accounts_created: int
    accounts_updated: int
    errors: list[str]


def is_staff_or_superuser(user: User | AnonymousUser) -> bool:
    """Check if user is staff or superuser."""
    return user.is_authenticated and getattr(user, "is_staff_user", False)


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

    bulk_filters = urlencode(
        {key: value for key, value in (("server", server_filter), ("status", status_filter)) if value}
    )
    bulk_url = reverse("provisioning:virtualmin_bulk_actions")

    context = {
        "page_title": "Virtualmin Accounts",
        "bulk_actions_url": f"{bulk_url}?{bulk_filters}" if bulk_filters else bulk_url,
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

    migration = account.migrations.first()

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
        "migration": migration,
        "migrate_url": reverse("provisioning:virtualmin_account_migrate", args=[account.pk]),
        "backup_url": reverse("provisioning:virtualmin_account_backup", args=[account.id]),
        "restore_url": reverse("provisioning:virtualmin_account_restore", args=[account.id]),
        "suspend_url": reverse("provisioning:virtualmin_account_suspend", args=[account.id]),
        "activate_url": reverse("provisioning:virtualmin_account_activate", args=[account.id]),
        "delete_url": reverse("provisioning:virtualmin_account_delete", args=[account.id]),
        "toggle_protection_url": reverse("provisioning:virtualmin_account_toggle_protection", args=[account.id]),
    }

    response = render(request, "provisioning/virtualmin/account_detail.html", context)
    if migration is not None and migration.status == "completed" and not migration.routing_note_shown:
        account.migrations.filter(pk=migration.pk, status="completed").update(routing_note_shown=True)
    return response


# ===============================================================================
# BACKUP AND RESTORE OPERATIONS
# ===============================================================================


@login_required
@user_passes_test(is_staff_or_superuser)
@audit_service_call("virtualmin_migrate_form")
def virtualmin_account_migrate(request: HttpRequest, account_id: str) -> HttpResponse:
    """Render a migration form or validate and enqueue one manual migration."""
    account = get_object_or_404(VirtualminAccount.objects.select_related("server"), pk=account_id)
    form = VirtualminMigrationForm(request.POST if request.method == "POST" else None, account=account)
    if request.method == "POST" and form.is_valid():
        result = VirtualminMigrationService().start_migration(
            account, form.cleaned_data["target_server"], initiated_by=cast(User, request.user)
        )
        if result.is_ok():
            messages.success(request, _("Migration queued. Follow its status before changing routing/DNS."))
            return redirect("provisioning:virtualmin_account_detail", account_id=account.pk)
        form.add_error(None, result.unwrap_err())
    return render(
        request,
        "provisioning/virtualmin/migrate_form.html",
        {
            "page_title": _("Migrate Virtualmin account"),
            "account": account,
            "form": form,
            "form_action": reverse("provisioning:virtualmin_account_migrate", args=[account.pk]),
            "cancel_url": reverse("provisioning:virtualmin_account_detail", args=[account.pk]),
        },
    )


@login_required
@user_passes_test(is_staff_or_superuser)
@require_http_methods(["POST"])
@audit_service_call("virtualmin_migration_resolve")
def virtualmin_migration_resolve(request: HttpRequest, account_id: str) -> HttpResponse:
    """Operator terminal resolution of a needs_review migration (releases the lock)."""
    from .virtualmin_migration_service import resolve_migration  # noqa: PLC0415

    account = get_object_or_404(VirtualminAccount, pk=account_id)
    # Bind to the migration the operator actually saw — a stale form must not
    # resolve a different migration that reached needs_review afterwards.
    try:
        migration_id = UUID(str(request.POST.get("migration_id", "")))
    except ValueError:
        migration_id = None
    migration = account.migrations.filter(pk=migration_id, status="needs_review").first() if migration_id else None
    if migration is None:
        messages.error(request, _("That migration is no longer awaiting review; re-check the current status."))
    else:
        result = resolve_migration(migration, resolved_by=cast(User, request.user), note=request.POST.get("note", ""))
        if result.is_ok():
            messages.success(request, _("Migration marked resolved. The account is unlocked."))
        else:
            messages.error(request, result.unwrap_err())
    return redirect("provisioning:virtualmin_account_detail", account_id=account.pk)


@login_required
@user_passes_test(is_staff_or_superuser)
@require_http_methods(["POST"])
@audit_service_call("virtualmin_job_resolve")
def virtualmin_job_resolve(request: HttpRequest, job_id: str) -> HttpResponse:
    """Operator terminal resolution of an attention (uncertain) backup/restore job."""
    job = get_object_or_404(VirtualminProvisioningJob, pk=job_id)
    note = request.POST.get("note", "").strip() or _("operator confirmed remote state")
    actor = request.user.email if request.user.is_authenticated else "system"
    # fsm-bypass: CharField job status; attention -> failed is the only edge.
    rows = VirtualminProvisioningJob.objects.filter(pk=job.pk, status="attention").update(
        status="failed",
        status_message=f"Manually resolved by {actor}: {note}",
        next_retry_at=None,
        updated_at=timezone.now(),
    )
    if rows:
        from .virtualmin_signals import audit_job_status_transition  # noqa: PLC0415  # Circular

        job.refresh_from_db()
        audit_job_status_transition(
            job, actor_type="user", user=request.user if request.user.is_authenticated else None
        )
        messages.success(request, _("Job marked resolved. The account is unlocked."))
    else:
        messages.error(request, _("Only a job awaiting attention can be resolved."))
    return redirect("provisioning:virtualmin_job_status", job_id=job.pk)


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
                return redirect("provisioning:virtualmin_job_status", job_id=job.id)
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
    backups_result = backup_service.list_backups(account=account)
    available_backups = backups_result.unwrap() if backups_result.is_ok() else []

    if not available_backups:
        messages.error(request, _("No backups available for this account."))
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
                force_restore=form.cleaned_data.get("force_restore", False),
            )
            restore_result = backup_management.create_restore_job(
                account=account,
                config=config,
                initiated_by=f"staff:{cast(User, request.user).email}",
            )

            if restore_result.is_ok():
                job = restore_result.unwrap()
                messages.success(request, f"Restore job created successfully! Job ID: {job.id}")
                return redirect("provisioning:virtualmin_job_status", job_id=job.id)
            else:
                messages.error(request, f"Failed to create restore: {restore_result.unwrap_err()}")
    else:
        form = VirtualminRestoreForm(available_backups=available_backups)

    breadcrumb_items = [
        {"text": "🏠 Management", "url": "/dashboard/"},
        {"text": "⚙️ Provisioning", "url": reverse("provisioning:services")},
        {"text": "🖥️ Virtualmin", "url": "#"},
        {"text": "Accounts", "url": reverse("provisioning:virtualmin_accounts")},
        {"text": account.domain, "url": reverse("provisioning:virtualmin_account_detail", args=[account.id])},
        {"text": "Restore"},  # Current page - no URL
    ]

    context = {
        "page_title": f"Restore Account: {account.domain}",
        "account": account,
        "breadcrumb_items": breadcrumb_items,
        "form": form,
        "available_backups": available_backups,
        "form_action": reverse("provisioning:virtualmin_account_restore", args=[account.id]),
        "cancel_url": reverse("provisioning:virtualmin_account_detail", args=[account.id]),
    }

    return render(request, "provisioning/virtualmin/restore_form.html", context)


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
        ssl_cert_fingerprint = request.POST.get("ssl_cert_fingerprint", "").strip()

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
            hostname=hostname,
            api_port=int(api_port),
            api_username=api_username,
            use_ssl=use_ssl,
            ssl_verify=ssl_verify,
            ssl_cert_fingerprint=ssl_cert_fingerprint,
        )
        # Set the password using the proper method (handles encryption)
        temp_server.set_api_password(api_password)

        # Test the connection using the OPERATOR-SUPPLIED credentials (use_credential_vault=False),
        # not whatever the vault holds for this hostname — otherwise testing an existing host would
        # authenticate with the stored vault entry and report a misleading success/failure.
        provisioning_service = VirtualminProvisioningService()
        result = provisioning_service.test_server_connection(temp_server, use_credential_vault=False)

        if result.is_ok():
            connection_info = result.unwrap()
            return HttpResponse(  # nosemgrep: direct-use-of-httpresponse — content is developer-controlled string/integer
                '<div class="bg-green-500/10 border border-green-500/20 rounded-lg p-4">'  # nosemgrep: raw-html-format — developer-controlled HTML confirmation string
                '<div class="flex items-center">'
                '<div class="flex-shrink-0">'
                '<svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">'
                '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" /></svg>'
                "</div>"
                '<div class="ml-3">'
                '<h3 class="text-sm font-medium text-green-400">Connection Successful</h3>'
                + format_html(
                    '<p class="text-sm text-green-300 mt-1">Successfully connected to Virtualmin at {}:{}</p>',
                    hostname,
                    api_port,
                )
                + format_html(
                    '<p class="text-sm text-green-200 mt-1">Server info: {}</p>',
                    connection_info.get("server_info", "Connected"),
                )
                + "</div>"
                "</div>"
                "</div>",
                content_type="text/html",
            )
        else:
            error_message = result.unwrap_err()
            # Provide more detailed error information for debugging
            return HttpResponse(  # nosemgrep: direct-use-of-httpresponse — content is developer-controlled string/integer
                '<div class="bg-red-500/10 border border-red-500/20 rounded-lg p-4">'  # nosemgrep: raw-html-format — developer-controlled HTML confirmation string
                '<div class="flex items-center">'
                '<div class="flex-shrink-0">'
                '<svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">'
                '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>'
                "</div>"
                '<div class="ml-3">'
                '<h3 class="text-sm font-medium text-red-400">Connection Failed</h3>'
                + format_html('<p class="text-sm text-red-300 mt-1"><strong>Error:</strong> {}</p>', error_message)
                + format_html(
                    '<p class="text-sm text-slate-400 mt-1"><strong>Trying to connect to:</strong> {}://{}:{}</p>',
                    "https" if use_ssl else "http",
                    hostname,
                    api_port,
                )
                + format_html('<p class="text-sm text-slate-400"><strong>Username:</strong> {}</p>', api_username)
                + format_html(
                    '<p class="text-sm text-slate-400"><strong>SSL Verify:</strong> {}</p>',
                    "Yes" if ssl_verify else "No",
                )
                + "</div>"
                "</div>"
                "</div>",
                content_type="text/html",
            )

    except Exception as e:
        logger.error(f"🔥 [TestConnection] Error testing connection: {e}")
        return HttpResponse(  # nosemgrep: direct-use-of-httpresponse — content is developer-controlled string/integer
            '<div class="bg-red-500/10 border border-red-500/20 rounded-lg p-4">'
            '<div class="flex items-center">'
            '<div class="flex-shrink-0">'
            '<svg class="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">'
            '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" /></svg>'
            "</div>"
            '<div class="ml-3">'
            + format_html('<h3 class="text-sm font-medium text-red-400">{}</h3>', _("Test Failed"))
            + format_html(
                '<p class="text-sm text-red-300 mt-1">{}</p>',
                _("An error occurred during connection test: %(error)s") % {"error": str(e)},
            )
            + "</div>"
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
        messages.error(request, _("No active Virtualmin servers found"))
        return redirect("provisioning:virtualmin_servers")

    backup_service = VirtualminBackupService(server)

    # Apply filters
    domain_filter = request.GET.get("domain")
    backup_type_filter = request.GET.get("type")
    try:
        max_age_days = int(request.GET.get("max_age", "30"))
        if max_age_days <= 0:
            raise ValueError("Nonpositive backup age")
    except ValueError:
        return HttpResponse(
            format_html("<p>{}</p>", _("Maximum backup age must be a positive integer.")),
            status=400,
        )

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

    # Translate display labels; keep stored enum values unchanged for filtering.
    backup_type_labels = {
        "full": _("Full Backup"),
        "incremental": _("Incremental Backup"),
        "config_only": _("Configuration Only"),
    }
    backup_status_labels = {
        "completed": _("Completed"),
        "failed": _("Failed"),
        "in_progress": _("In Progress"),
    }
    for backup in backups:
        backup["type_label"] = backup_type_labels.get(backup["backup_type"], _("Unknown"))
        backup["status_label"] = backup_status_labels.get(backup["status"], _("Unknown"))

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
                    "confirm": f"Delete backup {backup['backup_id']}?",  # nosemgrep: tainted-sql-string — UI confirmation string, not SQL
                },
            ],
        }
        for backup in backups
    ]

    # Get filter options
    domains = VirtualminAccount.objects.values_list("domain", flat=True).order_by("domain")
    backup_types = list(backup_type_labels.items())

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
    """🔄 Perform bulk actions on multiple Virtualmin accounts.

    GET and POST build the account list from the same validated filters, so a POST can only
    act on accounts the page listed. Suspend and Activate go through the Service (ADR-0051).
    """
    filter_form = VirtualminBulkFilterForm(request.GET)
    if not filter_form.is_valid():
        return HttpResponseBadRequest(str(_("Invalid filter.")))
    accounts = filter_form.accounts()
    # Each listed account is one POST field, and Django refuses a POST of more than 1,000
    # fields before any validation. Over the cap the page lists nothing, so nothing above it
    # can be selected, and asks for a narrower filter instead.
    matching = accounts.count()
    too_many = matching if matching > BULK_ACCOUNT_LIMIT else 0
    if too_many:
        accounts = accounts.none()
    query = filter_form.query_string()
    page_url = reverse("provisioning:virtualmin_bulk_actions")

    if request.method == "POST":
        # The same configured limit the executor uses, so every check runs in one wave.
        form = VirtualminBulkActionForm(
            request.POST, accounts=accounts, max_health_checks=get_max_concurrent_health_checks()
        )
        if form.is_valid():
            action = form.cleaned_data["action"]
            selected = list(form.cleaned_data["selected_accounts"])
            result = _execute_bulk_action(action, selected, form.cleaned_data)
            _handle_bulk_action_result(request, action, result)
            return redirect("provisioning:virtualmin_accounts")
    else:
        initial = {"selected_accounts": list(accounts)} if request.GET.get("select") == "all" else {}
        form = VirtualminBulkActionForm(accounts=accounts, initial=initial)

    selected_value = form["selected_accounts"].value() or []
    context = {
        "page_title": _("Bulk Actions"),
        "form": form,
        "filter_form": filter_form,
        "accounts": accounts,
        "too_many": too_many,
        "account_limit": BULK_ACCOUNT_LIMIT,
        "selected_ids": [str(getattr(value, "pk", value)) for value in selected_value],
        "form_action": f"{page_url}?{query}" if query else page_url,
        "select_all_url": f"{page_url}?{query}&select=all" if query else f"{page_url}?select=all",
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
        max_error_display = get_max_error_display()
        messages.error(
            request,
            _("Backup operation failed and was rolled back. Errors: %(errors)s%(omission)s")
            % {
                "errors": "; ".join(result.errors[:max_error_display]),
                "omission": "..." if len(result.errors) > max_error_display else "",
            },
        )
    else:
        messages.success(
            request,
            f"Backup jobs created for {result.successful_count}/{result.total_processed} accounts "
            f"({result.success_rate:.1f}% success) in {result.processing_time_seconds:.2f}s",
        )
        if result.failed_count > 0:
            messages.warning(request, f"{result.failed_count} backup operations failed. Check logs for details.")


def _handle_staff_action_result(request: HttpRequest, result: BulkOperationResult) -> None:
    """Report a bulk Suspend or Activate: what was queued, and why the rest was refused."""
    messages.success(
        request,
        _("Queued {done} of {total} accounts; the reconciler applies each change.").format(
            done=result.successful_count, total=result.total_processed
        ),
    )
    if result.errors:
        max_error_display = get_max_error_display()
        shown = "; ".join(result.errors[:max_error_display])
        more = "…" if len(result.errors) > max_error_display else ""
        messages.warning(
            request,
            _("{count} refused: {reasons}{more}").format(count=result.failed_count, reasons=shown, more=more),
        )


def _handle_health_check_action_result(request: HttpRequest, result: BulkOperationResult) -> None:
    """Handle health check action result and add appropriate messages."""
    messages.success(
        request,
        f"Health checks completed for {result.total_processed} accounts. "
        f"{result.successful_count} healthy ({result.success_rate:.1f}%) "
        f"in {result.processing_time_seconds:.2f}s",
    )
    if result.failed_count > 0:
        messages.warning(
            request, f"{result.failed_count} accounts failed health checks. See logs for detailed results."
        )


def _execute_bulk_action(
    action: str, accounts: list[VirtualminAccount], form_data: dict[str, Any]
) -> BulkOperationResult:
    """Execute the specified bulk action on accounts."""
    if action == "backup":
        return _execute_bulk_backup(accounts, form_data)
    elif action == "suspend":
        return _execute_bulk_staff_action(accounts, HostingAccountStaffActions.suspend)
    elif action == "activate":
        return _execute_bulk_staff_action(accounts, HostingAccountStaffActions.activate)
    elif action == "health_check":
        return _execute_bulk_health_check(accounts)
    else:
        return BulkOperationResult(
            total_processed=len(accounts),
            successful_count=0,
            failed_count=len(accounts),
            errors=[f"Unknown action: {action}"],
            rollback_performed=False,
        )


def _handle_bulk_action_result(request: HttpRequest, action: str, result: BulkOperationResult) -> None:
    """Handle bulk action result based on action type."""
    if action == "backup":
        _handle_backup_action_result(request, result)
    elif action in ("suspend", "activate"):
        _handle_staff_action_result(request, result)
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
            batch = accounts[i : i + batch_size]
            logger.debug(f"📦 [Bulk Backup] Processing batch {i // batch_size + 1} ({len(batch)} accounts)")

            for account in batch:
                try:
                    # Create backup job with proper error handling
                    backup_management = VirtualminBackupManagementService(account.server)
                    config = BackupConfig(backup_type=backup_type)

                    backup_result = backup_management.create_backup_job(
                        account=account, config=config, initiated_by="bulk_action"
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
            processing_time_seconds=processing_time,
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
            processing_time_seconds=processing_time,
        )


def _execute_bulk_staff_action(
    accounts: list[VirtualminAccount], action: Callable[[VirtualminAccount], Result[str, str]]
) -> BulkOperationResult:
    """Apply a staff Suspend or Activate to each account through the Service (#566, ADR-0051).

    Deliberately not one transaction: each account is its own short locked step inside the
    helper, so one refusal never undoes another, and each reconcile is queued on its own
    commit. The helpers never call Virtualmin; the reconciler applies every change.
    """
    start_time = time.perf_counter()
    errors: list[str] = []
    done = 0
    for account in accounts:
        result = action(account)
        if result.is_ok():
            done += 1
        else:
            errors.append(f"{account.domain}: {result.unwrap_err()}")
    return BulkOperationResult(
        total_processed=len(accounts),
        successful_count=done,
        failed_count=len(errors),
        errors=errors,
        processing_time_seconds=time.perf_counter() - start_time,
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
    if account.current_disk_usage_mb < 0:
        return False, str(_("Invalid disk usage data"))
    return True, ""


def _perform_gateway_connectivity_test(account: VirtualminAccount) -> tuple[bool, str]:
    """Perform Virtualmin gateway connectivity test."""
    try:
        config = VirtualminConfig(server=account.server)
        gateway = VirtualminGateway(config)

        deadline = _HEALTH_CHECK_DEADLINE.get()
        if deadline is None:
            healthy = gateway.ping_server()
        else:
            if time.perf_counter() >= deadline:
                return False, str(_("Health check timed out"))
            result = gateway.call("info", deadline=deadline)
            if time.perf_counter() >= deadline:
                return False, str(_("Health check timed out"))
            healthy = result.is_ok() and result.unwrap().success
        if not healthy:
            return False, str(_("Virtualmin server connectivity failed"))
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

    finally:
        # Runs in a pool thread. The ping resolves credentials through the vault, which opens
        # this thread's own database connection; Django closes connections only for the
        # request thread, so without this every worker would leave one open.
        connections.close_all()


def _health_check_until_deadline(
    account: VirtualminAccount, deadline: float
) -> tuple[VirtualminAccount, bool, str | None]:
    """Propagate the batch deadline without changing the single-check interface."""
    token = _HEALTH_CHECK_DEADLINE.set(deadline)
    try:
        if time.perf_counter() >= deadline:
            return account, False, str(_("Health check timed out"))
        return _perform_single_health_check(account)
    finally:
        _HEALTH_CHECK_DEADLINE.reset(token)


# Not atomic: it writes nothing, and a transaction would stay open across network pings.
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
        if not accounts:
            return BulkOperationResult(
                total_processed=0,
                successful_count=0,
                failed_count=0,
                errors=[],
                processing_time_seconds=time.perf_counter() - start_time,
            )

        # Snapshot the batch limits before dispatch; invalid legacy worker rows use the enforced default.
        worker_limit = get_max_concurrent_health_checks()
        if worker_limit < 1:
            worker_limit = _DEFAULT_MAX_CONCURRENT_HEALTH_CHECKS
        max_workers = min(worker_limit, len(accounts))
        overall_timeout = get_overall_health_check_timeout()

        deadline = time.perf_counter() + overall_timeout
        executor = ThreadPoolExecutor(max_workers=max_workers)
        future_to_account: dict[Future[tuple[VirtualminAccount, bool, str | None]], VirtualminAccount] = {}
        collected: set[Future[tuple[VirtualminAccount, bool, str | None]]] = set()
        try:
            future_to_account = {
                executor.submit(_health_check_until_deadline, account, deadline): account for account in accounts
            }
            try:
                for future in as_completed(future_to_account, timeout=max(0.0, deadline - time.perf_counter())):
                    collected.add(future)
                    account = future_to_account[future]
                    try:
                        account, success, error_msg = future.result()
                        if success:
                            successful_checks.append(account)
                            logger.debug(f"✅ [Health Check] {account.domain} - OK")
                        else:
                            errors.append(
                                _("Health check failed for %(domain)s: %(error)s")
                                % {"domain": account.domain, "error": error_msg}
                            )
                            logger.warning(f"⚠️ [Health Check] {account.domain} - {error_msg}")
                    except Exception as error:
                        errors.append(
                            _("Health check error for %(domain)s: %(error)s")
                            % {"domain": account.domain, "error": str(error)}
                        )
            except TimeoutError:
                logger.warning("⚠️ [Health Check] Overall sweep deadline reached")
        finally:
            for future, account in future_to_account.items():
                if future not in collected:
                    future.cancel()
                    errors.append(_("Health check timed out for %(domain)s") % {"domain": account.domain})
            executor.shutdown(wait=False, cancel_futures=True)

        processing_time = time.perf_counter() - start_time
        result = BulkOperationResult(
            total_processed=len(accounts),
            successful_count=len(successful_checks),
            failed_count=len(accounts) - len(successful_checks),
            errors=errors,
            rollback_performed=False,
            processing_time_seconds=processing_time,
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
            processing_time_seconds=processing_time,
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
def virtualmin_accounts_sync(  # noqa: C901, PLR0912, PLR0915  # Complexity: multi-step business logic
    request: HttpRequest,
) -> HttpResponse:  # Complexity: Virtualmin workflow  # Complexity: multi-step business logic
    """🔄 Sync accounts from active Virtualmin servers to PRAHO database."""

    # Get all active servers
    active_servers = VirtualminServer.objects.filter(status="active")

    if not active_servers.exists():
        messages.error(request, _("No active Virtualmin servers found to sync from"))
        return redirect("provisioning:virtualmin_accounts")

    sync_results: SyncResults = {
        "servers_checked": 0,
        "accounts_found": 0,
        "accounts_created": 0,
        "accounts_updated": 0,
        "errors": [],
    }

    provisioning_service = VirtualminProvisioningService()

    for server in active_servers:
        sync_results["servers_checked"] += 1

        try:
            # Get gateway for this server
            gateway = provisioning_service._get_gateway(server)

            # List domains from this server (lenient: one malformed row must
            # not abort the whole server's sync)
            domains_result = list_migration_domains(gateway, strict=False)

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
                if domain_data.get("enabled") is not True:
                    continue
                domain_name = domain_data.get("domain", "").strip()
                username = domain_data.get("username", "").strip()

                if not domain_name or not username:
                    continue

                if username not in accounts_by_username:
                    accounts_by_username[username] = {
                        "domains": [],
                        "primary_domain": domain_name,  # First domain becomes primary
                        "username": username,
                    }

                accounts_by_username[username]["domains"].append(domain_name)

            # Process each Virtualmin account (grouped by username)
            for username, account_data in accounts_by_username.items():
                try:
                    # Check if account already exists in PRAHO
                    account = VirtualminAccount.objects.get(virtualmin_username=username)
                    if account_has_active_migration(account):
                        logger.info("✅ [AccountSync] Migration lock: account=%s", account.pk)
                        continue
                    if account.server_id != server.pk and account.server.status == "active":
                        logger.info("✅ [AccountSync] Preserving active owner: account=%s", account.pk)
                        continue
                    if account.domain not in account_data["domains"]:
                        # Lenient listing parse may have dropped a malformed row —
                        # never replace authoritative domains with a partial subset
                        # that lost the account's primary domain.
                        logger.warning("⚠️ [AccountSync] Primary domain missing from listing: account=%s", account.pk)
                        continue
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

                            logger.info(
                                f"✅ [UsageSync] Updated usage for {username}: {domain_info['disk_usage_mb']}MB disk, {domain_info['bandwidth_usage_mb']}MB bandwidth"
                            )
                        else:
                            logger.warning(
                                f"⚠️ [UsageSync] Failed to get usage for {account.domain}: {domain_info_result.unwrap_err()}"
                            )
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

                        from apps.billing.currency_policy import get_selling_currency_policy  # noqa: PLC0415

                        # Existing services retain their stored money; only new imports need a retail price.
                        service = Service.objects.filter(username=username).first()
                        if service is None:
                            currency_code = get_selling_currency_policy().currency_code
                            retail_price = default_service_plan.get_price_for_currency(currency_code)
                            if retail_price is None:
                                error_msg = _("No active monthly price for plan %(plan)s in %(currency)s.") % {
                                    "plan": default_service_plan.name,
                                    "currency": currency_code,
                                }
                                sync_results["errors"].append(error_msg)
                                logger.warning("⚠️ [AccountSync] %s", error_msg)
                                continue
                            service, created = Service.objects.get_or_create(
                                username=username,
                                defaults={
                                    "currency_id": currency_code,
                                    "customer": default_customer,
                                    "service_plan": default_service_plan,
                                    "service_name": f"Virtualmin Account - {username}",
                                    "domain": account_data["primary_domain"],
                                    "status": "active",
                                    "billing_cycle": "monthly",
                                    "price": Decimal(retail_price.monthly_price_cents) / 100,
                                },
                            )
                        else:
                            created = False

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

                                logger.info(
                                    f"✅ [AccountSync] Fetched usage data for {account_data['primary_domain']}: {disk_usage_mb}MB disk, {bandwidth_usage_mb}MB bandwidth"
                                )
                            else:
                                logger.warning(
                                    f"⚠️ [AccountSync] Failed to fetch usage data for {account_data['primary_domain']}: {domain_info_result.unwrap_err()}"
                                )
                        except Exception as e:
                            logger.warning(
                                f"⚠️ [AccountSync] Exception fetching usage data for {account_data['primary_domain']}: {e!s}"
                            )

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
                            last_sync_at=timezone.now(),
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
        accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by(
            "-created_at"
        )
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
    """🚫 Suspend a hosting account by suspending its Service (#566, ADR-0051).

    The reconciler applies it to Virtualmin, so this never calls the panel itself.
    """
    account = get_object_or_404(VirtualminAccount, id=account_id)
    user_email = _get_user_email(request.user)

    result = HostingAccountStaffActions.suspend(account)
    if result.is_ok():
        messages.success(
            request,
            _("Suspension of {account} is queued; its service is suspended.").format(
                account=account.virtualmin_username
            ),
        )
        logger.info(f"✅ [AccountSuspend] {account.virtualmin_username} suspension queued by {user_email}")
    else:
        messages.error(request, result.unwrap_err())
        logger.warning(
            f"⚠️ [AccountSuspend] {account.virtualmin_username} refused for {user_email}: {result.unwrap_err()}"
        )

    # If HTMX request, check where we came from
    if request.headers.get("HX-Request"):
        # Check if coming from accounts list or detail page based on referrer
        referer = request.headers.get("HX-Current-URL", "")
        if f"accounts/{account.id}/" in referer:
            # Coming from detail page, refresh the page
            return redirect("provisioning:virtualmin_account_detail", account_id=account.id)
        else:
            # Coming from accounts list, return updated table
            accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by(
                "-created_at"
            )
            return render(request, "provisioning/virtualmin/partials/accounts_table.html", {"accounts": accounts})

    return redirect("provisioning:virtualmin_accounts")


@login_required
@user_passes_test(is_staff_or_superuser)
@require_POST
@audit_service_call("virtualmin_account_activate")
@monitor_performance(max_duration_seconds=15.0, alert_threshold=5.0)
def virtualmin_account_activate(request: HttpRequest, account_id: str) -> HttpResponse:
    """✅ Activate a hosting account by resuming its Service, or by queueing a reconcile (#566).

    Only a suspension staff made here can be lifted here; billing's and the customer's
    stay with their owners. The reconciler applies the result to Virtualmin.
    """
    account = get_object_or_404(VirtualminAccount, id=account_id)
    user_email = _get_user_email(request.user)

    result = HostingAccountStaffActions.activate(account)
    if result.is_ok():
        messages.success(
            request,
            _("Activation of {account} is queued.").format(account=account.virtualmin_username),
        )
        logger.info(f"✅ [AccountActivate] {account.virtualmin_username} {result.unwrap()} by {user_email}")
    else:
        messages.error(request, result.unwrap_err())
        logger.warning(
            f"⚠️ [AccountActivate] {account.virtualmin_username} refused for {user_email}: {result.unwrap_err()}"
        )

    # If HTMX request, check where we came from
    if request.headers.get("HX-Request"):
        # Check if coming from accounts list or detail page based on referrer
        referer = request.headers.get("HX-Current-URL", "")
        if f"accounts/{account.id}/" in referer:
            # Coming from detail page, refresh the page
            return redirect("provisioning:virtualmin_account_detail", account_id=account.id)
        else:
            # Coming from accounts list, return updated table
            accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by(
                "-created_at"
            )
            return render(request, "provisioning/virtualmin/partials/accounts_table.html", {"accounts": accounts})

    return redirect("provisioning:virtualmin_accounts")


@login_required
@admin_required  # Disarms the guard on virtualmin_account_delete — same tier as the delete itself.
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

        messages.success(request, f"{icon} Deletion protection {action} for account {account.virtualmin_username}")

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
                    "toggle_protection_url": reverse(
                        "provisioning:virtualmin_account_toggle_protection", args=[account.id]
                    ),
                    "delete_url": reverse("provisioning:virtualmin_account_delete", args=[account.id]),
                }
                return render(request, "provisioning/virtualmin/partials/quick_actions.html", context)
            else:
                # Coming from accounts list, return updated table
                accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by(
                    "-created_at"
                )
                return render(request, "provisioning/virtualmin/partials/accounts_table.html", {"accounts": accounts})

    return redirect("provisioning:virtualmin_accounts")


@login_required
@admin_required  # Permanent destruction of customer hosting. Admin/superuser only.
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
        accounts = VirtualminAccount.objects.select_related("server", "service", "service__customer").order_by(
            "-created_at"
        )
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

    context = {
        "job": job,
        "page_title": f"Job Status - {job.operation}",
        "breadcrumb_items": breadcrumb_items,
        "can_retry": job.status == "failed" and job.retry_count < job.max_retries,
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
        logs.append(
            {
                "timestamp": job.created_at.isoformat(),
                "level": "INFO",
                "message": f"Job created: {job.operation} for {job.account.domain if job.account else 'unknown'}",
            }
        )

        if job.started_at:
            logs.append({"timestamp": job.started_at.isoformat(), "level": "INFO", "message": "Job started"})

        if job.completed_at:
            logs.append(
                {
                    "timestamp": job.completed_at.isoformat(),
                    "level": "SUCCESS" if job.status == "completed" else "ERROR",
                    "message": f"Job {job.status}" + (f": {job.status_message}" if job.status_message else ""),
                }
            )

        # Add response data as structured logs
        if job.result:
            logs.append(
                {
                    "timestamp": (job.completed_at or job.updated_at).isoformat(),
                    "level": "DEBUG",
                    "message": f"Response: {job.result}",
                }
            )

        return JsonResponse({"logs": logs})

    # Regular template render for non-HTMX requests
    context = {
        "job": job,
        "page_title": f"Job Logs - {job.operation}",
    }

    return render(request, "provisioning/virtualmin/job_logs.html", context)
