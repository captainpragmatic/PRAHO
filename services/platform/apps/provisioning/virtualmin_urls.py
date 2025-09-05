# ===============================================================================
# VIRTUALMIN URLS - VIRTUALMIN SERVER & ACCOUNT MANAGEMENT
# ===============================================================================

from django.urls import path

from . import virtualmin_views

# Note: We don't set app_name here since these URLs are included
# in the main provisioning URLs with the "provisioning" namespace

urlpatterns = [
    # Virtualmin server management
    path("servers/", virtualmin_views.virtualmin_servers_list, name="virtualmin_servers"),
    path("servers/create/", virtualmin_views.virtualmin_server_create, name="virtualmin_server_create"),
    path(
        "servers/test-connection/",
        virtualmin_views.virtualmin_server_test_connection,
        name="virtualmin_server_test_connection",
    ),
    path("servers/<uuid:server_id>/", virtualmin_views.virtualmin_server_detail, name="virtualmin_server_detail"),
    path("servers/<uuid:server_id>/edit/", virtualmin_views.virtualmin_server_edit, name="virtualmin_server_edit"),
    path(
        "servers/<uuid:server_id>/health/",
        virtualmin_views.virtualmin_server_health_check,
        name="virtualmin_server_health",
    ),
    # Virtualmin account management
    path("accounts/", virtualmin_views.virtualmin_accounts_list, name="virtualmin_accounts"),
    path("accounts/new/", virtualmin_views.virtualmin_account_new, name="virtualmin_account_new"),
    path("accounts/sync/", virtualmin_views.virtualmin_accounts_sync, name="virtualmin_accounts_sync"),
    path("accounts/<uuid:account_id>/", virtualmin_views.virtualmin_account_detail, name="virtualmin_account_detail"),
    path(
        "accounts/<uuid:account_id>/delete/",
        virtualmin_views.virtualmin_account_delete,
        name="virtualmin_account_delete",
    ),
    path(
        "accounts/<uuid:account_id>/backup/",
        virtualmin_views.virtualmin_account_backup,
        name="virtualmin_account_backup",
    ),
    path(
        "accounts/<uuid:account_id>/restore/",
        virtualmin_views.virtualmin_account_restore,
        name="virtualmin_account_restore",
    ),
    path(
        "accounts/<uuid:account_id>/suspend/",
        virtualmin_views.virtualmin_account_suspend,
        name="virtualmin_account_suspend",
    ),
    path(
        "accounts/<uuid:account_id>/activate/",
        virtualmin_views.virtualmin_account_activate,
        name="virtualmin_account_activate",
    ),
    path(
        "accounts/<uuid:account_id>/toggle-protection/",
        virtualmin_views.virtualmin_account_toggle_protection,
        name="virtualmin_account_toggle_protection",
    ),
    # Backup and restore operations
    path("backups/", virtualmin_views.virtualmin_backups_list, name="virtualmin_backups"),
    path("jobs/<uuid:job_id>/status/", virtualmin_views.virtualmin_job_status, name="virtualmin_job_status"),
    path("jobs/<uuid:job_id>/logs/", virtualmin_views.virtualmin_job_logs, name="virtualmin_job_logs"),
    path("bulk-actions/", virtualmin_views.virtualmin_bulk_actions, name="virtualmin_bulk_actions"),
]
