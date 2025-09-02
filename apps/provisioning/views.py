# ===============================================================================
# PROVISIONING VIEWS BACKWARD COMPATIBILITY LAYER
# Re-exports all view functions for existing imports.
# ===============================================================================

# Import from feature view files
from .plan_views import plan_list
from .server_views import server_list
from .service_views import service_activate, service_create, service_detail, service_edit, service_list, service_suspend

# Re-export for URL patterns and external imports
__all__ = [
    # Plan views (alphabetical)
    'plan_list',
    # Server views (alphabetical)
    'server_list',
    # Service views (alphabetical)
    'service_activate',
    'service_create',
    'service_detail',
    'service_edit',
    'service_list',
    'service_suspend',
]
