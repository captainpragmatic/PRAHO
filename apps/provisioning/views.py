# ===============================================================================
# PROVISIONING VIEWS BACKWARD COMPATIBILITY LAYER
# Re-exports all view functions for existing imports.
# ===============================================================================

# Import from feature view files
from .service_views import service_list, service_detail, service_create, service_edit, service_suspend, service_activate
from .plan_views import plan_list
from .server_views import server_list

# Re-export for URL patterns and external imports
__all__ = [
    # Service views
    'service_list', 'service_detail', 'service_create', 'service_edit', 
    'service_suspend', 'service_activate',
    # Plan views
    'plan_list',
    # Server views  
    'server_list',
]