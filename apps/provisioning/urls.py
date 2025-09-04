# ===============================================================================
# PROVISIONING APP URLS - GENERAL HOSTING SERVICES MANAGEMENT
# ===============================================================================

from django.urls import include, path

from . import views
from .virtualmin_urls import urlpatterns as virtualmin_urlpatterns

app_name = "provisioning"

urlpatterns = [
    # General service management
    path("services/", views.service_list, name="services"),
    path("services/create/", views.service_create, name="service_create"),
    path("services/<int:pk>/", views.service_detail, name="service_detail"),
    path("services/<int:pk>/edit/", views.service_edit, name="service_edit"),
    path("services/<int:pk>/suspend/", views.service_suspend, name="service_suspend"),
    path("services/<int:pk>/activate/", views.service_activate, name="service_activate"),
    path("plans/", views.plan_list, name="plans"),
    path("servers/", views.server_list, name="servers"),
    # Virtualmin management (from virtualmin_urls.py)
    path("virtualmin/", include(virtualmin_urlpatterns)),
]
