# ===============================================================================
# DOMAIN URLS - CUSTOMER & STAFF DOMAIN MANAGEMENT
# ===============================================================================

from django.urls import path

from . import views

app_name = "domains"

urlpatterns = [
    # Customer domain management
    path("", views.domain_list, name="list"),
    path("<uuid:domain_id>/", views.domain_detail, name="detail"),
    path("register/", views.domain_register, name="register"),
    path("check-availability/", views.check_availability, name="check_availability"),
    path("<uuid:domain_id>/renew/", views.domain_renew, name="renew"),
    # TODO: Add DNS management view
    # path('<uuid:domain_id>/dns/', views.domain_dns, name='dns'),  # noqa: ERA001
    # Staff management views
    path("admin/", views.domain_admin_list, name="admin_list"),
    path("admin/tlds/", views.tld_list, name="tld_list"),
    path("admin/tlds/new/", views.tld_create, name="tld_create"),
    path("admin/tlds/<int:pk>/edit/", views.tld_edit, name="tld_edit"),
    path("admin/registrars/", views.registrar_list, name="registrar_list"),
    path("admin/registrars/new/", views.registrar_create, name="registrar_create"),
    path("admin/registrars/sync-all/", views.registrar_sync_all, name="registrar_sync_all"),
    path("admin/registrars/<int:pk>/edit/", views.registrar_edit, name="registrar_edit"),
]
