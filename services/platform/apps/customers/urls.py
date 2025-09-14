# ===============================================================================
# CUSTOMERS APP URLS - NORMALIZED MODEL STRUCTURE
# ===============================================================================

from django.urls import path

from . import views

app_name = "customers"

urlpatterns = [
    # Customer listing and search
    path("", views.customer_list, name="list"),
    path("search/", views.customer_search_api, name="search_api"),
    # API endpoints
    path("<int:customer_id>/services/", views.customer_services_api, name="services_api"),
    # Customer CRUD
    path("create/", views.customer_create, name="create"),
    path("<int:customer_id>/", views.customer_detail, name="detail"),
    path("<int:customer_id>/edit/", views.customer_edit, name="edit"),
    path("<int:customer_id>/delete/", views.customer_delete, name="delete"),
    # Customer Profile Management
    path("<int:customer_id>/tax-profile/", views.customer_tax_profile, name="tax_profile"),
    path("<int:customer_id>/billing-profile/", views.customer_billing_profile, name="billing_profile"),
    path("<int:customer_id>/address/add/", views.customer_address_add, name="address_add"),
    path("<int:customer_id>/note/add/", views.customer_note_add, name="note_add"),
    # User Management
    path("<int:customer_id>/assign-user/", views.customer_assign_user, name="assign_user"),
    path("<int:customer_id>/add-user/", views.customer_add_user, name="add_user"),
    path("<int:customer_id>/create-user/", views.customer_create_user, name="create_user"),
    path("<int:customer_id>/membership/<int:membership_id>/change-role/", views.change_user_role, name="change_user_role"),
    path("<int:customer_id>/user/<int:user_id>/toggle-status/", views.toggle_user_status, name="toggle_user_status"),
    path("<int:customer_id>/membership/<int:membership_id>/remove/", views.remove_user, name="remove_user"),
]
