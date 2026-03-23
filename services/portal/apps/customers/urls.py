"""
Portal Customers URL Configuration
Team management, tax profile, and address routes.
"""

from django.urls import path

from . import views

app_name = "customers"

urlpatterns = [
    path("team/", views.company_team_view, name="team"),
    path("team/invite/", views.company_team_invite_view, name="team_invite"),
    path("team/<int:target_user_id>/role/", views.company_team_role_view, name="team_role"),
    path("team/<int:target_user_id>/remove/", views.company_team_remove_view, name="team_remove"),
    path("tax/", views.company_tax_profile_view, name="tax_profile"),
    path("addresses/", views.company_addresses_view, name="addresses"),
    path("addresses/add/", views.company_address_add_view, name="address_add"),
    path("addresses/<int:address_id>/delete/", views.company_address_delete_view, name="address_delete"),
    path("addresses/<int:address_id>/set-primary/", views.company_address_set_primary_view, name="address_set_primary"),
    path("addresses/<int:address_id>/set-billing/", views.company_address_set_billing_view, name="address_set_billing"),
]
