# ===============================================================================
# CUSTOMER API URLS 🔗
# ===============================================================================

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    CustomerProfileAPIView,
    CustomerSearchViewSet,
    CustomerServicesViewSet,
    customer_addresses_add,
    customer_addresses_delete,
    customer_addresses_list,
    customer_addresses_set_billing,
    customer_addresses_set_primary,
    customer_addresses_update,
    customer_create_api,
    customer_detail_api,
    customer_register_api,
    customer_tax_profile_update,
    customer_update,
    customer_users_add,
    customer_users_create,
    customer_users_list,
    customer_users_remove,
    customer_users_role,
    customer_users_toggle_status,
    update_customer_billing_address,
)

# Create router for customer API endpoints
router = DefaultRouter()
router.register("search", CustomerSearchViewSet, basename="customer-search")
router.register("", CustomerServicesViewSet, basename="customer-services")

app_name = "customers"

urlpatterns = [
    # Customer registration endpoint (public)
    path("register/", customer_register_api, name="customer-register"),
    # Customer creation endpoint (HMAC authenticated, for Portal)
    path("create/", customer_create_api, name="customer-create"),
    # Customer profile management (authenticated)
    path("profile/", CustomerProfileAPIView.as_view(), name="customer-profile"),
    # Customer billing address update for checkout UX (HMAC authenticated)
    path("billing-address/", update_customer_billing_address, name="customer-billing-address"),
    # Customer detail endpoint (HMAC authenticated)
    path("details/", customer_detail_api, name="customer-detail"),
    # User management endpoints (HMAC authenticated, owner-only)
    path("users/", customer_users_list, name="customer-users-list"),
    path("users/add/", customer_users_add, name="customer-users-add"),
    path("users/create/", customer_users_create, name="customer-users-create"),
    path("users/role/", customer_users_role, name="customer-users-role"),
    path("users/remove/", customer_users_remove, name="customer-users-remove"),
    path("users/toggle-status/", customer_users_toggle_status, name="customer-users-toggle"),
    # Customer profile update endpoints (HMAC authenticated)
    path("update/", customer_update, name="customer-update"),
    path("tax-profile/", customer_tax_profile_update, name="customer-tax-profile"),
    # Address management endpoints (HMAC authenticated)
    path("addresses/", customer_addresses_list, name="customer-addresses-list"),
    path("addresses/add/", customer_addresses_add, name="customer-addresses-add"),
    path("addresses/update/", customer_addresses_update, name="customer-addresses-update"),
    path("addresses/delete/", customer_addresses_delete, name="customer-addresses-delete"),
    path("addresses/set-primary/", customer_addresses_set_primary, name="customer-addresses-set-primary"),
    path("addresses/set-billing/", customer_addresses_set_billing, name="customer-addresses-set-billing"),
    # Router-based endpoints
    path("", include(router.urls)),
]
