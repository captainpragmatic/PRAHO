# ===============================================================================
# CUSTOMER API URLS 🔗
# ===============================================================================

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    CustomerProfileAPIView,
    CustomerSearchViewSet,
    CustomerServicesViewSet,
    customer_create_api,
    customer_detail_api,
    customer_register_api,
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
    # Router-based endpoints
    path("", include(router.urls)),
]
