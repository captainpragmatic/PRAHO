# ===============================================================================
# CUSTOMER API URLS 🔗
# ===============================================================================

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    CustomerSearchViewSet, 
    CustomerServicesViewSet,
    customer_register_api,
    CustomerProfileAPIView,
    customer_detail_api
)

# Create router for customer API endpoints
router = DefaultRouter()
router.register('search', CustomerSearchViewSet, basename='customer-search')
router.register('', CustomerServicesViewSet, basename='customer-services')

app_name = 'customers'

urlpatterns = [
    # Customer registration endpoint (public)
    path('register/', customer_register_api, name='customer-register'),
    
    # Customer profile management (authenticated)
    path('profile/', CustomerProfileAPIView.as_view(), name='customer-profile'),
    
    # Customer detail endpoint (HMAC authenticated)
    path('details/', customer_detail_api, name='customer-detail'),
    
    # Router-based endpoints
    path('', include(router.urls)),
]
