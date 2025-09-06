# ===============================================================================
# CUSTOMER API URLS 🔗
# ===============================================================================

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CustomerSearchViewSet, CustomerServicesViewSet

# Create router for customer API endpoints
router = DefaultRouter()
router.register('search', CustomerSearchViewSet, basename='customer-search')
router.register('', CustomerServicesViewSet, basename='customer-services')

app_name = 'customers'

urlpatterns = [
    path('', include(router.urls)),
]
