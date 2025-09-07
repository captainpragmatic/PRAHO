# ===============================================================================
# SERVICES API URLS - CUSTOMER HOSTING SERVICES 📦
# ===============================================================================

from django.urls import path
from .views import (
    customer_services_api,
    customer_service_detail_api,
    customer_services_summary_api,
    available_service_plans_api,
    update_service_auto_renew_api,
    service_usage_stats_api
)

app_name = 'services'

urlpatterns = [
    # Services endpoints
    path('', customer_services_api, name='customer_services_list'),
    path('summary/', customer_services_summary_api, name='customer_services_summary'),
    path('plans/', available_service_plans_api, name='available_service_plans'),
    
    # Individual service endpoints
    path('<int:service_id>/', customer_service_detail_api, name='customer_service_detail'),
    path('<int:service_id>/auto-renew/', update_service_auto_renew_api, name='update_service_auto_renew'),
    path('<int:service_id>/usage/', service_usage_stats_api, name='service_usage_stats'),
]