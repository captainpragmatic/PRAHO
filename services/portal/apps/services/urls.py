# ===============================================================================
# CUSTOMER SERVICES URLS - PORTAL SERVICE 🔧
# ===============================================================================

from django.urls import path

from . import views

app_name = 'services'

urlpatterns = [
    # Main service views
    path('', views.service_list, name='list'),
    path('<int:service_id>/', views.service_detail, name='detail'),
    path('plans/', views.service_plans, name='plans'),
    
    # Service management
    path('<int:service_id>/request-action/', views.service_request_action, name='request_action'),
    
    # HTMX endpoints
    path('<int:service_id>/usage/', views.service_usage, name='usage'),
    
    # Dashboard widget
    path('widget/', views.services_dashboard_widget, name='dashboard_widget'),
]
