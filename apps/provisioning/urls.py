# ===============================================================================
# PROVISIONING APP URLS - HOSTING SERVICES
# ===============================================================================

from django.urls import path

from . import views

app_name = 'provisioning'

urlpatterns = [
    path('services/', views.service_list, name='services'),
    path('services/create/', views.service_create, name='service_create'),
    path('services/<int:pk>/', views.service_detail, name='service_detail'),
    path('services/<int:pk>/edit/', views.service_edit, name='service_edit'),
    path('services/<int:pk>/suspend/', views.service_suspend, name='service_suspend'),
    path('services/<int:pk>/activate/', views.service_activate, name='service_activate'),

    path('plans/', views.plan_list, name='plans'),
    path('servers/', views.server_list, name='servers'),
]
