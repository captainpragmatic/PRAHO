# ===============================================================================
# DOMAIN URLS - CUSTOMER & STAFF DOMAIN MANAGEMENT
# ===============================================================================

from django.urls import path

from . import views

app_name = 'domains'

urlpatterns = [
    # Customer domain management
    path('', views.domain_list, name='list'),
    path('<uuid:domain_id>/', views.domain_detail, name='detail'),
    path('register/', views.domain_register, name='register'),
    path('check-availability/', views.check_availability, name='check_availability'),
    path('<uuid:domain_id>/renew/', views.domain_renew, name='renew'),
    # TODO: Add DNS management view
    # path('<uuid:domain_id>/dns/', views.domain_dns, name='dns'),
    
    # Staff management views
    path('admin/', views.domain_admin_list, name='admin_list'),
    path('admin/tlds/', views.tld_list, name='tld_list'),
    path('admin/registrars/', views.registrar_list, name='registrar_list'),
]
