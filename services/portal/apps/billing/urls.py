# ===============================================================================
# PORTAL BILLING URLS - CUSTOMER INVOICE INTERFACE 💳
# ===============================================================================

from django.urls import path

from . import views

app_name = 'billing'

urlpatterns = [
    # Invoice list and detail views
    path('invoices/', views.invoices_list_view, name='invoices_list'),
    path('invoices/<str:invoice_number>/', views.invoice_detail_view, name='invoice_detail'),
    path('invoices/<str:invoice_number>/pdf/', views.invoice_pdf_export, name='invoice_pdf_export'),
    
    # Proforma detail views
    path('proformas/<str:proforma_number>/', views.proforma_detail_view, name='proforma_detail'),
    path('proformas/<str:proforma_number>/pdf/', views.proforma_pdf_export, name='proforma_pdf_export'),
    
    # Dashboard widget and actions
    path('dashboard-widget/', views.billing_dashboard_widget, name='dashboard_widget'),
    path('sync/', views.sync_invoices_action, name='sync_invoices'),
]
