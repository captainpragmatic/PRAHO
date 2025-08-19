# ===============================================================================
# BILLING APP URLS - INVOICE & PAYMENT MANAGEMENT
# ===============================================================================

from django.urls import path
from . import views

app_name = 'billing'

urlpatterns = [
    # Combined listing (proformas + invoices)
    path('invoices/', views.billing_list, name='invoice_list'),  # Updated view name
    
    # Proforma management (only these can be created manually)
    path('proformas/create/', views.proforma_create, name='proforma_create'),
    path('proformas/<int:pk>/', views.proforma_detail, name='proforma_detail'),
    path('proformas/<int:pk>/edit/', views.proforma_edit, name='proforma_edit'),
    path('proformas/<int:pk>/pdf/', views.proforma_pdf, name='proforma_pdf'),
    path('proformas/<int:pk>/send/', views.proforma_send, name='proforma_send'),
    path('proformas/<int:pk>/convert/', views.proforma_to_invoice, name='proforma_to_invoice'),
    
    # Invoice management (read-only, auto-generated from proformas)
    path('invoices/<int:pk>/', views.invoice_detail, name='invoice_detail'),
    path('invoices/<int:pk>/pdf/', views.invoice_pdf, name='invoice_pdf'),
    path('invoices/<int:pk>/send/', views.invoice_send, name='invoice_send'),
    
    # Romanian e-Factura integration
    path('invoices/<int:pk>/e-factura/', views.generate_e_factura, name='e_factura'),
    
    # Payment management
    path('payments/', views.payment_list, name='payment_list'),
    path('invoices/<int:pk>/pay/', views.process_payment, name='process_payment'),
    path('proformas/<int:pk>/pay/', views.process_proforma_payment, name='process_proforma_payment'),
    
    # Reports
    path('reports/', views.billing_reports, name='reports'),
    path('reports/vat/', views.vat_report, name='vat_report'),
]
