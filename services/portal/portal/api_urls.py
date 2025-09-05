# ===============================================================================
# PORTAL API URLS - AJAX ENDPOINTS 🔌
# ===============================================================================

"""
Portal API endpoints for AJAX calls from customer interface.
All endpoints proxy to Platform API service.
"""

from django.urls import path
from . import api_views

app_name = 'portal_api'

urlpatterns = [
    # Service management AJAX endpoints
    path('services/', api_views.ServicesAPIView.as_view(), name='services'),
    path('services/<str:service_id>/', api_views.ServiceDetailAPIView.as_view(), name='service_detail'),
    
    # Ticket management AJAX endpoints  
    path('tickets/', api_views.TicketsAPIView.as_view(), name='tickets'),
    path('tickets/<str:ticket_id>/', api_views.TicketDetailAPIView.as_view(), name='ticket_detail'),
    
    # Invoice management AJAX endpoints
    path('invoices/', api_views.InvoicesAPIView.as_view(), name='invoices'),
    path('invoices/<str:invoice_id>/', api_views.InvoiceDetailAPIView.as_view(), name='invoice_detail'),
]
