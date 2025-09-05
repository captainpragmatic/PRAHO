# ===============================================================================
# PORTAL CUSTOMER INTERFACE URLS 🌐
# ===============================================================================

"""
Portal customer-facing URL patterns.
All data retrieved via Platform API (no direct database access).
"""

from django.urls import path
from . import views

app_name = 'portal'

urlpatterns = [
    # Customer authentication
    path('', views.LoginView.as_view(), name='login'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    
    # Customer dashboard
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    
    # Customer services
    path('services/', views.ServicesView.as_view(), name='services'),
    path('services/<str:service_id>/', views.ServiceDetailView.as_view(), name='service_detail'),
    
    # Customer orders
    path('orders/', views.OrdersView.as_view(), name='orders'),
    path('orders/<str:order_id>/', views.OrderDetailView.as_view(), name='order_detail'),
    
    # Customer invoices  
    path('invoices/', views.InvoicesView.as_view(), name='invoices'),
    path('invoices/<str:invoice_id>/', views.InvoiceDetailView.as_view(), name='invoice_detail'),
    
    # Support tickets
    path('tickets/', views.TicketsView.as_view(), name='tickets'),
    path('tickets/new/', views.CreateTicketView.as_view(), name='create_ticket'),
    path('tickets/<str:ticket_id>/', views.TicketDetailView.as_view(), name='ticket_detail'),
    
    # Account management
    path('account/', views.AccountView.as_view(), name='account'),
    path('account/profile/', views.ProfileView.as_view(), name='profile'),
]
