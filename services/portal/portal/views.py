# ===============================================================================
# PORTAL CUSTOMER VIEWS 👥
# ===============================================================================

"""
Portal customer-facing views.
🚨 SECURITY: All data retrieved via Platform API (no direct database access).
"""

import logging
from typing import Any, Dict
from django.shortcuts import render, redirect
from django.views.generic import TemplateView, View
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from .services import platform_api, PlatformAPIException

logger = logging.getLogger(__name__)


class BasePortalView(TemplateView):
    """Base view for portal with common functionality."""
    
    def get_customer_id(self) -> str | None:
        """Get customer ID from session."""
        return self.request.session.get('customer_id')
    
    def require_authentication(self) -> bool:
        """Check if customer is authenticated."""
        customer_id = self.get_customer_id()
        if not customer_id:
            messages.error(self.request, 'Please log in to access this page.')
            return False
        return True


class LoginView(TemplateView):
    """Customer login page."""
    template_name = 'portal/login.html'
    
    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle login form submission."""
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        if not email or not password:
            messages.error(request, 'Please provide email and password.')
            return self.get(request)
        
        try:
            # Authenticate via Platform API
            customer_data = platform_api.authenticate_customer(email, password)
            
            if customer_data:
                # Store customer info in session
                request.session['customer_id'] = customer_data['id']
                request.session['customer_email'] = customer_data['email']
                request.session['customer_name'] = customer_data.get('name', '')
                
                logger.info(f"✅ [Portal Login] Customer {email} logged in successfully")
                messages.success(request, f'Welcome, {customer_data.get("name", "Customer")}!')
                return redirect('portal:dashboard')
            else:
                messages.error(request, 'Invalid email or password.')
                
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal Login] API error: {e}")
            messages.error(request, 'Login service temporarily unavailable.')
        
        return self.get(request)


class LogoutView(View):
    """Customer logout."""
    
    def get(self, request: HttpRequest) -> HttpResponse:
        """Handle logout."""
        request.session.flush()
        messages.success(request, 'You have been logged out successfully.')
        return redirect('portal:login')


class DashboardView(BasePortalView):
    """Customer dashboard."""
    template_name = 'portal/dashboard.html'
    
    def get(self, request: HttpRequest) -> HttpResponse:
        """Display customer dashboard."""
        if not self.require_authentication():
            return redirect('portal:login')
        
        return super().get(request)
    
    def get_context_data(self, **kwargs: Any) -> Dict[str, Any]:
        """Get dashboard context data."""
        context = super().get_context_data(**kwargs)
        customer_id = self.get_customer_id()
        
        try:
            # Get customer data via Platform API
            context['customer'] = platform_api.get_customer(customer_id)
            context['recent_orders'] = platform_api.get_customer_orders(customer_id)[:5]
            context['active_services'] = platform_api.get_customer_services(customer_id)
            
        except PlatformAPIException as e:
            logger.error(f"🔥 [Portal Dashboard] API error: {e}")
            messages.error(self.request, 'Unable to load dashboard data.')
            context.update({
                'customer': {},
                'recent_orders': [],
                'active_services': []
            })
        
        return context


# ===============================================================================
# PLACEHOLDER VIEWS - TO BE IMPLEMENTED
# ===============================================================================

class ServicesView(BasePortalView):
    """Customer services list."""
    template_name = 'portal/services.html'
    
    def get(self, request: HttpRequest) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class ServiceDetailView(BasePortalView):
    """Service detail page."""  
    template_name = 'portal/service_detail.html'
    
    def get(self, request: HttpRequest, service_id: str) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class OrdersView(BasePortalView):
    """Customer orders list."""
    template_name = 'portal/orders.html'
    
    def get(self, request: HttpRequest) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class OrderDetailView(BasePortalView):
    """Order detail page."""
    template_name = 'portal/order_detail.html'
    
    def get(self, request: HttpRequest, order_id: str) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class InvoicesView(BasePortalView):
    """Customer invoices list."""
    template_name = 'portal/invoices.html'
    
    def get(self, request: HttpRequest) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class InvoiceDetailView(BasePortalView):
    """Invoice detail page."""
    template_name = 'portal/invoice_detail.html'
    
    def get(self, request: HttpRequest, invoice_id: str) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class TicketsView(BasePortalView):
    """Support tickets list."""
    template_name = 'portal/tickets.html'
    
    def get(self, request: HttpRequest) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class CreateTicketView(BasePortalView):
    """Create support ticket."""
    template_name = 'portal/create_ticket.html'
    
    def get(self, request: HttpRequest) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class TicketDetailView(BasePortalView):
    """Support ticket detail."""
    template_name = 'portal/ticket_detail.html'
    
    def get(self, request: HttpRequest, ticket_id: str) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class AccountView(BasePortalView):
    """Customer account overview."""
    template_name = 'portal/account.html'
    
    def get(self, request: HttpRequest) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)


class ProfileView(BasePortalView):
    """Customer profile management."""
    template_name = 'portal/profile.html'
    
    def get(self, request: HttpRequest) -> HttpResponse:
        if not self.require_authentication():
            return redirect('portal:login')
        return super().get(request)
