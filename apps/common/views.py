# ===============================================================================
# DASHBOARD VIEW - MAIN PRAHO Platform OVERVIEW
# ===============================================================================

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.db.models import Count, Sum
from django.utils import timezone
from datetime import datetime, timedelta

from apps.customers.models import Customer
from apps.billing.models import Invoice
from apps.tickets.models import Ticket
from apps.provisioning.models import Service


@login_required
def dashboard_view(request):
    """
    🚀 Main dashboard with Romanian hosting business metrics
    Shows key statistics and recent activity for authenticated users
    """
    # ===============================================================================
    # STATS CALCULATION - CRITICAL BUSINESS METRICS
    # ===============================================================================
    
    # Get user's accessible customers (multi-tenant support)
    accessible_customers_list = request.user.get_accessible_customers()
    
    # Convert to QuerySet for database queries
    from django.db.models import QuerySet
    if isinstance(accessible_customers_list, QuerySet):
        # It's already a QuerySet (staff users)
        accessible_customers = accessible_customers_list
    else:
        # It's a list, convert to QuerySet
        if accessible_customers_list:
            customer_ids = [c.id for c in accessible_customers_list]
            accessible_customers = Customer.objects.filter(id__in=customer_ids)
        else:
            accessible_customers = Customer.objects.none()
    
    # Calculate key statistics
    stats = {
        'total_customers': accessible_customers.count(),
        'monthly_revenue': _calculate_monthly_revenue(accessible_customers),
        'open_tickets': _count_open_tickets(accessible_customers),
        'active_services': _count_active_services(accessible_customers),
    }
    
    # ===============================================================================
    # RECENT ACTIVITY - LAST 30 DAYS
    # ===============================================================================
    
    thirty_days_ago = timezone.now() - timedelta(days=30)
    
    # Recent invoices with Romanian formatting
    recent_invoices = Invoice.objects.filter(
        customer__in=accessible_customers,
        created_at__gte=thirty_days_ago
    ).select_related('customer').order_by('-created_at')[:5]
    
    # Recent support tickets
    recent_tickets = Ticket.objects.filter(
        customer__in=accessible_customers,
        created_at__gte=thirty_days_ago
    ).select_related('customer').order_by('-created_at')[:5]
    
    context = {
        'stats': stats,
        'recent_invoices': recent_invoices,
        'recent_tickets': recent_tickets,
        'current_time': timezone.now(),
        'app_version': '1.0.0',
        'current_year': datetime.now().year,
    }
    
    return render(request, 'dashboard.html', context)


# ===============================================================================
# HELPER FUNCTIONS - BUSINESS LOGIC
# ===============================================================================

def _calculate_monthly_revenue(customers):
    """Calculate total revenue for current month in RON"""
    current_month = timezone.now().replace(day=1)
    
    monthly_total = Invoice.objects.filter(
        customer__in=customers,
        created_at__gte=current_month,
        status='paid'
    ).aggregate(total=Sum('total_cents'))['total'] or 0
    
    return monthly_total


def _count_open_tickets(customers):
    """Count open support tickets requiring attention"""
    return Ticket.objects.filter(
        customer__in=customers,
        status__in=['open', 'in_progress']
    ).count()


def _count_active_services(customers):
    """Count active hosting services"""
    return Service.objects.filter(
        customer__in=customers,
        status='active'
    ).count()
