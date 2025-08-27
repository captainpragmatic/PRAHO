# ===============================================================================
# DASHBOARD VIEW - MAIN PRAHO Platform OVERVIEW
# ===============================================================================

from datetime import datetime, timedelta

from django.contrib.auth.decorators import login_required
from django.db.models import Sum
from django.db.models.query import QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.utils import timezone

from apps.billing.models import Invoice
from apps.customers.models import Customer
from apps.provisioning.models import Service
from apps.tickets.models import Ticket


@login_required
def dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    🚀 Main dashboard with Romanian hosting business metrics
    Shows key statistics and recent activity for authenticated users
    """
    # ===============================================================================
    # STATS CALCULATION - CRITICAL BUSINESS METRICS
    # ===============================================================================

    # Get user's accessible customers (multi-tenant support)
    # Type guard: @login_required ensures request.user is authenticated User instance
    user = request.user
    if not user.is_authenticated:
        return redirect('login')
    
    accessible_customers_list = user.get_accessible_customers()

    # Convert to QuerySet for database queries
    if isinstance(accessible_customers_list, QuerySet):
        # It's already a QuerySet (staff users)
        accessible_customers = accessible_customers_list
    # It's a list, convert to QuerySet
    elif accessible_customers_list:
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

def _calculate_monthly_revenue(customers: QuerySet[Customer]) -> int:
    """Calculate total revenue for current month in RON"""
    current_month = timezone.now().replace(day=1)

    monthly_total = Invoice.objects.filter(
        customer__in=customers,
        created_at__gte=current_month,
        status='paid'
    ).aggregate(total=Sum('total_cents'))['total'] or 0

    return monthly_total


def _count_open_tickets(customers: QuerySet[Customer]) -> int:
    """Count open support tickets requiring attention"""
    return Ticket.objects.filter(
        customer__in=customers,
        status__in=['open', 'in_progress']
    ).count()


def _count_active_services(customers: QuerySet[Customer]) -> int:
    """Count active hosting services"""
    return Service.objects.filter(
        customer__in=customers,
        status='active'
    ).count()
