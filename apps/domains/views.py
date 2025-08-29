# ===============================================================================
# DOMAIN VIEWS - CUSTOMER & STAFF DOMAIN MANAGEMENT
# ===============================================================================

from __future__ import annotations

import logging
from typing import Any, cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q, QuerySet
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods

from apps.common.decorators import staff_required
from apps.customers.models import Customer
from apps.users.models import User

from .models import TLD, Domain, DomainOrderItem, Registrar
from .services import (
    DomainLifecycleService,
    DomainRepository,
    DomainValidationService,
    RegistrarService,
    TLDService,
)

logger = logging.getLogger(__name__)


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

def _get_accessible_customer_ids(user: User) -> list[int]:
    """🔒 Helper to get customer IDs that user can access"""
    accessible_customers = user.get_accessible_customers()
    
    if hasattr(accessible_customers, 'values_list'):
        return list(accessible_customers.values_list('id', flat=True))
    elif isinstance(accessible_customers, (list, tuple)):
        return [c.id for c in accessible_customers]
    else:
        return []


def _build_domain_table_data(domains: QuerySet[Domain], user: User) -> dict[str, Any]:
    """🏗️ Build table data structure for domain templates"""
    columns = [
        {'label': 'Domain', 'width': 'w-1/3', 'sortable': True},
        {'label': 'TLD', 'width': 'w-20', 'align': 'center'},
        {'label': 'Status', 'width': 'w-24', 'align': 'center'},
        {'label': 'Expiry', 'width': 'w-32', 'sortable': True},
        {'label': 'Customer', 'width': 'w-1/4'},
    ]
    
    can_manage = user.is_staff or getattr(user, 'staff_role', None)
    
    rows = []
    for domain in domains:
        # Determine status badge variant
        status_variants = {
            'active': 'success',
            'pending': 'warning', 
            'expired': 'danger',
            'suspended': 'warning',
            'cancelled': 'secondary',
            'transfer_in': 'info',
            'transfer_out': 'info',
        }
        
        # Determine expiry status
        expiry_variant = 'secondary'
        expiry_title = ''
        if domain.expires_at:
            days_left = domain.days_until_expiry
            if days_left is not None:
                if days_left < 0:
                    expiry_variant = 'danger'
                    expiry_title = 'Domain has expired'
                elif days_left <= 7:
                    expiry_variant = 'danger' 
                    expiry_title = f'Expires in {days_left} days'
                elif days_left <= 30:
                    expiry_variant = 'warning'
                    expiry_title = f'Expires in {days_left} days'
                else:
                    expiry_variant = 'success'
                    expiry_title = f'Expires in {days_left} days'
        
        row_data = {
            'clickable': True,
            'click_url': f'/app/domains/{domain.id}/',
            'cells': [
                {
                    'component': 'text',
                    'text': domain.name,
                    'font_class': 'font-mono font-medium',
                },
                {
                    'component': 'badge',
                    'text': f'.{domain.tld.extension}',
                    'variant': 'secondary',
                    'align': 'center',
                    'font_class': 'font-mono text-xs',
                },
                {
                    'component': 'badge',
                    'text': domain.get_status_display(),
                    'variant': status_variants.get(domain.status, 'secondary'),
                    'align': 'center',
                },
                {
                    'component': 'text',
                    'text': domain.expires_at.strftime('%d %b %Y') if domain.expires_at else 'N/A',
                    'align': 'center',
                    'title': expiry_title,
                    'text_color': f'text-{expiry_variant}-600' if expiry_variant != 'secondary' else '',
                    'font_class': 'text-sm',
                },
                {
                    'component': 'text',
                    'text': domain.customer.get_display_name(),
                    'truncate': True,
                },
            ]
        }
        
        # Add actions if user can manage
        if can_manage:
            actions = []
            if domain.status == 'active':
                actions.extend([
                    {
                        'component': 'button',
                        'text': '🔄',
                        'title': 'Renew',
                        'variant': 'secondary',
                        'size': 'xs',
                        'href': f'/app/domains/{domain.id}/renew/',
                    },
                    {
                        'component': 'button',
                        'text': '⚙️',
                        'title': 'Manage DNS',
                        'variant': 'secondary',
                        'size': 'xs',
                        'href': f'/app/domains/{domain.id}/dns/',
                    },
                ])
            
            actions.append({
                'component': 'button',
                'text': '👁️',
                'title': 'View Details',
                'variant': 'secondary',
                'size': 'xs',
                'href': f'/app/domains/{domain.id}/',
            })
            
            row_data['actions'] = actions
        
        rows.append(row_data)
    
    return {'columns': columns, 'rows': rows}


# ===============================================================================
# CUSTOMER DOMAIN VIEWS
# ===============================================================================

@login_required
def domain_list(request: HttpRequest) -> HttpResponse:
    """🌍 Display domains for user's customers with search and filtering"""
    # Type guard: @login_required ensures authenticated user
    user = cast(User, request.user)
    customer_ids = _get_accessible_customer_ids(user)
    
    # Base queryset with optimized joins
    domains = Domain.objects.filter(
        customer_id__in=customer_ids
    ).select_related(
        'tld', 'registrar', 'customer'
    ).order_by('-created_at')
    
    # Search functionality
    search_query = request.GET.get('search', '').strip()
    if search_query:
        domains = domains.filter(
            Q(name__icontains=search_query) |
            Q(customer__company_name__icontains=search_query) |
            Q(customer__first_name__icontains=search_query) |
            Q(customer__last_name__icontains=search_query)
        )
    
    # Status filter
    status_filter = request.GET.get('status')
    if status_filter and status_filter != 'all':
        domains = domains.filter(status=status_filter)
    
    # TLD filter
    tld_filter = request.GET.get('tld')
    if tld_filter:
        domains = domains.filter(tld__extension=tld_filter)
    
    # Expiry filter
    expiry_filter = request.GET.get('expiry')
    if expiry_filter == 'expiring':
        # Domains expiring in next 30 days
        domains = DomainRepository.get_expiring_domains(30).filter(
            id__in=[d.id for d in domains]
        )
    elif expiry_filter == 'expired':
        domains = domains.filter(status='expired')
    
    # Pagination
    paginator = Paginator(domains, 25)
    page_number = request.GET.get('page')
    domains_page = paginator.get_page(page_number)
    
    # Statistics for filter counts
    total_count = Domain.objects.filter(customer_id__in=customer_ids).count()
    active_count = Domain.objects.filter(customer_id__in=customer_ids, status='active').count()
    expiring_count = DomainRepository.get_expiring_domains(30).filter(
        customer_id__in=customer_ids
    ).count()
    
    # Available TLDs for filter dropdown
    used_tlds = TLD.objects.filter(
        domains__customer_id__in=customer_ids
    ).values_list('extension', flat=True).distinct()
    
    # Build table data
    table_data = _build_domain_table_data(domains_page, user)
    
    context = {
        'domains': domains_page,
        'table_data': table_data,
        'search_query': search_query,
        'status_filter': status_filter,
        'tld_filter': tld_filter,
        'expiry_filter': expiry_filter,
        'total_count': total_count,
        'active_count': active_count,
        'expiring_count': expiring_count,
        'used_tlds': used_tlds,
        'can_register_domains': True,  # All users can register domains
    }
    
    return render(request, 'domains/domain_list.html', context)


@login_required
def domain_detail(request: HttpRequest, domain_id: str) -> HttpResponse:
    """🌍 Display domain details and management options"""
    # Type guard: @login_required ensures authenticated user
    user = cast(User, request.user)
    domain = get_object_or_404(Domain, id=domain_id)
    
    # Security check - user must have access to this domain's customer
    if not user.can_access_customer(domain.customer):
        messages.error(request, _("❌ You do not have permission to access this domain."))
        return redirect('domains:list')
    
    # Calculate days until expiry
    days_until_expiry = domain.days_until_expiry
    expiry_status = 'ok'
    expiry_message = ''
    
    if domain.expires_at:
        if days_until_expiry is not None:
            if days_until_expiry < 0:
                expiry_status = 'expired'
                expiry_message = f'Domain expired {abs(days_until_expiry)} days ago'
            elif days_until_expiry <= 7:
                expiry_status = 'critical'
                expiry_message = f'Domain expires in {days_until_expiry} days'
            elif days_until_expiry <= 30:
                expiry_status = 'warning'
                expiry_message = f'Domain expires in {days_until_expiry} days'
            else:
                expiry_message = f'Domain expires in {days_until_expiry} days'
    
    # Check user permissions for management actions
    can_manage = user.is_staff or getattr(user, 'staff_role', None)
    can_renew = domain.status == 'active'
    can_transfer = domain.status in ['active', 'suspended']
    can_modify_dns = domain.status == 'active' and can_manage
    
    # Get domain order history
    order_items = DomainOrderItem.objects.filter(
        domain=domain
    ).select_related('order').order_by('-created_at')
    
    context = {
        'domain': domain,
        'days_until_expiry': days_until_expiry,
        'expiry_status': expiry_status,
        'expiry_message': expiry_message,
        'can_manage': can_manage,
        'can_renew': can_renew,
        'can_transfer': can_transfer,
        'can_modify_dns': can_modify_dns,
        'order_items': order_items,
        'nameservers': domain.nameservers or [],
    }
    
    return render(request, 'domains/domain_detail.html', context)


@login_required
def domain_register(request: HttpRequest) -> HttpResponse:
    """🆕 Domain registration form and availability check"""
    # Type guard: @login_required ensures authenticated user
    user = cast(User, request.user)
    
    # Get user's accessible customers for dropdown
    accessible_customers = user.get_accessible_customers()
    if hasattr(accessible_customers, 'all'):
        customers = accessible_customers.all()
    elif isinstance(accessible_customers, (list, tuple)):
        customers = Customer.objects.filter(id__in=[c.id for c in accessible_customers])
    else:
        customers = Customer.objects.none()
    
    # Get featured and all TLDs for selection
    featured_tlds = TLDService.get_featured_tlds()[:6]  # Top 6 featured TLDs
    all_tlds = TLDService.get_available_tlds()
    
    # Handle form submission
    if request.method == 'POST':
        domain_name = request.POST.get('domain_name', '').strip().lower()
        selected_customer_id = request.POST.get('customer_id')
        years = int(request.POST.get('years', 1))
        whois_privacy = request.POST.get('whois_privacy') == 'on'
        auto_renew = request.POST.get('auto_renew') == 'on'
        
        # Validate inputs
        if not domain_name:
            messages.error(request, _("Please enter a domain name"))
        elif not selected_customer_id:
            messages.error(request, _("Please select a customer"))
        else:
            # Get selected customer and verify access
            try:
                customer = Customer.objects.get(id=selected_customer_id)
                if not user.can_access_customer(customer):
                    messages.error(request, _("❌ You do not have permission for this customer"))
                else:
                    # Validate domain and create registration
                    success, result = DomainLifecycleService.create_domain_registration(
                        customer=customer,
                        domain_name=domain_name,
                        years=years,
                        whois_privacy=whois_privacy,
                        auto_renew=auto_renew
                    )
                    
                    if success:
                        messages.success(request, _(f"✅ Domain {domain_name} registered successfully!"))
                        return redirect('domains:detail', domain_id=result.id)
                    else:
                        messages.error(request, _(f"❌ Registration failed: {result}"))
            
            except Customer.DoesNotExist:
                messages.error(request, _("Invalid customer selected"))
    
    # Calculate costs for featured TLDs
    tld_pricing = []
    for tld in featured_tlds:
        pricing = TLDService.calculate_domain_cost(tld, 1, False)
        tld_pricing.append({
            'tld': tld,
            'cost': pricing['total_cost'],
            'cost_cents': pricing['total_cost_cents'],
        })
    
    context = {
        'customers': customers,
        'featured_tlds': featured_tlds,
        'all_tlds': all_tlds,
        'tld_pricing': tld_pricing,
        'years_choices': list(range(1, 11)),  # 1-10 years
    }
    
    return render(request, 'domains/domain_register.html', context)


@login_required
@require_http_methods(["POST"])
def check_availability(request: HttpRequest) -> JsonResponse:
    """🔍 AJAX endpoint to check domain availability"""
    domain_name = request.POST.get('domain_name', '').strip().lower()
    
    # Validate domain name format
    is_valid, error_msg = DomainValidationService.validate_domain_name(domain_name)
    if not is_valid:
        return JsonResponse({
            'success': False,
            'error': str(error_msg)
        })
    
    # Extract TLD and check if supported
    tld_extension = DomainValidationService.extract_tld_from_domain(domain_name)
    tld = TLDService.get_tld_pricing(tld_extension)
    if not tld:
        return JsonResponse({
            'success': False,
            'error': _(f"TLD '.{tld_extension}' is not supported")
        })
    
    # Check if domain already exists in our system
    domain_exists = Domain.objects.filter(name=domain_name).exists()
    
    if domain_exists:
        return JsonResponse({
            'success': True,
            'available': False,
            'message': _("Domain is already registered"),
            'domain_name': domain_name
        })
    
    # Get registrar and check availability (placeholder implementation)
    registrar = RegistrarService.select_best_registrar_for_tld(tld)
    if not registrar:
        return JsonResponse({
            'success': False,
            'error': _("No available registrar for this TLD")
        })
    
    # For now, assume available if not in our database
    # TODO: Implement actual registrar API availability check
    
    # Calculate pricing
    pricing_1yr = TLDService.calculate_domain_cost(tld, 1, False)
    pricing_2yr = TLDService.calculate_domain_cost(tld, 2, False)
    
    return JsonResponse({
        'success': True,
        'available': True,
        'domain_name': domain_name,
        'tld_extension': tld_extension,
        'pricing': {
            '1_year': pricing_1yr,
            '2_years': pricing_2yr,
        },
        'whois_privacy_available': tld.whois_privacy_available,
        'registrar': registrar.display_name,
    })


@login_required
def domain_renew(request: HttpRequest, domain_id: str) -> HttpResponse:
    """🔄 Domain renewal form and processing"""
    # Type guard: @login_required ensures authenticated user
    user = cast(User, request.user)
    domain = get_object_or_404(Domain, id=domain_id)
    
    # Security check
    if not user.can_access_customer(domain.customer):
        messages.error(request, _("❌ You do not have permission to access this domain."))
        return redirect('domains:list')
    
    # Check if domain can be renewed
    if domain.status != 'active':
        messages.error(request, _("❌ Only active domains can be renewed."))
        return redirect('domains:detail', domain_id=domain_id)
    
    # Handle renewal request
    if request.method == 'POST':
        years = int(request.POST.get('years', 1))
        
        success, message = DomainLifecycleService.process_domain_renewal(
            domain=domain,
            years=years
        )
        
        if success:
            messages.success(request, _(f"✅ Domain renewed for {years} year(s)!"))
            return redirect('domains:detail', domain_id=domain_id)
        else:
            messages.error(request, _(f"❌ Renewal failed: {message}"))
    
    # Calculate renewal costs
    renewal_costs = []
    for years in [1, 2, 3, 5]:
        cost = TLDService.calculate_domain_cost(domain.tld, years, domain.whois_privacy)
        renewal_costs.append({
            'years': years,
            'cost': cost['total_cost'],
            'cost_cents': cost['total_cost_cents'],
        })
    
    context = {
        'domain': domain,
        'renewal_costs': renewal_costs,
        'days_until_expiry': domain.days_until_expiry,
    }
    
    return render(request, 'domains/domain_renew.html', context)


# ===============================================================================
# STAFF MANAGEMENT VIEWS
# ===============================================================================

@staff_required
def tld_list(request: HttpRequest) -> HttpResponse:
    """🌐 Staff view - Manage TLDs and pricing"""
    # Type guard: @staff_required ensures authenticated staff user
    user = cast(User, request.user)
    
    tlds = TLD.objects.all().prefetch_related(
        'registrar_assignments__registrar'
    ).order_by('extension')
    
    # Search functionality
    search_query = request.GET.get('search', '').strip()
    if search_query:
        tlds = tlds.filter(
            Q(extension__icontains=search_query) |
            Q(description__icontains=search_query)
        )
    
    # Status filter
    status_filter = request.GET.get('status')
    if status_filter == 'active':
        tlds = tlds.filter(is_active=True)
    elif status_filter == 'inactive':
        tlds = tlds.filter(is_active=False)
    elif status_filter == 'featured':
        tlds = tlds.filter(is_featured=True)
    
    # Pagination
    paginator = Paginator(tlds, 25)
    page_number = request.GET.get('page')
    tlds_page = paginator.get_page(page_number)
    
    # Statistics
    total_count = TLD.objects.count()
    active_count = TLD.objects.filter(is_active=True).count()
    featured_count = TLD.objects.filter(is_featured=True).count()
    
    context = {
        'tlds': tlds_page,
        'search_query': search_query,
        'status_filter': status_filter,
        'total_count': total_count,
        'active_count': active_count,
        'featured_count': featured_count,
    }
    
    return render(request, 'domains/staff/tld_list.html', context)


@staff_required
def registrar_list(request: HttpRequest) -> HttpResponse:
    """🏢 Staff view - Manage registrars and API configurations"""
    # Type guard: @staff_required ensures authenticated staff user
    user = cast(User, request.user)
    
    registrars = Registrar.objects.all().prefetch_related(
        'tld_assignments__tld'
    ).order_by('name')
    
    # Status filter
    status_filter = request.GET.get('status')
    if status_filter:
        registrars = registrars.filter(status=status_filter)
    
    # Pagination
    paginator = Paginator(registrars, 25)
    page_number = request.GET.get('page')
    registrars_page = paginator.get_page(page_number)
    
    # Statistics
    total_count = Registrar.objects.count()
    active_count = Registrar.objects.filter(status='active').count()
    suspended_count = Registrar.objects.filter(status='suspended').count()
    disabled_count = Registrar.objects.filter(status='disabled').count()
    
    context = {
        'registrars_page': registrars_page,
        'status_filter': status_filter,
        'total_count': total_count,
        'active_count': active_count,
        'suspended_count': suspended_count,
        'disabled_count': disabled_count,
    }
    
    return render(request, 'domains/staff/registrar_list.html', context)


@staff_required
def domain_admin_list(request: HttpRequest) -> HttpResponse:
    """🔧 Staff view - All domains across all customers"""
    # Type guard: @staff_required ensures authenticated staff user
    user = cast(User, request.user)
    
    # Base queryset with optimized joins
    domains = Domain.objects.all().select_related(
        'tld', 'registrar', 'customer'
    ).order_by('-created_at')
    
    # Search functionality
    search_query = request.GET.get('search', '').strip()
    if search_query:
        domains = domains.filter(
            Q(name__icontains=search_query) |
            Q(customer__company_name__icontains=search_query) |
            Q(customer__first_name__icontains=search_query) |
            Q(customer__last_name__icontains=search_query)
        )
    
    # Status filter
    status_filter = request.GET.get('status')
    if status_filter and status_filter != 'all':
        domains = domains.filter(status=status_filter)
    
    # Registrar filter
    registrar_filter = request.GET.get('registrar')
    if registrar_filter:
        domains = domains.filter(registrar_id=registrar_filter)
    
    # Expiry filter for staff management
    expiry_filter = request.GET.get('expiry')
    if expiry_filter == 'expiring':
        domains = DomainRepository.get_expiring_domains(30)
    elif expiry_filter == 'auto_renew':
        domains = DomainRepository.get_auto_renewal_candidates()
    
    # Pagination
    paginator = Paginator(domains, 50)  # More items per page for staff
    page_number = request.GET.get('page')
    domains_page = paginator.get_page(page_number)
    
    # Statistics
    total_count = Domain.objects.count()
    active_count = Domain.objects.filter(status='active').count()
    expiring_count = DomainRepository.get_expiring_domains(30).count()
    auto_renew_count = DomainRepository.get_auto_renewal_candidates().count()
    
    # Available registrars for filter
    registrars = Registrar.objects.filter(status='active').order_by('display_name')
    
    # Build table data
    table_data = _build_domain_table_data(domains_page, user)
    
    context = {
        'domains': domains_page,
        'table_data': table_data,
        'search_query': search_query,
        'status_filter': status_filter,
        'registrar_filter': registrar_filter,
        'expiry_filter': expiry_filter,
        'total_count': total_count,
        'active_count': active_count,
        'expiring_count': expiring_count,
        'auto_renew_count': auto_renew_count,
        'registrars': registrars,
    }
    
    return render(request, 'domains/staff/domain_admin_list.html', context)
