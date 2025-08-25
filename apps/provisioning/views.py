# ===============================================================================
# PROVISIONING VIEWS - HOSTING SERVICES MANAGEMENT
# ===============================================================================

from __future__ import annotations
from typing import Any

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from apps.customers.models import Customer

from .models import Server, Service, ServicePlan


def _get_accessible_customer_ids(user: Any) -> list[int]:
    """Helper to get customer IDs that user can access"""
    accessible_customers = user.get_accessible_customers()

    from django.db.models import QuerySet
    if isinstance(accessible_customers, QuerySet):
        return accessible_customers.values_list('id', flat=True)
    else:
        return [c.id for c in accessible_customers] if accessible_customers else []


@login_required
def service_list(request: HttpRequest) -> HttpResponse:
    """🚀 Display hosting services for user's customers"""
    customer_ids = _get_accessible_customer_ids(request.user)
    services = Service.objects.filter(customer_id__in=customer_ids).select_related('customer', 'service_plan').order_by('-created_at')

    # Filter by status
    status_filter = request.GET.get('status')
    if status_filter:
        services = services.filter(status=status_filter)

    # Pagination
    paginator = Paginator(services, 25)
    page_number = request.GET.get('page')
    services_page = paginator.get_page(page_number)

    context = {
        'services': services_page,
        'status_filter': status_filter,
        'active_count': services.filter(status='active').count(),
        'total_count': services.count(),
    }

    return render(request, 'provisioning/service_list.html', context)


@login_required
def service_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """🚀 Display service details and configuration"""
    service = get_object_or_404(Service, pk=pk)

    # Security check
    if not request.user.can_access_customer(service.customer):
        messages.error(request, _("❌ You do not have permission to access this service."))
        return redirect('provisioning:services')

    context = {
        'service': service,
        'can_manage': service.status in ['active', 'suspended'],
    }

    return render(request, 'provisioning/service_detail.html', context)


@login_required
def service_create(request: HttpRequest) -> HttpResponse:
    """➕ Create new hosting service"""
    # Get user's customers for dropdown
    accessible_customers = request.user.get_accessible_customers()
    if hasattr(accessible_customers, 'all'):
        customers = accessible_customers.all()
    elif isinstance(accessible_customers, list | tuple):
        customers = Customer.objects.filter(id__in=[c.id for c in accessible_customers])
    else:
        customers = accessible_customers
    plans = ServicePlan.objects.filter(is_active=True)

    if request.method == 'POST':
        customer_id = request.POST.get('customer_id')
        plan_id = request.POST.get('plan_id')
        domain = request.POST.get('domain')

        if customer_id and plan_id and domain:
            customer = get_object_or_404(Customer, pk=customer_id)

            # Security check
            accessible_customer_ids = _get_accessible_customer_ids(request.user)
            if int(customer_id) not in accessible_customer_ids:
                messages.error(request, _("❌ You do not have permission to create services for this customer."))
                return redirect('provisioning:services')
            plan = get_object_or_404(ServicePlan, pk=plan_id)

            service = Service.objects.create(
                customer=customer,
                plan=plan,
                domain=domain,
                status='pending',
            )

            messages.success(request, _("✅ Service for {domain} has been created!").format(domain=domain))
            return redirect('provisioning:service_detail', pk=service.pk)
        else:
            messages.error(request, _("❌ All fields are required."))

    context = {
        'customers': customers,
        'plans': plans,
    }

    return render(request, 'provisioning/service_form.html', context)


@login_required
def service_edit(request: HttpRequest, pk: int) -> HttpResponse:
    """✏️ Edit existing hosting service"""
    service = get_object_or_404(Service, pk=pk)

    # Security check
    if not request.user.can_access_customer(service.customer):
        messages.error(request, _("❌ You do not have permission to edit this service."))
        return redirect('provisioning:services')

    # Get user's customers for dropdown
    accessible_customers = request.user.get_accessible_customers()
    if hasattr(accessible_customers, 'all'):
        customers = accessible_customers.all()
    elif isinstance(accessible_customers, list | tuple):
        customers = Customer.objects.filter(id__in=[c.id for c in accessible_customers])
    else:
        customers = accessible_customers
    plans = ServicePlan.objects.filter(is_active=True)

    if request.method == 'POST':
        customer_id = request.POST.get('customer_id')
        plan_id = request.POST.get('plan_id')
        domain = request.POST.get('domain')

        if customer_id and plan_id and domain:
            customer = get_object_or_404(Customer, pk=customer_id)

            # Security check
            accessible_customer_ids = _get_accessible_customer_ids(request.user)
            if int(customer_id) not in accessible_customer_ids:
                messages.error(request, _("❌ You do not have permission to move services to this customer."))
                return redirect('provisioning:service_detail', pk=pk)

            plan = get_object_or_404(ServicePlan, pk=plan_id)

            # Update service
            service.customer = customer
            service.service_plan = plan
            service.domain = domain
            service.save()

            messages.success(request, _("✅ Service {domain} has been updated!").format(domain=domain))
            return redirect('provisioning:service_detail', pk=service.pk)
        else:
            messages.error(request, _("❌ All fields are required."))

    context = {
        'service': service,
        'customers': customers,
        'plans': plans,
        'is_edit': True,
    }

    return render(request, 'provisioning/service_form.html', context)


@login_required
def service_suspend(request: HttpRequest, pk: int) -> HttpResponse:
    """⏸️ Suspend hosting service"""
    service = get_object_or_404(Service, pk=pk)

    # Security check
    if not request.user.can_access_customer(service.customer):
        messages.error(request, _("❌ You do not have permission to suspend this service."))
        return redirect('provisioning:services')

    if request.method == 'POST':
        service.status = 'suspended'
        service.save()

        messages.success(request, _("⏸️ Service {domain} has been suspended!").format(domain=service.domain))
        return redirect('provisioning:service_detail', pk=pk)

    return render(request, 'provisioning/service_suspend.html', {'service': service})


@login_required
def service_activate(request: HttpRequest, pk: int) -> HttpResponse:
    """▶️ Activate suspended service"""
    service = get_object_or_404(Service, pk=pk)

    # Security check
    if not request.user.can_access_customer(service.customer):
        messages.error(request, _("❌ You do not have permission to activate this service."))
        return redirect('provisioning:services')

    service.status = 'active'
    service.save()

    messages.success(request, _("▶️ Service {domain} has been activated!").format(domain=service.domain))
    return redirect('provisioning:service_detail', pk=pk)


@login_required
def plan_list(request: HttpRequest) -> HttpResponse:
    """📋 Display available hosting plans"""
    plans = ServicePlan.objects.filter(is_active=True).order_by('price')

    context = {
        'plans': plans,
    }

    return render(request, 'provisioning/plan_list.html', context)


@login_required
def server_list(request: HttpRequest) -> HttpResponse:
    """🖥️ Display server infrastructure"""
    servers = Server.objects.all().order_by('name')

    context = {
        'servers': servers,
        'active_servers': servers.filter(status='active').count(),
        'total_servers': servers.count(),
    }

    return render(request, 'provisioning/server_list.html', context)
