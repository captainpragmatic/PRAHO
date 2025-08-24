# ===============================================================================
# CUSTOMERS VIEWS - NORMALIZED MODEL STRUCTURE
# ===============================================================================

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from typing import cast

from apps.common.types import Result, Ok, Err

from .models import (
    Customer, 
    CustomerTaxProfile, 
    CustomerBillingProfile, 
    CustomerAddress, 
    CustomerNote
)
from .forms import (
    CustomerForm, 
    CustomerCreationForm,
    CustomerUserAssignmentForm,
    CustomerTaxProfileForm,
    CustomerBillingProfileForm,
    CustomerAddressForm,
    CustomerNoteForm
)
from apps.users.services import CustomerUserService


@login_required
def customer_list(request):
    """
    👥 Display list of customers with search functionality
    Uses simplified Customer model with related data loaded efficiently
    """
    # Get user's accessible customers (multi-tenant)
    accessible_customers_list = request.user.get_accessible_customers()
    
    # Convert to QuerySet for database operations
    from django.db.models import QuerySet
    if isinstance(accessible_customers_list, QuerySet):
        customers = accessible_customers_list
    else:
        if accessible_customers_list:
            customer_ids = [c.id for c in accessible_customers_list]
            customers = Customer.objects.filter(id__in=customer_ids)
        else:
            customers = Customer.objects.none()
    
    # Search functionality - updated for new model structure
    search_query = request.GET.get('search', '')
    if search_query:
        customers = customers.filter(
            Q(company_name__icontains=search_query) |
            Q(name__icontains=search_query) |
            Q(primary_email__icontains=search_query) |
            Q(tax_profile__cui__icontains=search_query)  # Search in related tax profile
        ).distinct()
    
    # Expected queries: 3 (customers + tax profiles + addresses for display)
    customers = customers.select_related('tax_profile', 'billing_profile')\
                        .prefetch_related('addresses')\
                        .order_by('-created_at')
    
    # Pagination
    paginator = Paginator(customers, 25)
    page_number = request.GET.get('page')
    customers_page = paginator.get_page(page_number)
    
    context = {
        'customers': customers_page,
        'search_query': search_query,
        'total_customers': customers.count(),
    }
    
    return render(request, 'customers/list.html', context)


@login_required
def customer_detail(request, customer_id):
    """
    🔍 Customer detail view with all related information
    Shows normalized data from separate profile models
    """
    customer = get_object_or_404(Customer, id=customer_id)
    
    # Check access permissions
    if not request.user.can_access_customer(customer):
        messages.error(request, _('Access denied to this customer'))
        return redirect('customers:list')
    
    # Expected queries: 4 (customer + tax + billing + addresses)
    customer = Customer.objects.select_related('tax_profile', 'billing_profile')\
                              .prefetch_related('addresses', 'notes')\
                              .get(id=customer_id)
    
    # Get recent notes
    recent_notes = customer.notes.order_by('-created_at')[:5]
    
    context = {
        'customer': customer,
        'tax_profile': customer.get_tax_profile(),
        'billing_profile': customer.get_billing_profile(),
        'primary_address': customer.get_primary_address(),
        'billing_address': customer.get_billing_address(),
        'recent_notes': recent_notes,
    }
    
    return render(request, 'customers/detail.html', context)


@login_required
def customer_create(request):
    """
    ➕ Create new customer with all profiles and optional user assignment
    Uses composite form to handle normalized structure and user creation/linking
    """
    if request.method == 'POST':
        form = CustomerCreationForm(request.POST)
        if form.is_valid():
            try:
                # Save customer and get result data
                result = form.save(user=request.user)
                customer = result['customer']
                user_action = result['user_action']
                
                # Handle user assignment based on action
                if user_action == 'create':
                    # Auto-create user account
                    user_result = CustomerUserService.create_user_for_customer(
                        customer=customer,
                        first_name=form.cleaned_data.get('first_name', ''),
                        last_name=form.cleaned_data.get('last_name', ''),
                        send_welcome=result['send_welcome_email'],
                        created_by=request.user
                    )
                    
                    if user_result.is_ok():
                        user, email_sent = user_result.value
                        if email_sent:
                            messages.success(
                                request,
                                _('✅ Customer "{customer_name}" created successfully. Welcome email sent to {email}').format(
                                    customer_name=customer.name,
                                    email=user.email
                                )
                            )
                        else:
                            messages.success(
                                request,
                                _('✅ Customer "{customer_name}" created successfully. User account created for {email}').format(
                                    customer_name=customer.name,
                                    email=user.email
                                )
                            )
                            messages.warning(
                                request,
                                _('⚠️ Welcome email could not be sent. Please inform the user manually.')
                            )
                    else:  # user_result.is_err()
                        messages.success(
                            request,
                            _('✅ Customer "{customer_name}" created successfully').format(customer_name=customer.name)
                        )
                        messages.error(
                            request,
                            _('❌ Failed to create user account: {error}').format(error=user_result.error)
                        )
                
                elif user_action == 'link':
                    # Link existing user
                    existing_user = result['existing_user']
                    if existing_user:
                        link_result = CustomerUserService.link_existing_user(
                            user=existing_user,
                            customer=customer,
                            role='owner',
                            is_primary=True,
                            created_by=request.user
                        )
                        
                        if link_result.is_ok():
                            messages.success(
                                request,
                                _('✅ Customer "{customer_name}" created and linked to user {email}').format(
                                    customer_name=customer.name,
                                    email=existing_user.email
                                )
                            )
                        else:  # link_result.is_err()
                            messages.success(
                                request,
                                _('✅ Customer "{customer_name}" created successfully').format(customer_name=customer.name)
                            )
                            messages.error(
                                request,
                                _('❌ Failed to link user: {error}').format(error=link_result.error)
                            )
                
                else:  # user_action == 'skip'
                    messages.success(
                        request,
                        _('✅ Customer "{customer_name}" created successfully. No user assigned.').format(customer_name=customer.name)
                    )
                    messages.info(
                        request,
                        _('ℹ️ You can assign users later from the customer detail page.')
                    )
                
                return redirect('customers:detail', customer_id=customer.pk)
                
            except Exception as e:
                messages.error(request, _('❌ Error creating customer: {error}').format(error=str(e)))
        else:
            messages.error(request, _('❌ Please correct the errors below'))
    else:
        form = CustomerCreationForm()
    
    context = {
        'form': form,
        'action': _('Create'),
    }
    
    return render(request, 'customers/form.html', context)


@login_required
def customer_edit(request, customer_id):
    """
    ✏️ Edit customer core information
    Separate views for tax/billing/address profiles
    """
    customer = get_object_or_404(Customer, id=customer_id)
    
    # Check access permissions
    if not request.user.can_access_customer(customer):
        messages.error(request, _('Access denied to this customer'))
        return redirect('customers:list')
    
    if request.method == 'POST':
        form = CustomerForm(request.POST, instance=customer)
        if form.is_valid():
            form.save()
            messages.success(request, _('✅ Customer "{customer_name}" updated').format(customer_name=customer.get_display_name()))
            return redirect('customers:detail', customer_id=customer.id)
        else:
            messages.error(request, _('❌ Please correct the errors below'))
    else:
        form = CustomerForm(instance=customer)
    
    context = {
        'form': form,
        'customer': customer,
        'action': _('Edit'),
    }
    
    return render(request, 'customers/form.html', context)


@login_required
def customer_tax_profile(request, customer_id):
    """
    🧾 Edit customer tax profile (CUI, VAT, compliance)
    """
    customer = get_object_or_404(Customer, id=customer_id)
    
    # Check access permissions
    if not request.user.can_access_customer(customer):
        messages.error(request, _('Access denied to this customer'))
        return redirect('customers:list')
    
    # Get or create tax profile
    tax_profile, created = CustomerTaxProfile.objects.get_or_create(customer=customer)
    
    if request.method == 'POST':
        form = CustomerTaxProfileForm(request.POST, instance=tax_profile)
        if form.is_valid():
            form.save()
            messages.success(request, _('✅ Tax profile updated successfully'))
            return redirect('customers:detail', customer_id=customer.id)
        else:
            messages.error(request, _('❌ Please correct the errors below'))
    else:
        form = CustomerTaxProfileForm(instance=tax_profile)
    
    context = {
        'form': form,
        'customer': customer,
        'tax_profile': tax_profile,
        'action': _('Tax Profile'),
    }
    
    return render(request, 'customers/tax_profile_form.html', context)


@login_required
def customer_billing_profile(request, customer_id):
    """
    💰 Edit customer billing profile (payment terms, credit)
    """
    customer = get_object_or_404(Customer, id=customer_id)
    
    # Check access permissions
    if not request.user.can_access_customer(customer):
        messages.error(request, _('Access denied to this customer'))
        return redirect('customers:list')
    
    # Get or create billing profile
    billing_profile, created = CustomerBillingProfile.objects.get_or_create(customer=customer)
    
    if request.method == 'POST':
        form = CustomerBillingProfileForm(request.POST, instance=billing_profile)
        if form.is_valid():
            form.save()
            messages.success(request, _('✅ Billing profile updated successfully'))
            return redirect('customers:detail', customer_id=customer.id)
        else:
            messages.error(request, _('❌ Please correct the errors below'))
    else:
        form = CustomerBillingProfileForm(instance=billing_profile)
    
    context = {
        'form': form,
        'customer': customer,
        'billing_profile': billing_profile,
        'action': _('Billing Profile'),
    }
    
    return render(request, 'customers/billing_profile_form.html', context)


@login_required
def customer_address_add(request, customer_id):
    """
    🏠 Add new address for customer
    """
    customer = get_object_or_404(Customer, id=customer_id)
    
    # Check access permissions
    if not request.user.can_access_customer(customer):
        messages.error(request, _('Access denied to this customer'))
        return redirect('customers:list')
    
    if request.method == 'POST':
        form = CustomerAddressForm(request.POST)
        if form.is_valid():
            address = form.save(commit=False)
            address.customer = customer
            
            # Handle current address versioning
            address_type = address.address_type
            existing_current = CustomerAddress.objects.filter(
                customer=customer,
                address_type=address_type,
                is_current=True
            ).first()
            
            if existing_current:
                existing_current.is_current = False
                existing_current.save()
                address.version = existing_current.version + 1
            
            address.save()
            messages.success(request, _('✅ {address_type} address added').format(address_type=address.get_address_type_display()))
            return redirect('customers:detail', customer_id=customer.id)
        else:
            messages.error(request, _('❌ Please correct the errors below'))
    else:
        form = CustomerAddressForm()
    
    context = {
        'form': form,
        'customer': customer,
        'action': _('Add Address'),
    }
    
    return render(request, 'customers/address_form.html', context)


@login_required
def customer_note_add(request, customer_id):
    """
    📝 Add customer interaction note
    """
    customer = get_object_or_404(Customer, id=customer_id)
    
    # Check access permissions
    if not request.user.can_access_customer(customer):
        messages.error(request, _('Access denied to this customer'))
        return redirect('customers:list')
    
    if request.method == 'POST':
        form = CustomerNoteForm(request.POST)
        if form.is_valid():
            note = form.save(commit=False)
            note.customer = customer
            note.created_by = request.user
            note.save()
            messages.success(request, _('✅ Note added successfully'))
            return redirect('customers:detail', customer_id=customer.id)
        else:
            messages.error(request, _('❌ Please correct the errors below'))
    else:
        form = CustomerNoteForm()
    
    context = {
        'form': form,
        'customer': customer,
        'action': _('Add Note'),
    }
    
    return render(request, 'customers/note_form.html', context)


@login_required
def customer_delete(request, customer_id):
    """
    🗑️ Soft delete customer (preserves audit trail)
    """
    customer = get_object_or_404(Customer, id=customer_id)
    
    # Check access permissions
    if not request.user.can_access_customer(customer):
        messages.error(request, _('Access denied to this customer'))
        return redirect('customers:list')
    
    if request.method == 'POST':
        # Soft delete preserves all related data
        customer.soft_delete(user=request.user)
        messages.success(
            request, 
            _('🗑️ Customer "{customer_name}" deleted successfully').format(customer_name=customer.get_display_name())
        )
        return redirect('customers:list')
    
    context = {
        'customer': customer,
    }
    
    return render(request, 'customers/delete_confirm.html', context)


@login_required
def customer_search_api(request):
    """
    🔍 AJAX customer search for dropdowns
    """
    query = request.GET.get('q', '')
    if len(query) < 2:
        return JsonResponse({'results': []})
    
    customers = request.user.get_accessible_customers()
    
    # Filter based on search query
    if hasattr(customers, 'filter'):  # QuerySet
        customers = customers.filter(
            Q(name__icontains=query) |
            Q(company_name__icontains=query) |
            Q(primary_email__icontains=query)
        )[:10]
    else:  # List
        customers = [
            c for c in customers 
            if query.lower() in c.name.lower() or 
               query.lower() in c.company_name.lower() or
               query.lower() in c.primary_email.lower()
        ][:10]
    
    results = [
        {
            'id': customer.id,
            'text': customer.get_display_name(),
            'email': customer.primary_email,
        }
        for customer in customers
    ]
    
    return JsonResponse({'results': results})


@login_required
def customer_assign_user(request, customer_id):
    """
    🔗 Assign user to existing customer (for orphaned customers)
    Provides same three-option workflow as customer creation
    """
    customer = get_object_or_404(Customer, id=customer_id)
    
    # Check access permissions
    if not request.user.can_access_customer(customer):
        messages.error(request, _('Access denied to this customer'))
        return redirect('customers:list')
    
    if request.method == 'POST':
        form = CustomerUserAssignmentForm(data=request.POST, customer=customer)
        if form.is_valid():
            try:
                # Get form data
                assignment_data = form.save(customer=customer, created_by=request.user)
                action = assignment_data['action']
                
                if action == 'create':
                    # Auto-create user account using customer's email
                    send_welcome = bool(assignment_data.get('send_welcome_email', True))
                    user_result = CustomerUserService.create_user_for_customer(
                        customer=customer,
                        first_name=assignment_data['first_name'],
                        last_name=assignment_data['last_name'],
                        send_welcome=send_welcome,
                        created_by=request.user
                    )
                    
                    if user_result.is_ok():
                        user, email_sent = user_result.unwrap()
                        if email_sent:
                            messages.success(
                                request,
                                _('✅ User account created for {customer_name}. Welcome email sent to {email}').format(
                                    customer_name=customer.name,
                                    email=user.email
                                )
                            )
                        else:
                            messages.success(
                                request,
                                _('✅ User account created for {customer_name}: {email}').format(
                                    customer_name=customer.name,
                                    email=user.email
                                )
                            )
                            messages.warning(
                                request,
                                _('⚠️ Welcome email could not be sent. Please inform the user manually.')
                            )
                    else:  # user_result.is_err()
                        error_result = cast(Err, user_result)
                        messages.error(
                            request,
                            _('❌ Failed to create user account: {error}').format(error=error_result.error)
                        )
                
                elif action == 'link':
                    # Link existing user
                    existing_user = assignment_data['existing_user']
                    role = assignment_data['role']
                    
                    if existing_user:  # Ensure user is not None
                        from apps.users.models import User
                        if isinstance(existing_user, User):
                            link_result = CustomerUserService.link_existing_user(
                                user=existing_user,
                                customer=customer,
                                role=role,
                                is_primary=False,  # Existing customers might already have primary users
                                created_by=request.user
                            )
                            
                            if link_result.is_ok():
                                messages.success(
                                    request,
                                    _('✅ User {email} linked to customer "{customer_name}" with {role} role').format(
                                        email=existing_user.email,
                                        customer_name=customer.name,
                                        role=role
                                    )
                                )
                            else:  # link_result.is_err()
                                error_result = cast(Err, link_result)
                                messages.error(
                                    request,
                                    _('❌ Failed to link user: {error}').format(error=error_result.error)
                                )
                        else:
                            messages.error(request, _('❌ Invalid user selected'))
                    else:
                        messages.error(request, _('❌ No user selected for linking'))
                
                else:  # action == 'skip'
                    messages.info(
                        request,
                        _('ℹ️ User assignment skipped for customer "{customer_name}"').format(customer_name=customer.name)
                    )
                
                return redirect('customers:detail', customer_id=customer.pk)
                
            except Exception as e:
                messages.error(request, _('❌ Error assigning user: {error}').format(error=str(e)))
        else:
            messages.error(request, _('❌ Please correct the errors below'))
    else:
        form = CustomerUserAssignmentForm(customer=customer)
    
    context = {
        'form': form,
        'customer': customer,
        'action': _('Assign User'),
    }
    
    return render(request, 'customers/assign_user.html', context)
