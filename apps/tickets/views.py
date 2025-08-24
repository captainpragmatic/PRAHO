# ===============================================================================
# TICKETS VIEWS - SUPPORT SYSTEM
# ===============================================================================

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.utils.translation import gettext_lazy as _

from .models import Ticket, TicketComment


@login_required
def ticket_list(request):
    """🎫 Display support tickets for user's customers"""
    accessible_customers = request.user.get_accessible_customers()
    customer_ids = [customer.id for customer in accessible_customers]
    tickets = Ticket.objects.filter(customer_id__in=customer_ids).select_related('customer').order_by('-created_at')
    
    # Pagination
    paginator = Paginator(tickets, 25)
    page_number = request.GET.get('page')
    tickets_page = paginator.get_page(page_number)
    
    context = {
        'tickets': tickets_page,
        'open_count': tickets.filter(status__in=['open', 'in_progress']).count(),
        'total_count': tickets.count(),
    }
    
    return render(request, 'tickets/list.html', context)


@login_required
def ticket_detail(request, pk):
    """🎫 Display ticket details and conversation"""
    ticket = get_object_or_404(Ticket, pk=pk)
    
    # Security check - verify user has access to this customer
    accessible_customers = request.user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to access this ticket."))
        return redirect('tickets:list')
    
    context = {
        'ticket': ticket,
        'can_edit': ticket.status in ['open', 'in_progress'],
    }
    
    return render(request, 'tickets/detail.html', context)


@login_required
def ticket_create(request):
    """➕ Create new support ticket"""
    customers = request.user.get_accessible_customers()
    
    if request.method == 'POST':
        # Simplified ticket creation
        customer_id = request.POST.get('customer_id')
        subject = request.POST.get('subject')
        description = request.POST.get('description')
        priority = request.POST.get('priority', 'medium')
        
        if customer_id and subject and description:
            # Find customer in accessible customers
            accessible_customers = request.user.get_accessible_customers()
            customer = None
            for cust in accessible_customers:
                if str(cust.id) == str(customer_id):
                    customer = cust
                    break
            
            if not customer:
                messages.error(request, _("❌ You do not have permission to create tickets for this customer."))
                return redirect('tickets:create')
            
            ticket = Ticket.objects.create(
                customer=customer,
                title=subject, # Changed from subject to title
                description=description,
                priority=priority,
                status='open',
                created_by=request.user,
            )
            
            messages.success(request, _("✅ Ticket #{ticket_pk} has been created!").format(ticket_pk=ticket.pk))
            return redirect('tickets:detail', pk=ticket.pk)
        else:
            messages.error(request, _("❌ All fields are required."))
    
    context = {
        'customers': customers,
    }
    
    return render(request, 'tickets/form.html', context)


@login_required
def ticket_reply(request, pk):
    """💬 Add reply to ticket"""
    ticket = get_object_or_404(Ticket, pk=pk)
    
    # Security check - verify user has access to this customer
    accessible_customers = request.user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to reply to this ticket."))
        return redirect('tickets:list')
    
    if request.method == 'POST':
        reply_text = request.POST.get('reply')
        if reply_text:
            # Create TicketComment
            comment = TicketComment.objects.create(
                ticket=ticket,
                content=reply_text,
                comment_type='support' if request.user.role in ['support', 'admin', 'manager'] else 'customer',
                author=request.user,
                author_name=request.user.get_full_name(),
                author_email=request.user.email,
                is_public=True
            )
            
            # Update ticket status if it was new
            if ticket.status == 'new':
                ticket.status = 'open'
                ticket.save()
            
            messages.success(request, _("✅ Your reply has been added!"))
        else:
            messages.error(request, _("❌ The reply cannot be empty."))
    
    return redirect('tickets:detail', pk=pk)


@login_required
def ticket_close(request, pk):
    """✅ Close ticket"""
    ticket = get_object_or_404(Ticket, pk=pk)
    
    # Security check - verify user has access to this customer
    accessible_customers = request.user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to close this ticket."))
        return redirect('tickets:list')
    
    ticket.status = 'closed'
    ticket.save()
    
    messages.success(request, _("✅ Ticket #{ticket_pk} has been closed!").format(ticket_pk=ticket.pk))
    return redirect('tickets:detail', pk=pk)


@login_required
def ticket_reopen(request, pk):
    """🔄 Reopen closed ticket"""
    ticket = get_object_or_404(Ticket, pk=pk)
    
    # Security check - verify user has access to this customer
    accessible_customers = request.user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to reopen this ticket."))
        return redirect('tickets:list')
    
    ticket.status = 'open'
    ticket.save()
    
    messages.success(request, _("✅ Ticket #{ticket_pk} has been reopened!").format(ticket_pk=ticket.pk))
    return redirect('tickets:detail', pk=pk)
