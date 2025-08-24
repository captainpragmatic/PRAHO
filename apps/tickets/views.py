# ===============================================================================
# TICKETS VIEWS - SUPPORT SYSTEM
# ===============================================================================

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.utils.translation import gettext_lazy as _
from django.http import JsonResponse, HttpResponse

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
    
    # Filter comments based on user permissions
    if request.user.is_staff_user:
        # Staff can see all comments including internal notes
        comments = ticket.comments.all().order_by('created_at')
    else:
        # Customers can only see customer and support comments (never internal)
        comments = ticket.comments.filter(
            comment_type__in=['customer', 'support']
        ).order_by('created_at')
    
    context = {
        'ticket': ticket,
        'comments': comments,
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
        is_internal = request.POST.get('is_internal') == 'on'
        
        if reply_text:
            # Create TicketComment
            comment = TicketComment.objects.create(
                ticket=ticket,
                content=reply_text,
                comment_type='internal' if is_internal else ('support' if request.user.staff_role in ['support', 'admin', 'manager'] else 'customer'),
                author=request.user,
                author_name=request.user.get_full_name(),
                author_email=request.user.email,
                is_public=not is_internal
            )
            
            # Handle file attachments
            if request.FILES:
                from apps.tickets.models import TicketAttachment
                import mimetypes
                
                for uploaded_file in request.FILES.getlist('attachments'):
                    # Basic security checks
                    if uploaded_file.size > 10 * 1024 * 1024:  # 10MB limit
                        messages.warning(request, f"❌ File {uploaded_file.name} is too large (max 10MB).")
                        continue
                    
                    # Get content type
                    content_type, _unused = mimetypes.guess_type(uploaded_file.name)
                    if not content_type:
                        content_type = 'application/octet-stream'
                    
                    # Check allowed file types
                    allowed_types = [
                        'application/pdf',
                        'application/msword',
                        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        'text/plain',
                        'image/png',
                        'image/jpeg',
                        'image/jpg',
                        'application/zip',
                        'application/x-rar-compressed'
                    ]
                    
                    if content_type not in allowed_types:
                        messages.warning(request, f"❌ File type not allowed for {uploaded_file.name}.")
                        continue
                    
                    # Create attachment
                    TicketAttachment.objects.create(
                        ticket=ticket,
                        comment=comment,
                        file=uploaded_file,
                        filename=uploaded_file.name,
                        file_size=uploaded_file.size,
                        content_type=content_type,
                        uploaded_by=request.user
                    )
            
            # Update ticket status if it was new
            if ticket.status == 'new':
                ticket.status = 'open'
                ticket.save()
            
            # Check if this is an HTMX request
            if request.headers.get('HX-Request'):
                # Return the updated comments section
                comments = ticket.comments.all().order_by('created_at')
                return render(request, 'tickets/partials/comments_list.html', {
                    'ticket': ticket,
                    'comments': comments,
                })
            
            messages.success(request, _("✅ Your reply has been added!"))
        else:
            if request.headers.get('HX-Request'):
                return HttpResponse('<div class="text-red-500 text-sm">Reply cannot be empty.</div>')
            messages.error(request, _("❌ The reply cannot be empty."))
    
    return redirect('tickets:detail', pk=pk)


@login_required
def ticket_comments_htmx(request, pk):
    """🔄 HTMX endpoint for loading comments"""
    ticket = get_object_or_404(Ticket, pk=pk)
    
    # Security check - verify user has access to this customer
    accessible_customers = request.user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        return HttpResponse('<div class="text-red-500">Access denied</div>')
    
    # Filter comments based on user permissions
    if request.user.is_staff_user:
        # Staff can see all comments including internal notes
        comments = ticket.comments.all().order_by('created_at')
    else:
        # Customers can only see customer and support comments (never internal)
        comments = ticket.comments.filter(
            comment_type__in=['customer', 'support']
        ).order_by('created_at')
    
    return render(request, 'tickets/partials/comments_list.html', {
        'ticket': ticket,
        'comments': comments,
    })


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


@login_required
def download_attachment(request, attachment_id):
    """📎 Download ticket attachment"""
    from django.http import HttpResponse, Http404
    from django.core.exceptions import PermissionDenied
    from apps.tickets.models import TicketAttachment
    import os
    
    try:
        attachment = TicketAttachment.objects.select_related('ticket__customer').get(id=attachment_id)
    except TicketAttachment.DoesNotExist:
        raise Http404("Attachment not found")
    
    # Security check - verify user has access to this customer's ticket
    accessible_customers = request.user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if attachment.ticket.customer.id not in accessible_customer_ids:
        raise PermissionDenied("You do not have permission to access this attachment.")
    
    # Check if file exists
    if not attachment.file or not os.path.exists(attachment.file.path):
        raise Http404("File not found")
    
    # Return file response
    try:
        with open(attachment.file.path, 'rb') as f:
            response = HttpResponse(f.read(), content_type=attachment.content_type)
            response['Content-Disposition'] = f'attachment; filename="{attachment.filename}"'
            response['Content-Length'] = attachment.file_size
            return response
    except IOError:
        raise Http404("File could not be read")
