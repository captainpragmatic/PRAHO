# ===============================================================================
# TICKETS VIEWS - SUPPORT SYSTEM
# ===============================================================================

from __future__ import annotations

import mimetypes
import os

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.files.uploadedfile import UploadedFile
from django.core.paginator import Paginator
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _

from apps.users.models import User

from .models import Ticket, TicketAttachment, TicketComment


@login_required
def ticket_list(request: HttpRequest) -> HttpResponse:
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
def ticket_detail(request: HttpRequest, pk: int) -> HttpResponse:
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
def ticket_create(request: HttpRequest) -> HttpResponse:
    """+ Create new support ticket"""
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


def _validate_ticket_reply_access(user: User, ticket: Ticket) -> HttpResponse | None:
    """Validate user access to reply to ticket."""
    accessible_customers = user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(user.request, _("❌ You do not have permission to reply to this ticket."))
        return redirect('tickets:list')
    return None


def _validate_internal_note_permission(user: User, is_internal: bool, ticket_pk: int) -> HttpResponse | None:
    """Validate user permission to create internal notes."""
    if is_internal and not (user.is_staff or getattr(user, 'staff_role', None)):
        messages.error(user.request, _("❌ You do not have permission to create internal notes."))
        return redirect('tickets:detail', pk=ticket_pk)
    return None


def _determine_comment_type(user: User, is_internal: bool) -> str:
    """Determine the appropriate comment type based on user permissions."""
    if is_internal and (user.is_staff or getattr(user, 'staff_role', None)):
        return 'internal'
    elif user.staff_role in ['support', 'admin', 'manager']:
        return 'support'
    else:
        return 'customer'


def _is_file_size_valid(uploaded_file: UploadedFile) -> bool:
    """Check if uploaded file size is within limits."""
    return uploaded_file.size <= 10 * 1024 * 1024  # 10MB limit


def _is_file_type_allowed(content_type: str) -> bool:
    """Check if file type is in allowed list."""
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
    return content_type in allowed_types


def _process_ticket_attachments(request: HttpRequest, ticket: Ticket, comment: TicketComment) -> None:
    """Process and validate uploaded attachments."""
    if not request.FILES:
        return
        
    for uploaded_file in request.FILES.getlist('attachments'):
        # File size check
        if not _is_file_size_valid(uploaded_file):
            messages.warning(request, f"❌ File {uploaded_file.name} is too large (max 10MB).")
            continue

        # Content type detection
        content_type, _unused = mimetypes.guess_type(uploaded_file.name)
        if not content_type:
            content_type = 'application/octet-stream'

        # File type validation
        if not _is_file_type_allowed(content_type):
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


def _handle_ticket_reply_post(request: HttpRequest, ticket: Ticket) -> HttpResponse:
    """Handle POST request for ticket reply."""
    reply_text = request.POST.get('reply')
    is_internal = request.POST.get('is_internal') == 'on'

    # Validate internal note permission
    error_response = _validate_internal_note_permission(request.user, is_internal, ticket.pk)
    if error_response:
        return error_response

    if not reply_text:
        if request.headers.get('HX-Request'):
            return HttpResponse('<div class="text-red-500 text-sm">Reply cannot be empty.</div>')
        messages.error(request, _("❌ The reply cannot be empty."))
        return redirect('tickets:detail', pk=ticket.pk)

    # Create comment
    comment_type = _determine_comment_type(request.user, is_internal)
    is_public = not (is_internal and (request.user.is_staff or getattr(request.user, 'staff_role', None)))
    
    comment = TicketComment.objects.create(
        ticket=ticket,
        content=reply_text,
        comment_type=comment_type,
        author=request.user,
        author_name=request.user.get_full_name(),
        author_email=request.user.email,
        is_public=is_public
    )

    # Process attachments
    _process_ticket_attachments(request, ticket, comment)

    # Update ticket status if it was new
    if ticket.status == 'new':
        ticket.status = 'open'
        ticket.save()

    # Handle HTMX response
    if request.headers.get('HX-Request'):
        comments = ticket.comments.all().order_by('created_at')
        return render(request, 'tickets/partials/comments_list.html', {
            'ticket': ticket,
            'comments': comments,
        })

    messages.success(request, _("✅ Your reply has been added!"))
    return redirect('tickets:detail', pk=ticket.pk)


@login_required
def ticket_reply(request: HttpRequest, pk: int) -> HttpResponse:
    """💬 Add reply to ticket"""
    ticket = get_object_or_404(Ticket, pk=pk)

    # Guard clause for access validation
    request.user.request = request
    error_response = _validate_ticket_reply_access(request.user, ticket)
    if error_response:
        return error_response

    if request.method == 'POST':
        return _handle_ticket_reply_post(request, ticket)

    return redirect('tickets:detail', pk=pk)


@login_required
def ticket_comments_htmx(request: HttpRequest, pk: int) -> HttpResponse:
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
def ticket_close(request: HttpRequest, pk: int) -> HttpResponse:
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
def ticket_reopen(request: HttpRequest, pk: int) -> HttpResponse:
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
def download_attachment(request: HttpRequest, attachment_id: int) -> HttpResponse:
    """📎 Download ticket attachment"""
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
    except OSError:
        raise Http404("File could not be read")
