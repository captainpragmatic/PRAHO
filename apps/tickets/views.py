# ===============================================================================
# TICKETS VIEWS - SUPPORT SYSTEM
# ===============================================================================

from __future__ import annotations

import mimetypes
import os
from typing import cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.files.uploadedfile import UploadedFile
from django.core.paginator import Paginator
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.translation import gettext_lazy as _
from django_ratelimit.decorators import ratelimit

from apps.users.models import User

from .models import Ticket, TicketAttachment, TicketComment


@login_required
def ticket_list(request: HttpRequest) -> HttpResponse:
    """🎫 Display support tickets for user's customers"""
    user = cast(User, request.user)  # Safe after @login_required
    accessible_customers = user.get_accessible_customers()
    customer_ids = [customer.id for customer in accessible_customers]
    tickets = Ticket.objects.filter(customer_id__in=customer_ids).select_related("customer").order_by("-created_at")

    # Pagination
    paginator = Paginator(tickets, 25)
    page_number = request.GET.get("page")
    tickets_page = paginator.get_page(page_number)

    context = {
        "tickets": tickets_page,
        "open_count": tickets.filter(status__in=["open", "in_progress"]).count(),
        "total_count": tickets.count(),
    }

    return render(request, "tickets/list.html", context)


@login_required
def ticket_detail(request: HttpRequest, pk: int) -> HttpResponse:
    """🎫 Display ticket details and conversation"""
    user = cast(User, request.user)  # Safe after @login_required
    ticket = get_object_or_404(Ticket, pk=pk)

    # Security check - verify user has access to this customer
    accessible_customers = user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to access this ticket."))
        return redirect("tickets:list")

    # Filter comments based on user permissions
    if user.is_staff_user:
        # Staff can see all comments including internal notes
        comments = ticket.comments.all().order_by("created_at")
    else:
        # Customers can only see customer and support comments (never internal)
        comments = ticket.comments.filter(comment_type__in=["customer", "support"]).order_by("created_at")

    context = {
        "ticket": ticket,
        "comments": comments,
        "can_edit": ticket.status in ["open", "in_progress"],
    }

    return render(request, "tickets/detail.html", context)


@login_required
@ratelimit(key="user", rate="5/m", method="POST", block=False)
def ticket_create(request: HttpRequest) -> HttpResponse:
    """+ Create new support ticket"""
    user = cast(User, request.user)  # Safe after @login_required

    # Check rate limit
    if getattr(request, "limited", False):
        return HttpResponse("Rate limited", status=429)

    customers = user.get_accessible_customers()

    if request.method == "POST":
        # Simplified ticket creation
        customer_id = request.POST.get("customer_id")
        subject = request.POST.get("subject")
        description = request.POST.get("description")
        priority = request.POST.get("priority", "medium")

        if customer_id and subject and description:
            # Find customer in accessible customers
            accessible_customers = user.get_accessible_customers()
            customer = None
            for cust in accessible_customers:
                if str(cust.id) == str(customer_id):
                    customer = cust
                    break

            if not customer:
                messages.error(request, _("❌ You do not have permission to create tickets for this customer."))
                return redirect("tickets:create")

            ticket = Ticket.objects.create(
                customer=customer,
                title=subject,  # Changed from subject to title
                description=description,
                priority=priority,
                status="open",
                created_by=user,
            )

            messages.success(request, _("✅ Ticket #{ticket_pk} has been created!").format(ticket_pk=ticket.pk))
            return redirect("tickets:detail", pk=ticket.pk)
        else:
            messages.error(request, _("❌ All fields are required."))

    context = {
        "customers": customers,
    }

    return render(request, "tickets/form.html", context)


def _validate_ticket_reply_access(request: HttpRequest, user: User, ticket: Ticket) -> HttpResponse | None:
    """Validate user access to reply to ticket."""
    accessible_customers = user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to reply to this ticket."))
        return redirect("tickets:list")
    return None


def _validate_internal_note_permission(
    request: HttpRequest, user: User, is_internal: bool, ticket_pk: int
) -> HttpResponse | None:
    """Validate user permission to create internal notes."""
    if is_internal and not (user.is_staff or getattr(user, "staff_role", None)):
        messages.error(request, _("❌ You do not have permission to create internal notes."))
        return redirect("tickets:detail", pk=ticket_pk)
    return None


def _determine_comment_type(user: User, is_internal: bool) -> str:
    """Determine the appropriate comment type based on user permissions."""
    if is_internal and (user.is_staff or getattr(user, "staff_role", None)):
        return "internal"
    elif user.staff_role in ["support", "admin", "manager"]:
        return "support"
    else:
        return "customer"


def _is_file_size_valid(uploaded_file: UploadedFile) -> bool:
    """Check if uploaded file size is within limits."""
    if uploaded_file.size is None:
        return False
    return uploaded_file.size <= 10 * 1024 * 1024  # 10MB limit


def _is_file_type_allowed(content_type: str) -> bool:
    """Check if file type is in allowed list."""
    allowed_types = [
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "text/plain",
        "image/png",
        "image/jpeg",
        "image/jpg",
        "application/zip",
        "application/x-rar-compressed",
    ]
    return content_type in allowed_types


def _process_ticket_attachments(request: HttpRequest, ticket: Ticket, comment: TicketComment) -> None:
    """Process and validate uploaded attachments."""
    if not request.FILES:
        return

    user = cast(User, request.user)  # Safe as this is only called from authenticated views

    for uploaded_file in request.FILES.getlist("attachments"):
        # Skip files without proper attributes
        if not uploaded_file.name:
            messages.warning(request, "❌ File has no name.")
            continue

        # File size check
        if not _is_file_size_valid(uploaded_file):
            messages.warning(request, f"❌ File {uploaded_file.name} is too large (max 10MB).")
            continue

        # Content type detection
        content_type, _unused = mimetypes.guess_type(uploaded_file.name)
        if not content_type:
            content_type = "application/octet-stream"

        # File type validation
        if not _is_file_type_allowed(content_type):
            messages.warning(request, f"❌ File type not allowed for {uploaded_file.name}.")
            continue

        # Create attachment with proper null handling
        file_size = uploaded_file.size or 0  # Default to 0 if None
        TicketAttachment.objects.create(
            ticket=ticket,
            comment=comment,
            file=uploaded_file,
            filename=uploaded_file.name,
            file_size=file_size,
            content_type=content_type,
            uploaded_by=user,
        )


def _handle_ticket_reply_post(request: HttpRequest, ticket: Ticket) -> HttpResponse:
    """Handle POST request for ticket reply."""
    user = cast(User, request.user)  # Safe as this is only called from authenticated views
    reply_text = request.POST.get("reply")
    is_internal = request.POST.get("is_internal") == "on"

    # Validate internal note permission
    error_response = _validate_internal_note_permission(request, user, is_internal, ticket.pk)
    if error_response:
        return error_response

    if not reply_text:
        if request.headers.get("HX-Request"):
            return HttpResponse('<div class="text-red-500 text-sm">Reply cannot be empty.</div>')
        messages.error(request, _("❌ The reply cannot be empty."))
        return redirect("tickets:detail", pk=ticket.pk)

    # Create comment
    comment_type = _determine_comment_type(user, is_internal)
    is_public = not (is_internal and (user.is_staff or getattr(user, "staff_role", None)))

    comment = TicketComment.objects.create(
        ticket=ticket,
        content=reply_text,
        comment_type=comment_type,
        author=user,
        author_name=user.get_full_name(),
        author_email=user.email,
        is_public=is_public,
    )

    # Process attachments
    _process_ticket_attachments(request, ticket, comment)

    # Update ticket status if it was new
    if ticket.status == "new":
        ticket.status = "open"
        ticket.save()

    # Handle HTMX response
    if request.headers.get("HX-Request"):
        comments = ticket.comments.all().order_by("created_at")
        return render(
            request,
            "tickets/partials/comments_list.html",
            {
                "ticket": ticket,
                "comments": comments,
            },
        )

    messages.success(request, _("✅ Your reply has been added!"))
    return redirect("tickets:detail", pk=ticket.pk)


@login_required
def ticket_reply(request: HttpRequest, pk: int) -> HttpResponse:
    """💬 Add reply to ticket"""
    user = cast(User, request.user)  # Safe after @login_required
    ticket = get_object_or_404(Ticket, pk=pk)

    # Guard clause for access validation
    error_response = _validate_ticket_reply_access(request, user, ticket)
    if error_response:
        return error_response

    if request.method == "POST":
        return _handle_ticket_reply_post(request, ticket)

    return redirect("tickets:detail", pk=pk)


@login_required
def ticket_comments_htmx(request: HttpRequest, pk: int) -> HttpResponse:
    """🔄 HTMX endpoint for loading comments"""
    user = cast(User, request.user)  # Safe after @login_required
    ticket = get_object_or_404(Ticket, pk=pk)

    # Security check - verify user has access to this customer
    accessible_customers = user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        return HttpResponse('<div class="text-red-500">Access denied</div>')

    # Filter comments based on user permissions
    if user.is_staff_user:
        # Staff can see all comments including internal notes
        comments = ticket.comments.all().order_by("created_at")
    else:
        # Customers can only see customer and support comments (never internal)
        comments = ticket.comments.filter(comment_type__in=["customer", "support"]).order_by("created_at")

    return render(
        request,
        "tickets/partials/comments_list.html",
        {
            "ticket": ticket,
            "comments": comments,
        },
    )


@login_required
def ticket_close(request: HttpRequest, pk: int) -> HttpResponse:
    """✅ Close ticket"""
    user = cast(User, request.user)  # Safe after @login_required
    ticket = get_object_or_404(Ticket, pk=pk)

    # Security check - verify user has access to this customer
    accessible_customers = user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to close this ticket."))
        return redirect("tickets:list")

    ticket.status = "closed"
    ticket.save()

    messages.success(request, _("✅ Ticket #{ticket_pk} has been closed!").format(ticket_pk=ticket.pk))
    return redirect("tickets:detail", pk=pk)


@login_required
def ticket_reopen(request: HttpRequest, pk: int) -> HttpResponse:
    """🔄 Reopen closed ticket"""
    user = cast(User, request.user)  # Safe after @login_required
    ticket = get_object_or_404(Ticket, pk=pk)

    # Security check - verify user has access to this customer
    accessible_customers = user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to reopen this ticket."))
        return redirect("tickets:list")

    ticket.status = "open"
    ticket.save()

    messages.success(request, _("✅ Ticket #{ticket_pk} has been reopened!").format(ticket_pk=ticket.pk))
    return redirect("tickets:detail", pk=pk)


@login_required
@ratelimit(key="user", rate="30/m", method="GET", block=False)
def download_attachment(request: HttpRequest, attachment_id: int) -> HttpResponse:
    """📎 Download ticket attachment"""
    user = cast(User, request.user)  # Safe after @login_required

    # Check rate limit
    if getattr(request, "limited", False):
        return HttpResponse("Rate limited", status=429)

    try:
        attachment = TicketAttachment.objects.select_related("ticket__customer", "comment").get(id=attachment_id)
    except TicketAttachment.DoesNotExist:
        raise Http404("Attachment not found") from None

    # Security check - verify user has access to this customer's ticket
    accessible_customers = user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if attachment.ticket.customer.id not in accessible_customer_ids:
        raise PermissionDenied("You do not have permission to access this attachment.")

    # Check if attachment is safe
    if hasattr(attachment, "is_safe") and not attachment.is_safe:
        raise PermissionDenied("Access to this attachment is blocked for security reasons.")

    # Check internal attachment access (only staff can access internal attachments)
    if (
        attachment.comment
        and hasattr(attachment.comment, "comment_type")
        and attachment.comment.comment_type == "internal"
        and not user.is_staff
    ):
        raise PermissionDenied("Access denied to internal attachments.")

    # Check if file exists
    if not attachment.file or not attachment.file.name:
        raise Http404("File not found")

    # Get the file path as string to handle Path type properly
    file_path = str(attachment.file.path)
    if not os.path.exists(file_path):
        raise Http404("File not found")

    # Return file response
    try:
        with open(file_path, "rb") as f:
            response = HttpResponse(f.read(), content_type=attachment.content_type)
            response["Content-Disposition"] = f'attachment; filename="{attachment.filename}"'
            response["Content-Length"] = attachment.file_size
            return response
    except OSError:
        raise Http404("File could not be read") from None
