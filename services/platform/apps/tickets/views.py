# ===============================================================================
# TICKETS VIEWS - SUPPORT SYSTEM
# ===============================================================================

from __future__ import annotations

import logging
import mimetypes
import os
from dataclasses import dataclass
from typing import cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.files.uploadedfile import UploadedFile
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django_ratelimit.decorators import ratelimit

from apps.settings.services import SettingsService
from apps.users.models import User

from .models import Ticket, TicketAttachment, TicketComment
from .services import TicketStatusService

logger = logging.getLogger(__name__)

# Module-level default for file size limit (must match tickets.security)
_DEFAULT_MAX_FILE_SIZE_BYTES = 2097152  # 2MB


@dataclass
class TicketReplyData:
    """Data container for ticket reply validation"""

    reply_text: str
    reply_action: str
    resolution_code: str | None
    is_internal: bool


@login_required
def ticket_list(request: HttpRequest) -> HttpResponse:
    """🎫 Display support tickets for user's customers with filtering"""
    user = cast(User, request.user)  # Safe after @login_required
    accessible_customers = user.get_accessible_customers()
    customer_ids = [customer.id for customer in accessible_customers]

    # Base queryset
    tickets = Ticket.objects.filter(customer_id__in=customer_ids).select_related("customer").order_by("-created_at")

    # Get filter parameters
    search_query = request.GET.get("search", "").strip()
    status_filter = request.GET.get("status", "").strip()

    # Apply search filter
    if search_query:
        tickets = tickets.filter(
            Q(ticket_number__icontains=search_query)
            | Q(title__icontains=search_query)
            | Q(description__icontains=search_query)
            | Q(customer__name__icontains=search_query)
            | Q(contact_email__icontains=search_query)
        )

    # Apply status filter
    if status_filter:
        tickets = tickets.filter(status=status_filter)

    # Pagination
    paginator = Paginator(tickets, 25)
    page_number = request.GET.get("page")
    tickets_page = paginator.get_page(page_number)

    # Build URL parameters for pagination
    url_params = []
    if search_query:
        url_params.append(f"search={search_query}")
    if status_filter:
        url_params.append(f"status={status_filter}")
    url_params_str = "&".join(url_params)

    context = {
        "tickets": tickets_page,
        "open_count": tickets.filter(status__in=["open", "in_progress"]).count(),
        "waiting_count": tickets.filter(status="waiting_on_customer").count(),
        "total_count": tickets.count(),
        "search_query": search_query,
        "status_filter": status_filter,
        "url_params": url_params_str,
    }

    return render(request, "tickets/list.html", context)


@login_required
def ticket_search_htmx(request: HttpRequest) -> HttpResponse:
    """🔄 HTMX endpoint for live ticket filtering"""
    user = cast(User, request.user)  # Safe after @login_required
    accessible_customers = user.get_accessible_customers()
    customer_ids = [customer.id for customer in accessible_customers]

    # Base queryset
    tickets = Ticket.objects.filter(customer_id__in=customer_ids).select_related("customer").order_by("-created_at")

    # Get filter parameters
    search_query = request.GET.get("q", "").strip()
    status_filter = request.GET.get("status", "").strip()

    # Apply search filter
    if search_query:
        tickets = tickets.filter(
            Q(ticket_number__icontains=search_query)
            | Q(title__icontains=search_query)
            | Q(description__icontains=search_query)
            | Q(customer__name__icontains=search_query)
            | Q(contact_email__icontains=search_query)
        )

    # Apply status filter
    if status_filter:
        tickets = tickets.filter(status=status_filter)

    # Pagination for HTMX (first 25 results only for real-time filtering)
    tickets = tickets[:25]

    context = {
        "tickets": tickets,
        "search_query": search_query,
        "status_filter": status_filter,
    }

    return render(request, "tickets/partials/tickets_table.html", context)


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
        "can_edit": ticket.status != "closed",
        "is_waiting_on_customer": ticket.status == "waiting_on_customer",
        "customer_replied_recently": ticket.customer_replied_recently,
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

            # Use TicketStatusService for proper ticket creation
            ticket = TicketStatusService.create_ticket(
                customer=customer,
                title=subject,
                description=description,
                priority=priority,
                contact_email=user.email,
                contact_person=user.get_full_name(),
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
    max_file_size = SettingsService.get_integer_setting("tickets.max_file_size_bytes", _DEFAULT_MAX_FILE_SIZE_BYTES)
    return bool(uploaded_file.size <= max_file_size)


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
            max_size_mb = SettingsService.get_integer_setting(
                "tickets.max_file_size_bytes", _DEFAULT_MAX_FILE_SIZE_BYTES
            ) // (1024 * 1024)
            messages.warning(request, f"❌ File {uploaded_file.name} is too large (max {max_size_mb}MB).")
            continue

        # Content type detection
        content_type, _unused = mimetypes.guess_type(uploaded_file.name)
        if not content_type:
            content_type = "application/octet-stream"

        # File type validation
        if not _is_file_type_allowed(content_type):
            messages.warning(request, f"❌ File type not allowed for {uploaded_file.name}.")
            continue

        # TODO: Implement proper file security measures:
        #   1. Encrypt files at rest using AES-256 encryption
        #   2. Add virus scanning with ClamAV integration
        #   3. Store files outside web-accessible directory
        #   4. Implement secure file serving with access controls
        #   5. Add file content validation beyond MIME type checking

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


def _validate_ticket_reply_data(
    request: HttpRequest, user: User, ticket: Ticket, reply_data: TicketReplyData
) -> HttpResponse | None:
    """Validate reply data and return error response if invalid"""
    # Validate internal note permission
    error_response = _validate_internal_note_permission(request, user, reply_data.is_internal, ticket.pk)
    if error_response:
        return error_response

    if not reply_data.reply_text:
        if request.headers.get("HX-Request"):
            return HttpResponse('<div class="text-red-500 text-sm">Reply cannot be empty.</div>')
        messages.error(request, _("❌ The reply cannot be empty."))
        return redirect("tickets:detail", pk=ticket.pk)

    # Validate resolution code if closing
    if reply_data.reply_action == "close_with_resolution" and not reply_data.resolution_code:
        if request.headers.get("HX-Request"):
            return HttpResponse('<div class="text-red-500 text-sm">Resolution code required when closing ticket.</div>')
        messages.error(request, _("❌ Resolution code is required when closing the ticket."))
        return redirect("tickets:detail", pk=ticket.pk)

    return None


def _handle_ticket_status_update(
    request: HttpRequest, ticket: Ticket, user: User, reply_action: str, resolution_code: str | None
) -> tuple[str, HttpResponse | None]:
    """Handle ticket status updates and return success message and optional error response"""
    try:
        if user.is_staff_user:
            # Staff replies with actions
            if ticket.assigned_to is None:
                # First agent reply
                TicketStatusService.handle_first_agent_reply(
                    ticket=ticket, agent=user, reply_action=reply_action, resolution_code=resolution_code
                )
            else:
                # Subsequent agent reply
                TicketStatusService.handle_agent_reply(
                    ticket=ticket, agent=user, reply_action=reply_action, resolution_code=resolution_code
                )
        else:
            # Customer reply
            TicketStatusService.handle_customer_reply(ticket)

        success_messages = {
            "reply": _("✅ Your reply has been added!"),
            "reply_and_wait": _("✅ Reply added - ticket is now waiting for customer response."),
            "internal_note": _("✅ Internal note has been added."),
            "close_with_resolution": _("✅ Ticket has been closed with resolution: {resolution}").format(
                resolution=resolution_code
            ),
        }

        success_msg = success_messages.get(reply_action, _("✅ Your reply has been added!"))
        return str(success_msg), None

    except ValueError as e:
        # Handle validation errors from TicketStatusService
        if request.headers.get("HX-Request"):
            return "", HttpResponse(
                format_html('<div class="text-red-500 text-sm">Error: {}</div>', str(e))
            )  # nosemgrep: direct-use-of-httpresponse — content is developer-controlled string/integer
        messages.error(request, _("❌ Error: {error}").format(error=str(e)))
        return "", redirect("tickets:detail", pk=ticket.pk)


def _handle_ticket_reply_post(request: HttpRequest, ticket: Ticket) -> HttpResponse:
    """Handle POST request for ticket reply with new status system."""
    user = cast(User, request.user)  # Safe as this is only called from authenticated views
    reply_text = request.POST.get("reply")
    reply_action = request.POST.get("reply_action", "reply")  # New field for agent action
    is_internal = reply_action == "internal_note"  # Internal notes are determined by reply action
    resolution_code = request.POST.get("resolution_code")  # For closing tickets

    # Create reply data container
    reply_data = TicketReplyData(
        reply_text=reply_text or "", reply_action=reply_action, resolution_code=resolution_code, is_internal=is_internal
    )

    # Validate reply data
    validation_error = _validate_ticket_reply_data(request, user, ticket, reply_data)
    if validation_error:
        return validation_error

    # Create comment with reply action
    comment_type = _determine_comment_type(user, reply_data.is_internal)
    is_public = not (reply_data.is_internal and (user.is_staff or getattr(user, "staff_role", None)))

    logger.debug(
        f"🔍 [Tickets] Reply processing: action={reply_data.reply_action}, is_internal={reply_data.is_internal}, comment_type={comment_type}, is_public={is_public}"
    )

    comment = TicketComment.objects.create(
        ticket=ticket,
        content=reply_data.reply_text,
        comment_type=comment_type,
        author=user,
        author_name=user.get_full_name(),
        author_email=user.email,
        is_public=is_public,
        reply_action=reply_data.reply_action if user.is_staff_user else "",  # Only staff get reply actions
        sets_waiting_on_customer=(reply_data.reply_action == "reply_and_wait"),
    )

    # Process attachments
    _process_ticket_attachments(request, ticket, comment)

    # Handle status transitions
    success_msg, status_error = _handle_ticket_status_update(request, ticket, user, reply_action, resolution_code)
    if status_error:
        return status_error

    # Handle HTMX response
    if request.headers.get("HX-Request"):
        # Refresh ticket data and comments
        ticket.refresh_from_db()
        comments = ticket.comments.all().order_by("created_at")
        can_edit = ticket.status != "closed" or user.is_staff
        return render(
            request,
            "tickets/partials/status_and_comments.html",
            {
                "ticket": ticket,
                "comments": comments,
                "can_edit": can_edit,
            },
        )

    messages.success(request, success_msg)
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
    """✅ Close ticket with resolution code"""
    user = cast(User, request.user)  # Safe after @login_required
    ticket = get_object_or_404(Ticket, pk=pk)

    # Security check - verify user has access to this customer
    accessible_customers = user.get_accessible_customers()
    accessible_customer_ids = [customer.id for customer in accessible_customers]
    if ticket.customer.id not in accessible_customer_ids:
        messages.error(request, _("❌ You do not have permission to close this ticket."))
        return redirect("tickets:list")

    if request.method == "POST":
        resolution_code = request.POST.get("resolution_code")
        if not resolution_code:
            messages.error(request, _("❌ Resolution code is required to close the ticket."))
            return redirect("tickets:detail", pk=pk)

        try:
            # Use TicketStatusService for proper closing
            TicketStatusService.close_ticket(ticket, resolution_code)
            messages.success(
                request,
                _("✅ Ticket #{ticket_pk} has been closed with resolution: {resolution}").format(
                    ticket_pk=ticket.pk, resolution=resolution_code
                ),
            )
            return redirect("tickets:detail", pk=pk)
        except ValueError as e:
            messages.error(request, _("❌ Error closing ticket: {error}").format(error=str(e)))
            return redirect("tickets:detail", pk=pk)

    # For GET request, show the close form (handled by template)
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

    try:
        # Use TicketStatusService for proper reopening
        TicketStatusService.reopen_ticket(ticket)
        messages.success(request, _("✅ Ticket #{ticket_pk} has been reopened!").format(ticket_pk=ticket.pk))
        return redirect("tickets:detail", pk=pk)
    except ValueError as e:
        messages.error(request, _("❌ Error reopening ticket: {error}").format(error=str(e)))
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
