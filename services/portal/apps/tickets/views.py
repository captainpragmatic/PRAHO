# ===============================================================================
# CUSTOMER SUPPORT TICKETS VIEWS - PORTAL SERVICE 🎫
# ===============================================================================

import base64
import logging

from django.contrib import messages
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from .services import PlatformAPIError, TicketFilters, ticket_api

logger = logging.getLogger(__name__)


def _handle_ticket_error_response(request: HttpRequest, ticket_id: int, error_msg: str, status: int = 400) -> HttpResponse:
    """Helper to handle error responses for HTMX or regular requests"""
    if request.headers.get('HX-Request'):
        return JsonResponse({'error': error_msg}, status=status)
    messages.error(request, error_msg)
    return redirect('tickets:detail', ticket_id=ticket_id)


def _handle_ticket_success_response(request: HttpRequest, ticket_id: int, success_msg: str, context: dict | None = None, template: str = '') -> HttpResponse:
    """Helper to handle success responses for HTMX or regular requests"""
    if request.headers.get('HX-Request') and context and template:
        return render(request, template, context)
    messages.success(request, success_msg)
    return redirect('tickets:detail', ticket_id=ticket_id)


def ticket_list(request: HttpRequest) -> HttpResponse:
    """
    Customer ticket list view - shows only customer's tickets.
    Supports filtering by status, priority, and search.
    """
    # Check authentication via Django session
    customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    # Get filter parameters
    status_filter = request.GET.get('status', '')
    priority_filter = request.GET.get('priority', '')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    try:
        # Create filters object
        filters = TicketFilters(
            page=page,
            status=status_filter,
            priority=priority_filter,
            search=search_query
        )
        
        # Get tickets from platform API
        response = ticket_api.get_customer_tickets(
            customer_id=customer_id,
            user_id=user_id,
            filters=filters
        )
        
        tickets = response.get('results', [])
        total_count = response.get('count', 0)
        
        # Get summary for header stats
        summary = ticket_api.get_tickets_summary(customer_id, user_id)
        open_count = summary.get('open_tickets', 0)
        
        # Calculate pagination variables
        current_page = int(page) if page else 1
        total_pages = (total_count + 24) // 25 if total_count > 0 else 1  # 25 items per page
        
        # Calculate correct has_next and has_previous based on actual logic, not API response
        has_previous = current_page > 1
        has_next = current_page < total_pages
        
        logger.info(f"🐛 [Pagination Debug] page={page}, current_page={current_page}, total_count={total_count}, total_pages={total_pages}")
        logger.info(f"🐛 [Pagination Debug] has_next={has_next}, has_previous={has_previous}")
        logger.info(f"🐛 [Pagination Debug] API response next={response.get('next')}, previous={response.get('previous')}")
        
        # Create paginator data structure for platform component
        paginator_data = type('PaginatorData', (), {
            'has_previous': has_previous,
            'has_next': has_next,
            'previous_page_number': current_page - 1 if current_page > 1 else 1,
            'next_page_number': current_page + 1,
            'number': current_page,
            'has_other_pages': total_pages > 1,
            'start_index': (current_page - 1) * 25 + 1 if total_count > 0 else 0,
            'end_index': min(current_page * 25, total_count),
            'paginator': type('Paginator', (), {
                'count': total_count,
                'num_pages': total_pages,
                'page_range': range(1, total_pages + 1)
            })()
        })()
        
        # Build extra parameters for pagination URLs
        params = []
        if search_query:
            params.append(f'&search={search_query}')
        if status_filter:
            params.append(f'&status={status_filter}')
        if priority_filter:
            params.append(f'&priority={priority_filter}')
        pagination_params = ''.join(params)

        context = {
            'tickets': tickets,
            'total_count': total_count,
            'open_count': open_count,
            'status_filter': status_filter,
            'priority_filter': priority_filter,
            'search_query': search_query,
            'page': page,
            # Pagination info from API
            'has_next': has_next,
            'has_previous': has_previous,
            'current_page': current_page,
            'total_pages': total_pages,
            'previous_page_number': current_page - 1 if current_page > 1 else 1,
            'next_page_number': current_page + 1,
            # Platform pagination component data
            'paginator_data': paginator_data,
            'pagination_params': pagination_params,
        }
        
        logger.info(f"✅ [Tickets View] Loaded {len(tickets)} tickets for customer {customer_id}")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Tickets View] Error loading tickets for customer {customer_id}: {e}")
        messages.error(request, _('Unable to load support tickets. Please try again later.'))
        # Create empty paginator data for error state
        paginator_data = type('PaginatorData', (), {
            'has_previous': False,
            'has_next': False,
            'previous_page_number': 1,
            'next_page_number': 1,
            'number': 1,
            'has_other_pages': False,
            'start_index': 0,
            'end_index': 0,
            'paginator': type('Paginator', (), {
                'count': 0,
                'num_pages': 1,
                'page_range': range(1, 2)
            })()
        })()

        context = {
            'tickets': [],
            'total_count': 0,
            'open_count': 0,
            'status_filter': status_filter,
            'priority_filter': priority_filter,
            'search_query': search_query,
            'has_next': False,
            'has_previous': False,
            'current_page': 1,
            'total_pages': 1,
            'previous_page_number': 1,
            'next_page_number': 1,
            'error': True,
            # Platform pagination component data
            'paginator_data': paginator_data,
            'pagination_params': '',
        }
    
    return render(request, 'tickets/ticket_list.html', context)


def ticket_detail(request: HttpRequest, ticket_id: int) -> HttpResponse:
    """
    Customer ticket detail view - shows ticket info and conversation.
    Only accessible by ticket owner (customer).
    """
    # Check authentication via Django session
    customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    try:
        # Get ticket details (includes comments/replies)
        ticket_response = ticket_api.get_ticket_detail(customer_id, user_id, ticket_id)
        
        # Extract ticket data and replies from platform response
        if ticket_response.get('success') and 'data' in ticket_response:
            ticket = ticket_response['data'].get('ticket', {})
            replies = ticket.get('comments', [])  # Replies are in comments field
        else:
            ticket = ticket_response
            replies = ticket.get('comments', [])  # Fallback if response format is different
        
        context = {
            'ticket': ticket,
            'replies': replies,
            'can_reply': ticket.get('status') not in ['closed', 'resolved'],  # Customer can reply unless closed
        }
        
        logger.info(f"✅ [Tickets View] Loaded ticket {ticket_id} details for customer {customer_id}")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Tickets View] Error loading ticket {ticket_id} for customer {customer_id}: {e}")
        messages.error(request, _('Ticket not found or access denied.'))
        return redirect('tickets:list')
    
    return render(request, 'tickets/ticket_detail.html', context)


@csrf_protect
def ticket_create(request: HttpRequest) -> HttpResponse:
    """
    Create new support ticket view.
    Only authenticated customers can create tickets.
    """
    # Check authentication via Django session
    customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        description = request.POST.get('description', '').strip()
        priority = request.POST.get('priority', 'normal')
        category = request.POST.get('category', '')
        
        # Validation
        if not title or not description:
            messages.error(request, _('Title and description are required.'))
            return render(request, 'tickets/ticket_create.html', {
                'title': title,
                'description': description,
                'priority': priority,
                'category': category,
            })
        
        try:
            # Create ticket via platform API
            # contact_email and contact_person are automatically populated from authenticated customer
            ticket_data = {
                'customer_id': customer_id,
                'title': title,
                'description': description,
                'priority': priority,
                'category': category
            }
            ticket = ticket_api.create_ticket(ticket_data, user_id)
            
            # Extract ticket identifier for redirect and messages
            ticket_id = ticket.get('id') or ticket.get('pk') 
            ticket_number = ticket.get('ticket_number') or ticket_id
            
            messages.success(request, _('Support ticket created successfully. Ticket #{}.').format(
                ticket_number
            ))
            
            logger.info(f"✅ [Tickets View] Created ticket {ticket_id} for customer {customer_id}")
            
            # Handle missing ticket ID gracefully
            if ticket_id:
                return redirect('tickets:detail', ticket_id=ticket_id)
            else:
                logger.error(f"🔥 [Tickets View] No ticket ID returned from platform API: {ticket}")
                messages.error(request, _('Ticket created but unable to redirect to details. Please check your tickets list.'))
                return redirect('tickets:list')
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets View] Error creating ticket for customer {customer_id}: {e}")
            messages.error(request, _('Unable to create support ticket. Please try again later.'))
            # Preserve form data on API error
            return render(request, 'tickets/ticket_create.html', {
                'title': title,
                'description': description,
                'priority': priority,
                'category': category,
                'priorities': [
                    ('low', _('Low')),
                    ('normal', _('Normal')),
                    ('high', _('High')),
                    ('urgent', _('Urgent')),
                    ('critical', _('Critical')),
                ],
                'categories': [
                    ('', _('General Support')),
                    ('technical', _('Technical Issue')),
                    ('billing', _('Billing Question')),
                    ('hosting', _('Hosting Services')),
                    ('domain', _('Domain Management')),
                    ('email', _('Email Services')),
                ]
            })
    
    # GET request - show create form
    context = {
        'priorities': [
            ('low', _('Low')),
            ('normal', _('Normal')),
            ('high', _('High')),
            ('urgent', _('Urgent')),
            ('critical', _('Critical')),
        ],
        'categories': [
            ('', _('General Support')),
            ('technical', _('Technical Issue')),
            ('billing', _('Billing Question')),
            ('hosting', _('Hosting Services')),
            ('domain', _('Domain Management')),
            ('email', _('Email Services')),
        ]
    }
    
    return render(request, 'tickets/ticket_create.html', context)


@require_http_methods(["POST"])
def ticket_reply(request: HttpRequest, ticket_id: int) -> HttpResponse:
    """
    Add customer reply to existing ticket.
    HTMX endpoint for dynamic conversation updates.
    """
    # Check authentication via Django session
    customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    reply_text = request.POST.get('message', '').strip()
    
    if not reply_text:
        return _handle_ticket_error_response(request, ticket_id, _('Reply text is required.'))
    
    # Handle file attachments
    attachments = []
    uploaded_files = request.FILES.getlist('attachments')
    if uploaded_files:
        # Process uploaded files for API transmission
        for uploaded_file in uploaded_files:
            # Convert file to base64 for API transmission
            file_content = uploaded_file.read()
            file_data = {
                'filename': uploaded_file.name,
                'content': base64.b64encode(file_content).decode('utf-8'),
                'content_type': uploaded_file.content_type or 'application/octet-stream',
                'size': len(file_content)
            }
            attachments.append(file_data)
    
    try:
        # Add reply via platform API
        ticket_api.add_ticket_reply(
            customer_id=customer_id,
            user_id=user_id,
            ticket_id=ticket_id,
            message=reply_text,
            attachments=attachments if attachments else None
        )
        
        logger.info(f"✅ [Tickets View] Added reply to ticket {ticket_id} for customer {customer_id}")
        
        # Get updated ticket details for HTMX response
        if request.headers.get('HX-Request'):
            ticket_response = ticket_api.get_ticket_detail(customer_id, user_id, ticket_id)
            
            # Extract ticket and replies from the response
            if ticket_response.get('success') and 'data' in ticket_response:
                ticket = ticket_response['data'].get('ticket', {})
            else:
                ticket = ticket_response
            replies = ticket.get('comments', [])
                
            context = {'ticket': ticket, 'replies': replies}
            template = 'tickets/partials/status_and_comments.html'
            return _handle_ticket_success_response(request, ticket_id, _('Reply added successfully.'), context, template)
        
        return _handle_ticket_success_response(request, ticket_id, _('Reply added successfully.'))
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Tickets View] Error adding reply to ticket {ticket_id} for customer {customer_id}: {e}")
        return _handle_ticket_error_response(request, ticket_id, _('Unable to add reply. Please try again later.'), status=500)


def ticket_search_api(request: HttpRequest) -> JsonResponse:
    """
    HTMX search endpoint for live ticket filtering.
    Returns filtered ticket list partial.
    """
    # Check authentication via Django session
    customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    search_query = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '')
    priority_filter = request.GET.get('priority', '')
    
    try:
        response = ticket_api.get_customer_tickets(
            customer_id=customer_id,
            user_id=user_id,
            page=1,
            status=status_filter,
            priority=priority_filter,
            search=search_query
        )
        
        tickets = response.get('results', [])
        total_count = response.get('count', 0)
        
        # Calculate pagination variables for search results
        current_page = 1  # Search always returns page 1
        total_pages = (total_count + 24) // 25 if total_count > 0 else 1  # 25 items per page
        
        # Calculate correct has_next and has_previous based on actual logic
        has_previous = current_page > 1
        has_next = current_page < total_pages
        
        # Create paginator data structure for platform component
        paginator_data = type('PaginatorData', (), {
            'has_previous': has_previous,
            'has_next': has_next,
            'previous_page_number': current_page - 1 if current_page > 1 else 1,
            'next_page_number': current_page + 1,
            'number': current_page,
            'has_other_pages': total_pages > 1,
            'start_index': (current_page - 1) * 25 + 1 if total_count > 0 else 0,
            'end_index': min(current_page * 25, total_count),
            'paginator': type('Paginator', (), {
                'count': total_count,
                'num_pages': total_pages,
                'page_range': range(1, total_pages + 1)
            })()
        })()
        
        # Build extra parameters for pagination URLs
        params = []
        if search_query:
            params.append(f'&search={search_query}')
        if status_filter:
            params.append(f'&status={status_filter}')
        if priority_filter:
            params.append(f'&priority={priority_filter}')
        pagination_params = ''.join(params)
        
        return render(request, 'tickets/partials/tickets_table.html', {
            'tickets': tickets,
            'search_query': search_query,
            'status_filter': status_filter,
            'priority_filter': priority_filter,
            'total_count': total_count,
            'current_page': current_page,
            'total_pages': total_pages,
            'has_next': has_next,
            'has_previous': has_previous,
            'paginator_data': paginator_data,
            'pagination_params': pagination_params,
        })
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Tickets View] Error searching tickets for customer {customer_id}: {e}")
        # Create empty paginator data for error state
        paginator_data = type('PaginatorData', (), {
            'has_previous': False,
            'has_next': False,
            'previous_page_number': 1,
            'next_page_number': 1,
            'number': 1,
            'has_other_pages': False,
            'start_index': 0,
            'end_index': 0,
            'paginator': type('Paginator', (), {
                'count': 0,
                'num_pages': 1,
                'page_range': range(1, 2)
            })()
        })()
        
        return render(request, 'tickets/partials/tickets_table.html', {
            'tickets': [],
            'error': _('Search failed. Please try again.'),
            'total_count': 0,
            'current_page': 1,
            'total_pages': 1,
            'has_next': False,
            'has_previous': False,
            'paginator_data': paginator_data,
            'pagination_params': '',
        })


def tickets_dashboard_widget(request: HttpRequest) -> HttpResponse:
    """
    Dashboard widget showing ticket summary for customer.
    Used in main dashboard view.
    """
    # Check authentication via Django session
    customer_id = getattr(request, 'customer_id', None) or request.session.get('customer_id')
    user_id = request.session.get('user_id')
    if not customer_id or not user_id:
        return redirect('/login/')
    
    try:
        summary = ticket_api.get_tickets_summary(customer_id, user_id)
        
        # Get recent tickets (last 5)
        response = ticket_api.get_customer_tickets(customer_id, user_id, page=1)
        recent_tickets = response.get('results', [])[:5]
        
        context = {
            'summary': summary,
            'recent_tickets': recent_tickets,
        }
        
        return render(request, 'tickets/partials/dashboard_widget.html', context)
        
    except PlatformAPIError:
        # Return empty widget on error
        return render(request, 'tickets/partials/dashboard_widget.html', {
            'summary': {'total_tickets': 0, 'open_tickets': 0},
            'recent_tickets': [],
            'error': True
        })
