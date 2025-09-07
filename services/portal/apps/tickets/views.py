# ===============================================================================
# CUSTOMER SUPPORT TICKETS VIEWS - PORTAL SERVICE 🎫
# ===============================================================================

import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import JsonResponse, HttpRequest
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.utils.translation import gettext as _
from .services import ticket_api, PlatformAPIError

logger = logging.getLogger(__name__)


def ticket_list(request: HttpRequest):
    """
    Customer ticket list view - shows only customer's tickets.
    Supports filtering by status, priority, and search.
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    
    # Get filter parameters
    status_filter = request.GET.get('status', '')
    priority_filter = request.GET.get('priority', '')
    search_query = request.GET.get('search', '')
    page = request.GET.get('page', 1)
    
    try:
        # Get tickets from platform API
        response = ticket_api.get_customer_tickets(
            customer_id=customer_id,
            page=page,
            status=status_filter,
            priority=priority_filter,
            search=search_query
        )
        
        tickets = response.get('results', [])
        total_count = response.get('count', 0)
        
        # Get summary for header stats
        summary = ticket_api.get_tickets_summary(customer_id)
        open_count = summary.get('open_tickets', 0)
        
        context = {
            'tickets': tickets,
            'total_count': total_count,
            'open_count': open_count,
            'status_filter': status_filter,
            'priority_filter': priority_filter,
            'search_query': search_query,
            'page': page,
            # Pagination info from API
            'has_next': response.get('next') is not None,
            'has_previous': response.get('previous') is not None,
            'current_page': page,
        }
        
        logger.info(f"✅ [Tickets View] Loaded {len(tickets)} tickets for customer {customer_id}")
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Tickets View] Error loading tickets for customer {customer_id}: {e}")
        messages.error(request, _('Unable to load support tickets. Please try again later.'))
        context = {
            'tickets': [],
            'total_count': 0,
            'open_count': 0,
            'status_filter': status_filter,
            'priority_filter': priority_filter,
            'search_query': search_query,
            'error': True
        }
    
    return render(request, 'tickets/ticket_list.html', context)


def ticket_detail(request: HttpRequest, ticket_id: int):
    """
    Customer ticket detail view - shows ticket info and conversation.
    Only accessible by ticket owner (customer).
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    
    try:
        # Get ticket details
        ticket = ticket_api.get_ticket_detail(customer_id, ticket_id)
        
        # Get ticket replies/conversation
        replies = ticket_api.get_ticket_replies(customer_id, ticket_id)
        
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


def ticket_create(request: HttpRequest):
    """
    Create new support ticket view.
    Only authenticated customers can create tickets.
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
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
            ticket = ticket_api.create_ticket(
                customer_id=customer_id,
                title=title,
                description=description,
                priority=priority,
                category=category
            )
            
            messages.success(request, _('Support ticket created successfully. Ticket #{}.').format(
                ticket.get('ticket_number', ticket.get('id'))
            ))
            
            logger.info(f"✅ [Tickets View] Created ticket {ticket.get('id')} for customer {customer_id}")
            
            return redirect('tickets:detail', ticket_id=ticket['id'])
            
        except PlatformAPIError as e:
            logger.error(f"🔥 [Tickets View] Error creating ticket for customer {customer_id}: {e}")
            messages.error(request, _('Unable to create support ticket. Please try again later.'))
    
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
def ticket_reply(request: HttpRequest, ticket_id: int):
    """
    Add customer reply to existing ticket.
    HTMX endpoint for dynamic conversation updates.
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    
    reply_text = request.POST.get('reply', '').strip()
    
    if not reply_text:
        if request.headers.get('HX-Request'):
            return JsonResponse({'error': _('Reply text is required.')}, status=400)
        messages.error(request, _('Reply text is required.'))
        return redirect('tickets:detail', ticket_id=ticket_id)
    
    try:
        # Add reply via platform API
        reply = ticket_api.add_ticket_reply(
            customer_id=customer_id,
            ticket_id=ticket_id,
            message=reply_text
        )
        
        logger.info(f"✅ [Tickets View] Added reply to ticket {ticket_id} for customer {customer_id}")
        
        if request.headers.get('HX-Request'):
            # HTMX request - return updated replies partial
            replies = ticket_api.get_ticket_replies(customer_id, ticket_id)
            return render(request, 'tickets/partials/replies_list.html', {
                'replies': replies,
                'ticket_id': ticket_id
            })
        
        messages.success(request, _('Reply added successfully.'))
        return redirect('tickets:detail', ticket_id=ticket_id)
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Tickets View] Error adding reply to ticket {ticket_id} for customer {customer_id}: {e}")
        
        if request.headers.get('HX-Request'):
            return JsonResponse({'error': _('Unable to add reply. Please try again.')}, status=500)
        
        messages.error(request, _('Unable to add reply. Please try again later.'))
        return redirect('tickets:detail', ticket_id=ticket_id)


def ticket_search_api(request: HttpRequest):
    """
    HTMX search endpoint for live ticket filtering.
    Returns filtered ticket list partial.
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    
    search_query = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '')
    priority_filter = request.GET.get('priority', '')
    
    try:
        response = ticket_api.get_customer_tickets(
            customer_id=customer_id,
            page=1,
            status=status_filter,
            priority=priority_filter,
            search=search_query
        )
        
        tickets = response.get('results', [])
        
        return render(request, 'tickets/partials/tickets_table.html', {
            'tickets': tickets,
            'search_query': search_query,
        })
        
    except PlatformAPIError as e:
        logger.error(f"🔥 [Tickets View] Error searching tickets for customer {customer_id}: {e}")
        return render(request, 'tickets/partials/tickets_table.html', {
            'tickets': [],
            'error': _('Search failed. Please try again.')
        })


def tickets_dashboard_widget(request: HttpRequest):
    """
    Dashboard widget showing ticket summary for customer.
    Used in main dashboard view.
    """
    # Check authentication via Django session
    customer_id = request.session.get('customer_id')
    if not customer_id:
        return redirect('/login/')
    
    try:
        summary = ticket_api.get_tickets_summary(customer_id)
        
        # Get recent tickets (last 5)
        response = ticket_api.get_customer_tickets(customer_id, page=1)
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