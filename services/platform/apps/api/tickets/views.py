# ===============================================================================
# TICKETS API VIEWS - CUSTOMER SUPPORT OPERATIONS 🎫
# ===============================================================================

import logging

from django.db.models import Prefetch, Q
from django.http import Http404, HttpRequest, HttpResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.tickets.models import SupportCategory, Ticket, TicketAttachment, TicketComment
from apps.tickets.services import TicketStatusService

from ..secure_auth import require_customer_authentication
from .serializers import (
    CommentCreateSerializer,
    SupportCategorySerializer,
    TicketCreateSerializer,
    TicketDetailSerializer,
    TicketListSerializer,
)

logger = logging.getLogger(__name__)


# ===============================================================================
# CUSTOMER TICKETS LIST API 📋
# ===============================================================================

@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_tickets_api(request: HttpRequest, customer) -> Response:
    """
    📋 Customer Tickets List API
    
    POST /api/tickets/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_tickets",
        "timestamp": 1699999999,
        "status": "open",    // optional filter
        "priority": "high", // optional filter
        "search": "hosting", // optional search
        "page": 1,          // optional pagination
        "limit": 20         // optional limit
    }
    
    Response:
    {
        "success": true,
        "data": {
            "tickets": [...],
            "pagination": {
                "page": 1,
                "limit": 20,
                "total": 45,
                "pages": 3,
                "has_next": true,
                "has_previous": false
            },
            "stats": {
                "total": 45,
                "open": 12,
                "pending": 3,
                "resolved": 30
            }
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Customer ID from signed request body (no URL enumeration)
    - Uniform error responses prevent information leakage
    """
    try:
        # Get optional filters from HMAC-signed request body
        request_data = request.data if hasattr(request, 'data') else {}
        
        # Get base queryset for the authenticated customer
        tickets_qs = Ticket.objects.filter(
            customer=customer
        ).select_related(
            'customer', 'category', 'assigned_to', 'created_by', 'related_service'
        ).prefetch_related(
            'comments', 'attachments'
        ).order_by('-created_at')
        
        # Apply filters from request body
        status_filter = request_data.get('status', '').strip()
        if status_filter and status_filter in dict(Ticket.STATUS_CHOICES):
            tickets_qs = tickets_qs.filter(status=status_filter)
        
        priority_filter = request_data.get('priority', '').strip()
        if priority_filter and priority_filter in dict(Ticket.PRIORITY_CHOICES):
            tickets_qs = tickets_qs.filter(priority=priority_filter)
        
        search_query = request_data.get('search', '').strip()
        if search_query:
            tickets_qs = tickets_qs.filter(
                Q(title__icontains=search_query) |
                Q(description__icontains=search_query) |
                Q(ticket_number__icontains=search_query)
            )
        
        # Get statistics before pagination (updated for new 4-status system)
        total_tickets = tickets_qs.count()
        stats = {
            'total': total_tickets,
            'open': tickets_qs.filter(status='open').count(),
            'in_progress': tickets_qs.filter(status='in_progress').count(),
            'waiting_on_customer': tickets_qs.filter(status='waiting_on_customer').count(),
            'closed': tickets_qs.filter(status='closed').count()
        }
        
        # Pagination from request body
        try:
            page = int(request_data.get('page', 1))
            limit = min(int(request_data.get('limit', 20)), 100)  # Max 100 per page
        except (ValueError, TypeError):
            page = 1
            limit = 20
        
        page = max(page, 1)
        
        offset = (page - 1) * limit
        paginated_tickets = tickets_qs[offset:offset + limit]
        
        # Calculate pagination info
        total_pages = (total_tickets + limit - 1) // limit
        
        # Serialize tickets
        serializer = TicketListSerializer(paginated_tickets, many=True)
        
        response_data = {
            'success': True,
            'data': {
                'tickets': serializer.data,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': total_tickets,
                    'pages': total_pages,
                    'has_next': page < total_pages,
                    'has_previous': page > 1
                },
                'stats': stats
            }
        }
        
        logger.info(f"✅ [API] Customer tickets list: customer={customer.company_name}, count={len(serializer.data)}")
        return Response(response_data)
        
    except Exception as e:
        logger.error(f"🔥 [API] Customer tickets list error: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch tickets'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===============================================================================
# CUSTOMER TICKET DETAIL API 📄
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_ticket_detail_api(request: HttpRequest, customer, ticket_id: int) -> Response:
    """
    📄 Customer Ticket Detail API
    
    POST /api/tickets/{ticket_number}/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_ticket_detail",
        "timestamp": 1699999999
    }
    
    Response:
    {
        "success": true,
        "data": {
            "ticket": {...},
            "permissions": {
                "can_reply": true,
                "can_close": false,
                "can_edit": false
            }
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Ticket access restricted to customer only
    - Uniform error responses prevent information leakage
    """
    try:
        # Get ticket with access control for the authenticated customer
        try:
            # Prefetch only public comments and their attachments for customer context
            public_comments = Prefetch(
                'comments',
                queryset=TicketComment.objects.filter(is_public=True)
                .select_related('author')
                .order_by('created_at')
            )
            public_attachments = Prefetch(
                'attachments',
                queryset=TicketAttachment.objects.filter(comment__is_public=True)
                .order_by('uploaded_at')
            )

            ticket = Ticket.objects.select_related(
                'customer', 'category', 'assigned_to', 'created_by', 'related_service'
            ).prefetch_related(
                public_comments,
                public_attachments,
            ).get(
                id=ticket_id,
                customer=customer  # Ensure customer owns this ticket
            )
        except Ticket.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Ticket not found or access denied'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Serialize ticket data
        serializer = TicketDetailSerializer(ticket, context={'for_customer': True})
        
        # Customer permissions (limited compared to staff)
        permissions = {
            'can_reply': ticket.status not in ['closed', 'cancelled'],
            'can_close': False,  # Only staff can close tickets
            'can_edit': False,   # Only staff can edit tickets
            'can_rate': ticket.status in ['resolved', 'closed'] and not ticket.satisfaction_rating
        }
        
        response_data = {
            'success': True,
            'data': {
                'ticket': serializer.data,
                'permissions': permissions
            }
        }
        
        logger.info(f"✅ [API] Customer ticket detail: {ticket_id}, customer={customer.company_name}")
        return Response(response_data)
        
    except Exception as e:
        logger.error(f"🔥 [API] Customer ticket detail error for {ticket_id}: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch ticket details'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===============================================================================
# CUSTOMER TICKET CREATION API ✉️
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_ticket_create_api(request: HttpRequest, customer) -> Response:
    """
    ✉️ Customer Ticket Creation API
    
    POST /api/tickets/create/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "create_ticket",
        "timestamp": 1699999999,
        "title": "Website is down",
        "description": "Detailed description of the issue...",
        "priority": "high",
        "category": 1,
        "contact_person": "John Doe",
        "contact_email": "john@example.com",
        "contact_phone": "+40123456789"
    }
    
    Response:
    {
        "success": true,
        "data": {
            "ticket": {...},
            "message": "Ticket created successfully"
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Customer validated by secure authentication system
    """
    try:
        # Get ticket data from HMAC-signed request body
        request_data = request.data if hasattr(request, 'data') else {}
        
        # Prepare ticket data (exclude auth fields)
        ticket_data = {k: v for k, v in request_data.items() 
                      if k not in ['customer_id', 'action', 'timestamp']}
        
        # Validate request data
        logger.debug(f"🔍 [Tickets API] Validating ticket data: {ticket_data}")
        serializer = TicketCreateSerializer(data=ticket_data)
        if not serializer.is_valid():
            logger.error(f"🔥 [Tickets API] Validation failed: {serializer.errors}")
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create ticket
        ticket = Ticket.objects.create(
            customer=customer,
            source='api',
            status='open',
            **serializer.validated_data
        )
        
        # Return created ticket details
        # Reload with the same prefetching to keep payload limited and efficient
        public_comments = Prefetch(
            'comments',
            queryset=TicketComment.objects.filter(is_public=True)
            .select_related('author')
            .order_by('created_at')
        )
        public_attachments = Prefetch(
            'attachments',
            queryset=TicketAttachment.objects.filter(comment__is_public=True)
            .order_by('uploaded_at')
        )
        ticket = Ticket.objects.select_related(
            'customer', 'category', 'assigned_to', 'created_by', 'related_service'
        ).prefetch_related(
            public_comments,
            public_attachments,
        ).get(id=ticket.id)

        detail_serializer = TicketDetailSerializer(ticket, context={'for_customer': True})
        
        response_data = {
            'success': True,
            'data': {
                'ticket': detail_serializer.data,
                'message': f'Ticket #{ticket.ticket_number} created successfully'
            }
        }
        
        logger.info(f"✅ [API] Customer ticket created: #{ticket.ticket_number}, customer={customer.company_name}")
        return Response(response_data, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"🔥 [API] Customer ticket creation error: {e}")
        return Response({
            'success': False,
            'error': 'Unable to create ticket'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===============================================================================
# CUSTOMER TICKET REPLY API 💬
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_ticket_reply_api(request: HttpRequest, customer, ticket_id: int) -> Response:
    """
    💬 Customer Ticket Reply API
    
    POST /api/tickets/{ticket_number}/reply/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "reply_to_ticket",
        "timestamp": 1699999999,
        "content": "Thank you for your help. The issue is resolved."
    }
    
    Response:
    {
        "success": true,
        "data": {
            "comment": {...},
            "message": "Reply added successfully"
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Ticket access restricted to customer only
    """
    try:
        # Get ticket with access control for the authenticated customer
        try:
            ticket = Ticket.objects.get(
                id=ticket_id,
                customer=customer
            )
        except Ticket.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Ticket not found or access denied'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check if ticket allows replies
        if ticket.status in ['closed', 'cancelled']:
            return Response({
                'success': False,
                'error': 'Cannot reply to closed or cancelled tickets'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get comment data from HMAC-signed request body
        request_data = request.data if hasattr(request, 'data') else {}
        comment_data = {'content': request_data.get('content', '')}
        
        # Validate comment data
        serializer = CommentCreateSerializer(data=comment_data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create customer comment
        comment = TicketComment.objects.create(
            ticket=ticket,
            content=serializer.validated_data['content'],
            comment_type='customer',
            author_email=ticket.contact_email,
            author_name=ticket.contact_person or 'Customer',
            is_public=True
        )
        
        # Handle customer reply using TicketStatusService
        try:
            TicketStatusService.handle_customer_reply(ticket)
        except ValueError as e:
            # Log error but don't fail the comment creation
            logger.warning(f"⚠️ [API] Error handling customer reply for ticket {ticket.ticket_number}: {e}")
            # Fallback behavior for edge cases
            ticket.has_customer_replied = True
            ticket.customer_replied_at = timezone.now()
            ticket.save(update_fields=['has_customer_replied', 'customer_replied_at'])
        
        response_data = {
            'success': True,
            'data': {
                'comment': {
                    'id': comment.id,
                    'content': comment.content,
                    'author_name': comment.get_author_name(),
                    'created_at': comment.created_at.isoformat()
                },
                'message': 'Reply added successfully'
            }
        }
        
        logger.info(f"✅ [API] Customer ticket reply: #{ticket_id}, customer={customer.company_name}")
        return Response(response_data, status=status.HTTP_201_CREATED)
        
    except Exception as e:
        logger.error(f"🔥 [API] Customer ticket reply error for {ticket_id}: {e}")
        return Response({
            'success': False,
            'error': 'Unable to add reply'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===============================================================================
# CUSTOMER TICKETS SUMMARY API 📊
# ===============================================================================

@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_tickets_summary_api(request: HttpRequest, customer) -> Response:
    """
    📊 Customer Tickets Summary API
    
    POST /api/tickets/summary/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_tickets_summary",
        "timestamp": 1699999999
    }
    
    Response:
    {
        "success": true,
        "data": {
            "total_tickets": 45,
            "open_tickets": 12,
            "pending_tickets": 3,
            "resolved_tickets": 30,
            "average_response_time_hours": 4.5,
            "satisfaction_rating": 4.2,
            "recent_tickets": [...]
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - No enumeration attacks possible
    """
    try:
        # Get tickets queryset for the authenticated customer
        tickets_qs = Ticket.objects.filter(customer=customer)
        
        # Calculate summary statistics
        total_tickets = tickets_qs.count()
        open_tickets = tickets_qs.filter(status__in=['open', 'in_progress']).count()
        pending_tickets = tickets_qs.filter(status='pending').count()
        resolved_tickets = tickets_qs.filter(status__in=['resolved', 'closed']).count()
        
        # Calculate average response time (for tickets with first response)
        # TODO: SQLite doesn't support Avg() on datetime fields - implement manual calculation later
        average_response_time_hours = 0.0
        
        # Calculate satisfaction rating - temporarily disabled for SQLite compatibility
        # TODO: Re-enable when SQLite aggregation issues are resolved
        satisfaction_rating = 0.0
        
        # Get recent tickets (last 5)
        recent_tickets = tickets_qs.select_related(
            'category', 'assigned_to'
        ).prefetch_related(
            'comments', 'attachments'
        ).order_by('-created_at')[:5]
        
        recent_serializer = TicketListSerializer(recent_tickets, many=True)
        
        # Prepare summary data
        summary_data = {
            'total_tickets': total_tickets,
            'open_tickets': open_tickets,
            'pending_tickets': pending_tickets,
            'resolved_tickets': resolved_tickets,
            'average_response_time_hours': round(average_response_time_hours, 1),
            'satisfaction_rating': round(satisfaction_rating, 1),
            'recent_tickets': recent_serializer.data
        }
        
        response_data = {
            'success': True,
            'data': summary_data
        }
        
        logger.info(f"✅ [API] Customer tickets summary: customer={customer.company_name}")
        return Response(response_data)
        
    except Exception as e:
        logger.error(f"🔥 [API] Customer tickets summary error: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch tickets summary'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===============================================================================
# SUPPORT CATEGORIES API 📂
# ===============================================================================

@api_view(['GET'])
@permission_classes([AllowAny])  # HMAC auth handled by middleware
def support_categories_api(request: HttpRequest) -> Response:
    """
    📂 Support Categories API
    
    GET /api/tickets/categories/
    
    Response:
    {
        "success": true,
        "data": {
            "categories": [...]
        }
    }
    """
    try:
        # Get active categories
        categories = SupportCategory.objects.filter(
            is_active=True
        ).order_by('sort_order', 'name')
        
        serializer = SupportCategorySerializer(categories, many=True)
        
        response_data = {
            'success': True,
            'data': {
                'categories': serializer.data
            }
        }
        
        logger.info(f"✅ [API] Support categories list: count={len(serializer.data)}")
        return Response(response_data)
        
    except Exception as e:
        logger.error(f"🔥 [API] Support categories error: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch support categories'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ===============================================================================
# TICKET ATTACHMENT DOWNLOAD API 📎
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def ticket_attachment_download_api(request: HttpRequest, customer, ticket_id: int, attachment_id: int) -> HttpResponse:
    """
    📎 Ticket Attachment Download API
    
    POST /api/tickets/{ticket_number}/attachments/{attachment_id}/download/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "download_attachment",
        "timestamp": 1699999999
    }
    
    Returns file content with appropriate headers.
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Attachment access restricted to customer's tickets only
    """
    try:
        # Get attachment with access control for the authenticated customer
        try:
            attachment = TicketAttachment.objects.select_related('ticket').get(
                id=attachment_id,
                ticket__id=ticket_id,
                ticket__customer=customer,  # Ensure customer owns the ticket
                is_safe=True  # Only allow safe files
            )
        except TicketAttachment.DoesNotExist:
            raise Http404("Attachment not found or access denied")
        
        # Security check
        if not attachment.file or not attachment.is_safe:
            raise Http404("File not available")
        
        # Prepare response with file content
        response = HttpResponse(
            attachment.file.read(),
            content_type=attachment.content_type or 'application/octet-stream'
        )
        
        # Set download headers
        response['Content-Disposition'] = f'attachment; filename="{attachment.filename}"'
        response['Content-Length'] = attachment.file_size
        
        logger.info(f"✅ [API] Ticket attachment download: {attachment.filename}, ticket={ticket_number}")
        return response
        
    except Http404:
        raise
    except Exception as e:
        logger.error(f"🔥 [API] Ticket attachment download error: {e}")
        return HttpResponse('Unable to download attachment', status=500)
