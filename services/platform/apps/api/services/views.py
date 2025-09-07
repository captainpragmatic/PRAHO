# ===============================================================================
# SERVICES API VIEWS - CUSTOMER HOSTING SERVICES 📦
# ===============================================================================

import logging
from decimal import Decimal
from typing import Any, Dict, List

from django.core.paginator import Paginator
from django.db.models import Q, Count, Sum, Case, When, IntegerField
from django.http import HttpRequest, JsonResponse
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from apps.provisioning.service_models import Service, ServicePlan
from ..secure_auth import require_customer_authentication
from .serializers import (
    ServiceListSerializer,
    ServiceDetailSerializer,
    ServiceSummarySerializer,
    ServicePlanAvailableSerializer
)

logger = logging.getLogger(__name__)


@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_services_api(request: HttpRequest, customer) -> Response:
    """
    📦 Customer Services List API
    
    POST /api/services/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_services",
        "timestamp": 1699999999,
        "status": "active",       // optional filter
        "service_type": "web",   // optional filter
        "search": "example",     // optional search
        "page": 1,              // optional pagination
        "limit": 20             // optional limit
    }
    
    Returns:
        {
            "success": true,
            "data": {
                "services": [...],
                "pagination": {...},
                "stats": {...}
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
        
        # Build base queryset for the authenticated customer
        queryset = Service.objects.filter(customer=customer).select_related(
            'customer', 'service_plan', 'server'
        )
        
        # Apply filters from request body
        status_filter = request_data.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        service_type_filter = request_data.get('service_type')
        if service_type_filter:
            queryset = queryset.filter(service_plan__plan_type=service_type_filter)
        
        search_query = request_data.get('search')
        if search_query:
            queryset = queryset.filter(
                Q(service_name__icontains=search_query) |
                Q(domain__icontains=search_query) |
                Q(username__icontains=search_query)
            )
        
        # Get stats for this customer's services
        stats = queryset.aggregate(
            total=Count('id'),
            active=Count('id', filter=Q(status='active')),
            suspended=Count('id', filter=Q(status='suspended')),
            pending=Count('id', filter=Q(status='pending')),
            overdue=Count('id', filter=Q(expires_at__lt=timezone.now()))
        )
        
        # Order by creation date (newest first)
        queryset = queryset.order_by('-created_at')
        
        # Pagination from request body
        page = int(request_data.get('page', 1))
        limit = min(int(request_data.get('limit', 20)), 100)  # Max 100 items per page
        
        paginator = Paginator(queryset, limit)
        services_page = paginator.get_page(page)
        
        # Serialize data
        serializer = ServiceListSerializer(services_page.object_list, many=True)
        
        return Response({
            'success': True,
            'data': {
                'services': serializer.data,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': paginator.count,
                    'pages': paginator.num_pages,
                    'has_next': services_page.has_next(),
                    'has_previous': services_page.has_previous()
                },
                'stats': stats
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [Services API] Error fetching services list: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch services list'
        }, status=500)


@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_service_detail_api(request: HttpRequest, service_id: int, customer) -> Response:
    """
    📦 Customer Service Detail API
    
    POST /api/services/<service_id>/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_service_detail",
        "timestamp": 1699999999
    }
    
    Returns:
        {
            "success": true,
            "data": {
                "service": {...}
            }
        }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Service access restricted to customer only
    - Uniform error responses prevent information leakage
    """
    try:
        # Get service with customer access control for the authenticated customer
        try:
            service = Service.objects.select_related(
                'customer', 'service_plan', 'server'
            ).get(id=service_id, customer=customer)
        except Service.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Service not found or access denied'
            }, status=404)
        
        # Serialize data
        serializer = ServiceDetailSerializer(service)
        
        # Add usage trends (last 7 days simulation - in production would come from monitoring)
        usage_trends = {
            'disk_usage_trend': [],  # Would be populated from monitoring data
            'bandwidth_usage_trend': [],  # Would be populated from monitoring data
            'uptime_percentage': 99.9  # Would be calculated from monitoring data
        }
        
        return Response({
            'success': True,
            'data': {
                'service': serializer.data,
                'usage_trends': usage_trends
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [Services API] Error fetching service detail {service_id}: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch service details'
        }, status=500)


@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_services_summary_api(request: HttpRequest, customer) -> Response:
    """
    📊 Customer Services Summary API
    
    POST /api/services/summary/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_services_summary",
        "timestamp": 1699999999
    }
    
    Returns:
        {
            "success": true,
            "data": {
                "summary": {...}
            }
        }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - No enumeration attacks possible
    """
    try:
        # Get services for the authenticated customer
        services = Service.objects.filter(customer=customer).select_related('service_plan')
        
        # Calculate stats
        now = timezone.now()
        expiring_soon_date = now + timezone.timedelta(days=30)
        
        stats = services.aggregate(
            total=Count('id'),
            active=Count('id', filter=Q(status='active')),
            suspended=Count('id', filter=Q(status='suspended')),
            pending=Count('id', filter=Q(status='pending')),
            overdue=Count('id', filter=Q(expires_at__lt=now)),
            expiring_soon=Count('id', filter=Q(
                expires_at__lt=expiring_soon_date,
                expires_at__gte=now,
                status='active'
            ))
        )
        
        # Calculate cost information
        active_services = services.filter(status='active')
        total_monthly_cost = sum(
            service.service_plan.get_monthly_equivalent_price(service.billing_cycle)
            for service in active_services
        )
        total_monthly_cost_with_vat = total_monthly_cost * Decimal('1.19')  # Romanian VAT 19%
        
        # Calculate usage statistics
        total_disk_usage_gb = sum(service.disk_usage_mb / 1024 for service in services)
        total_bandwidth_usage_gb = sum(service.bandwidth_usage_mb / 1024 for service in services)
        
        # Service type breakdown
        service_types = {}
        for service in services:
            plan_type = service.service_plan.get_plan_type_display()
            service_types[plan_type] = service_types.get(plan_type, 0) + 1
        
        # Recent services (last 5)
        recent_services = services.order_by('-created_at')[:5]
        recent_services_serializer = ServiceListSerializer(recent_services, many=True)
        
        summary_data = {
            'total': stats['total'] or 0,
            'active': stats['active'] or 0,
            'suspended': stats['suspended'] or 0,
            'pending': stats['pending'] or 0,
            'overdue': stats['overdue'] or 0,
            'expiring_soon': stats['expiring_soon'] or 0,
            'total_monthly_cost': round(total_monthly_cost, 2),
            'total_monthly_cost_with_vat': round(total_monthly_cost_with_vat, 2),
            'total_disk_usage_gb': round(total_disk_usage_gb, 2),
            'total_bandwidth_usage_gb': round(total_bandwidth_usage_gb, 2),
            'service_types': service_types,
            'recent_services': recent_services_serializer.data
        }
        
        return Response({
            'success': True,
            'data': {
                'summary': summary_data
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [Services API] Error fetching services summary: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch services summary'
        }, status=500)


@api_view(['GET'])
@permission_classes([AllowAny])  # HMAC auth handled by middleware
def available_service_plans_api(request: HttpRequest) -> Response:
    """
    📦 Available Service Plans API
    
    GET /api/services/plans/
    
    Query Parameters:
        plan_type (str): Filter by plan type (optional)
        
    Returns:
        {
            "success": true,
            "data": {
                "plans": [...]
            }
        }
    """
    try:
        # Get available service plans
        queryset = ServicePlan.objects.filter(
            is_active=True,
            is_public=True
        ).order_by('plan_type', 'sort_order', 'price_monthly')
        
        # Apply plan type filter
        plan_type_filter = request.GET.get('plan_type')
        if plan_type_filter:
            queryset = queryset.filter(plan_type=plan_type_filter)
        
        # Serialize data
        serializer = ServicePlanAvailableSerializer(queryset, many=True)
        
        return Response({
            'success': True,
            'data': {
                'plans': serializer.data
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [Services API] Error fetching service plans: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch service plans'
        }, status=500)


@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def update_service_auto_renew_api(request: HttpRequest, service_id: int, customer) -> Response:
    """
    🔄 Update Service Auto-Renew API
    
    POST /api/services/<service_id>/auto-renew/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "update_auto_renew",
        "timestamp": 1699999999,
        "auto_renew": true/false
    }
    
    Returns:
        {
            "success": true,
            "data": {
                "service": {...}
            }
        }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Service access restricted to customer only
    """
    try:
        # Get service with customer access control for the authenticated customer
        try:
            service = Service.objects.select_related(
                'customer', 'service_plan', 'server'
            ).get(id=service_id, customer=customer)
        except Service.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Service not found or access denied'
            }, status=404)
        
        # Check if service allows auto-renew changes
        if service.status not in ['active', 'suspended']:
            return Response({
                'success': False,
                'error': 'Auto-renew cannot be modified for this service status'
            }, status=400)
        
        # Get auto_renew from HMAC-signed request body
        request_data = request.data if hasattr(request, 'data') else {}
        auto_renew = request_data.get('auto_renew')
        if auto_renew is None:
            return Response({
                'success': False,
                'error': 'auto_renew field is required'
            }, status=400)
        
        # Update auto-renew setting
        service.auto_renew = bool(auto_renew)
        service.save(update_fields=['auto_renew'])
        
        logger.info(f"✅ [Services API] Auto-renew updated for service {service_id}: {auto_renew}")
        
        # Serialize updated service
        serializer = ServiceListSerializer(service)
        
        return Response({
            'success': True,
            'data': {
                'service': serializer.data,
                'message': f'Auto-renew {"enabled" if auto_renew else "disabled"} successfully'
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [Services API] Error updating auto-renew for service {service_id}: {e}")
        return Response({
            'success': False,
            'error': 'Unable to update auto-renew setting'
        }, status=500)


@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def service_usage_stats_api(request: HttpRequest, service_id: int, customer) -> Response:
    """
    📊 Service Usage Statistics API
    
    POST /api/services/<service_id>/usage/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_usage_stats",
        "timestamp": 1699999999,
        "period": "30d"  // optional: 7d, 30d, 90d (default: 30d)
    }
    
    Returns:
        {
            "success": true,
            "data": {
                "usage": {...}
            }
        }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Service access restricted to customer only
    """
    try:
        # Get service with customer access control for the authenticated customer
        try:
            service = Service.objects.select_related(
                'customer', 'service_plan', 'server'
            ).get(id=service_id, customer=customer)
        except Service.DoesNotExist:
            return Response({
                'success': False,
                'error': 'Service not found or access denied'
            }, status=404)
        
        # Get period from HMAC-signed request body
        request_data = request.data if hasattr(request, 'data') else {}
        period = request_data.get('period', '30d')
        
        # In production, this would query actual usage metrics from monitoring system
        # For now, return current usage statistics
        usage_data = {
            'current_usage': {
                'disk_usage_gb': round(service.disk_usage_mb / 1024, 2),
                'disk_limit_gb': service.service_plan.disk_space_gb,
                'disk_usage_percentage': round((service.disk_usage_mb / 1024) / (service.service_plan.disk_space_gb or 1) * 100, 1) if service.service_plan.disk_space_gb else 0,
                
                'bandwidth_usage_gb': round(service.bandwidth_usage_mb / 1024, 2),
                'bandwidth_limit_gb': service.service_plan.bandwidth_gb,
                'bandwidth_usage_percentage': round((service.bandwidth_usage_mb / 1024) / (service.service_plan.bandwidth_gb or 1) * 100, 1) if service.service_plan.bandwidth_gb else 0,
                
                'email_accounts_used': service.email_accounts_used,
                'email_accounts_limit': service.service_plan.email_accounts,
                
                'databases_used': service.databases_used,
                'databases_limit': service.service_plan.databases
            },
            'historical_usage': {
                'period': period,
                'disk_usage_trend': [],  # Would be populated from monitoring
                'bandwidth_usage_trend': [],  # Would be populated from monitoring
                'uptime_percentage': 99.9  # Would be calculated from monitoring
            },
            'alerts': []  # Would include usage warnings, limits exceeded, etc.
        }
        
        # Add usage alerts
        if service.service_plan.disk_space_gb and (service.disk_usage_mb / 1024) > (service.service_plan.disk_space_gb * 0.8):
            usage_data['alerts'].append({
                'type': 'warning',
                'message': 'Disk usage is above 80% of limit',
                'resource': 'disk'
            })
        
        if service.service_plan.bandwidth_gb and (service.bandwidth_usage_mb / 1024) > (service.service_plan.bandwidth_gb * 0.8):
            usage_data['alerts'].append({
                'type': 'warning', 
                'message': 'Bandwidth usage is above 80% of limit',
                'resource': 'bandwidth'
            })
        
        return Response({
            'success': True,
            'data': {
                'usage': usage_data
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [Services API] Error fetching usage stats for service {service_id}: {e}")
        return Response({
            'success': False,
            'error': 'Unable to fetch usage statistics'
        }, status=500)