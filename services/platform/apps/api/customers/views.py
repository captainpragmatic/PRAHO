# ===============================================================================
# CUSTOMER API VIEWS 🎯
# ===============================================================================

import logging
from typing import Any, ClassVar, cast

from django.db.models import Q, QuerySet
from django.http import HttpRequest
from rest_framework import status
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api.core import ReadOnlyAPIViewSet
from apps.api.core.throttling import AuthThrottle, BurstAPIThrottle
from apps.api.secure_auth import require_customer_authentication
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User

from .serializers import (
    CustomerDetailSerializer,
    CustomerProfileSerializer,
    CustomerRegistrationSerializer,
    CustomerSearchSerializer,
    CustomerServiceSerializer,
)

logger = logging.getLogger(__name__)

# Constants
SEARCH_QUERY_MIN_LENGTH = 2


# ===============================================================================
# CUSTOMER SEARCH API 🔍
# ===============================================================================

class CustomerSearchViewSet(ReadOnlyAPIViewSet):
    """
    🔍 Customer search API for dropdowns and autocomplete.
    
    Migrated from apps.customers.customer_views.customer_search_api
    Now uses DRF with proper rate limiting and permissions.
    """
    
    serializer_class = CustomerSearchSerializer
    
    def get_queryset(self) -> QuerySet[Customer]:
        """Filter customers based on user access and search query"""
        user = cast(User, self.request.user)
        customers = user.get_accessible_customers()
        
        # Handle both QuerySet and list return types
        if hasattr(customers, "filter"):  # QuerySet
            return customers
        elif customers:  # List
            customer_ids = [c.id for c in customers]
            return Customer.objects.filter(id__in=customer_ids)
        else:
            return Customer.objects.none()
    
    def list(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Response:
        """
        Search customers with query parameter.
        
        Query Parameters:
            q (str): Search query (min 2 characters)
            
        Returns:
            List of customers matching the search query
        """
        query = request.GET.get("q", "")
        
        if len(query) < SEARCH_QUERY_MIN_LENGTH:
            return Response({"results": []})
        
        queryset = self.get_queryset()
        
        # Apply search filter
        if hasattr(queryset, "filter"):  # QuerySet
            filtered_customers = queryset.filter(
                Q(name__icontains=query) | 
                Q(company_name__icontains=query) | 
                Q(primary_email__icontains=query)
            )[:10]
        else:  # List (fallback)
            filtered_customers = [
                c for c in queryset
                if query.lower() in c.name.lower()
                or query.lower() in c.company_name.lower() 
                or query.lower() in c.primary_email.lower()
            ][:10]
        
        serializer = self.get_serializer(filtered_customers, many=True)
        return Response({"results": serializer.data})


# ===============================================================================
# CUSTOMER SERVICES API 🔗
# ===============================================================================

class CustomerServicesViewSet(ReadOnlyAPIViewSet):
    """
    🔗 Customer services API for ticket forms and service management.
    
    Migrated from apps.customers.customer_views.customer_services_api
    Currently returns empty list - placeholder for future service management.
    """
    
    serializer_class = CustomerServiceSerializer
    
    def get_queryset(self) -> QuerySet[Customer]:
        """Get customers the user has access to"""
        user = cast(User, self.request.user)
        accessible_customers = user.get_accessible_customers()
        
        if isinstance(accessible_customers, QuerySet):
            return accessible_customers
        elif accessible_customers:
            customer_ids = [c.id for c in accessible_customers]
            return Customer.objects.filter(id__in=customer_ids)
        else:
            return Customer.objects.none()
    
    @action(detail=True, methods=['get'], url_path='services')
    def services(self, request: HttpRequest, pk: str | None = None) -> Response:
        """
        Get services for a specific customer.
        
        Path Parameters:
            pk (int): Customer ID
            
        Returns:
            List of services for the customer (empty for now)
        """
        try:
            if pk is None:
                raise ValueError("Missing customer ID")
            customer_id = int(pk)
        except (ValueError, TypeError):
            return Response(
                {"error": "Invalid customer ID"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verify user has access to this customer
        queryset = self.get_queryset()
        if not queryset.filter(id=customer_id).exists():
            return Response(
                {"error": "Access denied"}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        # TODO: Implement actual service management
        # For now, return empty services list
        logger.info(f"🔗 [API] Customer services requested for customer {customer_id}")
        return Response([])  # Empty list for now


# ===============================================================================
# CUSTOMER REGISTRATION API 🔐
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([AuthThrottle])
def customer_register_api(request: HttpRequest) -> Response:
    """
    🔐 Customer Registration API
    
    POST /api/customers/register/
    
    Request Body:
    {
        "user_data": {
            "email": "user@company.com",
            "first_name": "Ion",
            "last_name": "Popescu",
            "phone": "+40.21.123.4567",
            "password": "secure_password_123"
        },
        "customer_data": {
            "customer_type": "company",
            "company_name": "Example SRL",
            "vat_number": "RO12345678",
            "address_line1": "Str. Example Nr. 123",
            "city": "București",
            "county": "București",
            "postal_code": "010001",
            "data_processing_consent": true,
            "marketing_consent": false
        }
    }
    
    Response:
    {
        "success": true,
        "user": {
            "id": 123,
            "email": "user@company.com",
            "first_name": "Ion",
            "last_name": "Popescu"
        },
        "customer": {
            "id": 456,
            "company_name": "Example SRL",
            "customer_type": "company"
        }
    }
    
    Security Features:
    - Rate limiting (5 requests per minute)
    - Romanian business validation
    - GDPR compliance checks
    - Input sanitization
    """
    serializer = CustomerRegistrationSerializer(
        data=request.data,
        context={'request': request}
    )
    
    if serializer.is_valid():
        try:
            result = serializer.save()
            logger.info(f"✅ [Customer Registration] Successfully created customer: {result['customer']['company_name']}")
            
            return Response({
                'success': True,
                'message': 'Customer registration successful',
                'user': result['user'],
                'customer': result['customer']
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"🔥 [Customer Registration] Registration failed: {e}")
            return Response({
                'success': False,
                'error': 'Registration failed. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        # Log validation errors (sanitized)
        error_fields = list(serializer.errors.keys())
        logger.warning(f"⚠️ [Customer Registration] Validation failed for fields: {error_fields}")
        
        return Response({
            'success': False,
            'error': 'Validation failed',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)


# ===============================================================================
# CUSTOMER PROFILE API 👤
# ===============================================================================

class CustomerProfileAPIView(APIView):
    """
    👤 Customer Profile Management API
    
    Handles GET (retrieve) and PUT/PATCH (update) for customer profile data.
    Integrates user fields and profile preferences in a single API.
    """
    
    permission_classes: ClassVar = [IsAuthenticated]
    throttle_classes: ClassVar = [BurstAPIThrottle]
    
    def get(self, request: HttpRequest) -> Response:
        """
        GET /api/customers/profile/
        
        Retrieve current user's profile data including:
        - User basic info (name, phone)
        - Profile preferences (language, timezone)
        - Notification settings
        
        Response:
        {
            "first_name": "Ion",
            "last_name": "Popescu",
            "phone": "+40.21.123.4567",
            "preferred_language": "ro",
            "timezone": "Europe/Bucharest",
            "email_notifications": true,
            "sms_notifications": false,
            "marketing_emails": false
        }
        """
        user = cast(User, request.user)
        serializer = CustomerProfileSerializer()
        data = serializer.to_representation(user)
        
        logger.info(f"📋 [Profile API] Profile retrieved for user: {user.email}")
        
        return Response({
            'success': True,
            'profile': data
        })
    
    def put(self, request: HttpRequest) -> Response:
        """
        PUT /api/customers/profile/
        
        Update user profile data (full update).
        
        Request Body:
        {
            "first_name": "Ion",
            "last_name": "Popescu",
            "phone": "+40.21.123.4567",
            "preferred_language": "ro",
            "timezone": "Europe/Bucharest",
            "email_notifications": true,
            "sms_notifications": false,
            "marketing_emails": false
        }
        """
        user = cast(User, request.user)
        serializer = CustomerProfileSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                updated_user = serializer.update(user, serializer.validated_data)
                response_data = serializer.to_representation(updated_user)
                
                logger.info(f"✅ [Profile API] Profile updated for user: {user.email}")
                
                return Response({
                    'success': True,
                    'message': 'Profile updated successfully',
                    'profile': response_data
                })
                
            except Exception as e:
                logger.error(f"🔥 [Profile API] Update failed for user {user.email}: {e}")
                return Response({
                    'success': False,
                    'error': 'Profile update failed. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            # Log validation errors
            error_fields = list(serializer.errors.keys())
            logger.warning(f"⚠️ [Profile API] Validation failed for user {user.email}, fields: {error_fields}")
            
            return Response({
                'success': False,
                'error': 'Validation failed',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
    
    def patch(self, request: HttpRequest) -> Response:
        """
        PATCH /api/customers/profile/
        
        Partial update of user profile data.
        Only provided fields will be updated.
        """
        user = cast(User, request.user)
        serializer = CustomerProfileSerializer(data=request.data, partial=True)
        
        if serializer.is_valid():
            try:
                updated_user = serializer.update(user, serializer.validated_data)
                response_data = serializer.to_representation(updated_user)
                
                logger.info(f"✅ [Profile API] Profile partially updated for user: {user.email}")
                
                return Response({
                    'success': True,
                    'message': 'Profile updated successfully',
                    'profile': response_data
                })
                
            except Exception as e:
                logger.error(f"🔥 [Profile API] Partial update failed for user {user.email}: {e}")
                return Response({
                    'success': False,
                    'error': 'Profile update failed. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                'success': False,
                'error': 'Validation failed',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


# ===============================================================================
# CUSTOMER DETAIL API 🏢
# ===============================================================================

@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_detail_api(request: HttpRequest, customer: Customer) -> Response:
    """
    🏢 Customer Detail API
    
    POST /api/customers/details/
    
    Returns customer details with optional expansions for authenticated customers.
    Uses HMAC authentication to prevent enumeration attacks.
    
    Request Body:
    {
        "customer_id": 123,
        "user_id": 456,
        "action": "get_customer_details",
        "timestamp": 1699999999,
        "include": ["stats", "membership", "billing_profile"]  // Optional
    }
    
    Response:
    {
        "success": true,
        "customer": {
            "id": 123,
            "display_name": "Test Company SRL",
            "customer_type": "company",
            "status": "active",
            "created_at": "2025-09-01T00:00:00Z",
            "updated_at": "2025-09-02T00:00:00Z",
            "name": "Ion Popescu",
            "company_name": "Test Company SRL",
            "primary_email": "contact@testcompany.ro", 
            "primary_phone": "+40.21.123.4567",
            "website": "https://testcompany.ro",
            "industry": "Technology",
            "tax_profile": {
                "vat_number": "RO12345678",
                "cui": "RO12345678",
                "is_vat_payer": true
            },
            "billing_profile": {
                "payment_terms": "net_30",
                "preferred_currency": "RON", 
                "invoice_delivery_method": "email",
                "auto_payment_enabled": false
            }
        },
        "meta": {  // Optional, based on 'include' parameter
            "membership": {
                "role": "owner"
            },
            "stats": {
                "services": 12,
                "open_tickets": 1,
                "outstanding_invoices": 0
            },
            "links": {
                "invoices": "/api/billing/invoices/",
                "services": "/api/services/",
                "tickets": "/api/tickets/"
            }
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Customer ID from signed request body (no URL enumeration)
    - Customer membership validation via @require_customer_authentication
    - Safe fields only (no CNP, banking details, or internal audit data)
    """
    try:
        # Extract optional includes from request
        request_data = getattr(request, 'data', {})
        includes = request_data.get('include', [])
        if isinstance(includes, str):
            includes = [includes]  # Handle single string
        
        # Optimize query with related fields
        customer_with_profiles = Customer.objects.select_related(
            'tax_profile', 'billing_profile'
        ).get(id=customer.id)
        
        # Serialize customer data
        serializer = CustomerDetailSerializer(customer_with_profiles)
        response_data = {
            'success': True,
            'customer': serializer.data
        }
        
        # Add optional expansions if requested
        if includes:
            meta = {}
            
            # Add membership role for requesting user
            if 'membership' in includes:
                user_id = request_data.get('user_id')
                if user_id:
                    try:
                        membership = CustomerMembership.objects.get(
                            user_id=user_id, customer=customer
                        )
                        meta['membership'] = {
                            'role': membership.role
                        }
                    except CustomerMembership.DoesNotExist:
                        # Default role if membership not found (shouldn't happen due to auth decorator)
                        meta['membership'] = {'role': 'member'}
            
            # Add stats if requested (cheap aggregates)
            if 'stats' in includes:
                # TODO: Replace with actual service/ticket/invoice counts from related models
                # For now, return placeholder values
                meta['stats'] = {
                    'services': 0,  # customer.services.filter(status='active').count()
                    'open_tickets': 0,  # customer.tickets.filter(status__in=['open', 'in_progress']).count()  
                    'outstanding_invoices': 0  # customer.invoices.filter(status='pending').count()
                }
            
            # Add billing profile if requested (already included in serializer, but could be conditional)
            if 'billing_profile' in includes:
                # Billing profile already included in customer serializer
                pass
                
            # Add convenience links
            if includes:  # Add links if any includes are requested
                meta['links'] = {
                    'invoices': '/api/billing/invoices/',
                    'services': '/api/services/',
                    'tickets': '/api/tickets/'
                }
            
            if meta:
                response_data['meta'] = meta
        
        logger.info(f"✅ [Customer Detail API] Retrieved details for customer {customer.company_name}")
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Customer.DoesNotExist:
        # This shouldn't happen due to @require_customer_authentication decorator
        logger.error(f"🔥 [Customer Detail API] Customer not found: {customer.id}")
        return Response({
            'success': False,
            'error': 'Customer not found'
        }, status=status.HTTP_404_NOT_FOUND)
        
    except Exception as e:
        logger.error(f"🔥 [Customer Detail API] Unexpected error for customer {customer.id}: {e}")
        return Response({
            'success': False,
            'error': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
