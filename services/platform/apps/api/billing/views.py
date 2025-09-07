# ===============================================================================
# BILLING API VIEWS - CUSTOMER INVOICE OPERATIONS 💳
# ===============================================================================

import logging
from typing import cast
from django.db.models import Q, QuerySet
from django.http import HttpRequest
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import BaseAuthentication
from rest_framework.response import Response

from apps.billing.models import Invoice, InvoiceLine, Currency
from apps.billing.proforma_models import ProformaInvoice, ProformaLine
from apps.billing.pdf_generators import RomanianInvoicePDFGenerator, RomanianProformaPDFGenerator
from ..secure_auth import require_customer_authentication
from .serializers import (
    InvoiceListSerializer,
    InvoiceDetailSerializer, 
    InvoiceSummarySerializer,
    CurrencySerializer,
    ProformaListSerializer,
    ProformaDetailSerializer
)

logger = logging.getLogger(__name__)


class MiddlewareUserAuthentication(BaseAuthentication):
    """
    🔒 Pass-through authentication that preserves middleware-set user.
    
    This allows DRF to work with users set by our HMAC middleware
    without overriding them with AnonymousUser.
    """
    def authenticate(self, request):
        # If middleware has set a user (not AnonymousUser), preserve it
        if hasattr(request, 'user') and request.user and not request.user.is_anonymous:
            return (request.user, None)
        # Otherwise, no authentication (will be AnonymousUser)
        return None


# ===============================================================================
# CUSTOMER INVOICE LIST API 📋
# ===============================================================================

@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # No permissions required (auth handled by secure_auth)
@require_customer_authentication  
def customer_invoices_api(request: HttpRequest, customer) -> Response:
    """
    📋 Customer Invoice List API
    
    POST /api/billing/invoices/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_invoices",
        "timestamp": 1699999999,
        "status": "issued",  // optional filter
        "page": 1,         // optional pagination
        "limit": 20        // optional limit
    }
    
    Response:
    {
        "success": true,
        "invoices": [
            {
                "id": 123,
                "number": "INV-000123",
                "status": "issued",
                "total_cents": 15000,
                "currency": {
                    "code": "RON",
                    "symbol": "lei"
                },
                "due_at": "2024-01-15T00:00:00Z",
                "created_at": "2024-01-01T10:30:00Z",
                "is_overdue": false
            }
        ],
        "pagination": {
            "current_page": 1,
            "total_pages": 3,
            "total_items": 45,
            "has_next": true,
            "has_previous": false
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
        
        # Build query for customer's invoices
        invoices_qs = Invoice.objects.filter(customer=customer).select_related('currency')
        
        # Apply status filter if provided in request body
        status_filter = request_data.get('status')
        if status_filter and status_filter in ['draft', 'issued', 'paid', 'overdue', 'void', 'refunded']:
            invoices_qs = invoices_qs.filter(status=status_filter)
        
        # Apply pagination from request body
        page = max(1, int(request_data.get('page', 1)))
        limit = min(100, max(1, int(request_data.get('limit', 20))))
        
        total_items = invoices_qs.count()
        total_pages = (total_items + limit - 1) // limit
        offset = (page - 1) * limit
        
        invoices = invoices_qs.order_by('-created_at')[offset:offset + limit]
        
        # Serialize data
        serializer = InvoiceListSerializer(invoices, many=True)
        
        logger.info(f"✅ [Billing API] Returned {len(invoices)} invoices for customer {customer.company_name}")
        
        return Response({
            'success': True,
            'invoices': serializer.data,
            'pagination': {
                'current_page': page,
                'total_pages': total_pages,
                'total_items': total_items,
                'has_next': page < total_pages,
                'has_previous': page > 1,
                'limit': limit
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [Billing API] Invoice list error: {e}")
        return Response({
            'success': False,
            'error': 'Invoice service temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ===============================================================================
# CUSTOMER INVOICE DETAIL API 📄
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_invoice_detail_api(request: HttpRequest, invoice_number: str, customer) -> Response:
    """
    📄 Customer Invoice Detail API
    
    POST /api/billing/invoices/{invoice_number}/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_invoice_detail",
        "timestamp": 1699999999
    }
    
    Response:
    {
        "success": true,
        "invoice": {
            "id": 123,
            "number": "INV-000123",
            "status": "issued",
            "subtotal_cents": 12605,
            "tax_cents": 2395,
            "total_cents": 15000,
            "currency": {
                "code": "RON",
                "symbol": "lei",
                "decimal_places": 2
            },
            "issued_at": "2024-01-01T10:30:00Z",
            "due_at": "2024-01-15T00:00:00Z",
            "bill_to": {
                "name": "Example SRL",
                "tax_id": "RO12345678",
                "email": "contact@example.ro",
                "address": "Str. Example Nr. 123, București"
            },
            "lines": [
                {
                    "description": "Web Hosting Premium",
                    "kind": "service",
                    "quantity": "1.000",
                    "unit_price_cents": 10000,
                    "tax_rate": "0.1900",
                    "line_total_cents": 11900
                }
            ],
            "pdf_url": "/invoices/pdf/INV-000123.pdf",
            "is_overdue": false,
            "amount_due": 15000
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Invoice access restricted to customer only
    - Uniform error responses prevent information leakage
    """
    try:
        # Find invoice for the authenticated customer
        try:
            invoice = Invoice.objects.select_related('currency', 'customer').prefetch_related('lines').get(
                number=invoice_number,
                customer=customer
            )
        except Invoice.DoesNotExist:
            logger.warning(f"🚨 [Billing API] Invoice access denied - {invoice_number} for customer {customer.company_name}")
            return Response({
                'success': False,
                'error': 'Invoice not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Serialize data
        serializer = InvoiceDetailSerializer(invoice)
        
        logger.info(f"✅ [Billing API] Invoice detail returned: {invoice_number} for customer {customer.company_name}")
        
        return Response({
            'success': True,
            'invoice': serializer.data
        })
        
    except Exception as e:
        logger.error(f"🔥 [Billing API] Invoice detail error for {invoice_number}: {e}")
        return Response({
            'success': False,
            'error': 'Invoice service temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ===============================================================================
# CUSTOMER INVOICE SUMMARY API 📊
# ===============================================================================

@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_invoice_summary_api(request: HttpRequest, customer) -> Response:
    """
    📊 Customer Invoice Summary API
    
    POST /api/billing/summary/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_billing_summary",
        "timestamp": 1699999999
    }
    
    Response:
    {
        "success": true,
        "summary": {
            "total_invoices": 45,
            "draft_invoices": 2,
            "issued_invoices": 8,
            "overdue_invoices": 1,
            "paid_invoices": 34,
            "total_amount_due_cents": 45000,
            "currency_code": "RON",
            "recent_invoices": [
                {
                    "number": "INV-000123",
                    "status": "issued",
                    "total_cents": 15000,
                    "due_at": "2024-01-15T00:00:00Z",
                    "is_overdue": false
                }
            ]
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - No enumeration attacks possible
    
    Used for customer dashboard billing widget.
    """
    try:
        # Build summary data for the authenticated customer
        invoices_qs = Invoice.objects.filter(customer=customer)
        
        summary_data = {
            'customer_id': customer.id,
            'invoices_queryset': invoices_qs
        }
        
        serializer = InvoiceSummarySerializer(summary_data)
        
        logger.info(f"✅ [Billing API] Invoice summary returned for customer {customer.company_name}")
        
        return Response({
            'success': True,
            'summary': serializer.data
        })
        
    except Exception as e:
        logger.error(f"🔥 [Billing API] Invoice summary error: {e}")
        return Response({
            'success': False,
            'error': 'Invoice service temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ===============================================================================
# CURRENCY LIST API 💱
# ===============================================================================

@api_view(['GET'])
@permission_classes([AllowAny])
def currencies_api(request: HttpRequest) -> Response:
    """
    💱 Currency List API
    
    GET /api/billing/currencies/
    
    Returns active currencies for invoice display formatting.
    
    Response:
    {
        "success": true,
        "currencies": [
            {
                "id": 1,
                "code": "RON",
                "name": "Romanian Leu",
                "symbol": "lei",
                "decimal_places": 2
            }
        ]
    }
    """
    try:
        currencies = Currency.objects.filter(is_active=True).order_by('code')
        serializer = CurrencySerializer(currencies, many=True)
        
        return Response({
            'success': True,
            'currencies': serializer.data
        })
        
    except Exception as e:
        logger.error(f"🔥 [Billing API] Currency list error: {e}")
        return Response({
            'success': False,
            'error': 'Currency service temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ===============================================================================
# CUSTOMER PROFORMA LIST API 📄
# ===============================================================================

@api_view(['POST'])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware + secure_auth
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_proformas_api(request: HttpRequest, customer) -> Response:
    """
    📄 Customer Proforma List API
    
    POST /api/billing/proformas/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_proformas",
        "timestamp": 1699999999,
        "status": "sent",   // optional filter
        "page": 1,         // optional pagination
        "limit": 20        // optional limit
    }
    
    Response:
    {
        "success": true,
        "proformas": [
            {
                "id": 123,
                "number": "PRO-000123",
                "status": "sent",
                "total_cents": 15000,
                "currency": {
                    "code": "RON",
                    "symbol": "lei"
                },
                "valid_until": "2024-01-15T00:00:00Z",
                "created_at": "2024-01-01T10:30:00Z",
                "is_expired": false
            }
        ],
        "pagination": {
            "current_page": 1,
            "total_pages": 3,
            "total_items": 45,
            "has_next": true,
            "has_previous": false
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
        
        # Build query for customer's proformas
        proformas_qs = ProformaInvoice.objects.filter(customer=customer).select_related('currency')
        
        # Apply status filter if provided in request body
        status_filter = request_data.get('status')
        if status_filter and status_filter in ['draft', 'sent', 'accepted', 'expired']:
            proformas_qs = proformas_qs.filter(status=status_filter)
        
        # Apply pagination from request body
        page = max(1, int(request_data.get('page', 1)))
        limit = min(100, max(1, int(request_data.get('limit', 20))))
        
        total_items = proformas_qs.count()
        total_pages = (total_items + limit - 1) // limit
        offset = (page - 1) * limit
        
        proformas = proformas_qs.order_by('-created_at')[offset:offset + limit]
        
        # Serialize data
        serializer = ProformaListSerializer(proformas, many=True)
        
        logger.info(f"✅ [Billing API] Returned {len(proformas)} proformas for customer {customer.company_name}")
        
        return Response({
            'success': True,
            'proformas': serializer.data,
            'pagination': {
                'current_page': page,
                'total_pages': total_pages,
                'total_items': total_items,
                'has_next': page < total_pages,
                'has_previous': page > 1,
                'limit': limit
            }
        })
        
    except Exception as e:
        logger.error(f"🔥 [Billing API] Proforma list error: {e}")
        return Response({
            'success': False,
            'error': 'Proforma service temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ===============================================================================
# CUSTOMER PROFORMA DETAIL API 📄
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def customer_proforma_detail_api(request: HttpRequest, proforma_number: str, customer) -> Response:
    """
    📄 Customer Proforma Detail API
    
    POST /api/billing/proformas/{proforma_number}/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "get_proforma_detail",
        "timestamp": 1699999999
    }
    
    Response:
    {
        "success": true,
        "proforma": {
            "id": 123,
            "number": "PRO-000123",
            "status": "sent",
            "subtotal_cents": 12605,
            "tax_cents": 2395,
            "total_cents": 15000,
            "currency": {
                "code": "RON",
                "symbol": "lei",
                "decimal_places": 2
            },
            "valid_until": "2024-01-15T00:00:00Z",
            "created_at": "2024-01-01T10:30:00Z",
            "bill_to": {
                "name": "Example SRL",
                "tax_id": "RO12345678",
                "email": "contact@example.ro",
                "address": "Str. Example Nr. 123, București"
            },
            "lines": [
                {
                    "description": "Web Hosting Premium",
                    "kind": "service",
                    "quantity": "1.000",
                    "unit_price_cents": 10000,
                    "tax_rate": "0.1900",
                    "line_total_cents": 11900
                }
            ],
            "pdf_url": "/proformas/pdf/PRO-000123.pdf",
            "is_expired": false,
            "notes": "Additional details..."
        }
    }
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Proforma access restricted to customer only
    - Uniform error responses prevent information leakage
    """
    try:
        # Find proforma for the authenticated customer
        try:
            proforma = ProformaInvoice.objects.select_related('currency', 'customer').prefetch_related('lines').get(
                number=proforma_number,
                customer=customer
            )
        except ProformaInvoice.DoesNotExist:
            logger.warning(f"🚨 [Billing API] Proforma access denied - {proforma_number} for customer {customer.company_name}")
            return Response({
                'success': False,
                'error': 'Proforma not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Serialize data
        serializer = ProformaDetailSerializer(proforma)
        
        logger.info(f"✅ [Billing API] Proforma detail returned: {proforma_number} for customer {customer.company_name}")
        
        return Response({
            'success': True,
            'proforma': serializer.data
        })
        
    except Exception as e:
        logger.error(f"🔥 [Billing API] Proforma detail error for {proforma_number}: {e}")
        return Response({
            'success': False,
            'error': 'Proforma service temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ===============================================================================
# PDF EXPORT ENDPOINTS 📄
# ===============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def invoice_pdf_export(request: HttpRequest, invoice_number: str, customer) -> Response:
    """
    📄 Export Invoice as PDF
    
    POST /api/billing/invoices/{invoice_number}/pdf/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "export_invoice_pdf",
        "timestamp": 1699999999
    }
    
    Response:
        PDF file with proper Content-Disposition headers for download
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Invoice access restricted to customer only
    - Generated using Romanian compliance PDF format
    """
    try:
        # Find invoice for the authenticated customer
        try:
            invoice = Invoice.objects.select_related('currency', 'customer').prefetch_related('lines').get(
                number=invoice_number,
                customer=customer
            )
        except Invoice.DoesNotExist:
            logger.warning(f"🚨 [Invoice PDF API] Invoice access denied - {invoice_number} for customer {customer.company_name}")
            return Response({
                'success': False,
                'error': 'Invoice not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Generate PDF using the same generator as platform
        pdf_generator = RomanianInvoicePDFGenerator(invoice)
        pdf_response = pdf_generator.generate_response()
        
        logger.info(f"✅ [Invoice PDF API] PDF generated for invoice {invoice_number} by customer {customer.company_name}")
        return pdf_response
        
    except Exception as e:
        logger.error(f"🔥 [Invoice PDF API] PDF generation error for {invoice_number}: {e}")
        return Response({
            'success': False,
            'error': 'PDF generation service temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)


@api_view(['POST'])
@permission_classes([AllowAny])  # HMAC auth handled by secure_auth
@require_customer_authentication
def proforma_pdf_export(request: HttpRequest, proforma_number: str, customer) -> Response:
    """
    📄 Export Proforma as PDF
    
    POST /api/billing/proformas/{proforma_number}/pdf/
    
    Request Body (HMAC-signed):
    {
        "customer_id": 123,
        "action": "export_proforma_pdf",
        "timestamp": 1699999999
    }
    
    Response:
        PDF file with proper Content-Disposition headers for download
    
    Security Features:
    - HMAC authentication required (customer passed by decorator)
    - Proforma access restricted to customer only  
    - Generated using Romanian compliance PDF format
    """
    try:
        # Find proforma for the authenticated customer
        try:
            proforma = ProformaInvoice.objects.select_related('currency', 'customer').prefetch_related('lines').get(
                number=proforma_number,
                customer=customer
            )
        except ProformaInvoice.DoesNotExist:
            logger.warning(f"🚨 [Proforma PDF API] Proforma access denied - {proforma_number} for customer {customer.company_name}")
            return Response({
                'success': False,
                'error': 'Proforma not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Generate PDF using the same generator as platform
        pdf_generator = RomanianProformaPDFGenerator(proforma)
        pdf_response = pdf_generator.generate_response()
        
        logger.info(f"✅ [Proforma PDF API] PDF generated for proforma {proforma_number} by customer {customer.company_name}")
        return pdf_response
        
    except Exception as e:
        logger.error(f"🔥 [Proforma PDF API] PDF generation error for {proforma_number}: {e}")
        return Response({
            'success': False,
            'error': 'PDF generation service temporarily unavailable'
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)