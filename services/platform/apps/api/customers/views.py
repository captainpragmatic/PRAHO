# ===============================================================================
# CUSTOMER API VIEWS 🎯
# ===============================================================================

import json
import logging
from typing import Any, ClassVar, cast

from django.db import IntegrityError, transaction
from django.db.models import Q, QuerySet
from django.http import HttpRequest
from rest_framework import status
from rest_framework.decorators import action, api_view, authentication_classes, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.api.core import ReadOnlyAPIViewSet
from apps.api.core.throttling import AuthThrottle, BurstAPIThrottle
from apps.api.secure_auth import public_api_endpoint, require_customer_authentication, require_portal_authentication
from apps.customers.contact_models import CustomerAddress
from apps.customers.contact_service import AddressData, ContactService
from apps.customers.models import Customer, CustomerTaxProfile
from apps.provisioning.service_models import Service
from apps.users.models import CustomerMembership, User

from .serializers import (
    CustomerBillingAddressUpdateSerializer,
    CustomerCreationSerializer,
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
        if isinstance(customers, QuerySet):
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
                Q(name__icontains=query) | Q(company_name__icontains=query) | Q(primary_email__icontains=query)
            )[:10]
        else:  # List (fallback)
            filtered_customers = [
                c
                for c in queryset
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

    @action(detail=True, methods=["get"], url_path="services")
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
            return Response({"error": "Invalid customer ID"}, status=status.HTTP_400_BAD_REQUEST)

        # Verify user has access to this customer
        queryset = self.get_queryset()
        if not queryset.filter(id=customer_id).exists():
            return Response({"error": "Access denied"}, status=status.HTTP_403_FORBIDDEN)

        services = (
            Service.objects.filter(customer_id=customer_id)
            .select_related("service_plan")
            .values("id", "service_name", "status", "domain", "service_plan__name", "created_at")
        )
        logger.info(f"🔗 [API] Customer services requested for customer {customer_id}")
        return Response(list(services))


# ===============================================================================
# CUSTOMER CREATION API 🏢
# ===============================================================================


@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by middleware
@permission_classes([AllowAny])  # HMAC auth via @require_portal_authentication below
@require_portal_authentication
def customer_create_api(request: HttpRequest) -> Response:
    """
    🏢 Customer Creation API (for existing users to create companies)

    POST /api/customers/create/

    This endpoint allows existing authenticated users to create new companies
    through the Portal. Unlike registration, this is for users who already have
    accounts and want to create additional companies.

    Request Body:
    {
        "user_id": 123,
        "action": "create_company",
        "timestamp": 1234567890,
        "company_data": {
            "name": "Test Company SRL",
            "company_name": "Test Company SRL",
            "vat_number": "RO12345678",
            "trade_registry_number": "J40/12345/2023",
            "industry": "Technology",
            "billing_address": {
                "street_address": "Str. Revolutiei Nr. 123",
                "city": "București",
                "state": "București",
                "postal_code": "010001",
                "country": "România"
            },
            "contact": {
                "primary_email": "contact@testcompany.ro",
                "primary_phone": "+40.21.123.4567",
                "website": "https://testcompany.ro"
            }
        }
    }

    Response:
    {
        "success": true,
        "customer_id": 456,
        "message": "Company created successfully"
    }

    Security Features:
    - HMAC authentication required
    - User validation (user must exist)
    - Romanian business validation
    - Automatic owner membership creation
    """
    try:
        # HMAC authentication enforced by @require_portal_authentication decorator.
        # Validate the request data structure
        user_id = request.data.get("user_id")
        action = request.data.get("action")
        company_data = request.data.get("company_data", {})

        if not user_id or action != "create_company":
            return Response({"success": False, "error": "Invalid request format"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate user exists
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"success": False, "error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Use CustomerCreationSerializer to validate and create customer
        serializer = CustomerCreationSerializer(data=company_data, context={"request": request, "user": user})

        if serializer.is_valid():
            result = serializer.save()

            logger.info(
                f"✅ [Customer Creation] Company '{result['customer']['company_name']}' created by user {user.email}"
            )

            return Response(
                {"success": True, "customer_id": result["customer"]["id"], "message": "Company created successfully"},
                status=status.HTTP_201_CREATED,
            )
        else:
            logger.warning(
                f"⚠️ [Customer Creation] Validation failed for user {user.email}: {list(serializer.errors.keys())}"
            )
            return Response(
                {"success": False, "error": "Validation failed", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

    except Exception as e:
        logger.error(f"🔥 [Customer Creation] Unexpected error: {e}")
        return Response(
            {"success": False, "error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ===============================================================================
# CUSTOMER REGISTRATION API 🔐
# ===============================================================================


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([AuthThrottle])
@public_api_endpoint
def customer_register_api(request: HttpRequest) -> Response:
    """
    🔐 Customer Registration API -- intentionally public.

    New customer registration; throttled by AuthThrottle.

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
    serializer = CustomerRegistrationSerializer(data=request.data, context={"request": request})

    if serializer.is_valid():
        try:
            result = serializer.save()
            logger.info(
                f"✅ [Customer Registration] Successfully created customer: {result['customer']['company_name']}"
            )

            return Response(
                {
                    "success": True,
                    "message": "Customer registration successful",
                    "user": result["user"],
                    "customer": result["customer"],
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"🔥 [Customer Registration] Registration failed: {e}")
            return Response(
                {"success": False, "error": "Registration failed. Please try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
    else:
        # Log validation errors (sanitized)
        error_fields = list(serializer.errors.keys())
        logger.warning(f"⚠️ [Customer Registration] Validation failed for fields: {error_fields}")

        return Response(
            {"success": False, "error": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )


# ===============================================================================
# CUSTOMER PROFILE API 👤
# ===============================================================================


class CustomerProfileAPIView(APIView):
    """
    👤 Customer Profile Management API - 🔒 SECURITY: POST-only with customer authentication

    🚨 SECURITY FIX: Converted from GET to POST with require_customer_authentication
    to prevent customer enumeration and unauthorized profile access.
    """

    permission_classes: ClassVar = [IsAuthenticated]
    throttle_classes: ClassVar = [BurstAPIThrottle]

    @require_customer_authentication
    def post(self, request: HttpRequest, customer: Customer) -> Response:
        """
        🔒 POST /api/customers/profile/ (SECURITY: Changed from GET)

        Retrieve customer profile data with proper authentication:
        - Customer-scoped authentication required
        - User basic info (name, phone)
        - Profile preferences (language, timezone)
        - Notification settings

        Request Body: { "action": "get_profile" }

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
        # 🔒 SECURITY: customer parameter injected by require_customer_authentication
        user = cast(User, request.user)
        serializer = CustomerProfileSerializer()
        data = serializer.to_representation(user)

        logger.info(f"🔒 [Profile API] Profile retrieved for customer {customer.id}, user: {user.email}")

        return Response({"success": True, "profile": data})

    @require_customer_authentication
    def put(self, request: HttpRequest, customer: Customer) -> Response:
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

                logger.info(f"🔒 [Profile API] Profile updated for customer {customer.id}, user: {user.email}")

                return Response({"success": True, "message": "Profile updated successfully", "profile": response_data})

            except Exception as e:
                logger.error(f"🔥 [Profile API] Update failed for user {user.email}: {e}")
                return Response(
                    {"success": False, "error": "Profile update failed. Please try again."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        else:
            # Log validation errors
            error_fields = list(serializer.errors.keys())
            logger.warning(f"⚠️ [Profile API] Validation failed for user {user.email}, fields: {error_fields}")

            return Response(
                {"success": False, "error": "Validation failed", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

    @require_customer_authentication
    def patch(self, request: HttpRequest, customer: Customer) -> Response:
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

                logger.info(
                    f"🔒 [Profile API] Profile partially updated for customer {customer.id}, user: {user.email}"
                )

                return Response({"success": True, "message": "Profile updated successfully", "profile": response_data})

            except Exception as e:
                logger.error(f"🔥 [Profile API] Partial update failed for user {user.email}: {e}")
                return Response(
                    {"success": False, "error": "Profile update failed. Please try again."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        else:
            return Response(
                {"success": False, "error": "Validation failed", "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )


# ===============================================================================
# CUSTOMER DETAIL API 🏢
# ===============================================================================


@api_view(["POST"])
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
        request_data = getattr(request, "data", {})
        includes = request_data.get("include", [])
        if isinstance(includes, str):
            includes = [includes]  # Handle single string

        # Optimize query with related fields
        customer_with_profiles = Customer.objects.select_related("tax_profile", "billing_profile").get(id=customer.id)

        # Serialize customer data
        serializer = CustomerDetailSerializer(customer_with_profiles)
        response_data = {"success": True, "customer": serializer.data}

        # Add optional expansions if requested
        if includes:
            meta: dict[str, Any] = {}

            # Add membership role for requesting user
            if "membership" in includes:
                user_id = request_data.get("user_id")
                if user_id:
                    try:
                        membership = CustomerMembership.objects.get(user_id=user_id, customer=customer)
                        meta["membership"] = {"role": membership.role}
                    except CustomerMembership.DoesNotExist:
                        # Default role if membership not found (shouldn't happen due to auth decorator)
                        meta["membership"] = {"role": "member"}

            # Add stats if requested (cheap aggregates)
            if "stats" in includes:
                meta["stats"] = {
                    "services": customer.services.filter(status="active").count(),
                    "open_tickets": customer.tickets.filter(status__in=["open", "in_progress"]).count(),
                    "outstanding_invoices": customer.invoices.filter(status__in=["issued", "overdue"]).count(),
                }

            # Add billing profile if requested (already included in serializer, but could be conditional)
            if "billing_profile" in includes:
                # Billing profile already included in customer serializer
                pass

            # Add convenience links
            if includes:  # Add links if any includes are requested
                meta["links"] = {
                    "invoices": "/api/billing/invoices/",
                    "services": "/api/services/",
                    "tickets": "/api/tickets/",
                }

            if meta:
                response_data["meta"] = meta

        logger.info(f"✅ [Customer Detail API] Retrieved details for customer {customer.company_name}")

        return Response(response_data, status=status.HTTP_200_OK)

    except Customer.DoesNotExist:
        # This shouldn't happen due to @require_customer_authentication decorator
        logger.error(f"🔥 [Customer Detail API] Customer not found: {customer.id}")
        return Response({"success": False, "error": "Customer not found"}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        logger.error(f"🔥 [Customer Detail API] Unexpected error for customer {customer.id}: {e}")
        return Response(
            {"success": False, "error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# ===============================================================================
# CUSTOMER BILLING ADDRESS UPDATE API 🏠 (CHECKOUT UX ENHANCEMENT)
# ===============================================================================


@api_view(["POST"])
@authentication_classes([])  # No DRF authentication - HMAC handled by @require_customer_authentication
@permission_classes([AllowAny])  # HMAC auth via @require_customer_authentication below
@throttle_classes([BurstAPIThrottle])
@require_customer_authentication
def update_customer_billing_address(  # noqa: C901, PLR0912, PLR0915  # Complexity: multi-step business logic
    request: Request, customer: Customer
) -> Response:
    """
    🏠 Update customer billing address during checkout validation failures.

    This endpoint enables seamless inline editing of customer profile data
    when checkout validation fails, providing a smooth UX without navigation disruption.

    POST /api/customers/billing-address/

    Request Body:
    {
        "timestamp": 1234567890,
        "user_id": 123,
        "company_name": "Test Company SRL",
        "contact_name": "Ion Popescu",
        "email": "contact@testcompany.com",
        "phone": "+40722123456",
        "address_line1": "Str. Revolutiei nr. 1",
        "city": "Bucharest",
        "county": "Bucharest",
        "postal_code": "010000",
        "country": "România",
        "fiscal_code": "RO12345678",
        "vat_number": "RO12345678"
    }

    Response:
    {
        "success": true,
        "message": "Billing address updated successfully"
    }

    Security:
    - HMAC authentication required
    - Customer scoped access only
    - Validation with Romanian business compliance
    - Rate limited (burst protection)
    """

    logger.info(f"🏠 [Billing Address API] Update request for customer {customer.id}")

    # Validate input using our custom serializer
    serializer = CustomerBillingAddressUpdateSerializer(data=request.data)
    if not serializer.is_valid():
        logger.warning(f"⚠️ [Billing Address API] Validation failed for customer {customer.id}")
        return Response(
            {"success": False, "error": "Validation failed", "errors": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    validated_data = serializer.validated_data

    # Resolve the acting user from the HMAC-signed body (user_id is validated by the decorator)
    user_id = request.data.get("user_id")
    try:
        acting_user = User.objects.get(id=int(user_id), is_active=True)
    except (User.DoesNotExist, TypeError, ValueError):
        logger.error(f"🔥 [Billing Address API] Could not resolve user_id={user_id} for customer {customer.id}")
        return Response(
            {"success": False, "error": "Invalid request context"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        with transaction.atomic():
            # F02 fix: Build update_fields dynamically — only save fields actually provided.
            # Unconditionally saving all 4 fields triggered unnecessary audit signals and
            # could overwrite values with stale data from a prior serializer state.
            customer_update_fields: list[str] = []
            if validated_data.get("company_name"):
                customer.company_name = validated_data["company_name"]
                customer_update_fields.append("company_name")
            if validated_data.get("contact_name"):
                customer.name = validated_data["contact_name"]
                customer_update_fields.append("name")
            if validated_data.get("email"):
                customer.primary_email = validated_data["email"]
                customer_update_fields.append("primary_email")
            if validated_data.get("phone"):
                customer.primary_phone = validated_data["phone"]
                customer_update_fields.append("primary_phone")

            if customer_update_fields:
                # Include updated_at so the auto_now field is written to DB even with update_fields.
                customer.save(update_fields=[*customer_update_fields, "updated_at"])

            # F03 fix: Use ContactService.create_address() for atomic versioning.
            # The previous get_or_create + setattr loop bypassed version history and
            # was vulnerable to UniqueConstraint races under concurrent writes.
            address_fields = {
                k: validated_data[k]
                for k in ("address_line1", "city", "county", "postal_code", "country", "address_line2")
                if k in validated_data
            }
            if address_fields:
                # If core fields provided, create new versioned address
                address_line1 = address_fields.get("address_line1", "")
                city = address_fields.get("city", "")
                if address_line1 and city:
                    address_data = AddressData(
                        address_type="primary",
                        address_line1=address_line1,
                        city=city,
                        county=address_fields.get("county", ""),
                        postal_code=address_fields.get("postal_code", ""),
                    )
                    ContactService.create_address(
                        customer=customer,
                        user=acting_user,
                        address_data=address_data,
                        is_current=True,
                        country=address_fields.get("country", "România"),
                        address_line2=address_fields.get("address_line2", ""),
                    )
                else:
                    # Partial update — update existing primary address in place
                    existing_addr = customer.get_primary_address()
                    if existing_addr:
                        for field, value in address_fields.items():
                            setattr(existing_addr, field, value)
                        existing_addr.save(update_fields=[*address_fields.keys(), "updated_at"])

            # Update or create tax profile for Romanian compliance
            tax_fields = {}
            if validated_data.get("fiscal_code"):
                tax_fields["cui"] = validated_data["fiscal_code"]
            if validated_data.get("vat_number"):
                tax_fields["vat_number"] = validated_data["vat_number"]
            if validated_data.get("registration_number"):
                tax_fields["registration_number"] = validated_data["registration_number"]

            if tax_fields:
                tax_profile, created = CustomerTaxProfile.objects.get_or_create(customer=customer, defaults=tax_fields)

                if not created:
                    for field, value in tax_fields.items():
                        setattr(tax_profile, field, value)
                    tax_profile.save()

        logger.info(f"✅ [Billing Address API] Successfully updated billing address for customer {customer.id}")

        return Response({"success": True, "message": "Billing address updated successfully"}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.error(f"🔥 [Billing Address API] Update failed for customer {customer.id}: {e}")
        return Response(
            {"success": False, "error": "Failed to update billing address. Please try again."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


# ===============================================================================
# CUSTOMER USER MANAGEMENT API 👥 (Phase 7 — Portal Parity)
# ===============================================================================

MAX_ADDRESSES_PER_CUSTOMER = 10


def _get_request_data(request: HttpRequest) -> dict[str, Any]:
    """Extract parsed request body data."""
    if hasattr(request, "data"):
        return dict(request.data)
    try:
        parsed: dict[str, Any] = json.loads(request.body)
        return parsed
    except json.JSONDecodeError:
        return {}


def _extract_user_id(data: dict[str, Any]) -> int:
    """Extract and validate user_id from request data. Raises ValueError if missing."""
    raw = data.get("user_id")
    if raw is None:
        msg = "user_id is required."
        raise ValueError(msg)
    return int(raw)


def _check_self_action(user_id: int | str | None, target_user_id: int | str | None) -> Response | None:
    """Return 400 if user_id and target_user_id refer to the same person."""
    if user_id is not None and target_user_id is not None and str(user_id) == str(target_user_id):
        return Response(
            {"success": False, "error": "Cannot perform this action on yourself."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return None


def _require_owner_role(user_id: int, customer: Customer) -> Response | None:
    """Return error response if user is not an owner of the customer."""
    membership = CustomerMembership.objects.filter(user_id=user_id, customer=customer, is_active=True).first()
    if not membership or membership.role != "owner":
        return Response(
            {"success": False, "error": "Owner role required for this action."},
            status=status.HTTP_403_FORBIDDEN,
        )
    return None


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_users_list(request: HttpRequest, customer: Customer) -> Response:
    """List users (memberships) for a customer."""
    memberships = (
        CustomerMembership.objects.filter(customer=customer, is_active=True)
        .select_related("user")
        .order_by("role", "user__email")
    )
    users_data = [
        {
            "user_id": m.user.id,
            "email": m.user.email,
            "first_name": m.user.first_name,
            "last_name": m.user.last_name,
            "role": m.role,
            "is_active": m.is_active,
            "is_primary": m.is_primary,
            "created_at": m.created_at.isoformat(),
        }
        for m in memberships
    ]
    return Response({"success": True, "users": users_data})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_users_add(request: HttpRequest, customer: Customer) -> Response:  # noqa: PLR0911
    """Add an existing user to a customer organization."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    # Require owner role
    owner_error = _require_owner_role(user_id, customer)
    if owner_error:
        return owner_error

    target_user_id = data.get("target_user_id")
    role = data.get("role", "viewer")

    if not target_user_id:
        return Response({"success": False, "error": "target_user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    # Validate role
    valid_roles = [c[0] for c in CustomerMembership.CUSTOMER_ROLE_CHOICES]
    if role not in valid_roles:
        return Response(
            {"success": False, "error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        target_user = User.objects.get(id=target_user_id, is_active=True)
    except User.DoesNotExist:
        return Response({"success": False, "error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    try:
        with transaction.atomic():
            if CustomerMembership.objects.filter(customer=customer, user=target_user).exists():
                return Response(
                    {"success": False, "error": "User is already a member."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            CustomerMembership.objects.create(customer=customer, user=target_user, role=role)
    except IntegrityError:
        return Response(
            {"success": False, "error": "User is already a member of this customer."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    logger.info(f"✅ [User Management API] User {target_user.email} added to customer {customer.id} as {role}")
    return Response({"success": True, "message": f"User added as {role}."})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_users_create(request: HttpRequest, customer: Customer) -> Response:
    """Create a new user and add them to the customer organization."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    owner_error = _require_owner_role(user_id, customer)
    if owner_error:
        return owner_error

    email = data.get("email", "").strip()
    role = data.get("role", "viewer")
    first_name = data.get("first_name", "").strip()
    last_name = data.get("last_name", "").strip()

    if not email:
        return Response({"success": False, "error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response(
            {"success": False, "error": "A user with this email already exists."}, status=status.HTTP_400_BAD_REQUEST
        )

    valid_roles = [c[0] for c in CustomerMembership.CUSTOMER_ROLE_CHOICES]
    if role not in valid_roles:
        return Response(
            {"success": False, "error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    with transaction.atomic():
        # Invite-only flow: user is created with an unusable password.
        # They must complete account setup via the password-reset link sent separately.
        new_user = User.objects.create_user(email=email, first_name=first_name, last_name=last_name)
        CustomerMembership.objects.create(customer=customer, user=new_user, role=role)

    logger.info(f"✅ [User Management API] New user {email} created and added to customer {customer.id}")
    return Response(
        {"success": True, "user_id": new_user.id, "message": f"User created and added as {role}."},
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_users_role(request: HttpRequest, customer: Customer) -> Response:  # noqa: PLR0911
    """Change a user's role within the customer organization."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    owner_error = _require_owner_role(user_id, customer)
    if owner_error:
        return owner_error

    target_user_id = data.get("target_user_id")
    new_role = data.get("new_role")

    if not target_user_id or not new_role:
        return Response(
            {"success": False, "error": "target_user_id and new_role are required."}, status=status.HTTP_400_BAD_REQUEST
        )

    self_error = _check_self_action(user_id, target_user_id)
    if self_error:
        return self_error

    valid_roles = [c[0] for c in CustomerMembership.CUSTOMER_ROLE_CHOICES]
    if new_role not in valid_roles:
        return Response(
            {"success": False, "error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        membership = CustomerMembership.objects.get(customer=customer, user_id=target_user_id, is_active=True)
    except CustomerMembership.DoesNotExist:
        return Response({"success": False, "error": "Membership not found."}, status=status.HTTP_404_NOT_FOUND)

    # Prevent demoting the last owner
    if membership.role == "owner" and new_role != "owner":
        owner_count = CustomerMembership.objects.filter(customer=customer, role="owner", is_active=True).count()
        if owner_count <= 1:
            return Response(
                {"success": False, "error": "Cannot remove the last owner. Assign another owner first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

    old_role = membership.role
    membership.role = new_role
    membership.save(update_fields=["role", "updated_at"])
    logger.info(
        f"✅ [User Management API] Role changed for user {target_user_id} on customer {customer.id}: {old_role} → {new_role}"
    )
    return Response({"success": True, "message": f"Role changed from {old_role} to {new_role}."})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_users_remove(request: HttpRequest, customer: Customer) -> Response:  # noqa: PLR0911
    """Remove a user from the customer organization."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    owner_error = _require_owner_role(user_id, customer)
    if owner_error:
        return owner_error

    target_user_id = data.get("target_user_id")
    if not target_user_id:
        return Response({"success": False, "error": "target_user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    self_error = _check_self_action(user_id, target_user_id)
    if self_error:
        return self_error

    try:
        membership = CustomerMembership.objects.get(customer=customer, user_id=target_user_id, is_active=True)
    except CustomerMembership.DoesNotExist:
        return Response({"success": False, "error": "Membership not found."}, status=status.HTTP_404_NOT_FOUND)

    # Prevent removing the last owner
    if membership.role == "owner":
        owner_count = CustomerMembership.objects.filter(customer=customer, role="owner", is_active=True).count()
        if owner_count <= 1:
            return Response(
                {"success": False, "error": "Cannot remove the last owner."}, status=status.HTTP_400_BAD_REQUEST
            )

    # Prevent removing the last user
    total_members = CustomerMembership.objects.filter(customer=customer, is_active=True).count()
    if total_members <= 1:
        return Response(
            {"success": False, "error": "Cannot remove the last member of a customer."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    membership.is_active = False
    membership.save(update_fields=["is_active", "updated_at"])
    logger.info(f"✅ [User Management API] User {target_user_id} removed from customer {customer.id}")
    return Response({"success": True, "message": "User removed from customer."})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_users_toggle_status(request: HttpRequest, customer: Customer) -> Response:  # noqa: PLR0911
    """Suspend or activate a user's membership."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    owner_error = _require_owner_role(user_id, customer)
    if owner_error:
        return owner_error

    target_user_id = data.get("target_user_id")
    if not target_user_id:
        return Response({"success": False, "error": "target_user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    self_error = _check_self_action(user_id, target_user_id)
    if self_error:
        return self_error

    try:
        target_user = User.objects.get(id=target_user_id)
    except User.DoesNotExist:
        return Response({"success": False, "error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    # Toggle membership-scoped active status (does not affect global user account)
    try:
        membership = CustomerMembership.objects.get(customer=customer, user=target_user)
    except CustomerMembership.DoesNotExist:
        return Response(
            {"success": False, "error": "User is not a member of this customer."}, status=status.HTTP_404_NOT_FOUND
        )

    membership.is_active = not membership.is_active
    membership.save(update_fields=["is_active", "updated_at"])
    new_status = "activated" if membership.is_active else "suspended"
    logger.info(f"✅ [User Management API] Membership for {target_user.email} {new_status} for customer {customer.id}")
    return Response({"success": True, "is_active": membership.is_active, "message": f"User {new_status}."})


# ===============================================================================
# CUSTOMER PROFILE & ADDRESS API 📍 (Phase 7 — Portal Parity)
# ===============================================================================


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_update(request: HttpRequest, customer: Customer) -> Response:
    """Update customer details (name, email, phone, etc.)."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    # Owner or billing role required
    membership = CustomerMembership.objects.filter(user_id=user_id, customer=customer, is_active=True).first()
    if not membership or membership.role not in ("owner", "billing"):
        return Response(
            {"success": False, "error": "Owner or billing role required."},
            status=status.HTTP_403_FORBIDDEN,
        )

    updatable_fields = {"name", "company_name", "primary_email", "primary_phone", "website", "industry"}
    update_fields = []
    for field in updatable_fields:
        if field in data:
            value = data[field]
            if not isinstance(value, str):
                return Response(
                    {"success": False, "error": f"Field '{field}' must be a string."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            setattr(customer, field, value.strip())
            update_fields.append(field)

    if update_fields:
        with transaction.atomic():
            customer.save(update_fields=[*update_fields, "updated_at"])
        logger.info(f"✅ [Customer API] Updated fields {update_fields} for customer {customer.id}")

    return Response({"success": True, "message": "Customer updated."})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_tax_profile_update(request: HttpRequest, customer: Customer) -> Response:
    """Update customer tax profile (CUI, VAT number, etc.)."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    membership = CustomerMembership.objects.filter(user_id=user_id, customer=customer, is_active=True).first()
    if not membership or membership.role not in ("owner", "billing"):
        return Response(
            {"success": False, "error": "Owner or billing role required."},
            status=status.HTTP_403_FORBIDDEN,
        )

    tax_bool_fields = {"is_vat_payer", "reverse_charge_eligible"}
    tax_string_fields = {"cui", "vat_number", "registration_number"}

    tax_profile, _created = CustomerTaxProfile.objects.get_or_create(customer=customer)
    update_fields = []
    for field in tax_bool_fields | tax_string_fields:
        if field in data:
            value = data[field]
            if field in tax_bool_fields:
                value = value.lower() in ("true", "1", "on", "yes") if isinstance(value, str) else bool(value)
            else:
                if not isinstance(value, str):
                    return Response(
                        {"success": False, "error": f"Field '{field}' must be a string."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                value = value.strip()
            setattr(tax_profile, field, value)
            update_fields.append(field)

    if update_fields:
        with transaction.atomic():
            tax_profile.save(update_fields=[*update_fields, "updated_at"])
        logger.info(f"✅ [Customer API] Updated tax profile fields {update_fields} for customer {customer.id}")

    return Response({"success": True, "message": "Tax profile updated."})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_addresses_list(request: HttpRequest, customer: Customer) -> Response:
    """List all addresses for a customer."""
    addresses = CustomerAddress.objects.filter(customer=customer).order_by("-is_current", "address_type")
    addresses_data = [
        {
            "id": addr.id,
            "address_type": addr.address_type,
            "is_current": addr.is_current,
            "address_line1": addr.address_line1,
            "address_line2": getattr(addr, "address_line2", ""),
            "city": addr.city,
            "county": addr.county,
            "country": addr.country,
            "postal_code": addr.postal_code,
        }
        for addr in addresses
    ]
    return Response({"success": True, "addresses": addresses_data})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_addresses_add(request: HttpRequest, customer: Customer) -> Response:  # noqa: PLR0911
    """Add a new address to a customer."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    owner_error = _require_owner_role(user_id, customer)
    if owner_error:
        return owner_error

    # Enforce max address limit
    current_count = CustomerAddress.objects.filter(customer=customer).count()
    if current_count >= MAX_ADDRESSES_PER_CUSTOMER:
        return Response(
            {"success": False, "error": f"Maximum of {MAX_ADDRESSES_PER_CUSTOMER} addresses per customer."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    address_type = data.get("address_type", "billing")
    valid_address_types = [c[0] for c in CustomerAddress.ADDRESS_TYPE_CHOICES]
    if address_type not in valid_address_types:
        return Response(
            {"success": False, "error": f"Invalid address_type. Must be one of: {', '.join(valid_address_types)}"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    address_line1 = data.get("address_line1", "").strip() if isinstance(data.get("address_line1"), str) else ""
    city = data.get("city", "").strip() if isinstance(data.get("city"), str) else ""
    if not address_line1:
        return Response(
            {"success": False, "error": "address_line1 is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if not city:
        return Response(
            {"success": False, "error": "city is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    address = CustomerAddress.objects.create(
        customer=customer,
        address_type=address_type,
        is_current=data.get("is_current", True),
        address_line1=address_line1,
        address_line2=data.get("address_line2", ""),
        city=city,
        county=data.get("county", ""),
        country=data.get("country", "Romania"),
        postal_code=data.get("postal_code", ""),
    )
    logger.info(f"✅ [Customer API] Address {address.id} added to customer {customer.id}")
    return Response(
        {"success": True, "address_id": address.id, "message": "Address added."}, status=status.HTTP_201_CREATED
    )


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_addresses_update(request: HttpRequest, customer: Customer) -> Response:
    """Update an existing customer address."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    owner_error = _require_owner_role(user_id, customer)
    if owner_error:
        return owner_error

    address_id = data.get("address_id")
    if not address_id:
        return Response({"success": False, "error": "address_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        address = CustomerAddress.objects.get(id=address_id, customer=customer)
    except CustomerAddress.DoesNotExist:
        return Response({"success": False, "error": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

    updatable = {
        "address_type",
        "is_current",
        "address_line1",
        "address_line2",
        "city",
        "county",
        "country",
        "postal_code",
    }
    update_fields = []
    for field in updatable:
        if field in data:
            setattr(address, field, data[field])
            update_fields.append(field)

    if update_fields:
        address.save(update_fields=[*update_fields, "updated_at"])
        logger.info(f"✅ [Customer API] Address {address_id} updated for customer {customer.id}")

    return Response({"success": True, "message": "Address updated."})


@api_view(["POST"])
@authentication_classes([])
@permission_classes([AllowAny])
@require_customer_authentication
def customer_addresses_delete(request: HttpRequest, customer: Customer) -> Response:
    """Delete a customer address."""
    data = _get_request_data(request)
    try:
        user_id = _extract_user_id(data)
    except ValueError:
        return Response({"success": False, "error": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    owner_error = _require_owner_role(user_id, customer)
    if owner_error:
        return owner_error

    address_id = data.get("address_id")
    if not address_id:
        return Response({"success": False, "error": "address_id is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        address = CustomerAddress.objects.get(id=address_id, customer=customer)
    except CustomerAddress.DoesNotExist:
        return Response({"success": False, "error": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

    acting_user = User.objects.filter(id=user_id).first()
    address.soft_delete(user=acting_user)
    logger.info(f"✅ [Customer API] Address {address_id} soft-deleted from customer {customer.id}")
    return Response({"success": True, "message": "Address deleted."})
