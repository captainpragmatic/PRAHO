"""
Portal Customer Management Views — Team, Tax Profile, Addresses.

Provides views for managing team members, tax profile data, and billing
addresses for a customer organisation via the Platform API.
"""

import logging

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.decorators import (
    require_authentication,
    require_billing_access,
    require_customer_role,
)
from apps.common.rate_limit_feedback import is_rate_limited_error

logger = logging.getLogger(__name__)

# Roles that are allowed to manage team membership and addresses.
_OWNER_ROLES = ["owner"]

# Valid assignable role values — matches Platform CustomerMembership.ROLE_CHOICES.
_VALID_ROLES: frozenset[str] = frozenset({"viewer", "tech", "billing", "owner"})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_customer_context(request: HttpRequest) -> tuple[int | None, int | None]:
    """Return (customer_id, user_id) integers from session, or (None, None)."""
    raw_customer = request.session.get("selected_customer_id") or request.session.get("customer_id")
    raw_user = request.session.get("user_id")
    try:
        customer_id: int | None = int(raw_customer) if raw_customer is not None else None
    except (ValueError, TypeError):
        customer_id = None
    try:
        user_id: int | None = int(raw_user) if raw_user is not None else None
    except (ValueError, TypeError):
        user_id = None
    return customer_id, user_id


def _get_user_role(request: HttpRequest, customer_id: int | None) -> str | None:
    """Return the current user's role for *customer_id*, or None."""
    if customer_id is None:
        return None
    memberships = request.session.get("user_memberships", [])
    for m in memberships:
        if str(m.get("customer_id")) == str(customer_id):
            return str(m.get("role", ""))
    return None


# ---------------------------------------------------------------------------
# Internal validation helpers
# ---------------------------------------------------------------------------


def _validate_invite_input(role: str, email: str) -> str | None:
    """Validate team-invite POST inputs.

    Returns an error message string if validation fails, or None on success.
    """
    if role not in _VALID_ROLES:
        return str(_("Invalid role selected."))
    if not email:
        return str(_("Email address is required."))
    try:
        EmailValidator()(email)
    except ValidationError:
        return str(_("Enter a valid email address."))
    return None


# ---------------------------------------------------------------------------
# Team views
# ---------------------------------------------------------------------------


@require_authentication
@require_http_methods(["GET"])
def company_team_view(request: HttpRequest) -> HttpResponse:
    """List all team members for the currently selected customer."""
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        messages.error(request, _("No customer selected."))
        return redirect("users:company_profile")

    user_role = _get_user_role(request, customer_id)
    can_manage_team = user_role in _OWNER_ROLES

    team_users: list[dict] = []
    try:
        response = api_client.get_customer_users(customer_id, user_id)
        if isinstance(response, dict) and response.get("success"):
            raw = response.get("users") or response.get("results") or []
            team_users = raw if isinstance(raw, list) else []
    except PlatformAPIError as exc:
        if is_rate_limited_error(exc):
            messages.warning(request, _("Too many requests. Please wait and try again."))
        else:
            logger.error("Failed to fetch customer users: %s", exc)
            messages.error(request, _("Could not load team members. Please try again."))

    context = {
        "users": team_users,
        "can_manage_team": can_manage_team,
        "user_role": user_role,
        "page_title": _("Team Members"),
    }
    return render(request, "customers/team.html", context)


@require_customer_role(required_roles=_OWNER_ROLES)
@require_http_methods(["GET", "POST"])
def company_team_invite_view(request: HttpRequest) -> HttpResponse:
    """Invite (create and add) a new user to the customer's team."""
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        messages.error(request, _("No customer selected."))
        return redirect("users:company_profile")

    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        role = request.POST.get("role", "viewer").strip()

        invite_error = _validate_invite_input(role, email)
        if invite_error:
            messages.error(request, invite_error)
            return render(request, "customers/team_invite.html", {"page_title": _("Invite Team Member")})

        try:
            response = api_client.create_customer_user(
                customer_id=customer_id,
                user_id=user_id,
                email=email,
                first_name=first_name,
                last_name=last_name,
                role=role,
            )
            if isinstance(response, dict) and response.get("success"):
                messages.success(request, _("Team member invited successfully."))
                return redirect("customers:team")
            error_detail = response.get("error", "") if isinstance(response, dict) else ""
            messages.error(request, error_detail or _("Could not invite team member. Please try again."))
        except PlatformAPIError as exc:
            if is_rate_limited_error(exc):
                messages.warning(request, _("Too many requests. Please wait and try again."))
            else:
                logger.error("Failed to create customer user: %s", exc)
                messages.error(request, _("Could not invite team member. Please try again."))

        return render(request, "customers/team_invite.html", {"page_title": _("Invite Team Member")})

    return render(request, "customers/team_invite.html", {"page_title": _("Invite Team Member")})


@require_customer_role(required_roles=_OWNER_ROLES)
@require_http_methods(["POST"])
def company_team_role_view(request: HttpRequest, target_user_id: int) -> HttpResponse:
    """Change a team member's role (POST only)."""
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        messages.error(request, _("No customer selected."))
        return redirect("users:company_profile")

    new_role = request.POST.get("role", "").strip()
    if not new_role:
        messages.error(request, _("Role is required."))
        return redirect("customers:team")

    if new_role not in _VALID_ROLES:
        messages.error(request, _("Invalid role selected."))
        return redirect("customers:team")

    try:
        response = api_client.change_customer_user_role(
            customer_id=customer_id,
            user_id=user_id,
            target_user_id=target_user_id,
            new_role=new_role,
        )
        if isinstance(response, dict) and response.get("success"):
            messages.success(request, _("Role updated successfully."))
        else:
            error_detail = response.get("error", "") if isinstance(response, dict) else ""
            messages.error(request, error_detail or _("Could not update role. Please try again."))
    except PlatformAPIError as exc:
        if is_rate_limited_error(exc):
            messages.warning(request, _("Too many requests. Please wait and try again."))
        else:
            logger.error("Failed to change user role: %s", exc)
            messages.error(request, _("Could not update role. Please try again."))

    return redirect("customers:team")


@require_customer_role(required_roles=_OWNER_ROLES)
@require_http_methods(["POST"])
def company_team_remove_view(request: HttpRequest, target_user_id: int) -> HttpResponse:
    """Remove a user from the customer's team (POST only)."""
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        messages.error(request, _("No customer selected."))
        return redirect("users:company_profile")

    try:
        response = api_client.remove_customer_user(
            customer_id=customer_id,
            user_id=user_id,
            target_user_id=target_user_id,
        )
        if isinstance(response, dict) and response.get("success"):
            messages.success(request, _("Team member removed successfully."))
        else:
            error_detail = response.get("error", "") if isinstance(response, dict) else ""
            messages.error(request, error_detail or _("Could not remove team member. Please try again."))
    except PlatformAPIError as exc:
        if is_rate_limited_error(exc):
            messages.warning(request, _("Too many requests. Please wait and try again."))
        else:
            logger.error("Failed to remove customer user: %s", exc)
            messages.error(request, _("Could not remove team member. Please try again."))

    return redirect("customers:team")


# ---------------------------------------------------------------------------
# Tax profile view
# ---------------------------------------------------------------------------


@require_billing_access()
@require_http_methods(["GET", "POST"])
def company_tax_profile_view(request: HttpRequest) -> HttpResponse:
    """View and edit the customer's tax profile (CUI, VAT, reverse charge)."""
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        messages.error(request, _("No customer selected."))
        return redirect("users:company_profile")

    user_role = _get_user_role(request, customer_id)
    can_edit = user_role in ["owner", "billing"]

    if request.method == "POST" and can_edit:
        payload: dict[str, object] = {
            "cui": request.POST.get("cui", "").strip(),
            "vat_number": request.POST.get("vat_number", "").strip(),
            "registration_number": request.POST.get("trade_registry_number", "").strip(),
            "is_vat_payer": request.POST.get("is_vat_payer") == "on",
            "reverse_charge_eligible": request.POST.get("reverse_charge_eligible") == "on",
        }
        try:
            response = api_client.update_customer_tax_profile(
                customer_id=customer_id,
                user_id=user_id,
                data=payload,
            )
            if isinstance(response, dict) and response.get("success"):
                messages.success(request, _("Tax profile updated successfully."))
                return redirect("customers:tax_profile")
            error_detail = response.get("error", "") if isinstance(response, dict) else ""
            messages.error(request, error_detail or _("Could not update tax profile. Please try again."))
        except PlatformAPIError as exc:
            if is_rate_limited_error(exc):
                messages.warning(request, _("Too many requests. Please wait and try again."))
            else:
                logger.error("Failed to update tax profile: %s", exc)
                messages.error(request, _("Could not update tax profile. Please try again."))

    # Fetch current tax data via customer details endpoint (includes tax_profile)
    tax_data: dict = {}
    try:
        response = api_client.post(
            "customers/details/",
            data={
                "customer_id": customer_id,
                "user_id": user_id,
                "action": "get_customer_details",
                "include": ["tax_profile"],
            },
            user_id=user_id,
        )
        if isinstance(response, dict) and response.get("success"):
            customer = response.get("customer", {})
            tax_data = customer.get("tax_profile", {})
    except PlatformAPIError as exc:
        if is_rate_limited_error(exc):
            messages.warning(request, _("Too many requests. Please wait and try again."))
        else:
            logger.error("Failed to fetch tax profile: %s", exc)
            messages.error(request, _("Could not load tax profile. Please try again."))

    context = {
        "tax_data": tax_data,
        "can_edit": can_edit,
        "page_title": _("Tax Profile"),
    }
    return render(request, "customers/tax_profile.html", context)


# ---------------------------------------------------------------------------
# Address views
# ---------------------------------------------------------------------------


@require_authentication
@require_http_methods(["GET"])
def company_addresses_view(request: HttpRequest) -> HttpResponse:
    """List all addresses for the currently selected customer."""
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        messages.error(request, _("No customer selected."))
        return redirect("users:company_profile")

    user_role = _get_user_role(request, customer_id)
    can_manage = user_role in _OWNER_ROLES

    address_list: list[dict] = []
    try:
        response = api_client.get_customer_addresses(customer_id, user_id)
        if isinstance(response, dict) and response.get("success"):
            raw = response.get("addresses") or response.get("results") or []
            address_list = raw if isinstance(raw, list) else []
    except PlatformAPIError as exc:
        if is_rate_limited_error(exc):
            messages.warning(request, _("Too many requests. Please wait and try again."))
        else:
            logger.error("Failed to fetch addresses: %s", exc)
            messages.error(request, _("Could not load addresses. Please try again."))

    context = {
        "addresses": address_list,
        "can_manage": can_manage,
        "page_title": _("Addresses"),
    }
    return render(request, "customers/addresses.html", context)


@require_customer_role(required_roles=_OWNER_ROLES)
@require_http_methods(["GET", "POST"])
def company_address_add_view(request: HttpRequest) -> HttpResponse:
    """Add a new address to the customer's account."""
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        messages.error(request, _("No customer selected."))
        return redirect("users:company_profile")

    if request.method == "POST":
        is_primary = request.POST.get("is_primary") in ("on", "true", "1", "yes")
        is_billing = request.POST.get("is_billing") in ("on", "true", "1", "yes")
        label = request.POST.get("label", "").strip()
        payload: dict[str, object] = {
            "is_primary": is_primary,
            "is_billing": is_billing,
            "label": label,
            "address_line1": request.POST.get("address_line1", "").strip(),
            "address_line2": request.POST.get("address_line2", "").strip(),
            "city": request.POST.get("city", "").strip(),
            "county": request.POST.get("county", "").strip(),
            "country": request.POST.get("country", "RO").strip(),
            "postal_code": request.POST.get("postal_code", "").strip(),
        }
        try:
            response = api_client.add_customer_address(
                customer_id=customer_id,
                user_id=user_id,
                data=payload,
            )
            if isinstance(response, dict) and response.get("success"):
                messages.success(request, _("Address added successfully."))
                return redirect("customers:addresses")
            error_detail = response.get("error", "") if isinstance(response, dict) else ""
            messages.error(request, error_detail or _("Could not add address. Please try again."))
        except PlatformAPIError as exc:
            if is_rate_limited_error(exc):
                messages.warning(request, _("Too many requests. Please wait and try again."))
            else:
                logger.error("Failed to add address: %s", exc)
                messages.error(request, _("Could not add address. Please try again."))

        return render(request, "customers/address_form.html", {"page_title": _("Add Address")})

    return render(request, "customers/address_form.html", {"page_title": _("Add Address")})


@require_customer_role(required_roles=_OWNER_ROLES)
@require_http_methods(["POST"])
def company_address_delete_view(request: HttpRequest, address_id: int) -> HttpResponse:
    """Delete an address from the customer's account (POST only)."""
    customer_id, user_id = _get_customer_context(request)
    if customer_id is None or user_id is None:
        messages.error(request, _("No customer selected."))
        return redirect("users:company_profile")

    try:
        response = api_client.delete_customer_address(
            customer_id=customer_id,
            user_id=user_id,
            address_id=address_id,
        )
        if isinstance(response, dict) and response.get("success"):
            messages.success(request, _("Address deleted successfully."))
        else:
            error_detail = response.get("error", "") if isinstance(response, dict) else ""
            messages.error(request, error_detail or _("Could not delete address. Please try again."))
    except PlatformAPIError as exc:
        if is_rate_limited_error(exc):
            messages.warning(request, _("Too many requests. Please wait and try again."))
        else:
            logger.error("Failed to delete address: %s", exc)
            messages.error(request, _("Could not delete address. Please try again."))

    return redirect("customers:addresses")
