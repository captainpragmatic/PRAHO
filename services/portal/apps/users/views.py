"""
Portal Users Views
Customer-facing login/logout with Platform API validation using Django sessions.
"""

import logging

from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render, resolve_url
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import activate
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.decorators import (
    log_access_attempt,
    require_any_role,
    require_authentication,
    require_billing_access,
)
from apps.users.forms import (
    ChangePasswordForm,
    CompanyCreationForm,
    CompanyProfileForm,
    CustomerLoginForm,
    CustomerProfileForm,
    CustomerRegistrationForm,
    PasswordResetRequestForm,
)

logger = logging.getLogger(__name__)


def _handle_mfa_error_redirect(request: HttpRequest, target_view: str, error_msg: str) -> HttpResponse:
    """Helper to handle MFA error responses with consistent redirect"""
    messages.error(request, error_msg)
    return redirect(target_view)


def _handle_mfa_success_redirect(request: HttpRequest, target_view: str, success_msg: str) -> HttpResponse:
    """Helper to handle MFA success responses with consistent redirect"""
    messages.success(request, success_msg)
    return redirect(target_view)


def _check_authentication_or_redirect(request: HttpRequest) -> HttpResponse | None:
    """Check authentication and return redirect if not authenticated, None if authenticated"""
    if not request.session.get("customer_id"):
        return redirect("/login/")
    return None


def _get_user_customer_memberships(request: HttpRequest) -> list[dict] | None:
    """Get user's customer memberships from Platform API"""
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    try:
        response = api_client.post(
            "users/customers/",
            data={
                "customer_id": user_id,  # Note: Platform expects customer_id field, not user_id
                "action": "get_user_customers",
                "timestamp": int(timezone.now().timestamp()),
            },
            user_id=user_id,
        )

        if response and response.get("success") and "results" in response:
            # Transform the response to match expected format
            memberships = [
                {
                    "customer_id": customer.get("id"),
                    "customer_name": customer.get(
                        "name", customer.get("company_name", f"Customer {customer.get('id')}")
                    ),
                    "role": customer.get("role", "viewer"),  # Use actual role from Platform API
                    "company_name": customer.get("company_name", ""),
                    "is_primary": customer.get("is_primary", False),
                }
                for customer in response["results"]
            ]
            return memberships
        return None

    except PlatformAPIError as e:
        logger.error(f"🔥 [Portal] Failed to fetch user customers: {e}")
        return None


def _get_selected_customer_id(request: HttpRequest) -> str | None:
    """Get the currently selected customer ID, fallback to session customer_id"""
    selected_customer_id = request.session.get("selected_customer_id")
    if selected_customer_id:
        return selected_customer_id

    # Fallback to login customer_id for backward compatibility
    return request.session.get("customer_id")


def _get_user_role_for_customer(request: HttpRequest, customer_id: str) -> str | None:
    """Get user's role for specific customer from cached memberships"""
    memberships = request.session.get("user_memberships", [])
    for membership in memberships:
        if str(membership.get("customer_id")) == str(customer_id):
            return membership.get("role")
    return None


def _can_edit_company_profile(request: HttpRequest, customer_id: str) -> bool:
    """Check if user can edit company profile for given customer"""
    role = _get_user_role_for_customer(request, customer_id)
    return role in ["owner", "billing"]


def _handle_totp_setup_get(request: HttpRequest, customer_id: str, customer_email: str) -> HttpResponse:
    """Handle GET request for TOTP setup"""
    try:
        totp_data = api_client.setup_totp_mfa(customer_id)
        if not totp_data:
            return _handle_mfa_error_redirect(
                request, "users:mfa_management", _("Failed to initialize MFA setup. Please try again.")
            )

        context = {
            "qr_code": totp_data.get("qr_code"),
            "secret": totp_data.get("secret"),
            "customer_email": customer_email,
            "customer_id": customer_id,
            "page_title": _("Set Up Authenticator App"),
            "brand_name": "PRAHO Portal",
        }
        return render(request, "users/mfa_setup_totp.html", context)

    except Exception as e:
        logger.error(f"🔥 [Portal MFA] Error initializing TOTP setup: {e}")
        return _handle_mfa_error_redirect(request, "users:mfa_management", _("An error occurred. Please try again."))


def _handle_totp_setup_post(request: HttpRequest, customer_id: str, token: str) -> HttpResponse:
    """Handle POST request for TOTP setup verification"""
    if not token:
        return _handle_mfa_error_redirect(request, "users:mfa_setup_totp", _("Please enter the verification code."))

    try:
        success = api_client.verify_totp_mfa(customer_id, token)
        if success:
            logger.info(f"✅ [Portal 2FA] TOTP enabled successfully for customer {customer_id}")
            return _handle_mfa_success_redirect(
                request, "users:mfa_management", _("Two-factor authentication has been enabled successfully!")
            )
        else:
            return _handle_mfa_error_redirect(
                request, "users:mfa_setup_totp", _("Invalid verification code. Please try again.")
            )

    except Exception as e:
        logger.error(f"🔥 [Portal 2FA] Error verifying TOTP: {e}")
        return _handle_mfa_error_redirect(request, "users:mfa_setup_totp", _("An error occurred. Please try again."))


def _get_safe_redirect_target(request: HttpRequest, fallback: str = "/dashboard/") -> str:
    """
    Validate and return a safe redirect target.
    Accepts only URLs that are on this host and use the expected scheme,
    otherwise returns the resolved fallback URL.
    """
    raw_next = request.GET.get("next") or request.POST.get("next") or ""

    # Resolve fallback first (can be a URL name or path)
    fallback_url = resolve_url(fallback)

    if not raw_next:
        return fallback_url

    # Allow only same-host redirects and proper scheme
    if url_has_allowed_host_and_scheme(raw_next, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return raw_next

    logger.warning(f"⚠️ [Portal Auth] Unsafe redirect target blocked: {raw_next}")
    return fallback_url


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    """
    Portal login view using Django sessions.
    Validates credentials via Platform API and creates secure sessions.
    """

    # Redirect if already authenticated
    if request.session.get("customer_id"):
        next_url = _get_safe_redirect_target(request, fallback="/dashboard/")
        return redirect(next_url)

    if request.method == "GET":
        form = CustomerLoginForm()
    else:  # POST
        form = CustomerLoginForm(request.POST)

        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]
            remember_me = form.cleaned_data.get("remember_me", False)

            try:
                # Validate credentials via Platform API
                auth_response = api_client.authenticate_customer(email, password)

                if auth_response and auth_response.get("valid"):
                    # Successful authentication - create Django session
                    user_id = auth_response.get("user_id")
                    customer_id = auth_response.get("customer_id")

                    logger.info(f"✅ [Portal Auth] Customer {email} authenticated successfully")

                    # ✅ CRITICAL: Prevent session fixation attacks
                    request.session.cycle_key()

                    # Store in Django session (secure, handled by framework)
                    # Store correct user_id (platform user.id) and primary customer_id separately
                    # Middleware will resolve active_customer_id from accessible customers list
                    request.session["user_id"] = user_id
                    request.session["customer_id"] = customer_id  # Legacy field, prefer active_customer_id
                    request.session["email"] = email
                    request.session["authenticated_at"] = timezone.now().isoformat()
                    request.session["remember_me"] = remember_me

                    # Fetch and cache user's customer memberships for role-based access
                    try:
                        memberships = _get_user_customer_memberships(request)
                        if memberships:
                            request.session["user_memberships"] = memberships
                    except Exception:
                        logger.debug("Could not fetch memberships on login")

                    # Set session expiry based on remember me checkbox
                    if remember_me:
                        session_age = settings.SESSION_COOKIE_AGE_REMEMBER_ME  # 30 days
                        logger.info(f"✅ [Portal Session] Extended session set for {email} (30 days)")
                    else:
                        session_age = settings.SESSION_COOKIE_AGE_DEFAULT  # 24 hours
                        logger.info(f"✅ [Portal Session] Standard session set for {email} (24 hours)")

                    request.session.set_expiry(session_age)

                    # Get customer name for personalized message
                    try:
                        profile_data = api_client.get_customer_profile(user_id)
                        if profile_data and profile_data.get("first_name"):
                            customer_name = profile_data.get("first_name")
                            messages.success(request, f"Sign in confirmed, {customer_name}!")
                        else:
                            # Fallback to email if name not available
                            messages.success(request, "Sign in confirmed!")
                    except Exception as e:
                        logger.warning(f"⚠️ [Portal Auth] Could not fetch profile for personalized message: {e}")
                        messages.success(request, "Sign in confirmed!")

                    next_url = _get_safe_redirect_target(request, fallback="/dashboard/")
                    return redirect(next_url)

                else:
                    logger.warning(f"⚠️ [Portal Auth] Invalid credentials for {email}")
                    messages.error(request, _("Invalid email address or password. Please try again."))

            except PlatformAPIError as e:
                logger.error(f"🔥 [Portal Auth] Platform API error during login: {e}")
                messages.error(request, _("Authentication service is temporarily unavailable. Please try again later."))

            except Exception as e:
                logger.error(f"🔥 [Portal Auth] Unexpected error during login: {e}")
                messages.error(request, _("An unexpected error occurred. Please try again."))

    context = {
        "form": form,
        "page_title": _("Customer Login"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/login.html", context)


@never_cache
@require_http_methods(["GET", "POST"])
def logout_view(request: HttpRequest) -> HttpResponse:
    """
    Secure logout using Django session flush (rotates session key).
    """

    # Log the logout
    customer_id = request.session.get("customer_id", "unknown")
    logger.info(f"✅ [Portal Auth] Customer {customer_id} logged out")

    if request.method == "POST":
        # Flush session (secure - rotates session key)
        request.session.flush()
        messages.success(request, _("You have been logged out successfully."))
        return redirect("/login/")

    # GET requests redirect to login
    return redirect("/login/")


def check_authentication(request: HttpRequest) -> dict | None:
    """
    Helper function to check if request is authenticated via Django session.

    Note: This only checks session existence. For views that need fresh customer data,
    call Platform API directly. Session validation happens at middleware level.
    """
    customer_id = request.session.get("customer_id")

    if not customer_id:
        return None

    # Return session data - middleware will handle deeper validation if needed
    return {
        "customer_id": customer_id,
        "email": request.session.get("email"),
        "authenticated_at": request.session.get("authenticated_at"),
    }


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def register_view(request: HttpRequest) -> HttpResponse:
    """
    Customer registration view using Platform API.
    Creates new customer accounts with Romanian business compliance.
    """

    # Redirect if already authenticated
    if request.session.get("customer_id"):
        return redirect("/dashboard/")

    if request.method == "GET":
        form = CustomerRegistrationForm()
    else:  # POST
        form = CustomerRegistrationForm(request.POST)

        if form.is_valid():
            try:
                # Register customer via Platform API
                registration_result = form.register_customer()

                if registration_result:
                    email = form.cleaned_data["email"]
                    logger.info(f"✅ [Portal Registration] Customer {email} registered successfully")

                    messages.success(request, _("Registration successful! You can now login with your credentials."))
                    return redirect("/login/")
                else:
                    messages.error(request, _("Registration failed. Please check your information and try again."))

            except Exception as e:
                logger.error(f"🔥 [Portal Registration] Unexpected error: {e}")
                messages.error(request, _("An unexpected error occurred during registration. Please try again."))

    context = {
        "form": form,
        "page_title": _("Customer Registration"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/register.html", context)


def _load_profile_form_data(request: HttpRequest, user_id: int) -> CustomerProfileForm:
    """Load and initialize profile form with existing data"""
    try:
        profile_data = api_client.get_customer_profile(user_id)

        if profile_data:
            return CustomerProfileForm(
                initial={
                    "first_name": profile_data.get("first_name", ""),
                    "last_name": profile_data.get("last_name", ""),
                    "phone": profile_data.get("phone", ""),
                    "preferred_language": profile_data.get("profile", {}).get("preferred_language", "en"),
                    "timezone": profile_data.get("profile", {}).get("timezone", "Europe/Bucharest"),
                }
            )
        else:
            return CustomerProfileForm()

    except Exception as e:
        logger.error(f"🔥 [Portal Profile] Error loading profile: {e}")
        messages.error(request, _("Error loading profile data."))
        return CustomerProfileForm()


def _handle_profile_update(
    request: HttpRequest, form: CustomerProfileForm, user_id: int, customer_id: str
) -> HttpResponse | None:
    """Handle profile update and return redirect response if successful"""
    if not form.is_valid():
        return None

    try:
        update_data = {
            "first_name": form.cleaned_data["first_name"],
            "last_name": form.cleaned_data["last_name"],
            "phone": form.cleaned_data["phone"],
            "preferred_language": form.cleaned_data.get("preferred_language", "en"),
            "timezone": form.cleaned_data.get("timezone", "Europe/Bucharest"),
        }

        result = api_client.update_customer_profile(user_id, update_data)

        if result:
            logger.info(f"✅ [Portal Profile] Profile updated for customer {customer_id}")

            # Handle language change
            new_language = form.cleaned_data.get("preferred_language", "en")
            current_language = request.session.get("_language", "en")

            if new_language != current_language:
                request.session["_language"] = new_language
                # Activate language immediately for this request (same as /i18n/setlang/)
                activate(new_language)
                logger.info(
                    f"✅ [Portal Profile] Language changed from {current_language} to {new_language} for customer {customer_id}"
                )
                logger.info(
                    f"🌐 [Portal Profile] Language activated: {new_language}, Test translation: {_('Language')}"
                )
                messages.success(request, _("Profile and language updated successfully!"))
            else:
                messages.success(request, _("Profile updated successfully!"))

            return redirect("users:profile")
        else:
            messages.error(request, _("Error updating profile. Please try again."))

    except Exception as e:
        logger.error(f"🔥 [Portal Profile] Error updating profile: {e}")
        messages.error(request, _("Error updating profile. Please try again."))

    return None


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
@require_authentication
@log_access_attempt
def profile_view(request: HttpRequest) -> HttpResponse:
    """
    🔒 Customer profile management view.
    Updates customer profile via Platform API with proper access control.
    """

    # Get IDs from session
    customer_id = request.session.get("customer_id")
    user_id = request.session.get("user_id")
    customer_email = request.session.get("email")

    if request.method == "GET":
        form = _load_profile_form_data(request, user_id)
    else:  # POST
        form = CustomerProfileForm(request.POST)

        # Handle profile update
        redirect_response = _handle_profile_update(request, form, user_id, customer_id)
        if redirect_response:
            return redirect_response

    # Get profile data from Platform API for context
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(user_id) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")

    # Load user memberships for customer selector
    if not request.session.get("user_memberships"):
        memberships = _get_user_customer_memberships(request)
        if memberships:
            request.session["user_memberships"] = memberships
            # Set default selected customer if not set
            if not request.session.get("selected_customer_id"):
                request.session["selected_customer_id"] = customer_id
                # Find the customer name and role for the default customer
                for membership in memberships:
                    if str(membership.get("customer_id")) == str(customer_id):
                        request.session["selected_customer_name"] = membership.get(
                            "customer_name", f"Customer {customer_id}"
                        )
                        request.session["selected_customer_role"] = membership.get("role", "viewer")
                        break

    context = {
        "form": form,
        "profile": profile_data,
        "customer_email": customer_email,
        "customer_id": customer_id,
        "page_title": _("Account Settings"),
        "brand_name": "PRAHO Portal",
        "user_memberships": request.session.get("user_memberships", []),
        "selected_customer_id": request.session.get("selected_customer_id", customer_id),
        "selected_customer_name": request.session.get("selected_customer_name", ""),
        "selected_customer_role": request.session.get("selected_customer_role", ""),
    }

    return render(request, "users/profile.html", context)


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def password_reset_view(request: HttpRequest) -> HttpResponse:
    """
    Password reset request view.
    Sends reset email via Platform API.
    """

    # Allow authenticated users to reset password

    if request.method == "GET":
        form = PasswordResetRequestForm()
    else:  # POST
        form = PasswordResetRequestForm(request.POST)

        if form.is_valid():
            email = form.cleaned_data["email"]
            try:
                # TODO: Call Platform API to send password reset email
                logger.info(f"✅ [Portal Password Reset] Reset requested for {email}")
                messages.success(
                    request, _("If an account with that email exists, you will receive password reset instructions.")
                )
                return redirect("/login/")

            except Exception as e:
                logger.error(f"🔥 [Portal Password Reset] Error requesting reset: {e}")
                messages.error(request, _("Error processing password reset request. Please try again."))

    context = {
        "form": form,
        "page_title": _("Password Reset"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/password_reset.html", context)


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def change_password_view(request: HttpRequest) -> HttpResponse:
    """
    Change password view for authenticated users.
    Allows logged-in users to change their password by providing current password.
    """

    # Check authentication - redirect to login if not authenticated
    if not request.session.get("customer_id"):
        return redirect("/login/")

    customer_id = request.session.get("customer_id")
    user_id = request.session.get("user_id")
    customer_email = request.session.get("email")

    if request.method == "GET":
        form = ChangePasswordForm()
    else:  # POST
        form = ChangePasswordForm(request.POST)

        if form.is_valid():
            current_password = form.cleaned_data["current_password"]
            new_password = form.cleaned_data["new_password"]

            try:
                # First verify current password via Platform API
                auth_response = api_client.authenticate_customer(customer_email, current_password)

                if not auth_response or not auth_response.get("valid"):
                    logger.warning(f"⚠️ [Portal Change Password] Invalid current password for {customer_email}")
                    messages.error(request, _("Current password is incorrect."))
                else:
                    # Update password via Platform API
                    update_result = api_client.update_customer_password(user_id, new_password)

                    if update_result:
                        logger.info(
                            f"✅ [Portal Change Password] Password changed successfully for customer {customer_id}"
                        )
                        messages.success(request, _("Password changed successfully!"))
                        return redirect("users:profile")
                    else:
                        logger.error(
                            f"🔥 [Portal Change Password] Failed to update password for customer {customer_id}"
                        )
                        messages.error(request, _("Error updating password. Please try again."))

            except PlatformAPIError as e:
                logger.error(f"🔥 [Portal Change Password] Platform API error: {e}")
                messages.error(request, _("Authentication service is temporarily unavailable. Please try again later."))

            except Exception as e:
                logger.error(f"🔥 [Portal Change Password] Unexpected error: {e}")
                messages.error(request, _("An unexpected error occurred. Please try again."))

    context = {
        "form": form,
        "customer_email": customer_email,
        "page_title": _("Change Password"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/change_password.html", context)


@never_cache
@require_http_methods(["GET"])
def privacy_dashboard_view(request: HttpRequest) -> HttpResponse:
    """
    Privacy dashboard view for authenticated users.
    Displays privacy settings and GDPR controls.
    """

    # Check authentication - redirect to login if not authenticated
    if not request.session.get("customer_id"):
        return redirect("/login/")

    customer_id = request.session.get("customer_id")
    customer_email = request.session.get("email")

    # Get customer profile data with privacy information
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(customer_id) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")

    context = {
        "profile": profile_data,
        "customer_email": customer_email,
        "customer_id": customer_id,
        "page_title": _("Privacy Dashboard"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/privacy_dashboard.html", context)


@never_cache
@require_http_methods(["GET", "POST"])
def data_export_view(request: HttpRequest) -> HttpResponse:
    """
    Data export request view for authenticated users.
    Allows users to request export of their personal data (GDPR Article 20).
    """

    # Check authentication - redirect to login if not authenticated
    if not request.session.get("customer_id"):
        return redirect("/login/")

    customer_id = request.session.get("customer_id")
    customer_email = request.session.get("email")

    if request.method == "POST":
        try:
            user_id = request.session.get("user_id")
            if not user_id:
                messages.error(request, _("Authentication required."))
                return redirect("users:data_export")

            result = api_client.request_data_export_secure(user_id)
            if result.get("success"):
                logger.info(f"✅ [Portal Data Export] Request created: export_id={result.get('export_id')}")
                messages.success(
                    request,
                    _(
                        "Data export request submitted successfully. You will receive an email with download instructions within 48 hours."
                    ),
                )
            else:
                messages.error(request, _("Failed to create export request. Please try again."))

        except PlatformAPIError:
            logger.warning("⚠️ [Portal Data Export] Platform API unavailable")
            messages.error(request, _("Service temporarily unavailable. Please try again later."))
        except Exception as e:
            logger.error(f"🔥 [Portal Data Export] Error processing request: {e}")
            messages.error(request, _("Error processing your data export request. Please try again."))

        # PRG: redirect after POST to prevent re-submission on refresh
        return redirect("users:data_export")

    # Fetch recent export requests for status display
    exports = []
    try:
        user_id = request.session.get("user_id")
        if user_id:
            result = api_client.get_data_export_status(user_id)
            if result.get("success"):
                exports = result.get("exports", [])
    except PlatformAPIError:
        logger.warning("⚠️ [Portal Data Export] Could not fetch export status")

    context = {
        "customer_email": customer_email,
        "customer_id": customer_id,
        "exports": exports,
        "page_title": _("Export My Data"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/data_export.html", context)


@never_cache
@require_http_methods(["GET"])
def consent_history_view(request: HttpRequest) -> HttpResponse:
    """
    Consent history view for authenticated users.
    Displays history of GDPR consents and marketing preferences.
    """

    # Check authentication - redirect to login if not authenticated
    if not request.session.get("customer_id"):
        return redirect("/login/")

    customer_id = request.session.get("customer_id")
    customer_email = request.session.get("email")

    # Get customer profile data with consent information
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(customer_id) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")

    # Fetch real consent history from Platform GDPR API
    consent_history = []
    cookie_consent_history = []
    try:
        user_id = request.session.get("user_id")
        if user_id:
            result = api_client.get_consent_history_secure(user_id)
            if result.get("success"):
                consent_history = result.get("consent_history", [])
                cookie_consent_history = result.get("cookie_consent_history", [])
    except PlatformAPIError:
        logger.warning("⚠️ [Portal Consent] Failed to fetch consent history from Platform")

    context = {
        "profile": profile_data,
        "customer_email": customer_email,
        "customer_id": customer_id,
        "consent_history": consent_history,
        "cookie_consent_history": cookie_consent_history,
        "page_title": _("Consent History"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/consent_history.html", context)


@never_cache
@require_http_methods(["GET"])
def mfa_management_view(request: HttpRequest) -> HttpResponse:
    """
    Multi-factor authentication management view for authenticated users.
    Allows users to enable/disable MFA and manage backup codes.
    """

    # Check authentication - redirect to login if not authenticated
    if not request.session.get("customer_id"):
        return redirect("/login/")

    customer_id = request.session.get("customer_id")
    customer_email = request.session.get("email")

    # Get customer profile data with 2FA status
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(customer_id) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")

    # Check if MFA is enabled for this customer
    mfa_enabled = profile_data.get("mfa_enabled", False)

    context = {
        "profile": profile_data,
        "customer_email": customer_email,
        "customer_id": customer_id,
        "mfa_enabled": mfa_enabled,
        "page_title": _("Multi-Factor Authentication"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/mfa_management.html", context)


@never_cache
@require_http_methods(["GET", "POST"])
def mfa_setup_totp_view(request: HttpRequest) -> HttpResponse:
    """
    TOTP (Authenticator App) MFA setup view for authenticated users.
    """

    # Check authentication - redirect to login if not authenticated
    auth_redirect = _check_authentication_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    customer_id = str(request.session.get("customer_id"))
    customer_email = request.session.get("email")

    if request.method == "GET":
        return _handle_totp_setup_get(request, customer_id, customer_email)
    else:  # POST - verify TOTP token
        token = request.POST.get("token", "").strip()
        return _handle_totp_setup_post(request, customer_id, token)


@never_cache
@require_http_methods(["GET"])
def mfa_backup_codes_view(request: HttpRequest) -> HttpResponse:
    """
    View and regenerate backup codes for authenticated users.
    """

    # Check authentication - redirect to login if not authenticated
    if not request.session.get("customer_id"):
        return redirect("/login/")

    customer_id = request.session.get("customer_id")
    customer_email = request.session.get("email")

    # Check if user has 2FA enabled
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(str(customer_id)) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")

    if not profile_data.get("mfa_enabled"):
        messages.warning(request, _("You need to enable 2FA first before accessing backup codes."))
        return redirect("users:mfa_management")

    # Get backup codes
    backup_codes = []
    try:
        backup_codes = api_client.get_backup_codes(str(customer_id)) or []
    except Exception as e:
        logger.error(f"🔥 [Portal 2FA] Error getting backup codes: {e}")
        messages.error(request, _("Error loading backup codes."))

    context = {
        "backup_codes": backup_codes,
        "customer_email": customer_email,
        "customer_id": customer_id,
        "page_title": _("Backup Codes"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/mfa_backup_codes.html", context)


@never_cache
@require_http_methods(["POST"])
def mfa_disable_view(request: HttpRequest) -> HttpResponse:
    """
    Disable 2FA for authenticated users.
    """

    # Check authentication - redirect to login if not authenticated
    if not request.session.get("customer_id"):
        return redirect("/login/")

    customer_id = request.session.get("customer_id")

    try:
        success = api_client.disable_mfa(str(customer_id))
        if success:
            logger.info(f"✅ [Portal 2FA] 2FA disabled successfully for customer {customer_id}")
            messages.success(request, _("Two-factor authentication has been disabled."))
        else:
            messages.error(request, _("Failed to disable 2FA. Please try again."))

    except Exception as e:
        logger.error(f"🔥 [Portal 2FA] Error disabling 2FA: {e}")
        messages.error(request, _("An error occurred. Please try again."))

    return redirect("users:mfa_management")


@never_cache
@require_http_methods(["GET"])
@require_any_role()
@log_access_attempt
def company_profile_view(request: HttpRequest) -> HttpResponse:
    """
    🔒 Company profile view - displays current company information.
    Shows company details including billing address, VAT number, contact information.
    Requires valid customer role access.
    """

    # Get selected customer context
    customer_id = _get_selected_customer_id(request)
    if not customer_id:
        messages.error(request, _("Please select a customer to view profile."))
        return redirect("/profile/")

    user_id = request.session.get("user_id")

    # Load user memberships if not cached
    if not request.session.get("user_memberships"):
        memberships = _get_user_customer_memberships(request)
        if memberships:
            request.session["user_memberships"] = memberships

    # Fetch company profile data from Platform API
    company_data = {}
    try:
        response = api_client.post(
            "customers/details/",
            data={
                "customer_id": customer_id,
                "user_id": user_id,
                "action": "get_customer_details",
                "timestamp": int(timezone.now().timestamp()),
                "include": ["billing_profile", "tax_profile"],
            },
            user_id=user_id,
        )

        if response.get("success"):
            customer = response.get("customer", {})
            billing_profile = customer.get("billing_profile", {})
            tax_profile = customer.get("tax_profile", {})

            company_data = {
                "company_name": customer.get("company_name", ""),
                "vat_number": tax_profile.get("vat_number", ""),
                "trade_registry_number": customer.get("trade_registry_number", ""),
                "primary_email": customer.get("primary_email", ""),
                "primary_phone": customer.get("primary_phone", ""),
                "website": customer.get("website", ""),
                "industry": customer.get("industry", ""),
                "billing_street": billing_profile.get("address_street", ""),
                "billing_city": billing_profile.get("address_city", ""),
                "billing_state": billing_profile.get("address_state", ""),
                "billing_postal_code": billing_profile.get("address_postal_code", ""),
                "billing_country": billing_profile.get("address_country", "RO"),
                "status": customer.get("status", ""),
                "customer_type": customer.get("customer_type", ""),
            }
        else:
            messages.error(request, _("Unable to load company profile data."))

    except PlatformAPIError as e:
        logger.error(f"🔥 [Portal] Company profile API error: {e}")
        messages.error(request, _("Error loading company profile. Please try again."))
    except Exception as e:
        logger.error(f"🔥 [Portal] Unexpected error loading company profile: {e}")
        messages.error(request, _("An unexpected error occurred."))

    context = {
        "company_data": company_data,
        "customer_email": request.session.get("email"),
        "page_title": _("Company Profile"),
        "brand_name": "PRAHO Portal",
        "selected_customer_id": customer_id,
        "selected_customer_name": request.session.get("selected_customer_name", ""),
        "selected_customer_role": request.session.get("selected_customer_role", ""),
        "can_edit_profile": _can_edit_company_profile(request, customer_id),
    }

    return render(request, "users/company_profile.html", context)


@never_cache
@require_http_methods(["GET", "POST"])
@require_billing_access()
@log_access_attempt
def company_profile_edit_view(request: HttpRequest) -> HttpResponse:
    """
    🔒 Company profile edit view - allows editing company information.
    Updates company details via Platform API with form validation.
    Requires billing or admin role access.
    """

    # Get selected customer context
    customer_id = _get_selected_customer_id(request)
    if not customer_id:
        messages.error(request, _("Please select a customer to edit profile."))
        return redirect("/profile/")

    user_id = request.session.get("user_id")

    # Check if user can edit company profile for this customer
    if not _can_edit_company_profile(request, customer_id):
        role = _get_user_role_for_customer(request, customer_id)
        messages.error(
            request,
            _("You don't have permission to edit this company profile. Your role: {role}").format(
                role=role or "Unknown"
            ),
        )
        return redirect("users:company_profile")

    if request.method == "GET":
        # Load current data and populate form
        form = CompanyProfileForm()

        try:
            response = api_client.post(
                "customers/details/",
                data={
                    "customer_id": customer_id,
                    "user_id": user_id,
                    "action": "get_customer_details",
                    "timestamp": int(timezone.now().timestamp()),
                    "include": ["billing_profile", "tax_profile"],
                },
                user_id=user_id,
            )

            if response.get("success"):
                customer = response.get("customer", {})
                billing_profile = customer.get("billing_profile", {})
                tax_profile = customer.get("tax_profile", {})

                initial_data = {
                    "company_name": customer.get("company_name", ""),
                    "vat_number": tax_profile.get("vat_number", ""),
                    "trade_registry_number": customer.get("trade_registry_number", ""),
                    "primary_email": customer.get("primary_email", ""),
                    "primary_phone": customer.get("primary_phone", ""),
                    "website": customer.get("website", ""),
                    "industry": customer.get("industry", ""),
                    "billing_street": billing_profile.get("address_street", ""),
                    "billing_city": billing_profile.get("address_city", ""),
                    "billing_state": billing_profile.get("address_state", ""),
                    "billing_postal_code": billing_profile.get("address_postal_code", ""),
                    "billing_country": billing_profile.get("address_country", "RO"),
                }
                form = CompanyProfileForm(initial=initial_data)
            else:
                messages.error(request, _("Unable to load current company data."))

        except Exception as e:
            logger.error(f"🔥 [Portal] Error loading company data for edit: {e}")
            messages.error(request, _("Error loading company data. Please try again."))

    else:  # POST - handle form submission
        form = CompanyProfileForm(request.POST)

        if form.is_valid():
            try:
                # Update company profile via Platform API using existing billing-address endpoint
                update_data = {
                    "customer_id": customer_id,
                    "user_id": user_id,
                    "timestamp": int(timezone.now().timestamp()),
                    "company_name": form.cleaned_data["company_name"],
                    "vat_number": form.cleaned_data["vat_number"],
                    "trade_registry_number": form.cleaned_data["trade_registry_number"],
                    "primary_email": form.cleaned_data["primary_email"],
                    "primary_phone": form.cleaned_data["primary_phone"],
                    "website": form.cleaned_data["website"],
                    "industry": form.cleaned_data["industry"],
                    "billing_address": {
                        "street": form.cleaned_data["billing_street"],
                        "city": form.cleaned_data["billing_city"],
                        "state": form.cleaned_data["billing_state"],
                        "postal_code": form.cleaned_data["billing_postal_code"],
                        "country": form.cleaned_data["billing_country"],
                    },
                }

                response = api_client.post("customers/billing-address/", data=update_data, user_id=user_id)

                if response.get("success"):
                    logger.info(f"✅ [Portal] Company profile updated successfully for customer {customer_id}")
                    messages.success(request, _("Company profile updated successfully!"))

                    # Handle redirect based on 'next' parameter for order flow continuity
                    next_url = request.GET.get("next") or request.POST.get("next")
                    if next_url and url_has_allowed_host_and_scheme(
                        url=next_url,
                        allowed_hosts={request.get_host()},
                        require_https=request.is_secure(),
                    ):
                        logger.info(f"✅ [Portal] Redirecting to next URL after profile update: {next_url}")
                        return redirect(next_url)

                    return redirect("users:company_profile")
                else:
                    error_msg = response.get("error", "Unknown error occurred")
                    messages.error(request, _("Failed to update profile: {}").format(error_msg))

            except PlatformAPIError as e:
                logger.error(f"🔥 [Portal] Company profile update API error: {e}")
                messages.error(request, _("Error updating company profile. Please try again."))
            except Exception as e:
                logger.error(f"🔥 [Portal] Unexpected error updating company profile: {e}")
                messages.error(request, _("An unexpected error occurred while updating profile."))
        else:
            messages.error(request, _("Please correct the errors below."))

    context = {
        "form": form,
        "customer_email": request.session.get("email"),
        "page_title": _("Edit Company Profile"),
        "brand_name": "PRAHO Portal",
        "selected_customer_id": customer_id,
        "selected_customer_name": request.session.get("selected_customer_name", ""),
        "selected_customer_role": request.session.get("selected_customer_role", ""),
    }

    return render(request, "users/company_profile_edit.html", context)


@never_cache
@require_http_methods(["POST"])
@csrf_protect
def switch_customer_view(request: HttpRequest) -> HttpResponse:
    """
    🔒 Switch active customer context for multi-customer users.
    Updates session with selected customer and refreshes customer data.
    Enhanced with real-time Platform API verification for security.
    """

    # Check authentication
    auth_redirect = _check_authentication_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    user_id = request.session.get("user_id")
    customer_id = request.POST.get("customer_id")

    if not customer_id:
        logger.warning(f"🚨 [Security] Empty customer_id in switch request from user {user_id}")
        messages.error(request, _("Please select a valid customer."))
        return redirect(request.META.get("HTTP_REFERER", "/profile/"))

    # 🔒 SECURITY: Real-time verification with Platform API
    try:
        response = api_client.post(
            "users/verify-customer-access/",
            {
                "user_id": user_id,
                "customer_id": customer_id,
                "timestamp": int(timezone.now().timestamp()),
                "action": "switch_customer",
            },
            user_id=user_id,
        )

        if not response or not response.get("success"):
            logger.warning(
                f"🚨 [Security] Platform API rejected customer switch: user {user_id} -> customer {customer_id}"
            )
            messages.error(request, _("Customer access verification failed. Please try again."))
            return redirect("/profile/")

        # Extract verified access information
        verification_data = response.get("data", {})
        if not verification_data.get("has_access"):
            logger.warning(
                f"🚨 [Security] Unauthorized customer switch attempt: user {user_id} -> customer {customer_id}"
            )
            messages.error(request, _("You don't have access to this customer."))
            return redirect("/profile/")

        # Get verified customer information
        selected_customer_name = verification_data.get("customer_name", f"Customer {customer_id}")
        selected_role = verification_data.get("role", "viewer")
        # Note: permissions available if needed for future use
        # permissions = verification_data.get('permissions', [])  # noqa: ERA001

    except PlatformAPIError as e:
        logger.error(
            f"🔥 [Security] Customer switch verification failed: user {user_id} -> customer {customer_id}, error: {e}"
        )
        messages.error(request, _("Unable to verify customer access. Please try again."))
        return redirect("/profile/")

    # 🔒 SECURITY: Also verify against cached memberships as backup
    memberships = _get_user_customer_memberships(request)
    if memberships:
        cached_access = any(str(membership.get("customer_id")) == str(customer_id) for membership in memberships)

        if not cached_access:
            logger.warning(
                f"🚨 [Security] Customer not found in cached memberships: user {user_id} -> customer {customer_id}"
            )
            # Still allow switch if Platform API approved, but log the discrepancy
            logger.warning("🚨 [Security] Cached memberships out of sync with Platform API")

    # Update session with verified customer information
    request.session["selected_customer_id"] = customer_id
    request.session["selected_customer_name"] = selected_customer_name
    request.session["selected_customer_role"] = selected_role

    # Update cached memberships with fresh data
    if memberships:
        request.session["user_memberships"] = memberships

    # 🔒 SECURITY: Log successful customer switch
    logger.info(
        f"✅ [Security] Customer switch successful: "
        f"user {user_id} -> customer {customer_id} ({selected_customer_name}) "
        f"with role {selected_role}"
    )

    # Success message with customer context
    role_display = {
        "owner": _("Owner"),
        "admin": _("Administrator"),
        "billing": _("Billing Manager"),
        "technical": _("Technical Manager"),
        "viewer": _("Viewer"),
    }.get(selected_role, selected_role.title())

    messages.success(
        request, _("Switched to {customer} ({role})").format(customer=selected_customer_name, role=role_display)
    )

    # Redirect to the page they came from, or profile by default
    next_url = request.POST.get("next", request.META.get("HTTP_REFERER", "/profile/"))
    return redirect(next_url)


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def create_company_view(request: HttpRequest) -> HttpResponse:
    """
    Create new company profile for authenticated user.
    User becomes owner of the new company.
    """

    # Check authentication
    auth_redirect = _check_authentication_or_redirect(request)
    if auth_redirect:
        return auth_redirect

    user_id = request.session.get("user_id")

    if request.method == "GET":
        # Show empty form
        form = CompanyCreationForm()
    else:  # POST - handle form submission
        form = CompanyCreationForm(request.POST)

        if form.is_valid():
            try:
                # Prepare data for Platform API
                company_data = {
                    "user_id": user_id,
                    "action": "create_company",
                    "timestamp": int(timezone.now().timestamp()),
                    "company_data": {
                        "name": form.cleaned_data["company_name"],
                        "company_name": form.cleaned_data["company_name"],
                        "vat_number": form.cleaned_data.get("vat_number", ""),
                        "trade_registry_number": form.cleaned_data.get("trade_registry_number", ""),
                        "industry": form.cleaned_data.get("industry", ""),
                        # Billing address
                        "billing_address": {
                            "street_address": form.cleaned_data["street_address"],
                            "city": form.cleaned_data["city"],
                            "state": form.cleaned_data.get("state", ""),
                            "postal_code": form.cleaned_data.get("postal_code", ""),
                            "country": form.cleaned_data.get("country", "România"),
                        },
                        # Business contact
                        "contact": {
                            "primary_email": form.cleaned_data["primary_email"],
                            "primary_phone": form.cleaned_data.get("primary_phone", ""),
                            "website": form.cleaned_data.get("website", ""),
                        },
                    },
                }

                # Call Platform API to create company
                response = api_client.post("customers/create/", data=company_data, user_id=user_id)

                if response.get("success"):
                    new_customer_id = response.get("customer_id")
                    company_name = form.cleaned_data["company_name"]

                    logger.info(f"✅ [Portal] Company '{company_name}' created successfully with ID {new_customer_id}")
                    messages.success(
                        request, _("Company '{}' created successfully! You are now the owner.").format(company_name)
                    )

                    # Clear cached memberships to refresh the list
                    if "user_memberships" in request.session:
                        del request.session["user_memberships"]

                    # Set the new company as the selected customer
                    if new_customer_id:
                        request.session["selected_customer_id"] = str(new_customer_id)
                        request.session["selected_customer_name"] = company_name
                        request.session["selected_customer_role"] = "owner"

                    # Redirect to profile to see the new company
                    return redirect("users:profile")
                else:
                    error_msg = response.get("error", "Unknown error occurred")
                    logger.error(f"🔥 [Portal] Company creation failed: {error_msg}")
                    messages.error(request, _("Failed to create company: {}").format(error_msg))

            except PlatformAPIError as e:
                logger.error(f"🔥 [Portal] Company creation API error: {e}")
                messages.error(request, _("Error creating company. Please try again."))

    context = {
        "form": form,
        "page_title": _("Create Company"),
        "brand_name": "PRAHO Portal",
    }

    return render(request, "users/create_company.html", context)
