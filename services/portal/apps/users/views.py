"""
Portal Users Views
Customer-facing login/logout with Platform API validation using Django sessions.
"""

import logging
import time
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any
from uuid import UUID

from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render, resolve_url
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme, urlencode
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy, ngettext
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods, require_POST

from apps.api_client.services import PlatformAPIError, api_client
from apps.common import altcha, request_context
from apps.common.decorators import (
    log_access_attempt,
    require_any_role,
    require_authentication,
    require_billing_access,
)
from apps.common.http import mark_download
from apps.common.localisation_middleware import sync_language_selection
from apps.common.localisation_services import company_lookup_available, store_localisation_preferences
from apps.common.middleware import SessionSecurityMiddleware
from apps.common.rate_limit_feedback import (
    build_maintenance_context,
    get_degraded_message,
    get_rate_limit_message,
    is_rate_limited_error,
    is_unavailable_error,
    render_platform_unavailable,
)
from apps.common.rate_limiting import mark_auth_failure, mark_auth_success
from apps.common.request_ip import get_safe_client_ip
from apps.common.session_store import SessionSaveContended
from apps.common.store_unavailable import end_session_or_unavailable
from apps.users import session_deadlines
from apps.users.constants import (
    PASSWORD_RESET_SESSION_KEY,
    REGISTRATION_CONFIRM_SESSION_KEY,
    REGISTRATION_INTENT_SESSION_KEY,
    REGISTRATION_PREFILL_SESSION_KEY,
    SIGNED_OUT_FLOW_SESSION_KEYS,
)
from apps.users.forms import (
    ChangePasswordForm,
    CompanyCreationForm,
    CompanyProfileForm,
    ConfirmIdentityForm,
    CustomerLoginForm,
    CustomerProfileForm,
    CustomerRegistrationForm,
    MFAReauthenticationForm,
    PasswordResetConfirmForm,
    PasswordResetRequestForm,
    RegistrationConfirmForm,
    TOTPSetupForm,
)
from apps.users.intent_capture import (
    capture_first_touch,
    capture_intent,
    registration_intent,
    resume_after_confirmation,
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
        if is_rate_limited_error(e):
            raise
        logger.error(f"🔥 [Portal] Failed to fetch user customers: {e}")
        return None


def _get_selected_customer_id(request: HttpRequest) -> str | None:
    """Get the currently selected customer ID, fallback to session customer_id"""
    selected_customer_id = request.session.get("selected_customer_id")
    if selected_customer_id:
        return str(selected_customer_id)

    # Fallback to login customer_id for backward compatibility
    cid = request.session.get("customer_id")
    return str(cid) if cid else None


def _get_user_role_for_customer(request: HttpRequest, customer_id: str) -> str | None:
    """Get user's role for specific customer from cached memberships"""
    memberships = request.session.get("user_memberships", [])
    for membership in memberships:
        if str(membership.get("customer_id")) == str(customer_id):
            role = membership.get("role")
            return str(role) if role is not None else None
    return None


def _can_edit_company_profile(request: HttpRequest, customer_id: str) -> bool:
    """Check if user can edit company profile for given customer"""
    role = _get_user_role_for_customer(request, customer_id)
    return role in ["owner", "billing"]


def _browser(request: HttpRequest) -> dict[str, str]:
    """The customer's browser, forwarded so Platform's audit trail names it rather than this server."""
    return {"client_ip": get_safe_client_ip(request), "user_agent": request.META.get("HTTP_USER_AGENT", "")}


def _handle_totp_setup_get(
    request: HttpRequest, customer_id: str, customer_email: str, form: TOTPSetupForm | None = None
) -> HttpResponse:
    """The setup page. Platform keeps one pending secret, so showing it again shows the same code."""
    try:
        user_id = request.session.get("user_id")
        totp_data = api_client.setup_totp_mfa(customer_id, user_id=user_id)
        if not totp_data:
            return _handle_mfa_error_redirect(
                request, "users:mfa_management", _("Failed to initialize MFA setup. Please try again.")
            )

        context = {
            "form": form or TOTPSetupForm(),
            "qr_code": totp_data.get("qr_code"),
            "secret": totp_data.get("secret"),
            "customer_email": customer_email,
            "customer_id": customer_id,
            "page_title": _("Set Up Authenticator App"),
        }
        return render(request, "users/mfa_setup_totp.html", context)

    except Exception as e:
        logger.error(f"🔥 [Portal MFA] Error initializing TOTP setup: {e}")
        return _handle_mfa_error_redirect(request, "users:mfa_management", _("An error occurred. Please try again."))


def _store_returned_session_auth_hash(request: HttpRequest, result: Mapping[str, object]) -> None:
    """Keep the Platform's new session binding; a response that omits it leaves the current one in place.

    An empty binding is rejected by the Platform on the next validation, so writing one on a
    response without the field (an old worker during a rolling deploy) would sign the user out.
    """
    returned = result.get("session_auth_hash")
    if isinstance(returned, str) and returned:
        request.session["session_auth_hash"] = returned


# Platform answers these before checking the password, so neither is a failed attempt: no reauth
# charge. A locked account reads like the rate limit it is, and lasts minutes, not one request.
ACCOUNT_LOCKED = "account_locked"
MFA_NOT_ENABLED = "mfa_not_enabled"
LOCKED_MESSAGE = gettext_lazy("Too many attempts. Please wait and try again.")


def _setup_refusal(request: HttpRequest, exc: PlatformAPIError, form: TOTPSetupForm) -> HttpResponse | None:
    """Explain a refused confirmation on the form; only a wrong password or code is a failed attempt.

    Returns a response only when the page should not be shown again.
    """
    code = (exc.response_data or {}).get("code")
    if exc.is_rate_limited:
        form.add_error(None, _("Too many attempts. Please wait and try again."))
    elif exc.is_degraded:
        # Nothing was verified, so this is not a wrong credential and spends no attempt.
        form.add_error(None, get_degraded_message(exc))
    elif code == "mfa_already_enabled":
        messages.info(request, _("Two-factor authentication is already on."))
        return redirect("users:mfa_management")
    elif code == "mfa_setup_expired":
        form.add_error(None, _("This setup expired. Scan the new code and try again."))
    elif code == ACCOUNT_LOCKED:
        form.add_error(None, LOCKED_MESSAGE)
    else:
        mark_auth_failure(request, bucket="reauth")
        form.add_error(None, _("The password or the code is incorrect."))
    return None


def _handle_totp_setup_post(request: HttpRequest, customer_id: str, customer_email: str) -> HttpResponse:
    """Confirm the setup; on any refusal show the same page, with the same secret, and say why."""
    form = TOTPSetupForm(request.POST)
    if not form.is_valid():
        return _handle_totp_setup_get(request, customer_id, customer_email, form)

    try:
        result = api_client.verify_totp_mfa(
            customer_id,
            form.cleaned_data["token"],
            form.cleaned_data["password"],
            user_id=request.session.get("user_id"),
            **_browser(request),
        )
    except SessionSaveContended:
        raise  # The session middleware answers 503 with Retry-After (ADR-0055).
    except PlatformAPIError as exc:
        leave = _setup_refusal(request, exc, form)
        return leave or _handle_totp_setup_get(request, customer_id, customer_email, form)

    _store_returned_session_auth_hash(request, result)
    request.session.cycle_key()
    logger.info(f"✅ [Portal 2FA] TOTP enabled successfully for customer {customer_id}")
    messages.success(request, _("Two-factor authentication has been enabled successfully!"))
    return _render_new_backup_codes(request, list(result.get("backup_codes", [])))


def _render_new_backup_codes(request: HttpRequest, codes: list[str]) -> HttpResponse:
    """New recovery codes, shown once in the response that made them and kept in no session (#689)."""
    return render(
        request,
        "users/mfa_backup_codes.html",
        {"backup_codes": codes, "remaining": len(codes), "form": MFAReauthenticationForm()},
    )


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
def login_view(request: HttpRequest) -> HttpResponse:  # noqa: C901, PLR0912, PLR0915
    """
    Portal login view using Django sessions.
    Validates credentials via Platform API and creates secure sessions.
    """

    # Redirect if already authenticated
    if request.session.get("customer_id"):
        next_url = _get_safe_redirect_target(request, fallback="/dashboard/")
        return redirect(next_url)

    # Drives the maintenance notice and the disabled submit below. Until `authenticate_customer`
    # stopped swallowing a 503 into `None`, this state was unreachable: a maintenance window
    # produced "Invalid email address or password", so the customer retyped a correct password
    # and was told it was wrong again.
    # Not just a boolean: `components/maintenance_inline_alert.html` renders a heading and a message
    # from the context, and this view supplied neither. The heading was hardcoded in the template until
    # the declared/undeclared distinction made it dynamic, so a real window here silently degraded to
    # "Temporarily unavailable" - and `maintenance_message` was never set at ALL, so the alert had been
    # rendering with an empty body. Found by running the browser test rather than by reading it.
    degraded_context: dict[str, object] = {}

    if request.method == "GET":
        capture_first_touch(request)
        form = CustomerLoginForm()
    else:  # POST
        form = CustomerLoginForm(request.POST)

        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]
            remember_me = form.cleaned_data.get("remember_me", False)

            try:
                # Validate credentials via Platform API
                mfa_token = form.cleaned_data.get("mfa_token", "")
                auth_response = api_client.authenticate_customer(
                    email,
                    password,
                    mfa_token=mfa_token,
                    client_ip=get_safe_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    remember_me=remember_me is True,
                )
                deadlines = None
                if auth_response and auth_response.get("valid"):
                    deadlines = session_deadlines.from_platform(auth_response, timezone.now())
                    if not auth_response.get("session_id") or deadlines is None:
                        # ADR-0017 section 5: a login Platform opened no usable session for cannot be used.
                        raise PlatformAPIError("Login answered without a usable Platform session", is_unavailable=True)

                if auth_response and auth_response.get("valid"):
                    # Successful authentication - create Django session
                    user_id = auth_response.get("user_id")
                    customer_id = auth_response.get("customer_id")

                    logger.info(f"✅ [Portal Auth] Customer {email} authenticated successfully")

                    # ✅ CRITICAL: Prevent session fixation attacks
                    request.session.cycle_key()
                    for key in SIGNED_OUT_FLOW_SESSION_KEYS:
                        request.session.pop(key, None)
                    # Bound to the browser that signed in, before any later request can claim it.
                    SessionSecurityMiddleware.stamp_fingerprint(
                        request.session, request.META.get("HTTP_USER_AGENT", "")
                    )

                    # Store in Django session (secure, handled by framework)
                    # Store correct user_id (platform user.id) and primary customer_id separately
                    # Middleware will resolve active_customer_id from accessible customers list
                    request.session.pop("_language", None)
                    request.session.pop("localisation_preferences_saved", None)
                    store_localisation_preferences(
                        request, auth_response.get("customer_data", {}).get("localisation_preferences")
                    )
                    request.session["user_id"] = user_id
                    request.session["customer_id"] = customer_id  # Legacy field, prefer active_customer_id
                    request.session["email"] = email
                    request.session["authenticated_at"] = timezone.now().isoformat()
                    request.session["session_auth_hash"] = auth_response.get("session_auth_hash") or ""
                    portal_session_id = str(auth_response["session_id"])
                    request.session["portal_session_id"] = portal_session_id
                    if deadlines is not None:  # always, past the check above
                        session_deadlines.store(request.session, deadlines)
                    # The membership and profile calls below already belong to this session.
                    request_context.bind(portal_session_id, user_id)

                    # Fetch and cache user's customer memberships for role-based access

                    try:
                        memberships = _get_user_customer_memberships(request)
                        if memberships:
                            request.session["user_memberships"] = memberships
                            request.session["user_memberships_fetched_at"] = time.time()
                            # Seed active_customer_id so middleware doesn't re-fetch
                            first_customer_id = memberships[0].get("customer_id")
                            request.session["active_customer_id"] = first_customer_id
                            # If platform returned no primary customer (e.g. superuser without
                            # is_primary membership), fall back to the first accessible customer.
                            if not customer_id:
                                customer_id = first_customer_id
                                request.session["customer_id"] = customer_id
                                logger.info(
                                    f"⚠️ [Portal Auth] No primary customer for {email}, "
                                    f"using first membership: customer {customer_id}"
                                )
                    except Exception:
                        logger.debug("Could not fetch memberships on login")

                    # The cookie lives as Platform's session does (ADR-0017 section 5): a remembered one
                    # until its end, any other until the browser closes (the stored row still ends at
                    # Platform's end; see apps.common.session_store).
                    if deadlines is not None:  # always, past the check above
                        request.session.set_expiry(deadlines.expires_at if deadlines.tier == "remember" else 0)

                    # Get customer name for personalized message
                    try:
                        profile_data = api_client.get_customer_profile(int(request.session["user_id"]))
                        if profile_data and profile_data.get("first_name"):
                            customer_name = profile_data.get("first_name")
                            messages.success(request, _("Sign in confirmed, %(name)s!") % {"name": customer_name})
                        else:
                            # Fallback to email if name not available
                            messages.success(request, _("Sign in confirmed!"))
                    except Exception as e:
                        logger.warning(f"⚠️ [Portal Auth] Could not fetch profile for personalized message: {e}")
                        messages.success(request, _("Sign in confirmed!"))

                    next_url = _get_safe_redirect_target(request, fallback="/dashboard/")
                    mark_auth_success(request)
                    return redirect(next_url)

                else:
                    logger.warning(f"⚠️ [Portal Auth] Invalid credentials for {email}")
                    mark_auth_failure(request)
                    form.add_error(None, _("Invalid email address or password. Please try again."))

            except PlatformAPIError as e:  # degradation- and rate-limit-aware, per state
                if getattr(e, "is_unavailable", False):
                    # `is_unavailable`, not `is_maintenance`: the customer cannot log in during an
                    # UNDECLARED outage either, and keying on the narrower flag sent a 502, a 504 and
                    # an unmarked 503 back to the generic branch - which is the original bug, a real
                    # outage reported as a wrong password. `get_degraded_message` decides whether the
                    # wording may call it planned.
                    logger.warning(f"⚠️ [Portal Auth] Login attempted while the platform was unavailable for {email}")
                    degraded_context = build_maintenance_context(request, e)
                    # The ALERT explains the platform's state; this form error explains why THIS
                    # submission went nowhere. Master's login-specific wording rather than
                    # `get_degraded_message`, which says "This information is temporarily
                    # unavailable" - the wrong register on a login form, and for a declared window
                    # merely a second copy of the sentence already in the alert above it.
                    form.add_error(
                        None, _("Authentication service is temporarily unavailable. Please try again later.")
                    )
                    # Deliberately NO `mark_auth_failure` here, unlike the throttle branch below.
                    # `authenticate_customer` raised, so no credential was ever verified - there is no
                    # guess to rate-limit. Counting it would spend the customer's attempt budget on an
                    # outage they did not cause and could lock them out of the form after the platform
                    # recovered. Nor is the omission exploitable: reaching it means making the platform
                    # answer 5xx at will, which is a denial of service, and during one no credential
                    # can be checked anyway.
                elif getattr(e, "is_rate_limited", False):
                    mark_auth_failure(request)
                    retry_after = getattr(e, "retry_after", None) or 30

                    logger.warning(f"⚠️ [Portal Auth] Login rate-limited for {email} (retry_after={retry_after}s)")
                    form.add_error(
                        None,
                        _("Too many login attempts. Please try again in %(seconds)s seconds.")
                        % {"seconds": retry_after},
                    )
                else:
                    logger.error(f"🔥 [Portal Auth] Platform API error during login: {e}")
                    messages.error(
                        request, _("Authentication service is temporarily unavailable. Please try again later.")
                    )

            except SessionSaveContended:
                raise  # The session middleware answers 503 with Retry-After (ADR-0055).
            except Exception as e:
                logger.error(f"🔥 [Portal Auth] Unexpected error during login: {e}")
                messages.error(request, _("An unexpected error occurred. Please try again."))

    context = {
        "form": form,
        "page_title": _("Customer Login"),
        **degraded_context,
    }

    return render(request, "users/login.html", context)


def _end_platform_session(request: HttpRequest) -> None:
    """End the Platform session at logout (ADR-0017 section 5); logout never waits on Platform.

    A failure is logged and the browser session still ends: the Platform row then ends at its
    idle deadline, and nothing can use it without this browser's cookie.
    """
    session_id = request.session.get("portal_session_id")
    user_id = request.session.get("user_id")
    if not session_id or not user_id:
        return
    try:
        api_client.end_session(int(user_id), str(session_id))
    except (PlatformAPIError, ValueError, TypeError):
        logger.warning("⚠️ [Portal Auth] Platform session not ended at logout; it ends at its idle deadline")
    request_context.forget_rejection()


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
        _end_platform_session(request)
        # End authentication and flush as one guarded operation.
        unavailable_response = end_session_or_unavailable(request)
        if unavailable_response is not None:
            return unavailable_response
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


def _redisplay_after_registration_refusal(
    request: HttpRequest, form: CustomerRegistrationForm, error: PlatformAPIError
) -> None:
    """Explain a refusal the customer cannot fix by editing, and keep what they typed."""
    if error.is_rate_limited:
        logger.warning("⚠️ [Portal Registration] Registration rate limit exceeded")
        messages.error(request, _("Too many registration attempts. Please try again later."))
    else:
        logger.warning(f"⚠️ [Portal Registration] Platform unavailable: {error}")
        messages.error(request, _("Registration is temporarily unavailable. Please try again in a few minutes."))


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
        capture_first_touch(request)
        if "p" in request.GET:
            return _take_registration_prefill(request, request.GET["p"])
        capture_intent(request)
        form = CustomerRegistrationForm(initial=request.session.get(REGISTRATION_PREFILL_SESSION_KEY))
    else:  # POST
        form = CustomerRegistrationForm(request.POST)

        if form.is_valid():
            try:
                # Register customer via Platform API
                registration_result = form.register_customer(
                    client_ip=get_safe_client_ip(request), intent=registration_intent(request)
                )

                if registration_result:
                    request.session.pop(REGISTRATION_PREFILL_SESSION_KEY, None)
                    # The same message whatever the address: Platform mails either a confirmation
                    # link or a note that the address already has an account.
                    messages.success(request, _("Thank you. Check your email for a message with the next step."))
                    return redirect("/login/")
                elif not form.errors:
                    # Field errors Platform answered with are shown on their fields instead.
                    messages.error(request, _("Registration failed. Please check your information and try again."))

            except PlatformAPIError as e:
                if e.is_rate_limited or e.is_unavailable:
                    _redisplay_after_registration_refusal(request, form, e)
                else:
                    logger.error(f"🔥 [Portal Registration] Platform API error: {e}")
                    messages.error(request, _("An unexpected error occurred during registration. Please try again."))
            except Exception as e:
                logger.error(f"🔥 [Portal Registration] Unexpected error: {e}")
                messages.error(request, _("An unexpected error occurred during registration. Please try again."))

    context = {
        "form": form,
        "page_title": _("Customer Registration"),
        "company_lookup_available": company_lookup_available(),
    }

    return render(request, "users/register.html", context)


def _take_registration_prefill(request: HttpRequest, token: str) -> HttpResponse:
    """Keep what a staff-minted link fills in, then show the form without the token in its URL.

    The link proves nothing about who opens it: the details only fill in the form, and stay editable.
    A token Platform does not accept fills in nothing.
    """
    try:
        prefill = api_client.read_registration_prefill(token, client_ip=get_safe_client_ip(request)).get("prefill")
    except PlatformAPIError:
        logger.warning("⚠️ [Portal Registration] Prefill link could not be read")
        prefill = None
    if isinstance(prefill, dict):
        if isinstance(prefill.get("fields"), dict) and prefill["fields"]:
            request.session[REGISTRATION_PREFILL_SESSION_KEY] = prefill["fields"]
        if isinstance(prefill.get("intent"), dict) and prefill["intent"]:
            request.session[REGISTRATION_INTENT_SESSION_KEY] = prefill["intent"]
    response = redirect("users:register")
    response["Referrer-Policy"] = "no-referrer"
    return response


@never_cache
@csrf_protect
@require_POST
def company_lookup_view(request: HttpRequest) -> JsonResponse:  # noqa: PLR0911  # one answer per refusal
    """A Romanian company's details from ANAF's register, to fill in the registration form.

    Platform answers from ANAF only, so this says nothing about who is registered here. Like the
    registration itself, it needs a solved proof-of-work while ALTCHA is on.
    """
    if not company_lookup_available():
        raise Http404
    if altcha.enabled() and not altcha.accept_solution(request.POST.get(altcha.FIELD_NAME, "")):
        return JsonResponse({"error": str(altcha.VERIFICATION_FAILED)}, status=400)
    cui = "".join(request.POST.get("cui", "").split()).upper().removeprefix("RO")
    if not (cui.isascii() and cui.isdigit() and 2 <= len(cui) <= 10):  # noqa: PLR2004  # CUI length
        return JsonResponse({"error": _("Enter a valid CUI.")}, status=400)
    unavailable = _("The company lookup is not available right now. Fill in the details yourself.")
    try:
        result = api_client.company_lookup(cui, client_ip=get_safe_client_ip(request))
    except PlatformAPIError as exc:
        if exc.is_rate_limited:
            return JsonResponse({"error": get_rate_limit_message(exc.retry_after)}, status=429)
        if exc.status_code == 400:  # noqa: PLR2004  # Platform refused the CUI
            return JsonResponse({"error": _("Enter a valid CUI.")}, status=400)
        return JsonResponse({"error": unavailable}, status=503)
    if not result.get("available"):
        return JsonResponse({"error": unavailable}, status=503)
    if not result.get("found"):
        return JsonResponse({"error": _("ANAF has no company with this CUI.")}, status=404)
    return JsonResponse({"company": result.get("company", {})})


def _load_profile_form_data(request: HttpRequest, user_id: int) -> CustomerProfileForm:
    """Load and initialize profile form with existing data"""
    try:
        profile_data = api_client.get_customer_profile(user_id)

        if profile_data:
            profile_values = profile_data.get("profile", {})
            preferences = profile_values.get("localisation_preferences", profile_values)
            store_localisation_preferences(request, preferences)
            return CustomerProfileForm(
                initial={
                    "first_name": profile_data.get("first_name", ""),
                    "last_name": profile_data.get("last_name", ""),
                    "phone": profile_data.get("phone", ""),
                    "preferred_language": preferences.get("preferred_language", ""),
                    "timezone": preferences.get("timezone", ""),
                    "date_format": preferences.get("date_format", ""),
                    "email_notifications": profile_data.get("profile", {}).get("email_notifications", True),
                    "sms_notifications": profile_data.get("profile", {}).get("sms_notifications", False),
                    "marketing_emails": profile_data.get("profile", {}).get("marketing_emails", False),
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
            "preferred_language": form.cleaned_data.get("preferred_language", ""),
            "timezone": form.cleaned_data.get("timezone", ""),
            "date_format": form.cleaned_data.get("date_format", ""),
            "email_notifications": form.cleaned_data.get("email_notifications", True),
            "sms_notifications": form.cleaned_data.get("sms_notifications", False),
            "marketing_emails": form.cleaned_data.get("marketing_emails", False),
        }

        result = api_client.update_customer_profile(user_id, update_data)

        if result:
            logger.info(f"✅ [Portal Profile] Profile updated for customer {customer_id}")

            request.session["localisation_preferences_saved"] = True
            store_localisation_preferences(request, update_data)
            messages.success(request, _("Profile updated successfully!"))
            response = redirect("users:profile")
            sync_language_selection(request, response, str(update_data["preferred_language"]))
            return response
        else:
            messages.error(request, _("Error updating profile. Please try again."))

    except Exception as e:
        logger.error(f"🔥 [Portal Profile] Error updating profile: {e}")
        messages.error(request, _("Error updating profile. Please try again."))

    return None


def _fetch_customer_cui(customer_id: str | int | None, user_id: str | int | None) -> str:
    """Fetch CUI from customer tax profile for display in company card."""
    if not customer_id or not user_id:
        return ""
    uid = int(user_id)
    try:
        response = api_client.post(
            "customers/details/",
            data={"customer_id": customer_id, "user_id": uid, "include": ["tax_profile"]},
            user_id=uid,
        )
        if isinstance(response, dict) and response.get("success"):
            cui: str = response.get("customer", {}).get("tax_profile", {}).get("cui", "")
            return cui
    except Exception as e:
        logger.debug("Could not load CUI for company card: %s", e)
    return ""


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
        form = _load_profile_form_data(request, int(user_id))  # type: ignore[arg-type]
    else:  # POST
        form = CustomerProfileForm(request.POST)

        # Handle profile update
        redirect_response = _handle_profile_update(request, form, int(user_id), str(customer_id))  # type: ignore[arg-type]
        if redirect_response:
            return redirect_response

    # Get profile data from Platform API for context
    profile_data = {}
    try:
        profile_data = api_client.get_customer_profile(int(request.session["user_id"])) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")

    # Load user memberships for customer selector
    if not request.session.get("user_memberships"):
        memberships = _get_user_customer_memberships(request)
        if memberships:
            request.session["user_memberships"] = memberships
            if not request.session.get("selected_customer_id"):
                request.session["selected_customer_id"] = customer_id
                # Defensive: pop the account-health cache in case a caller
                # populated it before initial customer selection. The lines
                # above only run on first-time selection where no cache
                # would normally exist; this is a guard against future
                # reordering rather than a fix for a current bug (H3c).
                request.session.pop("account_health_data", None)
                request.session.pop("account_health_fetched_at", None)

    # Ensure selected customer name/role are always populated from memberships
    if request.session.get("user_memberships") and not request.session.get("selected_customer_name"):
        sel_id = str(request.session.get("selected_customer_id", customer_id))
        for membership in request.session["user_memberships"]:
            if str(membership.get("customer_id")) == sel_id:
                request.session["selected_customer_name"] = membership.get("customer_name", f"Customer {sel_id}")
                request.session["selected_customer_role"] = membership.get("role", "viewer")
                break

    selected_customer_cui = _fetch_customer_cui(request.session.get("selected_customer_id", customer_id), user_id)

    context = {
        "form": form,
        "profile": profile_data,
        "customer_email": customer_email,
        "customer_id": customer_id,
        "page_title": _("Account Settings"),
        "user_memberships": request.session.get("user_memberships", []),
        "selected_customer_id": request.session.get("selected_customer_id", customer_id),
        "selected_customer_name": request.session.get("selected_customer_name", ""),
        "selected_customer_role": request.session.get("selected_customer_role", ""),
        "selected_customer_cui": selected_customer_cui,
        "can_edit_profile": _can_edit_company_profile(
            request, str(request.session.get("selected_customer_id", customer_id))
        ),
    }

    return render(request, "users/profile.html", context)


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def password_reset_view(request: HttpRequest) -> HttpResponse:
    """Submit recovery requests to Platform and show the same accepted response for every account."""
    form = PasswordResetRequestForm(request.POST if request.method == "POST" else None)
    response_status = 200
    retry_after = None
    if request.method == "POST" and form.is_valid():
        try:
            result = api_client.request_password_reset(
                form.cleaned_data["email"], client_ip=get_safe_client_ip(request)
            )
            if not result.get("success"):
                raise PlatformAPIError("Password reset was not accepted")
            messages.success(
                request,
                _(
                    "If an eligible account exists and email delivery is available, "
                    "you will receive password reset instructions."
                ),
            )
            return redirect("users:login")
        except PlatformAPIError as exc:
            response_status = 429 if exc.is_rate_limited else 503
            retry_after = exc.retry_after
            form.add_error(
                None,
                get_rate_limit_message(retry_after)
                if exc.is_rate_limited
                else get_degraded_message(exc)
                if exc.is_degraded
                else _("Password recovery is temporarily unavailable. Please try again later."),
            )
            logger.warning("⚠️ [Portal Password Reset] Request unavailable (status=%s)", exc.status_code)
    response = render(request, "users/password_reset.html", {"form": form}, status=response_status)
    if retry_after:
        response["Retry-After"] = str(retry_after)
    return response


def _add_reset_validation_errors(form: PasswordResetConfirmForm, payload: dict[str, object]) -> None:
    errors = payload.get("errors", {})
    if not isinstance(errors, dict):
        errors = {}
    for field, field_errors in errors.items():
        form_field = "confirm_password" if field == "new_password_confirm" else field
        form.add_error(form_field if form_field in form.fields else None, field_errors)
    if not errors:
        form.add_error(None, _("Please check your new password and try again."))


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def password_reset_confirm_view(
    request: HttpRequest, uidb64: str | None = None, token: str | None = None
) -> HttpResponse:
    """Keep recovery credentials in the session after opening the emailed link."""
    if uidb64 is not None and token is not None:
        if request.method != "GET":
            return HttpResponse(status=405)
        request.session[PASSWORD_RESET_SESSION_KEY] = {"uid": uidb64, "token": token}
        response = redirect("users:password_reset_confirm")
        response["Referrer-Policy"] = "no-referrer"
        return response

    credentials = request.session.get(PASSWORD_RESET_SESSION_KEY)
    form = PasswordResetConfirmForm(request.POST if request.method == "POST" else None)
    response_status = 200
    retry_after = None
    if credentials and request.method == "POST" and form.is_valid():
        try:
            result = api_client.confirm_password_reset(
                credentials["uid"],
                credentials["token"],
                form.cleaned_data["new_password"],
                form.cleaned_data["confirm_password"],
                client_ip=get_safe_client_ip(request),
            )
            if not result.get("success"):
                raise PlatformAPIError("Password reset was not accepted")
            unavailable_response = end_session_or_unavailable(request)
            if unavailable_response is not None:
                unavailable_response["Referrer-Policy"] = "no-referrer"
                return unavailable_response
            messages.success(request, _("Password reset successfully. Please sign in with your new password."))
            response = redirect("users:login")
            response["Referrer-Policy"] = "no-referrer"
            return response
        except PlatformAPIError as exc:
            payload = exc.response_data or {}
            if payload.get("code") == "invalid_reset_link":
                request.session.pop(PASSWORD_RESET_SESSION_KEY, None)
                credentials = None
                response_status = 400
            elif exc.status_code == HTTPStatus.BAD_REQUEST:
                _add_reset_validation_errors(form, payload)
                response_status = 400
            else:
                response_status = 429 if exc.is_rate_limited else 503
                retry_after = exc.retry_after
                form.add_error(
                    None,
                    get_rate_limit_message(retry_after)
                    if exc.is_rate_limited
                    else _("Password recovery is temporarily unavailable. Please try again later."),
                )
    elif credentials and request.method == "POST":
        response_status = 400
    response = render(
        request,
        "users/password_reset_confirm.html",
        {"form": form, "validlink": bool(credentials)},
        status=response_status,
    )
    # The token is already absent from this URL. Form POSTs need a real Origin for CSRF.
    response["Referrer-Policy"] = "same-origin"
    if retry_after:
        response["Retry-After"] = str(retry_after)
    return response


_CONFIRM_FIELD_NAMES = {"password": "new_password", "password_confirm": "confirm_password"}
TERMS_UNAVAILABLE = gettext_lazy("Registration opens once the Terms of Service are published.")


def _refusal_notice(exc: PlatformAPIError) -> tuple[str, int, int | None]:
    """A rate-limit or outage refusal as a notice, its status and its Retry-After."""
    if exc.is_rate_limited:
        return get_rate_limit_message(exc.retry_after), 429, exc.retry_after
    return _("Account confirmation is temporarily unavailable. Please try again later."), 503, exc.retry_after


def _load_registration(
    request: HttpRequest, link: dict[str, Any]
) -> tuple[dict[str, Any] | None, str, int, int | None]:
    """The details behind the session's link: (details, notice, status, Retry-After).

    Fetched once per link and kept with it in the session, so revisiting the page or a rejected
    password does not ask Platform again. None with no notice means the link is gone.
    """
    if isinstance(link.get("details"), dict) and "terms_document" in link["details"]:
        # Details from before the terms release they name are fetched again.
        return link["details"], "", 200, None
    try:
        details = api_client.get_pending_registration(
            link["registration_id"], link["token"], client_ip=get_safe_client_ip(request)
        ).get("registration")
    except PlatformAPIError as exc:
        code = (exc.response_data or {}).get("code")
        if code == "invalid_link":
            request.session.pop(REGISTRATION_CONFIRM_SESSION_KEY, None)
            return None, "", 400, None
        if code == "terms_unavailable":
            return None, str(TERMS_UNAVAILABLE), 409, None
        return (None, *_refusal_notice(exc))
    if not isinstance(details, dict):
        return (None, *_refusal_notice(PlatformAPIError("Pending registration answer without details")))
    request.session[REGISTRATION_CONFIRM_SESSION_KEY] = {**link, "details": details}
    return details, "", 200, None


def _terms_id(registration: dict[str, Any] | None) -> str:
    """The terms release a registration's details name, for the page to link and send back."""
    terms = (registration or {}).get("terms_document")
    return str(terms.get("document_id", "")) if isinstance(terms, dict) else ""


def _confirm_registration(
    request: HttpRequest, form: RegistrationConfirmForm, link: dict[str, Any], registration: dict[str, Any]
) -> tuple[HttpResponse | None, int, int | None, str]:
    """Submit the confirmation. Return a redirect on success, else a status, Retry-After and a notice.

    On success the sign-in page leads on to the product the registration came for, if any.

    The notice `terms_changed` means the terms release the page showed is no longer the one to accept.
    """
    try:
        result = api_client.confirm_registration(
            link["registration_id"],
            link["token"],
            form.cleaned_data["new_password"],
            form.cleaned_data["confirm_password"],
            marketing_consent=form.cleaned_data["marketing_consent"],
            terms_accepted=form.cleaned_data["terms_accepted"],
            terms_document_id=str(form.cleaned_data["terms_document_id"] or ""),
            client_ip=get_safe_client_ip(request),
        )
        if not result.get("success"):
            raise PlatformAPIError("Registration confirmation was not accepted")
    except PlatformAPIError as exc:
        payload = exc.response_data or {}
        code = payload.get("code")
        if code in {"invalid_link", "details_unavailable"}:
            request.session.pop(REGISTRATION_CONFIRM_SESSION_KEY, None)
            return None, (409 if code == "details_unavailable" else 400), None, code
        if code in {"terms_changed", "terms_unavailable"}:
            # Forget the details fetched for the link: the page is drawn again with the release in force.
            request.session[REGISTRATION_CONFIRM_SESSION_KEY] = {
                key: value for key, value in link.items() if key != "details"
            }
            form.add_error(None, _("The Terms of Service have changed. Please read them again before confirming."))
            # The tick was for the previous release: ask for it again.
            form.data = form.data.copy()
            form.data.pop("terms_accepted", None)
            return None, 409, None, "terms_changed"
        if exc.status_code == HTTPStatus.BAD_REQUEST:
            errors = payload.get("errors")
            for field, field_errors in (errors if isinstance(errors, dict) else {}).items():
                name = _CONFIRM_FIELD_NAMES.get(field, field)
                form.add_error(name if name in form.fields else None, field_errors)
            if not form.errors:
                form.add_error(None, _("Please check the form and try again."))
            return None, 400, None, ""
        notice, status, retry_after = _refusal_notice(exc)
        form.add_error(None, notice)
        return None, status, retry_after, ""
    request.session.pop(REGISTRATION_CONFIRM_SESSION_KEY, None)
    messages.success(request, _("Your account is confirmed. You can sign in now."))
    resume = resume_after_confirmation(request, registration.get("intent"))
    login = reverse("users:login")
    response = redirect(f"{login}?{urlencode({'next': resume})}" if resume else login)
    response["Referrer-Policy"] = "no-referrer"
    return response, 302, None, ""


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def register_confirm_view(
    request: HttpRequest, registration_id: UUID | None = None, token: str | None = None
) -> HttpResponse:
    """Finish a registration from its emailed link; the person confirming chooses the password.

    Opening the link only stores it in the session and redirects to a page without the token in
    its URL, as the password-reset link does, so a mail scanner that follows it changes nothing.
    The form carries the id of the registration it shows, so a tab left open on an earlier link
    cannot confirm a later one.
    """
    if registration_id is not None and token is not None:
        if request.method != "GET":
            return HttpResponse(status=405)
        request.session[REGISTRATION_CONFIRM_SESSION_KEY] = {"registration_id": str(registration_id), "token": token}
        response = redirect("users:register_confirm")
        response["Referrer-Policy"] = "no-referrer"
        return response

    link = request.session.get(REGISTRATION_CONFIRM_SESSION_KEY)
    registration, notice, status, retry_after = (None, "", 400, None) if not link else _load_registration(request, link)
    gone = "" if registration is not None or notice else "invalid_link"
    form = RegistrationConfirmForm(
        initial={"registration_id": link["registration_id"], "terms_document_id": _terms_id(registration)}
        if link
        else None
    )

    if link and registration is not None and request.method == "POST":
        posted = RegistrationConfirmForm(request.POST)
        if request.POST.get("registration_id") != link["registration_id"]:
            status, notice = 409, _("This page was for an earlier link. Check these details and submit again.")
        elif posted.is_valid():
            done, status, retry_after, gone = _confirm_registration(request, posted, link, registration)
            if done is not None:
                return done
            form = posted
            if gone == "terms_changed":
                # Show the release now in force, and send that one with the next submit.
                registration, notice, _status, retry_after = _load_registration(
                    request, request.session[REGISTRATION_CONFIRM_SESSION_KEY]
                )
                form.data = {**form.data, "terms_document_id": _terms_id(registration)}
                status, gone = 409, "" if registration is not None or notice else "invalid_link"
        else:
            status, form = 400, posted
    if not link and request.method == "GET":
        status = 200

    gone_messages = {
        "invalid_link": _("This link has expired or was already used."),
        "details_unavailable": _("These details are no longer available. Please register again."),
    }
    response = render(
        request,
        "users/register_confirm.html",
        {
            "form": form,
            "registration": None if gone else registration,
            "gone": gone_messages.get(gone, ""),
            "notice": notice,
        },
        status=status,
    )
    # The token is already absent from this URL. Form POSTs need a real Origin for CSRF.
    response["Referrer-Policy"] = "same-origin"
    if retry_after:
        response["Retry-After"] = str(retry_after)
    return response


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def change_password_view(request: HttpRequest) -> HttpResponse:
    """The Platform validates the old password and second factor before mutation."""
    if not request.session.get("user_id"):
        return redirect("users:login")
    form = ChangePasswordForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            result = api_client.update_customer_password(
                int(request.session["user_id"]),
                form.cleaned_data["new_password"],
                form.cleaned_data["current_password"],
                form.cleaned_data.get("token", ""),
            )
            if result and result.get("success"):
                request.session["session_auth_hash"] = result.get("session_auth_hash") or ""
                request.session.cycle_key()

                messages.success(request, _("Password changed successfully!"))
                return redirect("users:profile")
            form.add_error(None, _("Password change failed. Check your current password and authentication code."))
        except PlatformAPIError as exc:
            if is_rate_limited_error(exc):
                messages.warning(
                    request,
                    _("Too many attempts. Please try again in %(seconds)s seconds.")
                    % {"seconds": exc.retry_after or 30},
                )
            elif (exc.response_data or {}).get("code") == ACCOUNT_LOCKED:
                form.add_error(None, LOCKED_MESSAGE)
            else:
                form.add_error(None, _("Password change failed. Please try again."))
    return render(request, "users/change_password.html", {"form": form, "customer_email": request.session.get("email")})


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
        profile_data = api_client.get_customer_profile(int(request.session["user_id"])) or {}
    except Exception as e:
        logger.debug(f"Could not load profile data from Platform API: {e}")

    context = {
        "profile": profile_data,
        "customer_email": customer_email,
        "customer_id": customer_id,
        "page_title": _("Privacy Dashboard"),
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

            result = api_client.request_data_export_secure(user_id, ip_address=get_safe_client_ip(request))
            if result.get("success"):
                logger.info(f"✅ [Portal Data Export] Request created: export_id={result.get('export_id')}")
                messages.success(
                    request,
                    _("Your data export is being prepared. Refresh this page in a few minutes to download it."),
                )
            else:
                messages.error(request, _("Failed to create export request. Please try again."))

        except PlatformAPIError as e:
            if is_rate_limited_error(e):
                raise
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
    except PlatformAPIError:  # rate-limit-aware — informational status fetch, graceful degradation
        logger.warning("⚠️ [Portal Data Export] Could not fetch export status")

    context = {
        "customer_email": customer_email,
        "customer_id": customer_id,
        "exports": exports,
        "page_title": _("Export My Data"),
    }

    return render(request, "users/data_export.html", context)


@never_cache
@require_http_methods(["GET"])
def data_export_download_view(request: HttpRequest, export_id: UUID) -> HttpResponse:
    """Relay the signed-in user's own GDPR export file from Platform; nothing is kept here."""
    user_id = request.session.get("user_id")
    if not request.session.get("customer_id") or not user_id:
        return redirect("/login/")

    try:
        content = api_client.download_data_export(user_id, str(export_id), ip_address=get_safe_client_ip(request))
    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        if is_unavailable_error(e):
            logger.warning(f"⚠️ [Portal Data Export] Platform unavailable for export {export_id} download")
            messages.error(request, _("Service temporarily unavailable. Please try again later."))
            return redirect("users:data_export")
        if e.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE:
            messages.error(request, _("This export is too large to download here. Contact support to receive it."))
            return redirect("users:data_export")
        logger.warning(f"⚠️ [Portal Data Export] Export {export_id} not available (status {e.status_code})")
        messages.error(request, _("This export is not available to download. Request a new one below."))
        return redirect("users:data_export")

    response = HttpResponse(content, content_type="application/json")
    mark_download(response, f"gdpr-export-{export_id}.json")
    return response  # @never_cache marks it no-store


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
        profile_data = api_client.get_customer_profile(int(request.session["user_id"])) or {}
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
    except PlatformAPIError as exc:
        if is_unavailable_error(exc):
            return render_platform_unavailable(request, exc, status=200)
        logger.warning("⚠️ [Portal Consent] Failed to fetch consent history from Platform")

    context = {
        "profile": profile_data,
        "customer_email": customer_email,
        "customer_id": customer_id,
        "consent_history": consent_history,
        "cookie_consent_history": cookie_consent_history,
        "page_title": _("Consent History"),
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
        profile_data = api_client.get_customer_profile(int(request.session["user_id"])) or {}
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
        return _handle_totp_setup_get(request, customer_id, str(customer_email))
    return _handle_totp_setup_post(request, customer_id, str(customer_email))


@never_cache
@require_http_methods(["GET", "POST"])
def mfa_backup_codes_view(request: HttpRequest) -> HttpResponse:
    """Show newly issued codes once; stored hashes cannot be downloaded later."""
    if not request.session.get("user_id"):
        return redirect("users:login")
    user_id = int(request.session["user_id"])
    try:
        profile = api_client.get_customer_profile(user_id) or {}
    except PlatformAPIError as exc:
        # `get_customer_profile` now propagates a degraded platform instead of returning None, so
        # this view needs a handler: without one a maintenance window turned the backup-code page
        # into a 500, where before it redirected with a warning. Redirecting on an unknown MFA state
        # is the safe answer - "enable 2FA first" would be a guess, and the codes themselves are
        # never re-displayable.
        if not exc.is_degraded:
            raise
        # `get_degraded_message`, not the maintenance wording: an undeclared 502/503/504 here would
        # otherwise tell the customer their data is safe during a failure nobody has explained.
        messages.warning(request, get_degraded_message(exc))
        return redirect("users:mfa_management")
    if not profile.get("mfa_enabled"):
        messages.warning(request, _("You need to enable 2FA first before accessing backup codes."))
        return redirect("users:mfa_management")
    form = MFAReauthenticationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            result = api_client.regenerate_backup_codes(
                user_id, form.cleaned_data["password"], form.cleaned_data["token"], **_browser(request)
            )
            request.session.cycle_key()
            return _render_new_backup_codes(request, list(result["backup_codes"]))
        except PlatformAPIError as exc:
            code = (exc.response_data or {}).get("code")
            if exc.is_rate_limited or code == ACCOUNT_LOCKED:
                form.add_error(None, LOCKED_MESSAGE)
            elif exc.is_unavailable:
                # Nothing was verified, so this is not a wrong credential and spends no attempt.
                form.add_error(None, get_degraded_message(exc))
            elif code == MFA_NOT_ENABLED:
                messages.warning(request, _("You need to enable 2FA first before accessing backup codes."))
                return redirect("users:mfa_management")
            else:
                mark_auth_failure(request, bucket="reauth")
                form.add_error(None, _("Could not regenerate codes. Check your password and authentication code."))

    return render(
        request,
        "users/mfa_backup_codes.html",
        {"backup_codes": [], "remaining": profile.get("backup_codes_count", 0), "form": form},
    )


# Warn on the confirm page when this few backup codes are left.
LOW_BACKUP_CODES = 3


def _relative_next(raw: str) -> str:
    """A page on this site to go back to after confirming; any other target goes to the dashboard."""
    if raw.startswith("/") and not raw.startswith("//") and url_has_allowed_host_and_scheme(raw, allowed_hosts=set()):
        return raw
    return "/dashboard/"


@never_cache
@sensitive_post_parameters("password", "token")
@require_http_methods(["GET", "POST"])
def confirm_identity_view(request: HttpRequest) -> HttpResponse:
    """Ask for the password, and the code when 2FA is on, before a sensitive action (ADR-0017 section 6).

    Platform sends the browser here when an action needs an identity check from the last 300
    seconds; every signed-in role reaches it. Whether to ask for a code is read from Platform each
    time. Only a wrong answer spends the person's re-auth budget.
    """
    user_id = int(request.session["user_id"])
    next_url = _relative_next(request.GET.get("next") or request.POST.get("next") or "")
    # Read on the page only: an answer is checked by Platform, which decides whether a code is needed.
    status: dict[str, Any] = {}
    two_factor: bool | None = None
    if request.method == "GET":
        try:
            status = api_client.get_mfa_status(user_id)
            two_factor = bool(status.get("enabled"))
        except PlatformAPIError:
            two_factor = None  # unknown: the code is offered but optional
    form = ConfirmIdentityForm(request.POST or None, two_factor=two_factor)
    if request.method == "POST" and form.is_valid():
        try:
            api_client.confirm_identity(user_id, form.cleaned_data["password"], form.cleaned_data.get("token", ""))
        except PlatformAPIError as exc:
            code = (exc.response_data or {}).get("code")
            if code == "reauth_failed":
                mark_auth_failure(request, bucket="reauth")
                form.add_error(None, _("The password or code is not right."))
            elif code == ACCOUNT_LOCKED or exc.is_rate_limited:
                form.add_error(None, LOCKED_MESSAGE)
            else:
                form.add_error(None, _("We could not check that right now. Please try again in a moment."))
        else:
            mark_auth_success(request)
            # A new key, as at login: a copy of the old cookie must not share the window just opened.
            request.session.cycle_key()
            return redirect(next_url)
    remaining = int(status.get("backup_codes_remaining") or 0)
    low = two_factor is True and remaining <= LOW_BACKUP_CODES
    return render(
        request,
        "users/confirm_identity.html",
        {
            "form": form,
            "next": next_url,
            "backup_codes_warning": (
                ngettext("You have %(count)s backup code left.", "You have %(count)s backup codes left.", remaining)
                % {"count": remaining}
                if low
                else ""
            ),
        },
    )


@never_cache
@require_http_methods(["GET", "POST"])
def mfa_disable_view(request: HttpRequest) -> HttpResponse:
    """Require password and second factor before disabling account protection."""
    if not request.session.get("user_id"):
        return redirect("users:login")
    form = MFAReauthenticationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            result = api_client.disable_mfa(
                int(request.session["user_id"]),
                form.cleaned_data["password"],
                form.cleaned_data["token"],
                **_browser(request),
            )
            if result and result.get("success"):
                _store_returned_session_auth_hash(request, result)
                request.session.cycle_key()
                messages.success(request, _("Two-factor authentication has been disabled."))
                return redirect("users:mfa_management")
            mark_auth_failure(request, bucket="reauth")
            form.add_error(None, _("Could not disable MFA. Check your password and authentication code."))
        except PlatformAPIError as exc:
            code = (exc.response_data or {}).get("code")
            if exc.is_rate_limited or code == ACCOUNT_LOCKED:
                form.add_error(None, LOCKED_MESSAGE)
            elif exc.is_unavailable:
                # Nothing was verified, so this is not a wrong credential and spends no attempt.
                form.add_error(None, get_degraded_message(exc))
            elif code == MFA_NOT_ENABLED:
                return redirect("users:mfa_management")  # already off: that page says so
            elif code == "staff_mfa_required":
                # Platform's staff 2FA policy, not a wrong credential: say so and charge nothing.
                form.add_error(
                    None, _("Two-factor authentication is required for staff accounts, so it cannot be disabled.")
                )
            else:
                mark_auth_failure(request, bucket="reauth")
                form.add_error(None, _("Could not disable MFA. Check your password and authentication code."))

    return render(request, "users/mfa_disable.html", {"form": form})


@never_cache
@require_http_methods(["GET"])
@require_any_role()
@log_access_attempt
def company_profile_view(request: HttpRequest) -> HttpResponse:  # noqa: C901, PLR0912
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

    user_id: int | None = request.session.get("user_id")
    if not user_id:
        return redirect("/login/")

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
            tax_profile = customer.get("tax_profile") or {}

            # Fetch billing address from addresses endpoint (not billing_profile)
            billing_addr: dict[str, str] = {}
            try:
                addr_response = api_client.get_customer_addresses(
                    customer_id=int(customer_id),
                    user_id=int(user_id),
                )
                if isinstance(addr_response, dict) and addr_response.get("success"):
                    for addr in addr_response.get("addresses", []):
                        if addr.get("is_billing"):
                            billing_addr = addr
                            break
            except Exception as addr_err:
                if isinstance(addr_err, PlatformAPIError) and is_unavailable_error(addr_err):
                    return render_platform_unavailable(request, addr_err, status=200)
                logger.debug("Could not fetch billing address: %s", addr_err)

            company_data = {
                "company_name": customer.get("company_name", ""),
                "vat_number": tax_profile.get("vat_number", ""),
                "trade_registry_number": tax_profile.get("registration_number", ""),
                "industry": customer.get("industry", ""),
                "billing_address": {
                    "street_address": billing_addr.get("address_line1", ""),
                    "city": billing_addr.get("city", ""),
                    "state": billing_addr.get("county", ""),
                    "postal_code": billing_addr.get("postal_code", ""),
                    "country": billing_addr.get("country", ""),
                },
                "contact": {
                    "primary_email": customer.get("primary_email", ""),
                    "primary_phone": customer.get("primary_phone", ""),
                    "website": customer.get("website", ""),
                },
                "status": customer.get("status", ""),
                "customer_type": customer.get("customer_type", ""),
            }
        else:
            messages.error(request, _("Unable to load company profile data."))

    except PlatformAPIError as e:
        if is_rate_limited_error(e):
            raise
        if is_unavailable_error(e):
            return render_platform_unavailable(request, e, status=200)
        logger.error(f"🔥 [Portal] Company profile API error: {e}")
        messages.error(request, _("Error loading company profile. Please try again."))
    except Exception as e:
        logger.error(f"🔥 [Portal] Unexpected error loading company profile: {e}")
        messages.error(request, _("An unexpected error occurred."))

    context = {
        "company_data": company_data,
        "customer_email": request.session.get("email"),
        "page_title": _("Company Profile"),
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
def company_profile_edit_view(request: HttpRequest) -> HttpResponse:  # noqa: C901, PLR0912, PLR0915
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

    user_id: int | None = request.session.get("user_id")
    if not user_id:
        return redirect("/login/")

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
                tax_profile = customer.get("tax_profile") or {}

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
                # Update company profile via dedicated Platform API endpoint
                # VAT/billing address managed via dedicated pages (/company/tax/, /company/addresses/)
                profile_data = {
                    "company_name": form.cleaned_data["company_name"],
                    "primary_email": form.cleaned_data["primary_email"],
                    "primary_phone": form.cleaned_data["primary_phone"],
                    "website": form.cleaned_data["website"],
                    "industry": form.cleaned_data["industry"],
                }

                response = api_client.update_customer_company_profile(
                    customer_id=int(customer_id),
                    user_id=int(user_id),
                    data=profile_data,  # type narrowed by guards above
                )

                if response.get("success"):
                    logger.info(f"✅ [Portal] Company profile updated successfully for customer {customer_id}")
                    messages.success(request, _("Company profile updated successfully!"))

                    # Handle redirect based on 'next' parameter for order flow continuity
                    # SECURITY: "next" is a redirect URL param validated by url_has_allowed_host_and_scheme()
                    next_url = request.GET.get(
                        "next"
                    ) or request.POST.get(  # nosemgrep: django-using-request-post-after-is-valid
                        "next"
                    )
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
                if is_rate_limited_error(e):
                    raise
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
        referer = request.META.get("HTTP_REFERER", "/profile/")
        if not url_has_allowed_host_and_scheme(referer, allowed_hosts={request.get_host()}):
            referer = "/profile/"
        return redirect(referer)

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
        if is_rate_limited_error(e):
            raise
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

    # Invalidate the account-health session cache so the banner reflects
    # the newly-active customer instead of stale data for the previous
    # customer (PR #164 review finding H3a). The cache TTL is 5 minutes;
    # without this pop, users would see the wrong customer's overdue /
    # suspended / waiting banner until expiry.
    request.session.pop("account_health_data", None)
    request.session.pop("account_health_fetched_at", None)

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
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
        next_url = "/profile/"
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
                        # Auto-switch to a fresh customer context — invalidate
                        # the account-health cache (H3b). Same rationale as the
                        # explicit company-switcher view.
                        request.session.pop("account_health_data", None)
                        request.session.pop("account_health_fetched_at", None)

                    # Redirect to profile to see the new company
                    return redirect("users:profile")
                else:
                    error_msg = response.get("error", "Unknown error occurred")
                    logger.error(f"🔥 [Portal] Company creation failed: {error_msg}")
                    messages.error(request, _("Failed to create company: {}").format(error_msg))

            except PlatformAPIError as e:
                if is_rate_limited_error(e):
                    raise
                logger.error(f"🔥 [Portal] Company creation API error: {e}")
                messages.error(request, _("Error creating company. Please try again."))

    context = {
        "form": form,
        "page_title": _("Create Company"),
    }

    return render(request, "users/create_company.html", context)
