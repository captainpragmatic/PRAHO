"""
User management views for PRAHO Platform
Romanian-localized authentication and profile forms.
"""

import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, cast

import pyotp
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import (
    PasswordChangeView,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.db import Error as DatabaseFailure
from django.db import models, transaction
from django.db.models import QuerySet
from django.forms import Form
from django.http import HttpRequest, HttpResponse, HttpResponseBase, JsonResponse
from django.shortcuts import redirect, render, resolve_url
from django.urls import reverse, reverse_lazy
from django.utils.crypto import constant_time_compare
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _
from django.utils.translation import gettext_lazy
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView

from apps.audit.services import AuthenticationAuditService, LoginFailureEventData, LogoutEventData
from apps.common.constants import BACKUP_CODE_LOW_WARNING_THRESHOLD
from apps.common.rate_limiting import rate_limit
from apps.common.request_ip import get_safe_client_ip
from apps.common.transactions import best_effort_atomic

from .forms import (
    LoginForm,
    TwoFactorSetupForm,
    TwoFactorVerifyForm,
    UserProfileForm,
)
from .mfa import LOGIN_METHOD_REQUEST_ATTR, MFAService, TOTPService, verify_login_second_factor
from .models import CustomerMembership, User, UserLoginLog, UserProfile
from .services import SessionSecurityService

logger = logging.getLogger(__name__)

# Type alias for cleaner type hints
CustomUser = User

# ===============================================================================
# AUTHENTICATION VIEWS
# ===============================================================================


def _handle_rate_limit(request: HttpRequest, form: LoginForm) -> HttpResponse | None:
    """Handle rate limit logic, return response if rate limited, None otherwise"""
    if getattr(request, "limited", False) and not getattr(settings, "TESTING", False):
        # Audit logging handled by @rate_limit decorator
        messages.error(request, _("Too many login attempts. Please wait and try again."))
        return render(request, "users/login.html", {"form": form}, status=429)
    return None


def _login_candidate(email: str) -> User | None:
    """The account an email names, if any - looked up only to record a failure against it.

    The login view must not answer differently because this returns an account: a locked account
    used to get "Account temporarily locked" (and skip the password hash, so it also answered
    faster), which told anyone that the email exists. Lockout is enforced on the locked row in
    `_handle_successful_login`, and every failure gets the same message.
    """
    return User.objects.filter(email=email).first()


# The password step of an enrolled staff login parks its state here until mfa_verify.
PRE_2FA_SESSION_KEY = "pre_2fa"
PRE_2FA_TTL_SECONDS = 300


@dataclass(frozen=True)
class _PendingLogin:
    """A login that passed the password step and still owes the second factor."""

    user_id: int
    issued_at: int
    remember_me: bool
    next: str
    auth_hash: str
    backend: str


def _redirect(request: HttpRequest, url: str) -> HttpResponse:
    """Redirect, with a full-page HX-Redirect for HTMX requests."""
    if request.headers.get("HX-Request"):
        response = HttpResponse()
        response["HX-Redirect"] = url
        return response
    return redirect(url)


def _start_second_factor(request: HttpRequest, user: User, form: LoginForm, backend: str) -> HttpResponse:
    """Stop an enrolled user's login at the password and hand it to mfa_verify.

    No session is established and the failure counter is left alone: both happen only
    once the second factor passes.
    """
    next_url = _get_safe_redirect_target(request, fallback="dashboard")
    # A fresh key, so the pending state never rides on the pre-authentication session ID.
    request.session.cycle_key()
    request.session[PRE_2FA_SESSION_KEY] = {
        "user_id": user.pk,
        "issued_at": int(time.time()),
        "remember_me": bool(form.cleaned_data.get("remember_me")),
        "next": next_url,
        # Binds the pending login to the credentials it was started with.
        "auth_hash": user.get_session_auth_hash(),
        "backend": backend,
    }
    UserLoginLog.objects.create(
        user=user,
        ip_address=get_safe_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
        status="password_ok_2fa_pending",
    )
    return _redirect(request, reverse("users:mfa_verify"))


def _read_pending_login(request: HttpRequest) -> _PendingLogin | None:
    """Return the pending login if it is well formed and still fresh, else None."""
    raw = request.session.get(PRE_2FA_SESSION_KEY)
    if not isinstance(raw, dict):
        return None
    user_id, issued_at = raw.get("user_id"), raw.get("issued_at")
    remember_me, next_url = raw.get("remember_me"), raw.get("next")
    auth_hash, backend = raw.get("auth_hash"), raw.get("backend")
    well_formed = (
        type(user_id) is int
        and type(issued_at) is int
        and isinstance(remember_me, bool)
        and isinstance(next_url, str)
        and isinstance(auth_hash, str)
        and isinstance(backend, str)
    )
    if not well_formed:
        return None
    pending = _PendingLogin(
        user_id=cast(int, user_id),
        issued_at=cast(int, issued_at),
        remember_me=cast(bool, remember_me),
        next=cast(str, next_url),
        auth_hash=cast(str, auth_hash),
        backend=cast(str, backend),
    )
    age = int(time.time()) - pending.issued_at
    usable = (
        0 <= age <= PRE_2FA_TTL_SECONDS
        and pending.backend in settings.AUTHENTICATION_BACKENDS
        and url_has_allowed_host_and_scheme(
            url=pending.next,
            allowed_hosts={request.get_host()},
            require_https=getattr(settings, "USE_HTTPS", False),
        )
    )
    return pending if usable else None


def _record_locked_login(request: HttpRequest, user: User) -> None:
    """Record a locked account given the right password.

    authenticate() succeeded, so user_login_failed never fires: without this the strongest sign of
    an account under attack would leave no trace. It also keeps the work the same as every other
    refusal, which each write one login log row and one audit event.
    """
    UserLoginLog.objects.create(
        user=user,
        ip_address=get_safe_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
        status="account_locked",
    )
    with best_effort_atomic(logger=logger, scope="Auth", message="Could not audit a locked-account login"):
        AuthenticationAuditService.log_login_failed(
            LoginFailureEventData(
                email=user.email,
                user=user,
                failure_reason="account_locked",
                request=request,
                metadata={"login_method": "staff_web", "password_correct": True},
            )
        )


def _handle_successful_login(request: HttpRequest, user: User, form: LoginForm) -> HttpResponse:  # noqa: PLR0911  # Each return is a distinct refusal or hand-off
    """Handle successful login logic - staff only on platform"""
    # A locked account gets the wrong-password answer even with the right password, before any
    # branch that would confirm the password (such as the customer redirect below): otherwise
    # the lockout stops guessing nothing, and "locked" would confirm the email exists.
    if user.is_account_locked():
        _record_locked_login(request, user)
        messages.error(request, _("Incorrect email or password."))
        return render(request, "users/login.html", {"form": form})

    # Check if user is staff - customers must use portal
    if not user.is_staff_user:
        # Log the rejected customer login attempt
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_safe_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            status="rejected_customer",
        )

        # Don't actually log them in - reject with helpful message
        messages.error(
            request,
            _(
                "❌ This is the staff administration portal. Customers please use the customer portal to access your account."
            ),
        )

        # Handle HTMX requests
        if request.headers.get("HX-Request"):
            response = HttpResponse()
            response["HX-Redirect"] = reverse("users:login")
            return response

        return redirect("users:login")

    backend = str(getattr(user, "backend", ""))
    # Decide on the locked, freshly read row: an enrolment, deactivation, lockout or password
    # change that landed after authenticate() must not be missed, and login() must bind the
    # session to the credential version that row holds.
    with transaction.atomic():
        locked_user = User.objects.select_for_update().get(pk=user.pk)
        still_valid = (
            locked_user.password == user.password
            and locked_user.is_active
            and not locked_user.is_account_locked()
            and locked_user.is_staff_user
        )
        # Enrolled staff stop at the password: it must never establish a session (#590).
        password_only = still_valid and not locked_user.two_factor_enabled
        if password_only:
            request.session.pop(PRE_2FA_SESSION_KEY, None)
            _log_user_login(request, locked_user, "success")  # also resets the failure counter
            login(request, locked_user, backend=backend)

    if not still_valid:
        messages.error(request, _("Incorrect email or password."))
        return render(request, "users/login.html", {"form": form})
    if not password_only:
        return _start_second_factor(request, locked_user, form, backend)
    user = locked_user

    # Remember me handling and secure session timeout
    remember = bool(form.cleaned_data.get("remember_me"))
    if remember:
        request.session["remember_me"] = True
    else:
        request.session.pop("remember_me", None)

    # Update timeout policy based on context
    SessionSecurityService.update_session_timeout(request)

    # Only show welcome message for staff users since customers will be blocked by middleware
    if user.is_staff_user:
        messages.success(request, _("Welcome, {user_full_name}!").format(user_full_name=user.get_full_name()))

    next_url = _get_safe_redirect_target(request, fallback="dashboard")

    # Handle HTMX requests with full page reload
    if request.headers.get("HX-Request"):
        response = HttpResponse()
        response["HX-Redirect"] = next_url
        return response

    return redirect(next_url)


def _handle_failed_login(request: HttpRequest, user: User | None) -> None:
    """Handle failed login logic"""
    if user:
        # A locked account's lock is not extended by more attempts (as before), and the counter
        # write is best-effort: it runs only for real accounts, so its failure must not change the
        # answer an attacker sees.
        if not user.is_account_locked():
            try:
                user.increment_failed_login_attempts()
            except DatabaseFailure:
                logger.exception("🔥 [Auth] Could not record a failed login attempt")

        # Log failed login attempt
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_safe_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            status="failed_password",
        )
    else:
        # Log failed login for non-existent user (no user object)
        UserLoginLog.objects.create(
            user=None,
            ip_address=get_safe_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            status="failed_user_not_found",
        )


@rate_limit(key="ip", rate="15/m", method="POST")
@rate_limit(key="post:email", rate="8/m", method="POST")
def login_view(request: HttpRequest) -> HttpResponse:
    """Romanian-localized login view with account lockout protection"""
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = LoginForm(request.POST)

        # Check rate limiting
        if rate_limit_response := _handle_rate_limit(request, form):
            return rate_limit_response

        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]

            user = _login_candidate(email)

            # Authenticate every email the same way, locked accounts included: the locked-row
            # check in _handle_successful_login refuses them with the same message as a wrong
            # password, after the same hashing work.
            authenticated_user = authenticate(request, username=email, password=password)

            if authenticated_user:
                return _handle_successful_login(request, authenticated_user, form)
            else:
                _handle_failed_login(request, user)
                messages.error(request, _("Incorrect email or password."))
    else:
        form = LoginForm()

    return render(request, "users/login.html", {"form": form})


def logout_view(request: HttpRequest) -> HttpResponse:
    """
    Logout view with comprehensive audit logging

    Logs the logout event BEFORE clearing the session to capture
    complete context including session duration and security metadata.
    """
    user = None
    if request.user.is_authenticated:
        user = request.user

        # Log logout event BEFORE clearing session
        try:
            logout_data = LogoutEventData(
                user=user,
                logout_reason="manual",
                request=request,
                metadata={
                    "logout_triggered_by": "logout_view",
                    "session_key_before_logout": request.session.session_key,
                    "user_agent": request.META.get("HTTP_USER_AGENT", ""),
                },
            )
            AuthenticationAuditService.log_logout(logout_data)
            logger.info(f"✅ [Logout View] Audit logged for {user.email}")
        except Exception as e:
            # Don't let audit logging break logout
            logger.error(f"🔥 [Logout View] Failed to log logout for {user.email}: {e}")

        messages.success(request, _("You have been successfully logged out."))

    # Perform actual logout (this triggers the logout signal)
    logout(request)

    return redirect("users:login")


# ===============================================================================
# PASSWORD RESET
# ===============================================================================


@method_decorator(
    [
        rate_limit(key="ip", rate="15/h", method="POST"),  # 15 attempts per hour per IP
        rate_limit(key="header:user-agent", rate="30/h", method="POST"),  # 30 per user agent
    ],
    name="dispatch",
)
class SecurePasswordResetView(PasswordResetView):
    """Secure password reset request view with rate limiting and audit logging"""

    template_name = "users/password_reset.html"
    email_template_name = "users/password_reset_email.html"
    success_url = reverse_lazy("users:password_reset_done")

    def get_email_subject(self) -> str:
        """Get translatable email subject"""
        return _("Password reset for your account")

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        if getattr(request, "limited", False):
            UserLoginLog.objects.create(
                user=None,
                ip_address=get_safe_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                status="password_reset_rate_limited",
            )
            messages.error(request, _("Too many password reset attempts. Please wait before trying again."))
            return render(request, self.template_name, {"form": self.get_form()})
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: Any) -> HttpResponse:
        # Log password reset attempt for audit trail
        UserLoginLog.objects.create(
            user=None,  # Don't reveal if user exists in logs
            ip_address=get_safe_client_ip(self.request),
            user_agent=self.request.META.get("HTTP_USER_AGENT", ""),
            status="password_reset_requested",
        )
        return super().form_valid(form)


class SecurePasswordResetDoneView(PasswordResetDoneView):
    """Password reset done view"""

    template_name = "users/password_reset_done.html"


@method_decorator(
    [
        rate_limit(key="ip", rate="25/h", method="POST"),  # 25 password confirmations per hour per IP
    ],
    name="dispatch",
)
class SecurePasswordResetConfirmView(PasswordResetConfirmView):
    """Password reset confirmation view with audit logging and rate limiting"""

    template_name = "users/password_reset_confirm.html"
    success_url = reverse_lazy("users:password_reset_complete")

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        if getattr(request, "limited", False):
            UserLoginLog.objects.create(
                user=None,
                ip_address=get_safe_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                status="password_confirm_rate_limited",
            )
            messages.error(request, _("Too many password confirmation attempts. Please wait before trying again."))
            return render(request, self.template_name, {"form": self.get_form(), "validlink": False})
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: Any) -> HttpResponse:
        # Log successful password reset for audit
        user = form.user

        # Enhanced security logging
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_safe_client_ip(self.request),
            user_agent=self.request.META.get("HTTP_USER_AGENT", ""),
            status="password_reset_completed",
        )

        # Reset any account lockout since password was reset
        if hasattr(user, "account_locked_until") and user.account_locked_until:
            user.account_locked_until = None
            user.failed_login_attempts = 0  # Reset failed attempts counter
            user.save(update_fields=["account_locked_until", "failed_login_attempts"])

            # Log lockout reset
            UserLoginLog.objects.create(
                user=user,
                ip_address=get_safe_client_ip(self.request),
                user_agent=self.request.META.get("HTTP_USER_AGENT", ""),
                status="account_lockout_reset",
            )

        # 🔒 Sign out every session; enrolled MFA is kept, as in the API reset (#595)
        SessionSecurityService.secure_account_after_password_reset(user, get_safe_client_ip(self.request))

        return super().form_valid(form)

    def form_invalid(self, form: Form) -> HttpResponse:
        # Log failed password reset confirmation
        UserLoginLog.objects.create(
            user=None,
            ip_address=get_safe_client_ip(self.request),
            user_agent=self.request.META.get("HTTP_USER_AGENT", ""),
            status="password_reset_failed",
        )
        return super().form_invalid(form)


class SecurePasswordResetCompleteView(PasswordResetCompleteView):
    """Password reset complete view"""

    template_name = "users/password_reset_complete.html"


# Views for backward compatibility (use class-based views)
password_reset_view = SecurePasswordResetView.as_view()
password_reset_done_view = SecurePasswordResetDoneView.as_view()
password_reset_confirm_view = SecurePasswordResetConfirmView.as_view()
password_reset_complete_view = SecurePasswordResetCompleteView.as_view()


# ===============================================================================
# PASSWORD CHANGE
# ===============================================================================


@method_decorator(
    [
        rate_limit(key="user", rate="15/h", method="POST"),  # 15 password changes per hour per user
    ],
    name="dispatch",
)
class SecurePasswordChangeView(PasswordChangeView):
    """Secure password change view with rate limiting and audit logging"""

    template_name = "users/password_change.html"
    success_url = reverse_lazy("users:user_profile")

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        if getattr(request, "limited", False):
            if request.user.is_authenticated:
                UserLoginLog.objects.create(
                    user=request.user,
                    ip_address=get_safe_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    status="password_change_rate_limited",
                )
            messages.error(request, _("Too many password change attempts. Please wait before trying again."))
            return render(request, self.template_name, {"form": self.get_form()})
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form: Form) -> HttpResponse:
        # Log successful password change for audit - user is guaranteed to be authenticated due to LoginRequiredMixin
        UserLoginLog.objects.create(
            user=cast(User, self.request.user),
            ip_address=get_safe_client_ip(self.request),
            user_agent=self.request.META.get("HTTP_USER_AGENT", ""),
            status="password_changed",
        )

        # 🔒 Rotate session for security after password change
        SessionSecurityService.rotate_session_on_password_change(self.request)

        messages.success(self.request, _("Your password has been changed successfully!"))
        return super().form_valid(form)

    def form_invalid(self, form: Form) -> HttpResponse:
        # Log failed password change attempt - user is guaranteed to be authenticated due to LoginRequiredMixin
        UserLoginLog.objects.create(
            user=cast(User, self.request.user),
            ip_address=get_safe_client_ip(self.request),
            user_agent=self.request.META.get("HTTP_USER_AGENT", ""),
            status="password_change_failed",
        )
        return super().form_invalid(form)


# View for backward compatibility
password_change_view = SecurePasswordChangeView.as_view()


logger = logging.getLogger(__name__)

# ===============================================================================
# MULTI-FACTOR AUTHENTICATION SETUP FLOW
# ===============================================================================

# Define 2FA Setup Steps for Progress Indicator.
# Labels are lazy (like the reverse_lazy URLs): module-level gettext would
# freeze them to the import-time locale.
TWO_FACTOR_STEPS = [
    {
        "label": gettext_lazy("Choose Method"),
        "description": gettext_lazy("Select authentication method"),
        "url": reverse_lazy("users:mfa_setup"),
    },
    {
        "label": gettext_lazy("Set Up Method"),
        "description": gettext_lazy("Configure your authenticator"),
        "url": reverse_lazy("users:mfa_setup_totp"),
    },
    {
        "label": gettext_lazy("Complete"),
        "description": gettext_lazy("Save backup codes"),
        "url": reverse_lazy("users:mfa_backup_codes"),
    },
]


@login_required
def mfa_method_selection(request: HttpRequest) -> HttpResponse:
    """MFA method selection - first step in 2FA setup"""

    # Check if user already has 2FA enabled - user is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    if user.two_factor_enabled:
        messages.info(request, _("2FA is already enabled for your account."))
        return redirect("users:user_profile")

    context = {"steps": TWO_FACTOR_STEPS, "current_step": 1}
    return render(request, "users/mfa_method_selection.html", context)


@login_required
def mfa_setup_totp(request: HttpRequest) -> HttpResponse:
    """Set up 2FA for user account using new MFA service"""
    # Check if user already has 2FA enabled - user is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    if user.two_factor_enabled:
        messages.info(request, _("2FA is already enabled for your account."))
        return redirect("users:user_profile")

    if request.method == "POST":
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data["token"]
            secret = request.session.get("2fa_secret")

            # Create temporary user object with the secret to verify
            if secret:
                # Verify the TOTP code using pyotp directly for setup
                totp = pyotp.TOTP(secret)
                if totp.verify(token):
                    try:
                        # Enable TOTP using MFA service
                        secret, backup_codes = MFAService.enable_totp(user, request, secret=secret)

                        # 🔒 Rotate session for security after enabling 2FA
                        SessionSecurityService.rotate_session_on_2fa_change(request)
                        update_session_auth_hash(request, user)

                        messages.success(request, _("2FA has been enabled successfully!"))

                        # Store backup codes in session to display once
                        request.session["new_backup_codes"] = backup_codes

                        # Clear setup session
                        if "2fa_secret" in request.session:
                            del request.session["2fa_secret"]

                        return redirect("users:mfa_backup_codes")

                    except Exception as e:
                        logger.error(f"🔥 [2FA] Failed to enable TOTP: {e}")
                        messages.error(request, _("Failed to enable 2FA. Please try again."))
                else:
                    form.add_error("token", _("Invalid verification code. Please try again."))
            else:
                form.add_error(None, _("Setup session expired. Please start over."))
    else:
        form = TwoFactorSetupForm()

    # Generate new secret and QR code for setup
    secret = TOTPService.generate_secret()
    request.session["2fa_secret"] = secret

    # Generate QR code using the static method
    qr_data = TOTPService.generate_qr_code(user, secret)

    context = {
        "form": form,
        "qr_code": qr_data,
        "secret": secret,  # For manual entry
        "user": user,
        "steps": TWO_FACTOR_STEPS,
        "current_step": 2,
        "back_url": reverse("users:mfa_setup"),  # Explicit back to method selection
    }

    return render(request, "users/mfa_setup.html", context)


@login_required
def mfa_setup_webauthn(request: HttpRequest) -> HttpResponse:
    """WebAuthn/Passkey setup - future implementation"""

    # Check if user already has 2FA enabled - user is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    if user.two_factor_enabled:
        messages.info(request, _("2FA is already enabled for your account."))
        return redirect("users:user_profile")

    # For now, redirect to TOTP setup with a message
    messages.info(request, _("WebAuthn/Passkeys are coming soon! Please use the Authenticator App method for now."))
    return redirect("users:mfa_setup_totp")


def _handle_2fa_rate_limit(request: HttpRequest, pending_email: str) -> HttpResponse | None:
    """Handle rate limiting for 2FA verification."""
    if getattr(request, "limited", False) and not getattr(settings, "TESTING", False):
        # Audit logging handled by @rate_limit decorator
        messages.error(request, _("Too many verification attempts. Please wait and try again."))
        return render(
            request,
            "users/mfa_verify.html",
            {"form": TwoFactorVerifyForm(request.POST), "pending_email": pending_email},
            status=429,
        )
    return None


def _handle_backup_code_warnings(request: HttpRequest, user: User) -> None:
    """Handle backup code warning messages."""
    remaining_codes = len(user.backup_tokens)
    if remaining_codes == 0:
        messages.warning(request, _("You have used your last backup code! Please generate new ones in your profile."))
    elif remaining_codes <= BACKUP_CODE_LOW_WARNING_THRESHOLD:
        messages.warning(
            request,
            _("You have {count} backup codes remaining. Consider generating new ones.").format(count=remaining_codes),
        )
    else:
        messages.info(request, _("Backup code used. You have {count} codes remaining.").format(count=remaining_codes))


def _abandon_pending_login(request: HttpRequest) -> HttpResponse:
    """Drop the half-finished login and send the browser back to the password step."""
    request.session.pop(PRE_2FA_SESSION_KEY, None)
    return _redirect(request, reverse("users:login"))


def _pending_login_still_valid(user: User, pending: _PendingLogin) -> bool:
    """Re-check, on the locked row, everything the password step relied on."""
    return (
        user.is_active
        and not user.is_account_locked()
        and user.is_staff_user
        and user.two_factor_enabled
        and constant_time_compare(user.get_session_auth_hash(), pending.auth_hash)
    )


def _verify_pending_login(request: HttpRequest, pending: _PendingLogin, token: str) -> tuple[str, str | None]:
    """Check the code for the pending user and finish the login on success.

    Returns (outcome, method). The transaction is kept narrow: lock, re-check, verify,
    count or reset, login(). It always returns normally, so a failed attempt commits and
    counts toward the lockout.
    """
    with transaction.atomic():
        user = User.objects.select_for_update().filter(pk=pending.user_id).first()
        if user is None or not _pending_login_still_valid(user, pending):
            return "abandon", None
        result = verify_login_second_factor(user, token, request)
        if not result.accepted:
            _log_user_login(request, user, "failed_2fa")
            if user.is_account_locked():
                return "locked", None
            return ("rate_limited" if result.rate_limited else "invalid"), None
        _log_user_login(request, user, "success")  # also resets the failure counter
        # Read by the user_logged_in audit handler.
        setattr(request, LOGIN_METHOD_REQUEST_ATTR, f"2fa_{result.method}")
        login(request, user, backend=pending.backend)
        return "success", result.method


def _complete_pending_login(request: HttpRequest, pending: _PendingLogin, token: str) -> HttpResponse | None:
    """Run the second step; return the response, or None to show the form again."""
    try:
        outcome, method = _verify_pending_login(request, pending, token)
        if outcome == "success":
            request.session.pop(PRE_2FA_SESSION_KEY, None)
            if pending.remember_me:
                request.session["remember_me"] = True
            else:
                request.session.pop("remember_me", None)
            SessionSecurityService.update_session_timeout(request)
    except Exception:
        # Never leave a half-finished authenticated session behind.
        if request.user.is_authenticated:
            logout(request)
        raise

    if outcome == "abandon":
        messages.error(request, _("Your sign-in expired or your account changed. Please sign in again."))
        return _abandon_pending_login(request)
    if outcome == "locked":
        messages.error(request, _("Account temporarily locked for security reasons. Please try again later."))
        return _abandon_pending_login(request)
    if outcome == "rate_limited":
        messages.error(request, _("Too many verification attempts. Please wait and try again."))
        return None
    if outcome == "invalid":
        messages.error(request, _("The 2FA code or backup code is invalid."))
        return None

    user = cast(User, request.user)
    if method == "backup_code":
        _handle_backup_code_warnings(request, user)
    messages.success(request, _("Welcome, {user_full_name}!").format(user_full_name=user.get_full_name()))
    return _redirect(request, pending.next)


@rate_limit(key="ip", rate="15/m", method="POST")
def mfa_verify(request: HttpRequest) -> HttpResponse:
    """Second step of the staff login: check the code for the pending user, then log in."""
    if request.user.is_authenticated:
        request.session.pop(PRE_2FA_SESSION_KEY, None)
        return redirect("dashboard")

    pending = _read_pending_login(request)
    pending_user = User.objects.filter(pk=pending.user_id).first() if pending else None
    if pending is None or pending_user is None:
        return _abandon_pending_login(request)

    if request.method == "POST":
        rate_limit_response = _handle_2fa_rate_limit(request, pending_user.email)
        if rate_limit_response:
            return rate_limit_response

        form = TwoFactorVerifyForm(request.POST)
        if form.is_valid():
            response = _complete_pending_login(request, pending, form.cleaned_data["token"])
            if response is not None:
                return response
    else:
        form = TwoFactorVerifyForm()

    return render(request, "users/mfa_verify.html", {"form": form, "pending_email": pending_user.email})


@login_required
def mfa_backup_codes(request: HttpRequest) -> HttpResponse:
    """Display backup codes after 2FA setup or regeneration"""
    backup_codes = request.session.get("new_backup_codes")

    if not backup_codes:
        messages.error(request, _("No backup codes available."))
        return redirect("users:user_profile")

    # Clear from session after display
    del request.session["new_backup_codes"]

    return render(
        request,
        "users/mfa_backup_codes.html",
        {
            "backup_codes": backup_codes,
            "steps": TWO_FACTOR_STEPS,
            "current_step": 3,
            "back_url": reverse("users:mfa_setup_totp"),  # Back to TOTP setup
        },
    )


def _confirm_both_factors(request: HttpRequest, locked_user: User) -> str | None:
    """Check the posted password and a current second factor; return an error, or None.

    Mirrors the API's MFADisableSerializer: the caller holds select_for_update on the user,
    and a wrong code is not charged to the login lockout, as on the API.
    """
    password = request.POST.get("password", "")
    if not password or not locked_user.check_password(password):
        return _("Invalid password.")
    token = request.POST.get("token", "").strip()
    if not locked_user.two_factor_enabled or not MFAService.verify_mfa_code(locked_user, token, request)["success"]:
        return _("Invalid verification code.")
    return None


@login_required
def mfa_regenerate_backup_codes(request: HttpRequest) -> HttpResponse:
    """Regenerate backup codes for 2FA; needs the password and a current second factor (#595)."""
    # User is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    if not user.two_factor_enabled:
        messages.error(request, _("Two-factor authentication is not enabled."))
        return redirect("users:user_profile")

    if request.method == "POST":
        with transaction.atomic():
            locked_user = User.objects.select_for_update().get(pk=user.pk)
            error = _confirm_both_factors(request, locked_user)
            backup_codes = locked_user.generate_backup_codes() if error is None else []
        if error is not None:
            messages.error(request, error)
            return render(
                request, "users/mfa_regenerate_backup_codes.html", {"backup_count": len(locked_user.backup_tokens)}
            )
        # A 2FA change rotates the acting session's key, as enable and disable do. Only this
        # session: the codes are not part of the session auth hash and the credential version
        # does not change, so signing out other sessions here could not be relied on.
        request.session.cycle_key()
        request.session["new_backup_codes"] = backup_codes

        messages.success(request, _("New backup codes have been generated."))
        return redirect("users:mfa_backup_codes")

    return render(request, "users/mfa_regenerate_backup_codes.html", {"backup_count": len(user.backup_tokens)})


@login_required
def mfa_disable(request: HttpRequest) -> HttpResponse:
    """Disable 2FA; needs the password and a current second factor (#595)."""
    # User is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    if not user.two_factor_enabled:
        messages.info(request, _("Two-factor authentication is already disabled."))
        return redirect("users:user_profile")

    if request.method == "POST":
        # The password and a current second factor, as the API requires (#595)
        with transaction.atomic():
            locked_user = User.objects.select_for_update().get(pk=user.pk)
            error = _confirm_both_factors(request, locked_user)
            if error is None:
                MFAService.disable_totp(locked_user, request=request)
        if error is not None:
            messages.error(request, error)
            return render(request, "users/mfa_disable.html")

        # 🔒 Rotate session for security after disabling 2FA
        SessionSecurityService.rotate_session_on_2fa_change(request)
        update_session_auth_hash(request, locked_user)

        # Log the action
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_safe_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            status="two_factor_disabled",
        )

        messages.success(request, _("Two-factor authentication has been disabled."))
        return redirect("users:user_profile")

    return render(request, "users/mfa_disable.html")


# ===============================================================================
# USER PROFILE MANAGEMENT
# ===============================================================================


@login_required
def user_profile(request: HttpRequest) -> HttpResponse:
    """User profile view and editing"""
    # User is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    profile, _created = UserProfile.objects.get_or_create(user=user)

    if request.method == "POST":
        form_data = request.POST.copy()
        if "language" in form_data and "preferred_language" not in form_data:
            form_data["preferred_language"] = form_data["language"]
        # The staff page renders personal/localisation fields only. Preserve hidden
        # notification and emergency-contact preferences on these partial submissions.
        for field in UserProfileForm.Meta.fields:
            if field not in form_data:
                form_data[field] = getattr(profile, field)
        for field in ("first_name", "last_name", "phone"):
            if field not in form_data:
                form_data[field] = getattr(user, field)
        form = UserProfileForm(form_data, instance=profile)
        if form.is_valid():
            from apps.common.localisation_middleware import sync_language_selection  # noqa: PLC0415

            with transaction.atomic():
                form.save()
            messages.success(request, _("Profile updated successfully."))
            response = redirect("users:user_profile")
            sync_language_selection(request, response, profile.preferred_language)
            return response
    else:
        form = UserProfileForm(instance=profile)

    # 🚀 Performance: Prefetch customer memberships to prevent N+1 queries
    user_with_memberships = User.objects.prefetch_related("customer_memberships__customer").get(pk=user.pk)

    context = {
        "form": form,
        "profile": profile,
        "user": user_with_memberships,
        "accessible_customers": user_with_memberships.get_accessible_customers(),
        "recent_logins": UserLoginLog.objects.filter(user=user, status="success").order_by("-timestamp")[:5],
    }

    return render(request, "users/profile.html", context)


# ===============================================================================
# USER MANAGEMENT (ADMIN)
# ===============================================================================


class UserListView(LoginRequiredMixin, ListView):
    """List all users (admin only)"""

    model = User
    template_name = "users/user_list.html"
    context_object_name = "users"
    paginate_by = 50

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["staff_roles"] = User.STAFF_ROLE_CHOICES
        return context

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_authenticated or not getattr(request.user, "is_staff_user", False):
            messages.error(request, _("You do not have permission to access this page."))
            return redirect("dashboard")
        return cast(HttpResponse, super().dispatch(request, *args, **kwargs))

    def get_queryset(self) -> QuerySet[User]:
        queryset = User.objects.select_related("profile").order_by("-date_joined")

        # Filter by staff role
        staff_role = self.request.GET.get("staff_role")
        if staff_role:
            queryset = queryset.filter(staff_role=staff_role)

        # Search
        search = self.request.GET.get("search")
        if search:
            queryset = queryset.filter(
                models.Q(email__icontains=search)
                | models.Q(first_name__icontains=search)
                | models.Q(last_name__icontains=search)
            )

        return queryset


class UserDetailView(LoginRequiredMixin, DetailView):
    """User detail view (admin only)"""

    model = User
    template_name = "users/user_detail.html"
    context_object_name = "user_detail"

    def get_object(self, queryset: QuerySet[User] | None = None) -> User:
        """🚀 Performance: Prefetch customer memberships to prevent N+1 queries"""
        if queryset is None:
            queryset = self.get_queryset()

        obj: User = queryset.prefetch_related("customer_memberships__customer").get(pk=self.kwargs["pk"])
        return obj

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_authenticated or not getattr(request.user, "is_staff_user", False):
            messages.error(request, _("You do not have permission to access this page."))
            return redirect("dashboard")
        return cast(HttpResponse, super().dispatch(request, *args, **kwargs))

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        user = self.object

        context.update(
            {
                "profile": getattr(user, "profile", None),
                "accessible_customers": user.get_accessible_customers(),
                "recent_logins": UserLoginLog.objects.filter(user=user).order_by("-timestamp")[:10],
                "customer_memberships": CustomerMembership.objects.filter(user=user).select_related("customer"),
            }
        )

        return context


# ===============================================================================
# API ENDPOINTS
# ===============================================================================


# ===============================================================================
# EMAIL ENUMERATION PREVENTION - HARDENED ENDPOINT
# ===============================================================================

# Uniform response timing to prevent side-channel analysis
UNIFORM_MIN_DELAY = 0.08  # 80ms base delay
UNIFORM_JITTER = 0.05  # +0..50ms random jitter


def _sleep_uniform() -> None:
    """Add consistent timing delay to prevent timing-based enumeration attacks."""
    # Use secrets for cryptographically secure randomness in security context
    time.sleep(UNIFORM_MIN_DELAY + secrets.randbits(16) / 65536.0 * UNIFORM_JITTER)


def _uniform_response() -> JsonResponse:
    """
    Return identical response regardless of email existence.

    SECURITY: Never reveals whether email exists in database.
    Always returns same payload structure and HTTP status code.
    """
    return JsonResponse(
        {
            "message": _("Please complete registration to continue"),
            "success": True,
        },
        status=200,
    )


@require_http_methods(["POST"])
# Soft rate limiting - degrades gracefully without blocking legitimate users
@rate_limit(key="apps.users.ratelimit_keys.user_or_ip", rate="15/m", method="POST")  # Short window
@rate_limit(key="apps.users.ratelimit_keys.user_or_ip", rate="150/h", method="POST")  # Long window
def api_check_email(request: HttpRequest) -> JsonResponse:
    """
    🔒 HARDENED EMAIL VALIDATION ENDPOINT

    SECURITY FEATURES:
    - Uniform responses prevent email enumeration attacks
    - Soft rate limiting with user-aware keys
    - Consistent timing to prevent side-channel analysis
    - No database queries - zero information disclosure
    - Same HTTP status code regardless of input

    NOTE: Actual email uniqueness is enforced server-side during registration.
    This endpoint provides UX feedback without revealing account existence.
    """
    # Audit logging for rate limit violations handled by @rate_limit decorator

    # Uniform timing delay prevents timing-based enumeration
    _sleep_uniform()

    # SECURITY: Always return identical response - never reveal email existence
    # Uniqueness will be enforced during actual registration submission
    return _uniform_response()


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================


def _log_user_login(request: HttpRequest, user: User, status: str) -> None:
    """Log user login attempt"""
    UserLoginLog.objects.create(
        user=user,
        ip_address=get_safe_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
        status=status,
    )

    # Update user's last login IP
    if status == "success":
        user.last_login_ip = get_safe_client_ip(request)
        user.failed_login_attempts = 0  # Reset failed attempts
        user.account_locked_until = None
        user.save(update_fields=["last_login_ip", "failed_login_attempts", "account_locked_until"])


def _get_safe_redirect_target(request: HttpRequest, fallback: str = "dashboard") -> str:
    """Validate and return a safe redirect target.

    Accepts only URLs that are on this host and use the expected scheme,
    otherwise returns the resolved fallback URL name/path.
    """

    raw_next = request.GET.get("next") or ""
    # Resolve fallback first (can be a URL name)
    fallback_url = resolve_url(fallback)

    if not raw_next:
        return fallback_url

    # Allow only same-host redirects and proper scheme
    if url_has_allowed_host_and_scheme(
        url=raw_next,
        allowed_hosts={request.get_host()},
        require_https=getattr(settings, "USE_HTTPS", False),
    ):
        try:
            return resolve_url(raw_next)
        except Exception:
            return fallback_url

    return fallback_url
