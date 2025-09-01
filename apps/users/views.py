"""
User management views for PRAHO Platform
Romanian-localized authentication and profile forms.
"""

import hashlib
import logging
import secrets
import time
from typing import Any, cast
from uuid import uuid4

import pyotp
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import (
    PasswordChangeView,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.db import models
from django.db.models import QuerySet
from django.forms import Form
from django.http import HttpRequest, HttpResponse, HttpResponseBase, JsonResponse
from django.shortcuts import redirect, render, resolve_url
from django.template.loader import render_to_string
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_encode
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView
from django_ratelimit.decorators import ratelimit  # type: ignore[import-untyped]
from django_ratelimit.exceptions import Ratelimited  # type: ignore[import-untyped]

from apps.audit.services import AuthenticationAuditService, LogoutEventData, RateLimitEventData, SecurityAuditService
from apps.common.constants import BACKUP_CODE_LENGTH, BACKUP_CODE_LOW_WARNING_THRESHOLD
from apps.common.request_ip import get_safe_client_ip
from apps.common.validators import log_security_event

from .forms import (
    CustomerOnboardingRegistrationForm,
    LoginForm,
    TwoFactorSetupForm,
    TwoFactorVerifyForm,
    UserProfileForm,
)
from .mfa import MFAService, TOTPService
from .models import CustomerMembership, User, UserLoginLog, UserProfile
from .services import SessionSecurityService

logger = logging.getLogger(__name__)

# Type alias for cleaner type hints
CustomUser = User

# ===============================================================================
# AUTHENTICATION VIEWS
# ===============================================================================


@ratelimit(key="ip", rate="10/m", method="POST", block=False)  # type: ignore[misc]
@ratelimit(key="post:email", rate="5/m", method="POST", block=False)  # type: ignore[misc]
def login_view(request: HttpRequest) -> HttpResponse:
    """Romanian-localized login view with account lockout protection"""
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        # If rate-limited and not in test mode, show friendly error
        if getattr(request, "limited", False) and not getattr(settings, "TESTING", False):
            # Log rate limit event to audit system
            rate_limit_data = RateLimitEventData(
                endpoint="users:login",
                ip_address=get_safe_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                rate_limit_key="ip,email",
                rate_limit_rate="10/m,5/m",
            )
            SecurityAuditService.log_rate_limit_event(
                event_data=rate_limit_data,
                user=None,  # User not authenticated yet
            )
            messages.error(request, _("Too many login attempts. Please wait and try again."))
            return render(request, "users/login.html", {"form": LoginForm(request.POST)}, status=429)
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]

            # Check if user exists and account is not locked
            try:
                user = User.objects.get(email=email)
                if user.is_account_locked():
                    remaining_minutes = user.get_lockout_remaining_time()
                    messages.error(
                        request,
                        _("Account temporarily locked for security reasons. Try again in {minutes} minutes.").format(
                            minutes=remaining_minutes
                        ),
                    )
                    return render(request, "users/login.html", {"form": form})
            except User.DoesNotExist:
                # Don't reveal that user doesn't exist
                user = None

            # Authenticate user
            authenticated_user = authenticate(request, username=email, password=password)

            if authenticated_user:
                # Successful login - reset failed attempts and log success
                user_obj = cast(User, authenticated_user)
                user_obj.reset_failed_login_attempts()

                # Update login tracking
                user_obj.last_login_ip = get_safe_client_ip(request)
                user_obj.save(update_fields=["last_login_ip"])

                # Log successful login
                UserLoginLog.objects.create(
                    user=user_obj,
                    ip_address=get_safe_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    status="success",
                )

                login(request, user_obj)

                # Remember me handling and secure session timeout
                remember = bool(form.cleaned_data.get("remember_me"))
                if remember:
                    request.session["remember_me"] = True
                else:
                    request.session.pop("remember_me", None)

                # Update timeout policy based on context
                SessionSecurityService.update_session_timeout(request)

                messages.success(
                    request, _("Welcome, {user_full_name}!").format(user_full_name=user_obj.get_full_name())
                )

                next_url = _get_safe_redirect_target(request, fallback="dashboard")

                # Handle HTMX requests with full page reload
                if request.headers.get("HX-Request"):
                    response = HttpResponse()
                    response["HX-Redirect"] = next_url
                    return response

                return redirect(next_url)
            else:
                # Failed login - increment failed attempts if user exists
                if user:
                    user.increment_failed_login_attempts()

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

                messages.error(request, _("Incorrect email or password."))
    else:
        form = LoginForm()

    return render(request, "users/login.html", {"form": form})


@ratelimit(key="ip", rate="5/h", method="POST", block=False)  # type: ignore[misc]
@ratelimit(key="header:user-agent", rate="10/h", method="POST", block=False)  # type: ignore[misc]
def register_view(request: HttpRequest) -> HttpResponse:
    """Enhanced user registration with proper customer onboarding"""
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        if getattr(request, "limited", False) and not getattr(settings, "TESTING", False):
            # Log rate limit event to audit system
            rate_limit_data = RateLimitEventData(
                endpoint="users:register",
                ip_address=get_safe_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                rate_limit_key="ip,user-agent",
                rate_limit_rate="5/h,10/h",
            )
            SecurityAuditService.log_rate_limit_event(
                event_data=rate_limit_data,
                user=None,  # User not registered yet
            )
            messages.error(request, _("Too many registration attempts. Please wait and try again."))
            return render(
                request, "users/register.html", {"form": CustomerOnboardingRegistrationForm(request.POST)}, status=429
            )
        form = CustomerOnboardingRegistrationForm(request.POST)
        # Normalize email early and handle existing users with a neutral flow (prevents enumeration)
        raw_email = (request.POST.get("email") or "").lower()
        if raw_email and User.objects.filter(email=raw_email).exists():
            _audit_registration_attempt(request, raw_email, "existing_user")
            try:
                user = User.objects.get(email=raw_email)
                _send_password_reset_for_existing_user(user, request)
            except User.DoesNotExist:
                # Race condition: treat uniformly without leaking info
                pass
            _sleep_uniform()
            return redirect("users:registration_submitted")
        
        if form.is_valid():
            email = form.cleaned_data.get("email", "").lower()
            # Existing user path handled above; proceed with new user creation

            # New user path
            try:
                form.save()
                _audit_registration_attempt(request, email, "new_user")
                _sleep_uniform()
                return redirect("users:registration_submitted")
            except ValidationError:
                # Treat as validation failure
                _audit_registration_attempt(request, email, "form_validation_error")
            except Exception:
                # Likely integrity or unexpected issue; treat as existing for uniformity
                _audit_registration_attempt(request, email, "existing_user")
                try:
                    user = User.objects.get(email=email)
                    _send_password_reset_for_existing_user(user, request)
                except User.DoesNotExist:
                    pass
                _sleep_uniform()
                return redirect("users:registration_submitted")
        else:
            # Form validation errors path (keep user on page, but audit attempt)
            email = (request.POST.get("email") or "").lower()
            _audit_registration_attempt(request, email, "form_validation_error")
    else:
        form = CustomerOnboardingRegistrationForm()

    return render(request, "users/register.html", {"form": form})


def registration_submitted_view(request: HttpRequest) -> HttpResponse:
    """Neutral page shown after registration submission (prevents enumeration)."""
    return render(request, "users/registration_submitted.html")


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
        ratelimit(key="ip", rate="5/h", method="POST", block=True),  # 5 attempts per hour per IP
        ratelimit(key="header:user-agent", rate="10/h", method="POST", block=True),  # 10 per user agent
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
        try:
            return super().dispatch(request, *args, **kwargs)
        except Ratelimited:
            # Log rate limit exceeded
            UserLoginLog.objects.create(
                user=None,
                ip_address=get_safe_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                status="password_reset_rate_limited",
            )
            messages.error(request, _("Too many password reset attempts. Please wait before trying again."))
            return render(request, self.template_name, {"form": self.get_form()})

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
        ratelimit(key="ip", rate="10/h", method="POST", block=True),  # 10 password confirmations per hour per IP
    ],
    name="dispatch",
)
class SecurePasswordResetConfirmView(PasswordResetConfirmView):
    """Password reset confirmation view with audit logging and rate limiting"""

    template_name = "users/password_reset_confirm.html"
    success_url = reverse_lazy("users:password_reset_complete")

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        try:
            return super().dispatch(request, *args, **kwargs)
        except Ratelimited:
            # Log rate limit exceeded
            UserLoginLog.objects.create(
                user=None,
                ip_address=get_safe_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                status="password_confirm_rate_limited",
            )
            messages.error(request, _("Too many password confirmation attempts. Please wait before trying again."))
            return render(request, self.template_name, {"form": self.get_form(), "validlink": False})

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

        # 🔒 Clean up 2FA secrets and rotate sessions for security
        SessionSecurityService.cleanup_2fa_secrets_on_recovery(user, get_safe_client_ip(self.request))

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
        ratelimit(key="user", rate="10/h", method="POST", block=True),  # 10 password changes per hour per user
    ],
    name="dispatch",
)
class SecurePasswordChangeView(PasswordChangeView):
    """Secure password change view with rate limiting and audit logging"""

    template_name = "users/password_change.html"
    success_url = reverse_lazy("users:user_profile")

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponseBase:
        try:
            return super().dispatch(request, *args, **kwargs)
        except Ratelimited:
            # Log rate limit exceeded - only log if user is authenticated
            if request.user.is_authenticated:
                UserLoginLog.objects.create(
                    user=cast(User, request.user),
                    ip_address=get_safe_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                    status="password_change_rate_limited",
                )
            messages.error(request, _("Too many password change attempts. Please wait before trying again."))
            return render(request, self.template_name, {"form": self.get_form()})

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

# Define 2FA Setup Steps for Progress Indicator
TWO_FACTOR_STEPS = [
    {"label": _("Choose Method"), "description": _("Select authentication method"), "url": "users:two_factor_setup"},
    {
        "label": _("Set Up Method"),
        "description": _("Configure your authenticator"),
        "url": "users:two_factor_setup_totp",
    },
    {"label": _("Complete"), "description": _("Save backup codes"), "url": "users:two_factor_backup_codes"},
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
    return render(request, "users/two_factor_method_selection.html", context)


@login_required
def two_factor_setup_totp(request: HttpRequest) -> HttpResponse:
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
                        secret, backup_codes = MFAService.enable_totp(user, request)

                        # 🔒 Rotate session for security after enabling 2FA
                        SessionSecurityService.rotate_session_on_2fa_change(request)

                        messages.success(request, _("2FA has been enabled successfully!"))

                        # Store backup codes in session to display once
                        request.session["new_backup_codes"] = backup_codes

                        # Clear setup session
                        if "2fa_secret" in request.session:
                            del request.session["2fa_secret"]

                        return redirect("users:two_factor_backup_codes")

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
        "back_url": reverse("users:two_factor_setup"),  # Explicit back to method selection
    }

    return render(request, "users/two_factor_setup.html", context)


@login_required
def two_factor_setup_webauthn(request: HttpRequest) -> HttpResponse:
    """WebAuthn/Passkey setup - future implementation"""

    # Check if user already has 2FA enabled - user is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    if user.two_factor_enabled:
        messages.info(request, _("2FA is already enabled for your account."))
        return redirect("users:user_profile")

    # For now, redirect to TOTP setup with a message
    messages.info(request, _("WebAuthn/Passkeys are coming soon! Please use the Authenticator App method for now."))
    return redirect("users:two_factor_setup_totp")


def _handle_2fa_rate_limit(request: HttpRequest, user: User) -> HttpResponse | None:
    """Handle rate limiting for 2FA verification."""
    if getattr(request, "limited", False) and not getattr(settings, "TESTING", False):
        # Log rate limit event to audit system
        rate_limit_data = RateLimitEventData(
            endpoint="users:two_factor_verify",
            ip_address=get_safe_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            rate_limit_key="ip",
            rate_limit_rate="10/m",
        )
        SecurityAuditService.log_rate_limit_event(
            event_data=rate_limit_data,
            user=user,  # User is partially authenticated at this point
        )
        messages.error(request, _("Too many verification attempts. Please wait and try again."))
        return render(
            request,
            "users/two_factor_verify.html",
            {"form": TwoFactorVerifyForm(request.POST), "user": user},
            status=429,
        )
    return None


def _verify_2fa_token(user: User, token: str) -> tuple[bool, bool]:
    """Verify 2FA token (TOTP or backup code)."""
    # Try TOTP code first
    totp_valid = pyotp.TOTP(user.two_factor_secret).verify(token)
    backup_code_valid = False

    # If TOTP fails, try backup code (8 digits)
    if not totp_valid and len(token) == BACKUP_CODE_LENGTH and token.isdigit():
        backup_code_valid = user.verify_backup_code(token)

    return totp_valid, backup_code_valid


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


@ratelimit(key="ip", rate="10/m", method="POST", block=False)  # type: ignore[misc]
def two_factor_verify(request: HttpRequest) -> HttpResponse:
    """Verify 2FA token during login"""
    user_id = request.session.get("pre_2fa_user_id")
    if not user_id:
        return redirect("users:login")

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        request.session.pop("pre_2fa_user_id", None)
        return redirect("users:login")

    if request.method == "POST":
        # Check rate limiting
        rate_limit_response = _handle_2fa_rate_limit(request, user)
        if rate_limit_response:
            return rate_limit_response

        form = TwoFactorVerifyForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data["token"]
            totp_valid, backup_code_valid = _verify_2fa_token(user, token)

            if totp_valid or backup_code_valid:
                # Complete login
                login(request, user)
                request.session.pop("pre_2fa_user_id", None)

                # Log which method was used
                method = "totp" if totp_valid else "backup_code"
                _log_user_login(request, user, f"success_2fa_{method}")

                if backup_code_valid:
                    _handle_backup_code_warnings(request, user)

                messages.success(request, _("Welcome, {user_full_name}!").format(user_full_name=user.get_full_name()))

                next_url = _get_safe_redirect_target(request, fallback="dashboard")
                return redirect(next_url)
            else:
                _log_user_login(request, user, "failed_2fa")
                messages.error(request, _("The 2FA code or backup code is invalid."))
    else:
        form = TwoFactorVerifyForm()

    return render(request, "users/two_factor_verify.html", {"form": form, "user": user})


@login_required
def two_factor_backup_codes(request: HttpRequest) -> HttpResponse:
    """Display backup codes after 2FA setup or regeneration"""
    backup_codes = request.session.get("new_backup_codes")

    if not backup_codes:
        messages.error(request, _("No backup codes available."))
        return redirect("users:user_profile")

    # Clear from session after display
    del request.session["new_backup_codes"]

    return render(
        request,
        "users/two_factor_backup_codes.html",
        {
            "backup_codes": backup_codes,
            "steps": TWO_FACTOR_STEPS,
            "current_step": 3,
            "back_url": reverse("users:two_factor_setup_totp"),  # Back to TOTP setup
        },
    )


@login_required
def two_factor_regenerate_backup_codes(request: HttpRequest) -> HttpResponse:
    """Regenerate backup codes for 2FA"""
    # User is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    if not user.two_factor_enabled:
        messages.error(request, _("Two-factor authentication is not enabled."))
        return redirect("users:user_profile")

    if request.method == "POST":
        # Generate new backup codes
        backup_codes = user.generate_backup_codes()
        request.session["new_backup_codes"] = backup_codes

        messages.success(request, _("New backup codes have been generated."))
        return redirect("users:two_factor_backup_codes")

    return render(request, "users/two_factor_regenerate_backup_codes.html", {"backup_count": len(user.backup_tokens)})


@login_required
def two_factor_disable(request: HttpRequest) -> HttpResponse:
    """Disable 2FA for user account"""
    # User is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    if not user.two_factor_enabled:
        messages.info(request, _("Two-factor authentication is already disabled."))
        return redirect("users:user_profile")

    if request.method == "POST":
        # Verify current password for security
        password = request.POST.get("password")
        if not password or not user.check_password(password):
            messages.error(request, _("Invalid password."))
            return render(request, "users/two_factor_disable.html")

        # Disable 2FA
        user.two_factor_enabled = False
        user.two_factor_secret = ""  # nosec B105
        user.backup_tokens = []
        user.save(update_fields=["two_factor_enabled", "_two_factor_secret", "backup_tokens"])

        # 🔒 Rotate session for security after disabling 2FA
        SessionSecurityService.rotate_session_on_2fa_change(request)

        # Log the action
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_safe_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            status="two_factor_disabled",
        )

        messages.success(request, _("Two-factor authentication has been disabled."))
        return redirect("users:user_profile")

    return render(request, "users/two_factor_disable.html")


# ===============================================================================
# USER PROFILE MANAGEMENT
# ===============================================================================


@login_required
def user_profile(request: HttpRequest) -> HttpResponse:
    """User profile view and editing"""
    # User is guaranteed to be authenticated due to @login_required
    user = cast(User, request.user)
    profile, created = UserProfile.objects.get_or_create(user=user)

    if request.method == "POST":
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, _("Profile updated successfully."))
            return redirect("users:user_profile")
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

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_authenticated or not cast(User, request.user).is_staff:
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

        return queryset.prefetch_related("customer_memberships__customer").get(pk=self.kwargs["pk"])

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not request.user.is_authenticated or not cast(User, request.user).is_staff:
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
@ratelimit(key="apps.users.ratelimit_keys.user_or_ip", rate="10/m", method="POST", block=False)  # type: ignore[misc]  # Short window
@ratelimit(key="apps.users.ratelimit_keys.user_or_ip", rate="100/h", method="POST", block=False)  # type: ignore[misc]  # Long window
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
    # Check if user hit rate limits (soft limiting - no 429 errors)
    was_limited = getattr(request, "limited", False)

    if was_limited:
        # Log security event for monitoring
        log_security_event(
            "email_check_rate_limited",
            {
                "rate_limited": True,
                "ip_address": get_safe_client_ip(request),
                "user_authenticated": request.user.is_authenticated,
            },
            get_safe_client_ip(request),
        )

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


def _audit_registration_attempt(request: HttpRequest, email: str, result_type: str) -> dict[str, Any]:
    """Audit a registration attempt with correlation and privacy-preserving details."""
    # Ensure session key exists without assuming session middleware
    session_key = None
    try:
        session = getattr(request, "session", None)
        if session is not None:
            session_key = session.session_key
            if not session_key:
                session.modified = True
                session.save()
                session_key = session.session_key
    except Exception:  # pragma: no cover
        session_key = None

    details: dict[str, Any] = {
        "correlation_id": str(uuid4()),
        "timestamp": timezone.now().isoformat(),
        "email_hash": hashlib.sha256(email.lower().encode()).hexdigest()[:16],
        "result_type": result_type,
        "session_key": session_key,
    }
    log_security_event(event_type="registration_attempt", details=details, request_ip=get_safe_client_ip(request))
    return details


def _send_password_reset_for_existing_user(user: User, request: HttpRequest) -> None:
    """Send a neutral password-reset style email for existing users who re-register."""
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    context = {
        "user": user,
        "uid": uid,
        "token": token,
        "protocol": "https" if getattr(settings, "USE_HTTPS", False) else "http",
        "domain": getattr(settings, "DOMAIN_NAME", request.get_host() or "localhost"),
    }

    subject = str(_("Account Access - PRAHO Platform"))
    text_body = render_to_string("users/emails/existing_user_registration.txt", context)
    html_body = render_to_string("users/emails/existing_user_registration.html", context)

    email = EmailMultiAlternatives(subject=subject, body=text_body, to=[user.email])
    email.attach_alternative(html_body, "text/html")
    email.send(fail_silently=False)


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
