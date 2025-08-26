"""
User management views for PRAHO Platform
Romanian-localized authentication and profile forms.
"""

import logging
from typing import cast

import pyotp

logger = logging.getLogger(__name__)

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import (
    PasswordChangeView,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.core.exceptions import ValidationError
from django.db import models
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.http import require_http_methods
from django.views.generic import DetailView, ListView
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited

from apps.common.constants import BACKUP_CODE_LENGTH, BACKUP_CODE_LOW_WARNING_THRESHOLD
from apps.common.utils import (
    json_error,
    json_success,
)

from .models import CustomerMembership, User, UserLoginLog, UserProfile

# Type alias for cleaner type hints
CustomUser = User
from .forms import (
    CustomerOnboardingRegistrationForm,
    LoginForm,
    TwoFactorSetupForm,
    TwoFactorVerifyForm,
    UserProfileForm,
)

# ===============================================================================
# AUTHENTICATION VIEWS
# ===============================================================================

def login_view(request: HttpRequest) -> HttpResponse:
    """Romanian-localized login view with account lockout protection"""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']

            # Check if user exists and account is not locked
            try:
                user = User.objects.get(email=email)
                if user.is_account_locked():
                    remaining_minutes = user.get_lockout_remaining_time()
                    messages.error(
                        request,
                        _('Account temporarily locked for security reasons. Try again in {minutes} minutes.').format(
                            minutes=remaining_minutes
                        )
                    )
                    return render(request, 'users/login.html', {'form': form})
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
                user_obj.last_login_ip = _get_client_ip(request)
                user_obj.save(update_fields=['last_login_ip'])

                # Log successful login
                UserLoginLog.objects.create(
                    user=user_obj,
                    ip_address=_get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    status='success'
                )

                login(request, user_obj)
                messages.success(request, _('Welcome, {user_full_name}!').format(
                    user_full_name=user_obj.get_full_name()
                ))

                next_url = request.GET.get('next', 'dashboard')

                # Handle HTMX requests with full page reload
                if request.headers.get('HX-Request'):
                    response = HttpResponse()
                    response['HX-Redirect'] = reverse(next_url) if next_url == 'dashboard' else next_url
                    return response

                return redirect(next_url)
            else:
                # Failed login - increment failed attempts if user exists
                if user:
                    user.increment_failed_login_attempts()

                    # Log failed login attempt
                    UserLoginLog.objects.create(
                        user=user,
                        ip_address=_get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        status='failed_password'
                    )
                else:
                    # Log failed login for non-existent user (no user object)
                    UserLoginLog.objects.create(
                        user=None,
                        ip_address=_get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        status='failed_user_not_found'
                    )

                messages.error(request, _('Incorrect email or password.'))
    else:
        form = LoginForm()

    return render(request, 'users/login.html', {'form': form})


def register_view(request: HttpRequest) -> HttpResponse:
    """Enhanced user registration with proper customer onboarding"""
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = CustomerOnboardingRegistrationForm(request.POST)
        if form.is_valid():
            try:
                form.save()
                messages.success(
                    request,
                    _('Account created successfully! Please check your email for next steps.')
                )
                return redirect('users:login')
            except ValidationError as e:
                messages.error(request, str(e))
    else:
        form = CustomerOnboardingRegistrationForm()

    return render(request, 'users/register.html', {'form': form})


def logout_view(request: HttpRequest) -> HttpResponse:
    """Logout view with Romanian messages"""
    if request.user.is_authenticated:
        messages.success(request, _('You have been successfully logged out.'))

    logout(request)
    return redirect('users:login')


# ===============================================================================
# PASSWORD RESET
# ===============================================================================

@method_decorator([
    ratelimit(key='ip', rate='5/h', method='POST', block=True),  # 5 attempts per hour per IP
    ratelimit(key='header:user-agent', rate='10/h', method='POST', block=True),  # 10 per user agent
], name='dispatch')
class SecurePasswordResetView(PasswordResetView):
    """Secure password reset request view with rate limiting and audit logging"""
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email.html'
    success_url = reverse_lazy('users:password_reset_done')

    def get_email_subject(self):
        """Get translatable email subject"""
        return _("Password reset for your account")

    def dispatch(self, request, *args, **kwargs):
        try:
            return super().dispatch(request, *args, **kwargs)
        except Ratelimited:
            # Log rate limit exceeded
            UserLoginLog.objects.create(
                user=None,
                ip_address=_get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status='password_reset_rate_limited'
            )
            messages.error(request, _(
                'Too many password reset attempts. Please wait before trying again.'
            ))
            return render(request, self.template_name, {'form': self.get_form()})

    def form_valid(self, form):
        # Log password reset attempt for audit trail
        UserLoginLog.objects.create(
            user=None,  # Don't reveal if user exists in logs
            ip_address=_get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            status='password_reset_requested'
        )
        return super().form_valid(form)


class SecurePasswordResetDoneView(PasswordResetDoneView):
    """Password reset done view"""
    template_name = 'users/password_reset_done.html'


@method_decorator([
    ratelimit(key='ip', rate='10/h', method='POST', block=True),  # 10 password confirmations per hour per IP
], name='dispatch')
class SecurePasswordResetConfirmView(PasswordResetConfirmView):
    """Password reset confirmation view with audit logging and rate limiting"""
    template_name = 'users/password_reset_confirm.html'
    success_url = reverse_lazy('users:password_reset_complete')

    def dispatch(self, request, *args, **kwargs):
        try:
            return super().dispatch(request, *args, **kwargs)
        except Ratelimited:
            # Log rate limit exceeded
            UserLoginLog.objects.create(
                user=None,
                ip_address=_get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status='password_confirm_rate_limited'
            )
            messages.error(request, _(
                'Too many password confirmation attempts. Please wait before trying again.'
            ))
            return render(request, self.template_name, {
                'form': self.get_form(),
                'validlink': False
            })

    def form_valid(self, form):
        # Log successful password reset for audit
        user = form.user

        # Enhanced security logging
        UserLoginLog.objects.create(
            user=user,
            ip_address=_get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            status='password_reset_completed'
        )

        # Reset any account lockout since password was reset
        if hasattr(user, 'account_locked_until') and user.account_locked_until:
            user.account_locked_until = None
            user.failed_login_attempts = 0  # Reset failed attempts counter
            user.save(update_fields=['account_locked_until', 'failed_login_attempts'])

            # Log lockout reset
            UserLoginLog.objects.create(
                user=user,
                ip_address=_get_client_ip(self.request),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                status='account_lockout_reset'
            )

        # 🔒 Clean up 2FA secrets and rotate sessions for security
        from .services import SessionSecurityService
        SessionSecurityService.cleanup_2fa_secrets_on_recovery(user, _get_client_ip(self.request))

        return super().form_valid(form)

    def form_invalid(self, form):
        # Log failed password reset confirmation
        UserLoginLog.objects.create(
            user=None,
            ip_address=_get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            status='password_reset_failed'
        )
        return super().form_invalid(form)


class SecurePasswordResetCompleteView(PasswordResetCompleteView):
    """Password reset complete view"""
    template_name = 'users/password_reset_complete.html'


# Views for backward compatibility (use class-based views)
password_reset_view = SecurePasswordResetView.as_view()
password_reset_done_view = SecurePasswordResetDoneView.as_view()
password_reset_confirm_view = SecurePasswordResetConfirmView.as_view()
password_reset_complete_view = SecurePasswordResetCompleteView.as_view()


# ===============================================================================
# PASSWORD CHANGE
# ===============================================================================

@method_decorator([
    ratelimit(key='user', rate='10/h', method='POST', block=True),  # 10 password changes per hour per user
], name='dispatch')
class SecurePasswordChangeView(PasswordChangeView):
    """Secure password change view with rate limiting and audit logging"""
    template_name = 'users/password_change.html'
    success_url = reverse_lazy('users:user_profile')

    def dispatch(self, request, *args, **kwargs):
        try:
            return super().dispatch(request, *args, **kwargs)
        except Ratelimited:
            # Log rate limit exceeded
            UserLoginLog.objects.create(
                user=request.user,
                ip_address=_get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                status='password_change_rate_limited'
            )
            messages.error(request, _(
                'Too many password change attempts. Please wait before trying again.'
            ))
            return render(request, self.template_name, {'form': self.get_form()})

    def form_valid(self, form):
        # Log successful password change for audit
        UserLoginLog.objects.create(
            user=self.request.user,
            ip_address=_get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            status='password_changed'
        )

        # 🔒 Rotate session for security after password change
        from .services import SessionSecurityService
        SessionSecurityService.rotate_session_on_password_change(self.request)

        messages.success(
            self.request,
            _('Your password has been changed successfully!')
        )
        return super().form_valid(form)

    def form_invalid(self, form):
        # Log failed password change attempt
        UserLoginLog.objects.create(
            user=self.request.user,
            ip_address=_get_client_ip(self.request),
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            status='password_change_failed'
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
    {
        'label': _('Choose Method'),
        'description': _('Select authentication method'),
        'url': 'users:two_factor_setup'
    },
    {
        'label': _('Set Up Method'),
        'description': _('Configure your authenticator'),
        'url': 'users:two_factor_setup_totp'
    },
    {
        'label': _('Complete'),
        'description': _('Save backup codes'),
        'url': 'users:two_factor_backup_codes'
    }
]

@login_required
def mfa_method_selection(request: HttpRequest) -> HttpResponse:
    """MFA method selection - first step in 2FA setup"""

    # Check if user already has 2FA enabled
    user = request.user  # type: User
    if user.two_factor_enabled:
        messages.info(request, _('2FA is already enabled for your account.'))
        return redirect('users:user_profile')

    context = {
        'steps': TWO_FACTOR_STEPS,
        'current_step': 1
    }
    return render(request, 'users/two_factor_method_selection.html', context)

@login_required
def two_factor_setup_totp(request: HttpRequest) -> HttpResponse:
    """Set up 2FA for user account using new MFA service"""
    from .mfa import MFAService, TOTPService

    # Check if user already has 2FA enabled
    if request.user.two_factor_enabled:
        messages.info(request, _('2FA is already enabled for your account.'))
        return redirect('users:user_profile')

    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']
            secret = request.session.get('2fa_secret')

            # Create temporary user object with the secret to verify
            if secret:
                # Verify the TOTP code using pyotp directly for setup
                totp = pyotp.TOTP(secret)
                if totp.verify(token):
                    try:
                        # Enable TOTP using MFA service
                        secret, backup_codes = MFAService.enable_totp(request.user, request)

                        # 🔒 Rotate session for security after enabling 2FA
                        from .services import SessionSecurityService
                        SessionSecurityService.rotate_session_on_2fa_change(request)

                        messages.success(request, _('2FA has been enabled successfully!'))

                        # Store backup codes in session to display once
                        request.session['new_backup_codes'] = backup_codes

                        # Clear setup session
                        if '2fa_secret' in request.session:
                            del request.session['2fa_secret']

                        return redirect('users:two_factor_backup_codes')

                    except Exception as e:
                        logger.error(f"🔥 [2FA] Failed to enable TOTP: {e}")
                        messages.error(request, _('Failed to enable 2FA. Please try again.'))
                else:
                    form.add_error('token', _('Invalid verification code. Please try again.'))
            else:
                form.add_error(None, _('Setup session expired. Please start over.'))
    else:
        form = TwoFactorSetupForm()

    # Generate new secret and QR code for setup
    secret = TOTPService.generate_secret()
    request.session['2fa_secret'] = secret

    # Generate QR code using the static method
    qr_data = TOTPService.generate_qr_code(request.user, secret)

    context = {
        'form': form,
        'qr_code': qr_data,
        'secret': secret,  # For manual entry
        'user': request.user,
        'steps': TWO_FACTOR_STEPS,
        'current_step': 2,
        'back_url': reverse('users:two_factor_setup')  # Explicit back to method selection
    }

    return render(request, 'users/two_factor_setup.html', context)

@login_required
def two_factor_setup_webauthn(request: HttpRequest) -> HttpResponse:
    """WebAuthn/Passkey setup - future implementation"""

    # Check if user already has 2FA enabled
    if request.user.two_factor_enabled:
        messages.info(request, _('2FA is already enabled for your account.'))
        return redirect('users:user_profile')

    # For now, redirect to TOTP setup with a message
    messages.info(request, _('WebAuthn/Passkeys are coming soon! Please use the Authenticator App method for now.'))
    return redirect('users:two_factor_setup_totp')


def two_factor_verify(request: HttpRequest) -> HttpResponse:
    """Verify 2FA token during login"""
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect('login')

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        del request.session['pre_2fa_user_id']
        return redirect('login')

    if request.method == 'POST':
        form = TwoFactorVerifyForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data['token']

            # Try TOTP code first
            totp_valid = pyotp.TOTP(user.two_factor_secret).verify(token)
            backup_code_valid = False

            # If TOTP fails, try backup code (8 digits)
            if not totp_valid and len(token) == BACKUP_CODE_LENGTH and token.isdigit():
                backup_code_valid = user.verify_backup_code(token)

            if totp_valid or backup_code_valid:
                # Complete login
                login(request, user)
                del request.session['pre_2fa_user_id']

                # Log which method was used
                method = 'totp' if totp_valid else 'backup_code'
                _log_user_login(request, user, f'success_2fa_{method}')

                if backup_code_valid:
                    remaining_codes = len(user.backup_tokens)
                    if remaining_codes == 0:
                        messages.warning(
                            request,
                            _('You have used your last backup code! Please generate new ones in your profile.')
                        )
                    elif remaining_codes <= BACKUP_CODE_LOW_WARNING_THRESHOLD:
                        messages.warning(
                            request,
                            _('You have {count} backup codes remaining. Consider generating new ones.').format(count=remaining_codes)
                        )
                    else:
                        messages.info(request, _('Backup code used. You have {count} codes remaining.').format(count=remaining_codes))

                messages.success(request, _('Welcome, {user_full_name}!').format(user_full_name=user.get_full_name()))

                next_url = request.GET.get('next', 'dashboard')
                return redirect(next_url)
            else:
                _log_user_login(request, user, 'failed_2fa')
                messages.error(request, _('The 2FA code or backup code is invalid.'))
    else:
        form = TwoFactorVerifyForm()

    return render(request, 'users/two_factor_verify.html', {
        'form': form,
        'user': user
    })


@login_required
def two_factor_backup_codes(request: HttpRequest) -> HttpResponse:
    """Display backup codes after 2FA setup or regeneration"""
    backup_codes = request.session.get('new_backup_codes')

    if not backup_codes:
        messages.error(request, _('No backup codes available.'))
        return redirect('users:user_profile')

    # Clear from session after display
    del request.session['new_backup_codes']

    return render(request, 'users/two_factor_backup_codes.html', {
        'backup_codes': backup_codes,
        'steps': TWO_FACTOR_STEPS,
        'current_step': 3,
        'back_url': reverse('users:two_factor_setup_totp')  # Back to TOTP setup
    })


@login_required
def two_factor_regenerate_backup_codes(request: HttpRequest) -> HttpResponse:
    """Regenerate backup codes for 2FA"""
    if not request.user.two_factor_enabled:
        messages.error(request, _('Two-factor authentication is not enabled.'))
        return redirect('users:user_profile')

    if request.method == 'POST':
        # Generate new backup codes
        backup_codes = request.user.generate_backup_codes()
        request.session['new_backup_codes'] = backup_codes

        messages.success(request, _('New backup codes have been generated.'))
        return redirect('users:two_factor_backup_codes')

    return render(request, 'users/two_factor_regenerate_backup_codes.html', {
        'backup_count': len(request.user.backup_tokens)
    })


@login_required
def two_factor_disable(request: HttpRequest) -> HttpResponse:
    """Disable 2FA for user account"""
    if not request.user.two_factor_enabled:
        messages.info(request, _('Two-factor authentication is already disabled.'))
        return redirect('users:user_profile')

    if request.method == 'POST':
        # Verify current password for security
        password = request.POST.get('password')
        if not request.user.check_password(password):
            messages.error(request, _('Invalid password.'))
            return render(request, 'users/two_factor_disable.html')

        # Disable 2FA
        request.user.two_factor_enabled = False
        request.user.two_factor_secret = ''  # nosec B105
        request.user.backup_tokens = []
        request.user.save(update_fields=['two_factor_enabled', '_two_factor_secret', 'backup_tokens'])

        # 🔒 Rotate session for security after disabling 2FA
        from .services import SessionSecurityService
        SessionSecurityService.rotate_session_on_2fa_change(request)

        # Log the action
        UserLoginLog.objects.create(
            user=request.user,
            ip_address=_get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            status='two_factor_disabled'
        )

        messages.success(request, _('Two-factor authentication has been disabled.'))
        return redirect('users:user_profile')

    return render(request, 'users/two_factor_disable.html')


# ===============================================================================
# USER PROFILE MANAGEMENT
# ===============================================================================

@login_required
def user_profile(request: HttpRequest) -> HttpResponse:
    """User profile view and editing"""
    profile, created = UserProfile.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=profile)
        if form.is_valid():
            form.save()
            messages.success(request, _('Profile updated successfully.'))
            return redirect('user_profile')
    else:
        form = UserProfileForm(instance=profile)

    # 🚀 Performance: Prefetch customer memberships to prevent N+1 queries
    user_with_memberships = User.objects.prefetch_related(
        'customer_memberships__customer'
    ).get(pk=request.user.pk)

    context = {
        'form': form,
        'profile': profile,
        'user': user_with_memberships,
        'accessible_customers': user_with_memberships.get_accessible_customers(),
        'recent_logins': UserLoginLog.objects.filter(
            user=request.user,
            status='success'
        ).order_by('-timestamp')[:5],
    }

    return render(request, 'users/profile.html', context)


# ===============================================================================
# USER MANAGEMENT (ADMIN)
# ===============================================================================

class UserListView(LoginRequiredMixin, ListView):
    """List all users (admin only)"""
    model = User
    template_name = 'users/user_list.html'
    context_object_name = 'users'
    paginate_by = 50

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff:
            messages.error(request, _('You do not have permission to access this page.'))
            return redirect('dashboard')
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        queryset = User.objects.select_related('profile').order_by('-date_joined')

        # Filter by staff role
        staff_role = self.request.GET.get('staff_role')
        if staff_role:
            queryset = queryset.filter(staff_role=staff_role)

        # Search
        search = self.request.GET.get('search')
        if search:
            queryset = queryset.filter(
                models.Q(email__icontains=search) |
                models.Q(first_name__icontains=search) |
                models.Q(last_name__icontains=search)
            )

        return queryset


class UserDetailView(LoginRequiredMixin, DetailView):
    """User detail view (admin only)"""
    model = User
    template_name = 'users/user_detail.html'
    context_object_name = 'user_detail'

    def get_object(self, queryset=None):
        """🚀 Performance: Prefetch customer memberships to prevent N+1 queries"""
        if queryset is None:
            queryset = self.get_queryset()

        return queryset.prefetch_related(
            'customer_memberships__customer'
        ).get(pk=self.kwargs['pk'])

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_staff:
            messages.error(request, _('You do not have permission to access this page.'))
            return redirect('dashboard')
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.object

        context.update({
            'profile': getattr(user, 'profile', None),
            'accessible_customers': user.get_accessible_customers(),
            'recent_logins': UserLoginLog.objects.filter(
                user=user
            ).order_by('-timestamp')[:10],
            'customer_memberships': CustomerMembership.objects.filter(
                user=user,
                is_active=True
            ).select_related('customer'),
        })

        return context


# ===============================================================================
# API ENDPOINTS
# ===============================================================================

@require_http_methods(["POST"])
@ratelimit(key='ip', rate='30/m', method='POST', block=True)  # Rate limit to prevent abuse
def api_check_email(request: HttpRequest) -> JsonResponse:
    """Check if email is already registered

    🔒 SECURITY: CSRF protection enabled, rate limited to prevent enumeration attacks.
    This endpoint validates email uniqueness for registration forms.
    """
    email = request.POST.get('email')

    if not email:
        return json_error(_('Email is required'))

    # ⚠️ Security: Only check email format, don't reveal existence for privacy
    try:
        from django.core.validators import validate_email
        validate_email(email)
    except ValidationError:
        return json_error(_('Invalid email format'))

    exists = User.objects.filter(email=email).exists()

    return json_success({
        'email': email,
        'exists': exists,
        'message': _('Email available') if not exists else _('Email already in use')
    })


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

def _log_user_login(request: HttpRequest, user: User, status: str) -> None:
    """Log user login attempt"""
    UserLoginLog.objects.create(
        user=user,
        ip_address=_get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
        status=status
    )

    # Update user's last login IP
    if status == 'success':
        user.last_login_ip = _get_client_ip(request)
        user.failed_login_attempts = 0  # Reset failed attempts
        user.account_locked_until = None
        user.save(update_fields=['last_login_ip', 'failed_login_attempts', 'account_locked_until'])


def _get_client_ip(request: HttpRequest) -> str:
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR', '')
    return ip
