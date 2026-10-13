"""
User forms for PRAHO Platform
Romanian-localized authentication and profile forms.
"""

import re
from collections.abc import Callable
from typing import Any, ClassVar, TypeVar, cast

from django import forms
from django.conf import settings
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm, UserCreationForm
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.utils import timezone  # For GDPR consent timestamps
from django.utils.translation import gettext_lazy as _

from apps.common.localisation import DATE_FORMAT_CHOICES, INHERIT_LABEL, LANGUAGE_CHOICES, TIMEZONES

from .models import CustomerMembership, User, UserProfile

T = TypeVar("T")

# Romanian validation constants
MIN_VAT_DIGITS = 6  # Minimum number of digits in Romanian VAT number


class OneTimeCodeInput(forms.TextInput):
    """Keep authentication codes visible while typing without redisplaying submitted values."""

    def format_value(self, value: object) -> None:
        return None


def _api_token_default_ttl_initial() -> int | None:
    """Mirror the deployment token-expiry default in the creation form."""
    default_ttl = int(getattr(settings, "API_TOKEN_DEFAULT_TTL_DAYS", 90))
    return default_ttl if default_ttl > 0 else None


class APITokenCreateForm(forms.Form):
    """Validate staff-created API token metadata."""

    name = forms.CharField(
        label=_("Name"),
        max_length=100,
        help_text=_("A short label identifying the script or integration."),
    )
    description = forms.CharField(
        label=_("Description"),
        required=False,
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text=_("Optional details about this token's purpose."),
    )
    ttl_days = forms.IntegerField(
        label=_("Expires after"),
        required=False,
        min_value=1,
        initial=_api_token_default_ttl_initial,
        help_text=_("Days until expiry. Leave blank to use the deployment default."),
    )

    def clean_name(self) -> str:
        name = cast(str, self.cleaned_data["name"])
        if not name.isprintable():
            raise ValidationError(_("Token name must not contain control characters."))
        return name


class LoginForm(forms.Form):
    """Romanian login form"""

    email = forms.EmailField(
        label=_("Email"),
        widget=forms.EmailInput(attrs={"class": "form-input", "placeholder": _("name@example.com"), "autofocus": True}),
    )
    password = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"class": "form-input", "placeholder": _("Your password")}),
    )
    remember_me = forms.BooleanField(
        label=_("Remember me"), required=False, widget=forms.CheckboxInput(attrs={"class": "form-checkbox"})
    )


class UserRegistrationForm(UserCreationForm):
    """Romanian user registration form"""

    email = forms.EmailField(
        label=_("Email"),
        help_text=_("The email address will be used for authentication."),
        widget=forms.EmailInput(
            attrs={
                "class": "pl-10 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md bg-slate-800 text-white placeholder-slate-400",
                "placeholder": _("name@example.com"),
            }
        ),
    )

    first_name = forms.CharField(
        label=_("First Name"),
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "pl-10 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md bg-slate-800 text-white placeholder-slate-400",
                "placeholder": _("John"),
            }
        ),
    )

    last_name = forms.CharField(
        label=_("Last Name"),
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "pl-10 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md bg-slate-800 text-white placeholder-slate-400",
                "placeholder": _("Doe"),
            }
        ),
    )

    phone = forms.CharField(
        label=_("Phone"),
        required=False,
        help_text=_("Romanian phone number (+40.XX.XXX.XXXX)"),
        widget=forms.TextInput(
            attrs={
                "class": "pl-10 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md bg-slate-800 text-white placeholder-slate-400",
                "placeholder": "+40.21.123.4567",
            }
        ),
    )

    accepts_marketing = forms.BooleanField(
        label=_("I agree to receive commercial offers by email"),
        required=False,
        widget=forms.CheckboxInput(
            attrs={"class": "focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded bg-slate-700"}
        ),
    )

    gdpr_consent = forms.BooleanField(
        label=_("I accept the processing of personal data according to GDPR"),
        required=True,
        widget=forms.CheckboxInput(
            attrs={"class": "focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded bg-slate-700"}
        ),
    )

    class Meta:
        model = User
        fields: ClassVar[tuple[str, ...]] = (
            "email",
            "first_name",
            "last_name",
            "phone",
            "password1",
            "password2",
            "accepts_marketing",
            "gdpr_consent",
        )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Customize password fields
        self.fields["password1"].label = _("Password")
        self.fields["password1"].widget.attrs.update(
            {
                "class": "pl-10 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md bg-slate-800 text-white placeholder-slate-400",
                "placeholder": _("Minimum 12 characters"),
            }
        )

        self.fields["password2"].label = _("Confirm password")
        self.fields["password2"].widget.attrs.update(
            {
                "class": "pl-10 focus:ring-blue-500 focus:border-blue-500 block w-full shadow-sm sm:text-sm border-gray-300 rounded-md bg-slate-800 text-white placeholder-slate-400",
                "placeholder": _("Repeat password"),
            }
        )

        # Remove username field requirement
        if "username" in self.fields:
            del self.fields["username"]

    def clean_email(self) -> str:
        # Normalize email to lowercase; use raw data as fallback to avoid dependency on cleaned_data population
        raw = self.data.get("email") if hasattr(self, "data") else None
        email: str | None = self.cleaned_data.get("email") if hasattr(self, "cleaned_data") else None
        normalized = (email or raw or "").lower()
        return normalized or ""

    def is_valid(self) -> bool:
        """Suppress model-level unique email errors to prevent enumeration.

        If the only validation error is the unique constraint on email,
        treat the form as valid so the view can apply neutral handling.
        """
        valid = super().is_valid()
        if valid:
            return True

        # Check if the only error is unique email
        errors = self.errors
        if (
            errors
            and set(errors.keys()) == {"email"}
            and all(getattr(err, "code", None) in {"unique", None} for err in errors.as_data().get("email", []))
        ):
            # Remove email error and proceed as valid
            self.errors.pop("email", None)
            return True
        return False

    def clean_phone(self) -> str:
        """Validate Romanian phone number format"""
        phone: str | None = self.cleaned_data.get("phone")
        if phone and phone.strip():
            phone = phone.strip()
            # Romanian phone patterns: +40.XX.XXX.XXXX, +40 XXX XXX XXX, 07XXXXXXXX
            # Allow digits with dots or spaces as separators, or plain 10-digit starting with 0
            if not re.match(r"^(\+40[\.\s]*[0-9][\.\s0-9]{8,11}[0-9]|0[0-9]{9})$", phone):
                raise ValidationError(_("Invalid phone number format. Use Romanian format: +40.XX.XXX.XXXX"))
        return phone or ""

    def save(self, commit: bool = True) -> User:
        user = super().save(commit=False)
        user.username = self.cleaned_data["email"]  # Use email as username
        user.email = self.cleaned_data["email"]
        user.accepts_marketing = self.cleaned_data["accepts_marketing"]
        # Ensure staff_role is never NULL at DB level
        if user.staff_role is None:
            user.staff_role = ""

        if commit:
            user.save()

            # Set GDPR consent date
            user.gdpr_consent_date = timezone.now()
            user.save(update_fields=["gdpr_consent_date"])

        return cast(User, user)


class UserProfileForm(forms.ModelForm):
    """User profile editing form"""

    # Add user fields to the form
    first_name = forms.CharField(
        label=_("First Name"), max_length=30, widget=forms.TextInput(attrs={"class": "form-input"})
    )

    last_name = forms.CharField(
        label=_("Last Name"), max_length=30, widget=forms.TextInput(attrs={"class": "form-input"})
    )

    phone = forms.CharField(
        label=_("Phone"),
        required=False,
        widget=forms.TextInput(attrs={"class": "form-input", "placeholder": "+40.21.123.4567"}),
    )

    class Meta:
        model = UserProfile
        fields: ClassVar[tuple[str, ...]] = (
            "preferred_language",
            "timezone",
            "date_format",
            "email_notifications",
            "sms_notifications",
            "marketing_emails",
            "emergency_contact_name",
            "emergency_contact_phone",
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            "preferred_language": forms.Select(attrs={"class": "form-select"}),
            "timezone": forms.Select(attrs={"class": "form-select"}),
            "date_format": forms.Select(attrs={"class": "form-select"}),
            "email_notifications": forms.CheckboxInput(attrs={"class": "form-checkbox"}),
            "sms_notifications": forms.CheckboxInput(attrs={"class": "form-checkbox"}),
            "marketing_emails": forms.CheckboxInput(attrs={"class": "form-checkbox"}),
            "emergency_contact_name": forms.TextInput(
                attrs={"class": "form-input", "placeholder": _("Emergency contact name")}
            ),
            "emergency_contact_phone": forms.TextInput(attrs={"class": "form-input", "placeholder": "+40.XX.XXX.XXXX"}),
        }

        labels: ClassVar[dict[str, Any]] = {
            "preferred_language": _("Preferred language"),
            "timezone": _("Timezone"),
            "date_format": _("Date format"),
            "email_notifications": _("Email notifications"),
            "sms_notifications": _("SMS notifications"),
            "marketing_emails": _("Marketing emails"),
            "emergency_contact_name": _("Emergency contact name"),
            "emergency_contact_phone": _("Emergency contact phone"),
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self.fields["preferred_language"].choices = [("", INHERIT_LABEL), *LANGUAGE_CHOICES]
        timezone_field = self.fields["timezone"]
        self.fields["timezone"] = forms.ChoiceField(
            required=timezone_field.required,
            label=timezone_field.label,
            help_text=timezone_field.help_text,
            widget=timezone_field.widget,
            choices=[("", INHERIT_LABEL), *((zone, zone) for zone in sorted(TIMEZONES))],
        )
        self.fields["date_format"].choices = [("", INHERIT_LABEL), *DATE_FORMAT_CHOICES]
        # Pre-populate user fields
        if self.instance and self.instance.user:
            self.fields["first_name"].initial = self.instance.user.first_name
            self.fields["last_name"].initial = self.instance.user.last_name
            self.fields["phone"].initial = self.instance.user.phone

    def clean_phone(self) -> str:
        """Validate Romanian phone number format"""
        phone: str | None = self.cleaned_data.get("phone")
        if phone and phone.strip():
            phone = phone.strip()
            # Romanian phone patterns: +40.XX.XXX.XXXX, +40 XXX XXX XXX, 07XXXXXXXX
            # Allow digits with dots or spaces as separators, or plain 10-digit starting with 0
            if not re.match(r"^(\+40[\.\s]*[0-9][\.\s0-9]{8,11}[0-9]|0[0-9]{9})$", phone):
                raise ValidationError(_("Invalid phone number format. Use Romanian format: +40.XX.XXX.XXXX"))
        return phone or ""

    def save(self, commit: bool = True) -> UserProfile:
        profile = super().save(commit=False)

        # Update user fields
        if commit and profile.user:
            user = profile.user
            user.first_name = self.cleaned_data["first_name"]
            user.last_name = self.cleaned_data["last_name"]
            user.phone = self.cleaned_data["phone"]
            user.save(update_fields=["first_name", "last_name", "phone"])

        if commit:
            profile.save()

        return cast(UserProfile, profile)


class TwoFactorSetupForm(forms.Form):
    """Two-factor authentication setup form"""

    # Not required by the form: an empty password gets the same answer as a wrong one.
    password = forms.CharField(
        label=_("Current password"),
        required=False,
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )

    token = forms.CharField(
        label=_("Verification code"),
        max_length=6,
        min_length=6,
        widget=OneTimeCodeInput(
            attrs={
                "class": "form-input text-center",
                "placeholder": "123456",
                "autocomplete": "off",
                "pattern": "[0-9]{6}",
                "inputmode": "numeric",
            }
        ),
        help_text=_("Enter the code from the authenticator app"),
    )

    def clean_token(self) -> str:
        token: str | None = self.cleaned_data.get("token")
        if token and not token.isdigit():
            raise ValidationError(_("The code must contain only digits."))
        return token or ""


class TwoFactorVerifyForm(forms.Form):
    """Two-factor authentication verification form"""

    token = forms.CharField(
        label=_("2FA Code"),
        max_length=8,  # Support both TOTP (6 digits) and backup codes (8 digits)
        min_length=6,
        widget=OneTimeCodeInput(
            attrs={
                "class": "form-input text-center",
                "placeholder": "123456",
                "autocomplete": "off",
                "autofocus": True,
                "pattern": "[0-9]{6,8}",  # Accept 6-8 digits
                "inputmode": "numeric",
            }
        ),
        help_text=_("Enter the code from the authenticator app or backup code"),
    )

    def clean_token(self) -> str:
        token: str | None = self.cleaned_data.get("token")
        if token and not token.isdigit():
            raise ValidationError(_("The code must contain only digits."))
        return token or ""


class PasswordResetRequestForm(forms.Form):
    """Password reset request form"""

    email = forms.EmailField(
        label=_("Email"),
        widget=forms.EmailInput(attrs={"class": "form-input", "placeholder": _("name@example.com"), "autofocus": True}),
        help_text=_("Enter the email associated with your account."),
    )

    def clean_email(self) -> str:
        email: str | None = self.cleaned_data.get("email")
        if email and not User.objects.filter(email=email).exists():
            raise ValidationError(_("There is no account with this email address."))
        return email or ""


class CustomerMembershipForm(forms.ModelForm):
    """Form for managing customer memberships (PostgreSQL-aligned)"""

    class Meta:
        model = CustomerMembership
        fields: ClassVar = ["role", "is_primary"]
        widgets: ClassVar = {
            "role": forms.Select(attrs={"class": "form-select"}),
            "is_primary": forms.CheckboxInput(attrs={"class": "form-checkbox"}),
        }
        labels: ClassVar = {
            "role": _("Role"),
            "is_primary": _("Primary Membership"),
        }


# ===============================================================================
# PASSWORD WRITES (#689)
# ===============================================================================


class PasswordAuthorityChanged(Exception):  # noqa: N818  # names the condition, like DatabaseError
    """What allowed this password write (the old password, a reset link) no longer holds on the row."""


def apply_password_change(user_pk: int, new_password: str, *, still_authorised: Callable[[User], bool]) -> User:
    """Write a new password under the row lock, after re-checking what authorised it.

    The forms validate against the instance loaded at the start of the request. Saving that
    instance whole wrote back anything changed meanwhile (an administrator's 2FA reset, the
    cached profile), and a password changed by another request was overwritten by one whose
    authority it had already lost. Here the row is locked, the authority re-checked on it, the
    policy re-run against it, and only the password column written. A pending authenticator
    setup is dropped (ADR-0058). The account is returned as committed, so the caller binds the
    session to the new credentials.
    """
    from django.contrib.auth.password_validation import validate_password  # noqa: PLC0415
    from django.db import transaction  # noqa: PLC0415

    from .pending_totp import discard  # noqa: PLC0415  # Circular: pending_totp imports models

    with transaction.atomic():
        locked = User.objects.select_for_update().get(pk=user_pk)
        if not still_authorised(locked):
            raise PasswordAuthorityChanged
        validate_password(new_password, locked)
        locked.set_password(new_password)
        locked.save(update_fields=["password"])
        discard(user_pk)
        return User.objects.select_related("credential_version").get(pk=user_pk)


class LockedPasswordChangeForm(PasswordChangeForm):
    """Django's change form, with the write done by apply_password_change.

    save(commit=False) sets the password on the instance only, as Django's does.
    """

    def save(self, commit: bool = True) -> User:
        if not commit:
            return cast(User, super().save(commit=False))
        old_password = self.cleaned_data["old_password"]
        written = apply_password_change(
            self.user.pk,
            self.cleaned_data["new_password1"],
            still_authorised=lambda locked: locked.check_password(old_password),
        )
        self.user = written
        return written


class LockedSetPasswordForm(SetPasswordForm):
    """Django's reset form, with the write done by apply_password_change.

    The link's token is re-checked on the locked row: it is derived from the password hash, so
    a password changed after the link was opened invalidates it.
    """

    def __init__(self, user: User, *args: Any, reset_token: str = "", **kwargs: Any) -> None:
        super().__init__(user, *args, **kwargs)
        self.reset_token = reset_token

    def save(self, commit: bool = True) -> User:
        if not commit:
            return cast(User, super().save(commit=False))
        token = self.reset_token
        written = apply_password_change(
            self.user.pk,
            self.cleaned_data["new_password1"],
            still_authorised=lambda locked: bool(token) and default_token_generator.check_token(locked, token),
        )
        self.user = written
        return written


# ===============================================================================
# 2FA CHANGES THAT NEED THE PASSWORD, A CODE AND A CONFIRMATION (#689)
# ===============================================================================


class _MFACredentialChangeForm(forms.Form):
    """The password and a current second factor. Both are checked on the locked row by the view.

    Neither is required here: an empty password or code gets the same answer as a wrong one.
    """

    password = forms.CharField(required=False, strip=False, widget=forms.PasswordInput)
    token = forms.CharField(required=False, max_length=8)


class MFADisableForm(_MFACredentialChangeForm):
    confirm_disable = forms.BooleanField(
        required=True,
        error_messages={"required": _("Confirm that you understand what disabling 2FA does.")},
    )


class MFARegenerateForm(_MFACredentialChangeForm):
    confirm_regenerate = forms.BooleanField(
        required=True,
        error_messages={"required": _("Confirm that your current backup codes will stop working.")},
    )
