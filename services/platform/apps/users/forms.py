"""
User forms for PRAHO Platform
Romanian-localized authentication and profile forms.
"""

import re
from typing import Any, ClassVar, TypeVar, cast

import pytz
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.utils import timezone  # For GDPR consent timestamps
from django.utils.translation import gettext_lazy as _

from .models import CustomerMembership, User, UserProfile
from .services import UserRegistrationService

T = TypeVar("T")

# Romanian validation constants
MIN_VAT_DIGITS = 6  # Minimum number of digits in Romanian VAT number
CNP_LENGTH = 13  # Romanian CNP (Personal Numeric Code) is exactly 13 digits


class LoginForm(forms.Form):
    """Romanian login form"""

    email = forms.EmailField(
        label=_("Email"),
        widget=forms.EmailInput(attrs={"class": "form-input", "placeholder": _("name@example.com"), "autofocus": True}),
    )
    password = forms.CharField(
        label=_("Password"),
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

        # Pre-populate user fields
        if self.instance and self.instance.user:
            self.fields["first_name"].initial = self.instance.user.first_name
            self.fields["last_name"].initial = self.instance.user.last_name
            self.fields["phone"].initial = self.instance.user.phone

    def clean_timezone(self) -> str:
        """Validate timezone"""
        timezone: str | None = self.cleaned_data.get("timezone")
        if timezone and timezone not in pytz.all_timezones:
            raise ValidationError(_("Invalid timezone selected."))
        return timezone or ""

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

    token = forms.CharField(
        label=_("Verification code"),
        max_length=6,
        min_length=6,
        widget=forms.TextInput(
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
        widget=forms.TextInput(
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


class CustomerOnboardingRegistrationForm(UserCreationForm):
    """
    🏢 Enhanced registration form with customer organization creation
    Ensures every user is properly associated with a customer entity
    """

    # ===============================================================================
    # USER INFORMATION
    # ===============================================================================

    email = forms.EmailField(
        label=_("Email Address"),
        help_text=_("This will be used for authentication and billing notifications."),
        widget=forms.EmailInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": _("your@company.com"),
            }
        ),
    )

    first_name = forms.CharField(
        label=_("First Name"),
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": _("Ion"),
            }
        ),
    )

    last_name = forms.CharField(
        label=_("Last Name"),
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": _("Popescu"),
            }
        ),
    )

    phone = forms.CharField(
        label=_("Phone Number"),
        required=False,
        help_text=_("Romanian phone number (+40.XX.XXX.XXXX)"),
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": "+40.21.123.4567",
            }
        ),
    )

    # ===============================================================================
    # CUSTOMER ORGANIZATION INFORMATION
    # ===============================================================================

    customer_type = forms.ChoiceField(
        label=_("Organization Type"),
        choices=UserRegistrationService.CUSTOMER_TYPES,
        initial="srl",
        help_text=_("Select your business type for proper invoicing and VAT handling."),
        widget=forms.Select(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white focus:outline-none focus:ring-blue-500 focus:border-blue-500"
            }
        ),
    )

    cnp = forms.CharField(
        label=_("CNP"),
        max_length=13,
        required=False,
        help_text=_("Cod Numeric Personal (13 cifre). Required for individuals."),
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": "1234567890123",
            }
        ),
    )

    company_name = forms.CharField(
        label=_("Company/Organization Name"),
        max_length=255,
        help_text=_("Official name as it appears on legal documents."),
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": _("Your Company SRL"),
            }
        ),
    )

    vat_number = forms.CharField(
        label=_("VAT Number"),
        max_length=20,
        required=False,
        help_text=_("Romanian VAT number (RO12345678) - required for VAT registered companies."),
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": "RO12345678",
            }
        ),
    )

    # ===============================================================================
    # ADDRESS INFORMATION
    # ===============================================================================

    address_line1 = forms.CharField(
        label=_("Address"),
        max_length=200,
        help_text=_("Street address of your business."),
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": _("Str. Example Nr. 123"),
            }
        ),
    )

    city = forms.CharField(
        label=_("City"),
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": _("București"),
            }
        ),
    )

    county = forms.CharField(
        label=_("County"),
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": _("București"),
            }
        ),
    )

    postal_code = forms.CharField(
        label=_("Postal Code"),
        max_length=10,
        widget=forms.TextInput(
            attrs={
                "class": "block w-full px-3 py-2 border border-slate-600 rounded-md shadow-sm bg-slate-800 text-white placeholder-slate-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500",
                "placeholder": "010001",
            }
        ),
    )

    # ===============================================================================
    # GDPR COMPLIANCE
    # ===============================================================================

    data_processing_consent = forms.BooleanField(
        label=_("I agree to data processing"),
        help_text=_("Required: Agreement to process personal data according to GDPR."),
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )

    marketing_consent = forms.BooleanField(
        label=_("I agree to receive marketing communications"),
        required=False,
        help_text=_("Optional: Receive newsletters and product updates."),
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )

    terms_accepted = forms.BooleanField(
        label=_("I accept the terms and conditions"),
        help_text=_("Required: Agreement to terms of service."),
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )

    class Meta:
        model = User
        fields: ClassVar[tuple[str, ...]] = ("email", "first_name", "last_name", "phone", "password1", "password2")

    def clean_email(self) -> str:
        raw = self.data.get("email") if hasattr(self, "data") else None
        email: str | None = self.cleaned_data.get("email") if hasattr(self, "cleaned_data") else None
        normalized = (email or raw or "").lower()
        return normalized or ""

    def is_valid(self) -> bool:
        """Suppress unique email errors for neutral, enumeration-safe flow."""
        valid = super().is_valid()
        if valid:
            return True
        errors = self.errors
        if (
            errors
            and set(errors.keys()) == {"email"}
            and all(getattr(err, "code", None) in {"unique", None} for err in errors.as_data().get("email", []))
        ):
            self.errors.pop("email", None)
            return True
        return False

    def clean_vat_number(self) -> str:
        """Validate VAT number format"""
        vat_number: str = self.cleaned_data.get("vat_number", "").strip()
        if vat_number:
            # Check if VAT number is in valid Romanian format
            if not vat_number.startswith("RO"):
                # Only auto-prepend RO if it looks like a numeric VAT number
                if vat_number.isdigit() and len(vat_number) >= MIN_VAT_DIGITS:
                    vat_number = f"RO{vat_number}"
                else:
                    raise ValidationError(_("VAT number must start with RO followed by digits (e.g., RO12345678)"))
            else:
                # Validate that after RO we have digits
                vat_digits = vat_number[2:]
                if not vat_digits.isdigit() or len(vat_digits) < MIN_VAT_DIGITS:
                    raise ValidationError(_("VAT number must start with RO followed by digits (e.g., RO12345678)"))
        return vat_number

    def clean_cnp(self) -> str:
        """Validate CNP format (13 digits)."""
        cnp: str = (self.cleaned_data.get("cnp") or "").strip()
        if cnp and not (cnp.isdigit() and len(cnp) == CNP_LENGTH):
            raise ValidationError(_("CNP must be exactly 13 digits."))
        return cnp

    def clean_customer_type(self) -> str:
        """Validate customer type"""
        customer_type: str | None = self.cleaned_data.get("customer_type")
        if customer_type not in dict(UserRegistrationService.CUSTOMER_TYPES):
            raise ValidationError(_("Invalid customer type selected."))
        return customer_type or ""

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean()
        customer_type = cleaned.get("customer_type") or self.data.get("customer_type")
        cnp = (cleaned.get("cnp") or "").strip()

        # Require CNP for individuals
        if customer_type == "individual" and not cnp:
            self.add_error("cnp", _("CNP is required for individuals."))

        return cleaned

    def save(self, commit: bool = True) -> User:
        """Save user and create customer organization"""
        if not commit:
            raise ValidationError(_("CustomerOnboardingRegistrationForm must be saved with commit=True"))

        # Extract form data
        user_data: dict[str, str] = {
            "email": self.cleaned_data["email"],
            "first_name": self.cleaned_data["first_name"],
            "last_name": self.cleaned_data["last_name"],
            "phone": self.cleaned_data.get("phone", ""),
            "password": self.cleaned_data["password1"],
        }

        customer_data: dict[str, str] = {
            "customer_type": self.cleaned_data["customer_type"],
            "company_name": self.cleaned_data["company_name"],
            "vat_number": self.cleaned_data.get("vat_number", ""),
            "cnp": self.cleaned_data.get("cnp", ""),
            "address_line1": self.cleaned_data["address_line1"],
            "city": self.cleaned_data["city"],
            "county": self.cleaned_data["county"],
            "postal_code": self.cleaned_data["postal_code"],
            "data_processing_consent": self.cleaned_data["data_processing_consent"],
            "marketing_consent": self.cleaned_data.get("marketing_consent", False),
        }

        # Use UserRegistrationService for proper customer onboarding
        registration_service = UserRegistrationService()
        result = registration_service.register_new_customer_owner(user_data=user_data, customer_data=customer_data)

        if result.is_err():
            raise ValidationError(_("Registration failed: %(error)s") % {"error": result.unwrap_err()})

        user, _customer = result.unwrap()
        return user
