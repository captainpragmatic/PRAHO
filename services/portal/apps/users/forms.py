"""
Portal Customer Forms
Customer-facing forms with dark theme styling and Platform API integration.
"""

import logging
import re
from typing import Any

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.api_client.services import PlatformAPIError, api_client

logger = logging.getLogger(__name__)

# Romanian validation constants
MIN_VAT_DIGITS = 6
CNP_LENGTH = 13  # Romanian Personal Numeric Code length

# Password validation constants
REGISTRATION_PASSWORD_MIN_LENGTH = 12
CHANGE_PASSWORD_MIN_LENGTH = 8


class CustomerLoginForm(forms.Form):
    """
    Customer login form with dark theme styling.
    Authenticates against Platform API service.
    """

    email = forms.EmailField(
        label=_("Email Address"),
        widget=forms.EmailInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("your@company.com"),
                "autofocus": True,
            }
        ),
    )

    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Your password"),
            }
        ),
    )

    remember_me = forms.BooleanField(
        label=_("Remember me for 30 days"),
        required=False,
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )


class CustomerRegistrationForm(forms.Form):
    """
    Customer registration form with Romanian business context.
    Sends registration data to Platform API for processing.
    """

    # ===============================================================================
    # USER INFORMATION
    # ===============================================================================

    email = forms.EmailField(
        label=_("Email Address"),
        help_text=_("This will be used for authentication and billing notifications."),
        widget=forms.EmailInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("your@company.com"),
            }
        ),
    )

    first_name = forms.CharField(
        label=_("First Name"),
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Ion"),
            }
        ),
    )

    last_name = forms.CharField(
        label=_("Last Name"),
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
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
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "+40.21.123.4567",
            }
        ),
    )

    password1 = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Minimum 12 characters"),
            }
        ),
    )

    password2 = forms.CharField(
        label=_("Confirm Password"),
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Repeat password"),
            }
        ),
    )

    # ===============================================================================
    # COMPANY INFORMATION
    # ===============================================================================

    customer_type = forms.ChoiceField(
        label=_("Organization Type"),
        choices=[
            ("srl", _("SRL (Limited Liability Company)")),
            ("pfa", _("PFA (Authorized Individual)")),
            ("sa", _("SA (Joint Stock Company)")),
            ("ong", _("ONG (Non-Profit Organization)")),
            ("individual", _("Individual")),
        ],
        initial="srl",
        help_text=_("Select your business type for proper invoicing and VAT handling."),
        widget=forms.Select(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500",
                "onchange": "toggleIndividualFields(this.value)",
            }
        ),
    )

    company_name = forms.CharField(
        label=_("Company/Organization Name"),
        max_length=255,
        help_text=_("Official name as it appears on legal documents."),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
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
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "RO12345678",
                "id": "id_vat_number",
            }
        ),
    )

    cnp = forms.CharField(
        label=_("CNP (Cod Numeric Personal)"),
        max_length=13,
        required=False,
        help_text=_("Romanian Personal Identification Number - required for individuals."),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "1234567890123",
                "id": "id_cnp",
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
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Str. Example Nr. 123"),
            }
        ),
    )

    city = forms.CharField(
        label=_("City"),
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("București"),
            }
        ),
    )

    county = forms.CharField(
        label=_("County"),
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("București"),
            }
        ),
    )

    postal_code = forms.CharField(
        label=_("Postal Code"),
        max_length=10,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "010001",
            }
        ),
    )

    # ===============================================================================
    # GDPR COMPLIANCE
    # ===============================================================================

    data_processing_consent = forms.BooleanField(
        label=_("I agree to data processing according to GDPR"),
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

    def clean_email(self) -> str:
        email = self.cleaned_data.get("email", "").lower().strip()
        return email

    def clean_password2(self) -> str:
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            raise ValidationError(_("The two password fields didn't match."))

        if password1 and len(password1) < REGISTRATION_PASSWORD_MIN_LENGTH:
            raise ValidationError(_("Password must be at least 12 characters long."))

        return password2 or ""

    def clean_phone(self) -> str:
        """Validate Romanian phone number format"""
        phone = self.cleaned_data.get("phone", "").strip()
        # Romanian phone patterns: +40.XX.XXX.XXXX, +40 XXX XXX XXX, 07XXXXXXXX
        if phone and not re.match(r"^(\+40[\.\s]*[0-9][\.\s0-9]{8,11}[0-9]|0[0-9]{9})$", phone):
            raise ValidationError(_("Invalid phone number format. Use Romanian format: +40.XX.XXX.XXXX"))
        return phone

    def clean_vat_number(self) -> str:
        """Validate VAT number format"""
        vat_number = self.cleaned_data.get("vat_number", "").strip()
        if vat_number:
            if not vat_number.startswith("RO"):
                if vat_number.isdigit() and len(vat_number) >= MIN_VAT_DIGITS:
                    vat_number = f"RO{vat_number}"
                else:
                    raise ValidationError(_("VAT number must start with RO followed by digits (e.g., RO12345678)"))
            else:
                vat_digits = vat_number[2:]
                if not vat_digits.isdigit() or len(vat_digits) < MIN_VAT_DIGITS:
                    raise ValidationError(_("VAT number must start with RO followed by digits (e.g., RO12345678)"))
        return vat_number

    def clean_cnp(self) -> str:
        """Validate Romanian CNP (Cod Numeric Personal) format"""
        cnp = self.cleaned_data.get("cnp", "").strip()
        if cnp:
            # CNP must be exactly 13 digits
            if not cnp.isdigit() or len(cnp) != CNP_LENGTH:
                raise ValidationError(_("CNP must be exactly 13 digits."))

            # Basic CNP checksum validation (simplified)
            # Full validation would include birth date validation, county codes, etc.
            if cnp[0] not in "1234567890":  # Valid century markers
                raise ValidationError(_("Invalid CNP format."))

        return cnp

    def clean(self) -> dict[str, Any]:
        """Custom validation that depends on multiple fields"""
        cleaned_data = super().clean()
        customer_type = cleaned_data.get("customer_type")
        vat_number = cleaned_data.get("vat_number")
        cnp = cleaned_data.get("cnp")

        # Validate that individuals have CNP, companies have VAT
        if customer_type == "individual":
            if not cnp:
                raise ValidationError({"cnp": _("CNP is required for individuals.")})
            if vat_number:
                # Clear VAT number for individuals
                cleaned_data["vat_number"] = ""
        # For companies, CNP should be cleared
        elif cnp:
            cleaned_data["cnp"] = ""

        return cleaned_data

    def register_customer(self) -> dict[str, Any] | None:
        """
        Register customer via Platform API.
        Returns customer data on success, None on failure.
        """
        try:
            registration_data = {
                "user_data": {
                    "email": self.cleaned_data["email"],
                    "first_name": self.cleaned_data["first_name"],
                    "last_name": self.cleaned_data["last_name"],
                    "phone": self.cleaned_data.get("phone", ""),
                    "password": self.cleaned_data["password1"],
                },
                "customer_data": {
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
                },
            }

            # Call Platform API for customer registration
            response = api_client._make_request("POST", "/customers/register/", data=registration_data)
            return response

        except PlatformAPIError as e:
            logger.error(f"🔥 [Portal Registration] Platform API error: {e}")
            return None
        except Exception as e:
            logger.error(f"🔥 [Portal Registration] Unexpected error: {e}")
            return None


class CustomerProfileForm(forms.Form):
    """
    Customer profile editing form with dark theme.
    Updates customer data via Platform API.
    """

    first_name = forms.CharField(
        label=_("First Name"),
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400"
            }
        ),
    )

    last_name = forms.CharField(
        label=_("Last Name"),
        max_length=30,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400"
            }
        ),
    )

    phone = forms.CharField(
        label=_("Phone Number"),
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "+40.21.123.4567",
            }
        ),
    )

    preferred_language = forms.ChoiceField(
        label=_("Preferred Language"),
        choices=[
            ("ro", _("Română")),
            ("en", _("English")),
        ],
        initial="ro",
        widget=forms.Select(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            }
        ),
    )

    timezone = forms.ChoiceField(
        label=_("Timezone"),
        choices=[
            ("Europe/Bucharest", _("Europe/Bucharest (Romania)")),
            ("UTC", _("UTC (Universal Time)")),
            ("Europe/London", _("Europe/London")),
            ("Europe/Paris", _("Europe/Paris")),
        ],
        initial="Europe/Bucharest",
        widget=forms.Select(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            }
        ),
    )

    email_notifications = forms.BooleanField(
        label=_("Email notifications"),
        required=False,
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )

    sms_notifications = forms.BooleanField(
        label=_("SMS notifications"),
        required=False,
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )

    marketing_emails = forms.BooleanField(
        label=_("Marketing emails"),
        required=False,
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )

    def clean_phone(self) -> str:
        """Validate Romanian phone number format"""
        phone = self.cleaned_data.get("phone", "").strip()
        if phone and not re.match(r"^(\+40[\.\s]*[0-9][\.\s0-9]{8,11}[0-9]|0[0-9]{9})$", phone):
            raise ValidationError(_("Invalid phone number format. Use Romanian format: +40.XX.XXX.XXXX"))
        return phone


class TwoFactorSetupForm(forms.Form):
    """Two-factor authentication setup form with dark theme"""

    token = forms.CharField(
        label=_("Verification Code"),
        max_length=6,
        min_length=6,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg text-center focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "123456",
                "autocomplete": "off",
                "pattern": "[0-9]{6}",
                "inputmode": "numeric",
            }
        ),
        help_text=_("Enter the code from the authenticator app"),
    )

    def clean_token(self) -> str:
        token = self.cleaned_data.get("token", "").strip()
        if token and not token.isdigit():
            raise ValidationError(_("The code must contain only digits."))
        return token


class TwoFactorVerifyForm(forms.Form):
    """Two-factor authentication verification form with dark theme"""

    token = forms.CharField(
        label=_("2FA Code"),
        max_length=8,
        min_length=6,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg text-center focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "123456",
                "autocomplete": "off",
                "autofocus": True,
                "pattern": "[0-9]{6,8}",
                "inputmode": "numeric",
            }
        ),
        help_text=_("Enter the code from the authenticator app or backup code"),
    )

    def clean_token(self) -> str:
        token = self.cleaned_data.get("token", "").strip()
        if token and not token.isdigit():
            raise ValidationError(_("The code must contain only digits."))
        return token


class PasswordResetRequestForm(forms.Form):
    """Password reset request form with dark theme"""

    email = forms.EmailField(
        label=_("Email Address"),
        widget=forms.EmailInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("your@company.com"),
                "autofocus": True,
            }
        ),
        help_text=_("Enter the email associated with your account."),
    )


class ChangePasswordForm(forms.Form):
    """Change password form for authenticated users"""

    current_password = forms.CharField(
        label=_("Current Password"),
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Enter your current password"),
                "autocomplete": "current-password",
            }
        ),
        help_text=_("Enter your current password to verify identity."),
    )

    new_password = forms.CharField(
        label=_("New Password"),
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Enter your new password"),
                "autocomplete": "new-password",
            }
        ),
        help_text=_("Choose a strong password with at least 8 characters."),
    )

    confirm_password = forms.CharField(
        label=_("Confirm New Password"),
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Confirm your new password"),
                "autocomplete": "new-password",
            }
        ),
        help_text=_("Re-enter your new password to confirm."),
    )

    def clean(self) -> dict[str, Any]:
        cleaned_data = super().clean()
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and confirm_password and new_password != confirm_password:
            raise ValidationError(_("New password and confirmation don't match."))

        if new_password and len(new_password) < CHANGE_PASSWORD_MIN_LENGTH:
            raise ValidationError(_("Password must be at least 8 characters long."))

        return cleaned_data


class CompanyProfileForm(forms.Form):
    """
    Company profile management form with Romanian business compliance.
    Handles company name, billing address, CUI/VAT, and business contact information.
    """

    company_name = forms.CharField(
        label=_("Company Name"),
        max_length=200,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. Test Company SRL"),
            }
        ),
        help_text=_("Official company name as registered"),
    )

    vat_number = forms.CharField(
        label=_("VAT Number / CUI"),
        max_length=50,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("RO12345678"),
            }
        ),
        help_text=_("Romanian VAT number or CUI"),
    )

    trade_registry_number = forms.CharField(
        label=_("Trade Registry Number"),
        max_length=50,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("J40/1234/2023"),
            }
        ),
        help_text=_("Trade registry number (optional)"),
    )

    # Billing Address
    billing_street = forms.CharField(
        label=_("Street Address"),
        max_length=200,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Strada Exemple nr. 123"),
            }
        ),
        help_text=_("Street name and number"),
    )

    billing_city = forms.CharField(
        label=_("City"),
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("București"),
            }
        ),
    )

    billing_state = forms.CharField(
        label=_("County/State"),
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("București"),
            }
        ),
    )

    billing_postal_code = forms.CharField(
        label=_("Postal Code"),
        max_length=20,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("010101"),
            }
        ),
    )

    billing_country = forms.CharField(
        label=_("Country"),
        initial="RO",
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-700 text-slate-300 rounded-lg cursor-not-allowed",
                "readonly": True,
            }
        ),
        help_text=_("Currently only Romania (RO) is supported"),
    )

    # Business Contact Information
    primary_email = forms.EmailField(
        label=_("Primary Email"),
        widget=forms.EmailInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("contact@company.ro"),
            }
        ),
        help_text=_("Main business email address"),
    )

    primary_phone = forms.CharField(
        label=_("Primary Phone"),
        max_length=20,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("+40.21.123.4567"),
            }
        ),
        help_text=_("Primary business phone number"),
    )

    website = forms.URLField(
        label=_("Website"),
        required=False,
        widget=forms.URLInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("https://company.ro"),
            }
        ),
        help_text=_("Company website (optional)"),
    )

    industry = forms.CharField(
        label=_("Industry"),
        max_length=100,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Technology, Retail, Manufacturing, etc."),
            }
        ),
        help_text=_("Business industry (optional)"),
    )

    def clean_vat_number(self) -> str:
        """Validate Romanian VAT number format"""
        vat_number = self.cleaned_data.get("vat_number", "").strip().upper()

        if not vat_number:
            raise ValidationError(_("VAT number / CUI is required"))

        # Remove RO prefix for validation
        clean_vat = vat_number.replace("RO", "").strip()

        # Check if it's numeric and has appropriate length
        if not clean_vat.isdigit():
            raise ValidationError(_("VAT number must contain only digits (optionally prefixed with RO)"))

        if len(clean_vat) < MIN_VAT_DIGITS:
            raise ValidationError(_("VAT number must have at least 6 digits"))

        # Return with RO prefix
        return f"RO{clean_vat}"

    def clean_primary_phone(self) -> str:
        """Validate Romanian phone number format"""
        phone = self.cleaned_data.get("primary_phone", "").strip()
        if phone and not re.match(r"^(\+40[\.\s]*[0-9][\.\s0-9]{8,11}[0-9]|0[0-9]{9})$", phone):
            raise ValidationError(_("Invalid phone number format. Use Romanian format: +40.XX.XXX.XXXX"))
        return phone


class CompanyCreationForm(forms.Form):
    """
    Company creation form with comprehensive Romanian business validation.
    Creates a new customer with complete business profile information.
    """

    # Company Basic Information
    company_name = forms.CharField(
        label=_("Company Name"),
        max_length=200,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. Innovative Solutions SRL"),
            }
        ),
        help_text=_("Official company name as registered with ONRC"),
    )

    vat_number = forms.CharField(
        label=_("VAT Number / CUI"),
        max_length=20,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. RO12345678"),
            }
        ),
        help_text=_("Romanian VAT number (CUI) - required for invoicing"),
    )

    trade_registry_number = forms.CharField(
        label=_("Trade Registry Number"),
        max_length=50,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. J40/1234/2023"),
            }
        ),
        help_text=_("Trade registry number from ONRC"),
    )

    industry = forms.CharField(
        label=_("Industry"),
        max_length=100,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. Information Technology"),
            }
        ),
        help_text=_("Primary business industry"),
    )

    # Billing Address
    street_address = forms.CharField(
        label=_("Street Address"),
        max_length=255,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. Strada Victoriei nr. 123, sector 1"),
            }
        ),
        help_text=_("Complete street address with number"),
    )

    city = forms.CharField(
        label=_("City"),
        max_length=100,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. București"),
            }
        ),
        help_text=_("City name"),
    )

    state = forms.CharField(
        label=_("County / State"),
        max_length=100,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. București"),
            }
        ),
        help_text=_("County or state"),
    )

    postal_code = forms.CharField(
        label=_("Postal Code"),
        max_length=20,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. 010001"),
            }
        ),
        help_text=_("Romanian postal code"),
    )

    country = forms.CharField(
        label=_("Country"),
        initial="România",
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
            }
        ),
        help_text=_("Country name"),
    )

    # Business Contact Information
    primary_email = forms.EmailField(
        label=_("Primary Business Email"),
        widget=forms.EmailInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("contact@company.com"),
            }
        ),
        help_text=_("Main business email address"),
    )

    primary_phone = forms.CharField(
        label=_("Primary Phone Number"),
        max_length=20,
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("+40 21 XXX XXXX"),
            }
        ),
        help_text=_("Business phone number with country code"),
    )

    website = forms.URLField(
        label=_("Company Website"),
        required=False,
        widget=forms.URLInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("https://www.company.com"),
            }
        ),
        help_text=_("Company website URL"),
    )

    # Terms and Agreements
    agree_terms = forms.BooleanField(
        label=_("I agree to the Terms of Service and Privacy Policy"),
        widget=forms.CheckboxInput(
            attrs={
                "class": "rounded border-slate-600 bg-slate-800 text-blue-600 focus:ring-blue-500 focus:ring-2",
            }
        ),
        help_text=_("You must agree to create a company profile"),
    )

    def clean_company_name(self):
        """Validate company name"""
        company_name = self.cleaned_data.get("company_name", "").strip()

        if not company_name:
            raise forms.ValidationError(_("Company name is required"))

        if len(company_name) < 3:
            raise forms.ValidationError(_("Company name must be at least 3 characters long"))

        # Check for common Romanian business suffixes
        valid_suffixes = ["SRL", "SA", "PFA", "II", "IF", "SNC", "SCS", "ONG"]
        has_valid_suffix = any(company_name.upper().endswith(suffix) for suffix in valid_suffixes)

        if not has_valid_suffix:
            logger.warning(f"Company name '{company_name}' doesn't end with common Romanian business suffix")

        return company_name

    def clean_vat_number(self):
        """Validate Romanian VAT number (CUI)"""
        vat_number = self.cleaned_data.get("vat_number", "").strip()

        if not vat_number:
            return vat_number

        # Remove spaces and common prefixes
        vat_number = vat_number.replace(" ", "").upper()
        if vat_number.startswith("RO"):
            vat_number = vat_number[2:]

        # Check if it's numeric and has valid length
        if not vat_number.isdigit():
            raise forms.ValidationError(_("VAT number must contain only numbers (after RO prefix)"))

        if len(vat_number) < 2 or len(vat_number) > 10:
            raise forms.ValidationError(_("Romanian VAT number must be between 2-10 digits"))

        return f"RO{vat_number}"

    def clean_primary_phone(self):
        """Validate Romanian phone number"""
        phone = self.cleaned_data.get("primary_phone", "").strip()

        if not phone:
            return phone

        # Remove common separators
        phone_clean = phone.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")

        # Romanian phone number patterns
        if phone_clean.startswith("+40"):
            phone_clean = phone_clean[3:]
        elif phone_clean.startswith("0040"):
            phone_clean = phone_clean[4:]
        elif phone_clean.startswith("40"):
            phone_clean = phone_clean[2:]

        # Remove leading 0 if present
        if phone_clean.startswith("0"):
            phone_clean = phone_clean[1:]

        # Check if it's a valid Romanian mobile/landline
        if not phone_clean.isdigit() or len(phone_clean) != 9:
            raise forms.ValidationError(_("Please enter a valid Romanian phone number"))

        # Check if it starts with valid prefixes
        valid_prefixes = ["2", "3", "7"]  # landline, landline, mobile
        if not any(phone_clean.startswith(prefix) for prefix in valid_prefixes):
            raise forms.ValidationError(_("Phone number must start with a valid Romanian prefix"))

        return f"+40{phone_clean}"

    def clean_postal_code(self):
        """Validate Romanian postal code"""
        postal_code = self.cleaned_data.get("postal_code", "").strip()

        if not postal_code:
            return postal_code

        # Romanian postal codes are 6 digits
        if not postal_code.isdigit() or len(postal_code) != 6:
            raise forms.ValidationError(_("Romanian postal code must be exactly 6 digits"))

        return postal_code

    def clean(self):
        """Cross-field validation"""
        cleaned_data = super().clean()

        # If VAT number is provided, trade registry should also be provided
        vat_number = cleaned_data.get("vat_number")
        trade_registry = cleaned_data.get("trade_registry_number")

        if vat_number and not trade_registry:
            self.add_error(
                "trade_registry_number", _("Trade registry number is recommended when VAT number is provided")
            )

        return cleaned_data
