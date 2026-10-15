"""
Portal Customer Forms
Customer-facing forms with dark theme styling and Platform API integration.
"""

import logging
import re
from typing import Any

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import get_language
from django.utils.translation import gettext_lazy as _

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.altcha import AltchaFormMixin
from apps.common.identity_fields import clean_with_country, normalize_phone, normalize_vat_number
from apps.common.localisation import (
    DATE_FORMAT_CHOICES,
    INHERIT_LABEL,
    LANGUAGE_CHOICES,
    TIMEZONES,
    country_name,
    normalize_country_code,
)
from apps.common.localisation_forms import CountryDefaultsMixin
from apps.common.localisation_services import get_localisation_defaults

logger = logging.getLogger(__name__)


# Password validation constants
REGISTRATION_PASSWORD_MIN_LENGTH = 12

MIN_NAME_LENGTH = 3


class OneTimeCodeInput(forms.TextInput):
    """A visible code field that, like PasswordInput, never redisplays a submitted value.

    Authenticator and recovery codes are secrets; they must not be echoed back into the page
    when the form is re-rendered with errors. They stay visible while typing, unlike passwords.
    """

    def format_value(self, value: object) -> None:
        return None


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
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Your password"),
            }
        ),
    )

    mfa_token = forms.CharField(
        label=_("Authenticator or recovery code"),
        required=False,
        max_length=8,
        help_text=_("Required only when two-factor authentication is enabled."),
        widget=OneTimeCodeInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric"}),
    )

    remember_me = forms.BooleanField(
        label=_("Remember me for 30 days"),
        required=False,
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )


class CustomerRegistrationForm(AltchaFormMixin, CountryDefaultsMixin, forms.Form):
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
        help_text=_("With its country code, e.g. +40 721 123 456. A Romanian number may start with 0."),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "+40.21.123.4567",
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
        help_text=_("The company's VAT number, with or without the country prefix, if it is VAT-registered."),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "RO12345678",
                "id": "id_vat_number",
            }
        ),
    )

    cui = forms.CharField(
        label=_("CUI"),
        max_length=20,
        required=False,
        help_text=_("Digits only; an RO prefix is accepted and removed."),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": "12345678",
                "id": "id_cui",
            }
        ),
    )

    trade_registry_number = forms.CharField(
        label=_("Trade Registry Number"),
        max_length=50,
        required=False,
        help_text=_("Trade registry number from ONRC"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("e.g. J40/1234/2023"),
                "id": "id_trade_registry_number",
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
        required=False,
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

    country = forms.CharField(label=_("Country"), max_length=100, required=False)

    def clean_country(self) -> str:
        return self.cleaned_data.get("country") or country_name(get_localisation_defaults().default_country)

    def default_country_is_romania(self) -> bool:
        return get_localisation_defaults().default_country == "RO"

    def asks_romanian_company_ids(self) -> bool:
        """Whether the page opens with the CUI and trade registry number: Romanian identifiers.

        The billing country decides, or the default country when none was given, as clean() does.
        register-toggle.js follows the country field from then on.
        """
        country = self.data.get("country") if self.is_bound else self.initial.get("country")
        return normalize_country_code(country) == "RO" if country else self.default_country_is_romania()

    # ===============================================================================
    # GDPR COMPLIANCE
    # ===============================================================================

    terms_accepted = forms.BooleanField(
        label=_("I accept the terms and conditions"),
        help_text=_("Required: Agreement to terms of service."),
        widget=forms.CheckboxInput(
            attrs={"class": "h-4 w-4 text-blue-600 focus:ring-blue-500 border-slate-600 rounded bg-slate-800"}
        ),
    )

    def clean_email(self) -> str:
        email = str(self.cleaned_data.get("email", "")).lower().strip()
        return email

    def clean_cui(self) -> str:
        """The CUI's digits; Platform verifies the check digit and shows its answer on this field."""
        cui = "".join(str(self.cleaned_data.get("cui", "")).split()).upper().removeprefix("RO")
        if cui and not (cui.isascii() and cui.isdigit() and 2 <= len(cui) <= 10):  # noqa: PLR2004  # CUI length
            raise ValidationError(_("Enter a valid CUI."))
        return cui

    def clean_trade_registry_number(self) -> str:
        number = " ".join(str(self.cleaned_data.get("trade_registry_number", "")).upper().split())
        if number and not re.fullmatch(r"[A-Z0-9/.\- ]{3,50}", number):
            raise ValidationError(_("Enter a valid trade registry number."))
        return number

    def clean(self) -> dict[str, Any]:
        """Ask a company for its VAT number or CUI in Romania; an individual gives no fiscal identifier.

        "Romania" is the billing country, or the default country when none was given, as Platform
        decides it. Platform checks the identifiers in full.
        """
        cleaned_data = super().clean() or {}
        # The phone and VAT number follow the billing country's rules; it is cleaned after them.
        for name, normalize in (("phone", normalize_phone), ("vat_number", normalize_vat_number)):
            clean_with_country(self, name, normalize, cleaned_data.get("country"))
        in_romania = normalize_country_code(cleaned_data.get("country")) == "RO"

        if cleaned_data.get("customer_type") == "individual":
            cleaned_data.update(vat_number="", cui="", trade_registry_number="")
            self._drop_errors("vat_number", "cui", "trade_registry_number")
            return cleaned_data

        if (
            in_romania
            and not cleaned_data.get("vat_number")
            and not cleaned_data.get("cui")
            and not ({"vat_number", "cui"} & set(self.errors))
        ):
            self.add_error("cui", _("Enter the company's VAT number or CUI."))
        return cleaned_data

    def _drop_errors(self, *names: str) -> None:
        """Forget field errors for identifiers that do not apply: their values are not sent."""
        for name in names:
            self._errors.pop(name, None)

    # Platform's field names for the registration, mapped onto this form's fields.
    _PLATFORM_FIELDS = dict(  # noqa: C408  # identifier kwargs, as below
        cui="cui",
        registration_number="trade_registry_number",
        vat_number="vat_number",
        country="country",
        company_name="company_name",
    )
    _PLATFORM_USER_FIELDS = dict(email="email", first_name="first_name", last_name="last_name", phone="phone")  # noqa: C408

    def _show_platform_field_errors(self, error: PlatformAPIError) -> bool:
        """Put the field errors Platform answered with on this form's fields; True if any were."""
        errors = (error.response_data or {}).get("errors")
        shown = False
        for group, fields in (("customer_data", self._PLATFORM_FIELDS), ("user_data", self._PLATFORM_USER_FIELDS)):
            group_errors = errors.get(group) if isinstance(errors, dict) else None
            for field, messages in (group_errors if isinstance(group_errors, dict) else {}).items():
                name = fields.get(field)
                if name and isinstance(messages, list):
                    self.add_error(name, [str(message) for message in messages])
                    shown = True
        return shown

    # The form offers Romanian legal-entity granularity (SRL/SA/ONG); the platform
    # registration serializer only accepts individual/company/pfa/ngo. Map before sending
    # so a submission (including the default SRL) is not rejected at the API boundary.
    # Built with identifier kwargs rather than string-literal keys so the CSP inline-handler
    # inventory guardrail does not mistake the non-profit key for an on*= event handler.
    _CUSTOMER_TYPE_TO_PLATFORM = dict(srl="company", sa="company", ong="ngo")  # noqa: C408

    def register_customer(self, client_ip: str = "", intent: dict[str, str] | None = None) -> dict[str, Any] | None:
        """
        Send the registration to Platform, which stores it and mails the address.
        Returns Platform's answer, the same for every address, or None on a refusal.
        intent is what the visitor came to buy and where from (apps.users.intent_capture).
        """
        try:
            form_customer_type = self.cleaned_data["customer_type"]
            registration_data = {
                "user_data": {
                    "email": self.cleaned_data["email"],
                    "first_name": self.cleaned_data["first_name"],
                    "last_name": self.cleaned_data["last_name"],
                    "phone": self.cleaned_data.get("phone", ""),
                },
                "customer_data": {
                    "customer_type": self._CUSTOMER_TYPE_TO_PLATFORM.get(form_customer_type, form_customer_type),
                    "company_name": self.cleaned_data["company_name"],
                    "vat_number": self.cleaned_data.get("vat_number", ""),
                    "cui": self.cleaned_data.get("cui", ""),
                    "registration_number": self.cleaned_data.get("trade_registry_number", ""),
                    "address_line1": self.cleaned_data["address_line1"],
                    "city": self.cleaned_data["city"],
                    "county": self.cleaned_data["county"],
                    "postal_code": self.cleaned_data["postal_code"],
                    "country": self.cleaned_data["country"],
                    "terms_accepted": self.cleaned_data.get("terms_accepted", False),
                },
                "language": "ro" if (get_language() or "").startswith("ro") else "en",
                "intent": intent or {},
            }
            return api_client.register_customer(registration_data, client_ip=client_ip)

        except PlatformAPIError as e:
            # Refusals the customer cannot fix by editing the form go back to the view
            if e.is_rate_limited or e.is_unavailable:
                raise
            if self._show_platform_field_errors(e):
                logger.info("💡 [Portal Registration] Platform refused fields: %s", sorted(self.errors))
            else:
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
        required=False,
        choices=[("", INHERIT_LABEL), *LANGUAGE_CHOICES],
    )
    timezone = forms.ChoiceField(
        label=_("Timezone"),
        required=False,
        choices=[("", INHERIT_LABEL), *((zone, zone) for zone in sorted(TIMEZONES))],
    )
    date_format = forms.ChoiceField(
        label=_("Date format"),
        required=False,
        choices=[("", INHERIT_LABEL), *DATE_FORMAT_CHOICES],
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
        """The number in international form: a person's country is not known here."""
        return normalize_phone(self.cleaned_data.get("phone"))


class TwoFactorSetupForm(forms.Form):
    """Two-factor authentication setup form with dark theme"""

    token = forms.CharField(
        label=_("Verification Code"),
        max_length=6,
        min_length=6,
        widget=OneTimeCodeInput(
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
        token = str(self.cleaned_data.get("token", "")).strip()
        if token and not token.isdigit():
            raise ValidationError(_("The code must contain only digits."))
        return token


class TwoFactorVerifyForm(forms.Form):
    """Two-factor authentication verification form with dark theme"""

    token = forms.CharField(
        label=_("2FA Code"),
        max_length=8,
        min_length=6,
        widget=OneTimeCodeInput(
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
        token = str(self.cleaned_data.get("token", "")).strip()
        if token and not token.isdigit():
            raise ValidationError(_("The code must contain only digits."))
        return token


class PasswordResetRequestForm(AltchaFormMixin, forms.Form):
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


class PasswordResetConfirmForm(forms.Form):
    """Collect and confirm a replacement password."""

    new_password = forms.CharField(
        label=_("New Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text=_("Choose a strong password with at least 12 characters."),
    )
    confirm_password = forms.CharField(
        label=_("Confirm New Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
        help_text=_("Re-enter your new password to confirm."),
    )

    def clean(self) -> dict[str, Any]:
        cleaned_data = super().clean() or {}
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and confirm_password and new_password != confirm_password:
            raise ValidationError(_("New password and confirmation don't match."))

        # The Platform's reset serializer requires twelve characters; say so before the round trip.
        if new_password and len(new_password) < REGISTRATION_PASSWORD_MIN_LENGTH:
            raise ValidationError(_("Password must be at least 12 characters long."))

        return cleaned_data


class RegistrationConfirmForm(PasswordResetConfirmForm):
    """The password and consent a registration's mailbox holder gives to finish it."""

    # Which registration the page showed. Compared with the session's link, never sent on.
    registration_id = forms.CharField(widget=forms.HiddenInput, required=False)

    marketing_consent = forms.BooleanField(
        label=_("Send me news and offers by email."),
        required=False,
    )
    # The page links one terms release, and sends that one on: Platform records it, or refuses it
    # once another is in force.
    terms_accepted = forms.BooleanField(
        label=_("I have read and accept the Terms of Service."),
        required=True,
    )
    terms_document_id = forms.UUIDField(widget=forms.HiddenInput, required=False)


class ChangePasswordForm(forms.Form):
    """Change password form for authenticated users"""

    token = forms.CharField(
        label=_("Authenticator or recovery code"),
        required=False,
        max_length=8,
        help_text=_("Required only when two-factor authentication is enabled."),
        widget=OneTimeCodeInput(attrs={"autocomplete": "one-time-code", "inputmode": "numeric"}),
    )

    current_password = forms.CharField(
        label=_("Current Password"),
        strip=False,
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
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "class": "w-full px-4 py-3 border border-slate-600 bg-slate-800 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 placeholder-slate-400",
                "placeholder": _("Enter your new password"),
                "autocomplete": "new-password",
            }
        ),
        help_text=_("Choose a strong password with at least 12 characters."),
    )

    confirm_password = forms.CharField(
        label=_("Confirm New Password"),
        strip=False,
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
        cleaned_data = super().clean() or {}
        new_password = cleaned_data.get("new_password")
        confirm_password = cleaned_data.get("confirm_password")

        if new_password and confirm_password and new_password != confirm_password:
            raise ValidationError(_("New password and confirmation don't match."))

        if new_password and len(new_password) < REGISTRATION_PASSWORD_MIN_LENGTH:
            raise ValidationError(_("Password must be at least 12 characters long."))

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

    # VAT/CUI and billing address are managed via dedicated pages:
    # - Tax Profile: /company/tax/
    # - Addresses: /company/addresses/

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

    def clean_primary_phone(self) -> str:
        """The number in international form: this form does not know the company's country."""
        return normalize_phone(self.cleaned_data.get("primary_phone"))


class CompanyCreationForm(CountryDefaultsMixin, forms.Form):
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
        help_text=_("The company's VAT number, with or without the country prefix, if it is VAT-registered."),
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
        help_text=_("Six digits in Romania"),
    )

    country = forms.CharField(
        label=_("Country"),
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

    def clean_company_name(self) -> str:
        """Validate company name"""
        company_name = str(self.cleaned_data.get("company_name", "")).strip()

        if not company_name:
            raise forms.ValidationError(_("Company name is required"))

        if len(company_name) < MIN_NAME_LENGTH:
            raise forms.ValidationError(_("Company name must be at least 3 characters long"))

        # Check for common Romanian business suffixes
        valid_suffixes = ["SRL", "SA", "PFA", "II", "IF", "SNC", "SCS", "ONG"]
        has_valid_suffix = any(company_name.upper().endswith(suffix) for suffix in valid_suffixes)

        if not has_valid_suffix:
            logger.warning(f"Company name '{company_name}' doesn't end with common Romanian business suffix")

        return company_name

    def clean(self) -> dict[str, Any]:
        """Cross-field validation"""
        cleaned_data = super().clean() or {}
        # The phone and VAT number follow the company's country; it is cleaned after them.
        for name, normalize in (("primary_phone", normalize_phone), ("vat_number", normalize_vat_number)):
            clean_with_country(self, name, normalize, cleaned_data.get("country"))

        # If VAT number is provided, trade registry should also be provided
        vat_number = cleaned_data.get("vat_number")
        trade_registry = cleaned_data.get("trade_registry_number")

        if vat_number and not trade_registry:
            self.add_error(
                "trade_registry_number", _("Trade registry number is recommended when VAT number is provided")
            )

        return cleaned_data


class TOTPSetupForm(forms.Form):
    """Confirming an authenticator: a 6-digit code from the app and the current password (#689).

    The password stops a hijacked session enrolling its own app. Platform checks both; this
    form only refuses a request that could not be right, so nothing is sent for it.
    """

    token = forms.RegexField(
        regex=r"^\d{6}$",
        label=_("Verification code"),
        error_messages={"invalid": _("Enter the 6-digit code from your authenticator app.")},
    )
    password = forms.CharField(
        label=_("Current password"),
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )


class MFAReauthenticationForm(TwoFactorVerifyForm):
    """Step-up credentials for MFA removal and recovery-code regeneration."""

    password = forms.CharField(label=_("Current password"), widget=forms.PasswordInput, strip=False)
