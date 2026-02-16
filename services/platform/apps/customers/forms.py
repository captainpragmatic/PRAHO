# ===============================================================================
# CUSTOMER FORMS - NORMALIZED MODEL STRUCTURE
# ===============================================================================

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.forms.models import ModelChoiceField  # For form field type checking
from django.utils.translation import gettext_lazy as _

from apps.common.validators import SecureInputValidator
from apps.users.models import CustomerMembership

from .models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerNote,
    CustomerTaxProfile,
)

if TYPE_CHECKING:
    from apps.users.models import User
else:
    User = get_user_model()

# Constants
MAX_RO_PREFIXED_ID_LENGTH = 12  # 'RO' + up to 10 digits


# ===============================================================================
# VALIDATOR WRAPPERS
# ===============================================================================


def validate_safe_url_wrapper(value: Any) -> None:
    """Django form validator wrapper for SecureInputValidator.validate_safe_url"""
    if value:  # Only validate if value is provided (for optional fields)
        SecureInputValidator.validate_safe_url(str(value))


# ===============================================================================
# CORE CUSTOMER FORM (SIMPLIFIED)
# ===============================================================================


class CustomerForm(forms.ModelForm):  # type: ignore[type-arg]
    """
    Core customer information form.
    Only essential identifying information.
    """

    website = forms.URLField(
        required=False,
        label=_("Website"),
        assume_scheme="https",
        validators=[validate_safe_url_wrapper],
        widget=forms.URLInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("https://example.com"),
            }
        ),
    )

    class Meta:
        model = Customer
        fields: ClassVar[tuple[str, ...]] = (
            "name",
            "customer_type",
            "company_name",
            "primary_email",
            "primary_phone",
            "industry",
            "website",
            "data_processing_consent",
            "marketing_consent",
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            "name": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("Customer name/designation"),
                }
            ),
            "company_name": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("SC EXAMPLE SRL"),
                }
            ),
            "primary_email": forms.EmailInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("contact@example.com"),
                }
            ),
            "primary_phone": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("+40 721 123 456"),
                }
            ),
            "industry": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("IT & Software"),
                }
            ),
        }

    def clean_company_name(self) -> str:
        """Require company name for companies"""
        customer_type: str | None = self.cleaned_data.get("customer_type")
        company_name: str | None = self.cleaned_data.get("company_name")

        if customer_type == "company" and not company_name:
            raise ValidationError(_("Company name is required for companies"))

        return company_name or ""

    def clean_website(self) -> str:
        """Validate website URL for SSRF prevention"""
        website: str | None = self.cleaned_data.get("website")
        if website:
            return SecureInputValidator.validate_safe_url(website)
        return website or ""


# ===============================================================================
# TAX PROFILE FORM (ROMANIAN COMPLIANCE)
# ===============================================================================


class CustomerTaxProfileForm(forms.ModelForm):  # type: ignore[type-arg]
    """
    Romanian tax compliance form - CUI, VAT, registration.
    """

    # Override fields to avoid default max_length errors masking our security messages
    cui = forms.CharField(required=False)
    vat_number = forms.CharField(required=False)

    class Meta:
        model = CustomerTaxProfile
        fields: ClassVar[tuple[str, ...]] = (
            "cui",
            "registration_number",
            "is_vat_payer",
            "vat_number",
            "vat_rate",
            "reverse_charge_eligible",
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            "cui": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("RO12345678"),
                }
            ),
            "vat_number": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("RO12345678"),
                }
            ),
            "registration_number": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("J40/1234/2023"),
                }
            ),
            "vat_rate": forms.NumberInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "step": "0.01",
                    "min": "0",
                    "max": "100",
                }
            ),
        }

    def clean_cui(self) -> str:
        """🔒 Validate Romanian CUI format with ReDoS protection"""
        cui: str | None = self.cleaned_data.get("cui")
        if cui:
            # Security: Prevent ReDoS attacks with strict input length validation
            if len(cui) > MAX_RO_PREFIXED_ID_LENGTH:  # RO + max 10 digits
                raise ValidationError(_("CUI too long"))
            # Security: Use more specific regex pattern to prevent ReDoS
            if not re.match(r"^RO\d{6,10}$", cui):  # Romanian CUI is typically 6-10 digits
                raise ValidationError(_("CUI must be in format RO followed by 6-10 digits"))
        return cui or ""

    def clean_vat_number(self) -> str:
        """🔒 Validate VAT number format with ReDoS protection"""
        vat_number: str | None = self.cleaned_data.get("vat_number")
        is_vat_payer: bool | None = self.cleaned_data.get("is_vat_payer")

        if is_vat_payer and not vat_number:
            raise ValidationError(_("VAT number is required for VAT payers"))

        if vat_number:
            # Security: Prevent ReDoS attacks with strict input length validation
            if len(vat_number) > MAX_RO_PREFIXED_ID_LENGTH:  # RO + max 10 digits
                raise ValidationError(_("VAT number too long"))
            # Security: Use more specific regex pattern to prevent ReDoS
            if not re.match(r"^RO\d{6,10}$", vat_number):  # Romanian VAT is typically 6-10 digits
                raise ValidationError(_("VAT number must be in format RO followed by 6-10 digits"))

        return vat_number or ""


# ===============================================================================
# BILLING PROFILE FORM
# ===============================================================================


class CustomerBillingProfileForm(forms.ModelForm):  # type: ignore[type-arg]
    """
    Customer billing and financial information form.
    """

    class Meta:
        model = CustomerBillingProfile
        fields: ClassVar[tuple[str, ...]] = (
            "payment_terms",
            "credit_limit",
            "preferred_currency",
            "invoice_delivery_method",
            "auto_payment_enabled",
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            "payment_terms": forms.NumberInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "min": "1",
                    "max": "365",
                }
            ),
            "credit_limit": forms.NumberInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "step": "0.01",
                    "min": "0",
                }
            ),
        }

    def clean_credit_limit(self) -> float:
        """Ensure credit limit is not negative"""
        credit_limit: float | None = self.cleaned_data.get("credit_limit")
        if credit_limit is not None and credit_limit < 0:
            raise ValidationError(_("Credit limit cannot be negative"))
        return credit_limit or 0.0


# ===============================================================================
# ADDRESS FORM
# ===============================================================================


class CustomerAddressForm(forms.ModelForm):  # type: ignore[type-arg]
    """
    Customer address form with Romanian fields.
    """

    class Meta:
        model = CustomerAddress
        fields: ClassVar[tuple[str, ...]] = (
            "address_type",
            "address_line1",
            "address_line2",
            "city",
            "county",
            "postal_code",
            "country",
        )

        widgets: ClassVar[dict[str, forms.Widget]] = {
            "address_line1": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("Example Street, no. 123"),
                }
            ),
            "address_line2": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("Block A, Apt. 45 (optional)"),
                }
            ),
            "city": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("Bucharest"),
                }
            ),
            "county": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("Sector 1 / Cluj"),
                }
            ),
            "postal_code": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("010101"),
                }
            ),
            "country": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "value": _("Romania"),
                }
            ),
        }

    def clean_postal_code(self) -> str:
        """Validate Romanian postal code format"""
        postal_code: str | None = self.cleaned_data.get("postal_code")
        country: str | None = self.cleaned_data.get("country")

        if country == "România" and postal_code and not re.match(r"^\d{6}$", postal_code):
            raise ValidationError(_("Romanian postal codes must be 6 digits"))

        return postal_code or ""


# ===============================================================================
# CUSTOMER NOTE FORM
# ===============================================================================


class CustomerNoteForm(forms.ModelForm):  # type: ignore[type-arg]
    """
    Customer interaction notes form.
    """

    class Meta:
        model = CustomerNote
        fields: ClassVar[tuple[str, ...]] = ("note_type", "title", "content", "is_important", "is_private")

        widgets: ClassVar[dict[str, forms.Widget]] = {
            "title": forms.TextInput(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "placeholder": _("Note Title"),
                }
            ),
            "content": forms.Textarea(
                attrs={
                    "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                    "rows": 4,
                    "placeholder": _("Details..."),
                }
            ),
        }


# ===============================================================================
# COMPOSITE CUSTOMER CREATION FORM
# ===============================================================================


class CustomerCreationForm(forms.Form):
    """
    Composite form for creating a customer with all profiles.
    Aligned with registration form structure for consistency.
    """

    # User Account Assignment
    user_action = forms.ChoiceField(
        choices=[
            ("create", _("Create new user account")),
            ("link", _("Link existing user")),
            ("skip", _("Skip user assignment")),
        ],
        initial="create",
        label=_("User Account Assignment"),
        help_text=_("Choose how to handle user assignment for this customer"),
        widget=forms.RadioSelect(attrs={"class": "user-action-radio"}),
    )

    existing_user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        label=_("Existing User"),
        help_text=_("Select an existing user to assign as owner"),
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500",
                "x-show": "userAction === 'link'",
                "x-cloak": "true",
            }
        ),
        empty_label=_("Select a user..."),
    )

    send_welcome_email = forms.BooleanField(
        initial=True,
        required=False,
        label=_("Send welcome email"),
        help_text=_("Send welcome email with login instructions"),
        widget=forms.CheckboxInput(
            attrs={
                "class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500",
                "x-show": "userAction === 'create'",
                "x-cloak": "true",
            }
        ),
    )

    # Personal/Contact Information (matching registration)
    first_name = forms.CharField(
        max_length=150,
        label=_("First Name"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("First Name"),
            }
        ),
    )
    last_name = forms.CharField(
        max_length=150,
        label=_("Last Name"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Last Name"),
            }
        ),
    )
    email = forms.EmailField(
        label=_("Primary Email"),
        widget=forms.EmailInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("contact@example.com"),
            }
        ),
    )
    phone = forms.CharField(
        max_length=20,
        label=_("Primary Phone"),
        help_text=_("Format: +40 21 123 4567 or 0712 345 678"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("+40 721 123 456"),
            }
        ),
    )

    # Business Information (matching registration)
    customer_type = forms.ChoiceField(
        choices=Customer.CUSTOMER_TYPE_CHOICES,
        label=_("Customer Type"),
        help_text=_("Individual, company, PFA, or NGO"),
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
            }
        ),
    )
    company_name = forms.CharField(
        max_length=255,
        required=False,
        label=_("Company Name"),
        help_text=_("Required for companies, PFA, and NGOs"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("SC EXAMPLE SRL"),
            }
        ),
    )
    industry = forms.CharField(
        max_length=100,
        required=False,
        label=_("Industry"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("IT & Software"),
            }
        ),
    )
    website = forms.URLField(
        required=False,
        label=_("Website"),
        assume_scheme="https",
        validators=[validate_safe_url_wrapper],
        widget=forms.URLInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("https://example.com"),
            }
        ),
    )

    # Romanian Tax Information
    cui = forms.CharField(
        max_length=20,
        required=False,
        label=_("CUI/CIF"),
        help_text=_("Format: RO12345678 (6-10 digits after RO)"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("RO12345678"),
            }
        ),
    )
    vat_number = forms.CharField(
        max_length=20,
        required=False,
        label=_("VAT Number"),
        help_text=_("Romanian VAT registration number"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("RO12345678"),
            }
        ),
    )
    is_vat_payer = forms.BooleanField(
        required=False,
        label=_("VAT Payer"),
        help_text=_("Customer is registered for VAT"),
        widget=forms.CheckboxInput(
            attrs={"class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500"}
        ),
    )

    # Address Information (matching registration)
    address_line1 = forms.CharField(
        max_length=200,
        label=_("Address Line 1"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Example Street, no. 123"),
            }
        ),
    )
    address_line2 = forms.CharField(
        max_length=200,
        required=False,
        label=_("Address Line 2"),
        help_text=_("Apartment, suite, unit, building, floor, etc."),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Block A, Apt. 45 (optional)"),
            }
        ),
    )
    city = forms.CharField(
        max_length=100,
        label=_("City"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Bucharest"),
            }
        ),
    )
    county = forms.CharField(
        max_length=100,
        label=_("County"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Sector 1 / Cluj"),
            }
        ),
    )
    postal_code = forms.CharField(
        max_length=10,
        label=_("Postal Code"),
        help_text=_("Romanian postal codes are 6 digits"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("010101"),
            }
        ),
    )

    # Billing Configuration
    payment_terms = forms.IntegerField(
        initial=30,
        label=_("Payment Terms (days)"),
        help_text=_("Number of days for payment"),
        widget=forms.NumberInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "min": "1",
                "max": "365",
            }
        ),
    )
    credit_limit = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        initial=0,
        label=_("Credit Limit (RON)"),
        help_text=_("Maximum credit allowed"),
        widget=forms.NumberInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "step": "0.01",
                "min": "0",
            }
        ),
    )
    preferred_currency = forms.ChoiceField(
        choices=[("RON", "RON"), ("EUR", "EUR"), ("USD", "USD")],
        initial="RON",
        label=_("Preferred Currency"),
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
            }
        ),
    )

    # GDPR Compliance (matching registration)
    data_processing_consent = forms.BooleanField(
        required=True,
        label=_("Data Processing Consent"),
        help_text=_("Customer has given consent for personal data processing according to GDPR"),
        widget=forms.CheckboxInput(
            attrs={"class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500"}
        ),
    )
    marketing_consent = forms.BooleanField(
        required=False,
        label=_("Marketing Communications Consent"),
        help_text=_("Customer consents to receive marketing communications"),
        widget=forms.CheckboxInput(
            attrs={"class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500"}
        ),
    )

    def clean(self) -> dict[str, Any]:
        """Cross-field validation"""
        cleaned_data = super().clean()

        # Guard clause: if cleaned_data is None (validation failed), return early
        if cleaned_data is None:
            return {}

        customer_type: str | None = cleaned_data.get("customer_type")
        company_name: str | None = cleaned_data.get("company_name")
        vat_number: str | None = cleaned_data.get("vat_number")
        is_vat_payer: bool | None = cleaned_data.get("is_vat_payer")
        cui: str | None = cleaned_data.get("cui")
        user_action: str | None = cleaned_data.get("user_action")
        existing_user: User | None = cleaned_data.get("existing_user")
        email: str | None = cleaned_data.get("email")

        # Require company name for companies, PFA, and NGOs
        if customer_type in ["company", "pfa", "ngo"] and not company_name:
            raise ValidationError(_("Company name is required for companies, PFA, and NGOs"))

        # Validate CUI format
        if cui and not re.match(r"^RO\d{6,10}$", cui):
            raise ValidationError(_("CUI must be in format RO followed by 6-10 digits"))

        # Validate VAT number format and requirement
        if is_vat_payer and not vat_number:
            raise ValidationError(_("VAT number is required for VAT payers"))

        if vat_number and not re.match(r"^RO\d{6,10}$", vat_number):
            raise ValidationError(_("VAT number must be in format RO followed by 6-10 digits"))

        # User action validation
        if user_action == "link" and not existing_user:
            raise ValidationError(_("Please select an existing user to link."))

        if user_action == "create" and email and User.objects.filter(email=email).exists():
            raise ValidationError(
                _('A user with email {email} already exists. Please choose "Link existing user" instead.').format(
                    email=email
                )
            )

        return cleaned_data

    def save(self, user: User | None = None) -> dict[str, Any]:
        """Create customer with all related profiles and handle user assignment"""
        data = self.cleaned_data

        # Build customer name from first_name + last_name
        full_name = f"{data['first_name']} {data['last_name']}".strip()

        # Create core customer
        customer = Customer.objects.create(
            name=full_name,
            customer_type=data["customer_type"],
            company_name=data.get("company_name", ""),
            primary_email=data["email"],
            primary_phone=data["phone"],
            industry=data.get("industry", ""),
            website=data.get("website", ""),
            data_processing_consent=data["data_processing_consent"],
            marketing_consent=data.get("marketing_consent", False),
            created_by=user,
        )

        # Create tax profile
        CustomerTaxProfile.objects.create(
            customer=customer,
            cui=data.get("cui", ""),
            is_vat_payer=data.get("is_vat_payer", False),
            vat_number=data.get("vat_number", ""),
            vat_rate=21.0 if data.get("is_vat_payer", False) else 0.0,
        )

        # Create billing profile
        CustomerBillingProfile.objects.create(
            customer=customer,
            payment_terms=data["payment_terms"],
            credit_limit=data["credit_limit"],
            preferred_currency=data.get("preferred_currency", "RON"),
        )

        # Create primary address
        CustomerAddress.objects.create(
            customer=customer,
            address_type="primary",
            address_line1=data["address_line1"],
            address_line2=data.get("address_line2", ""),
            city=data["city"],
            county=data["county"],
            postal_code=data["postal_code"],
            country="Romania",
            is_current=True,
        )

        # Return customer and user action data for view to handle
        return {
            "customer": customer,
            "user_action": data.get("user_action"),
            "existing_user": data.get("existing_user"),
            "send_welcome_email": data.get("send_welcome_email", True),
        }


# ===============================================================================
# COMPREHENSIVE CUSTOMER EDIT FORM
# ===============================================================================


class CustomerEditForm(forms.Form):
    """
    Comprehensive customer edit form for updating all customer information.
    Combines core customer, tax profile, billing profile, and address information.
    """

    # Core Customer Information
    name = forms.CharField(
        max_length=255,
        label=_("Customer Name"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Customer name/designation"),
            }
        ),
    )
    customer_type = forms.ChoiceField(
        choices=Customer.CUSTOMER_TYPE_CHOICES,
        label=_("Customer Type"),
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
            }
        ),
    )
    company_name = forms.CharField(
        max_length=255,
        required=False,
        label=_("Company Name"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("SC EXAMPLE SRL"),
            }
        ),
    )
    primary_email = forms.EmailField(
        label=_("Primary Email"),
        widget=forms.EmailInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("contact@example.com"),
            }
        ),
    )
    primary_phone = forms.CharField(
        max_length=20,
        required=False,
        label=_("Primary Phone"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("+40 721 123 456"),
            }
        ),
    )
    industry = forms.CharField(
        max_length=100,
        required=False,
        label=_("Industry"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("IT & Software"),
            }
        ),
    )
    website = forms.URLField(
        required=False,
        label=_("Website"),
        assume_scheme="https",
        validators=[validate_safe_url_wrapper],
        widget=forms.URLInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("https://example.com"),
            }
        ),
    )

    # Tax Profile Information
    cui = forms.CharField(
        max_length=20,
        required=False,
        label=_("CUI/CIF"),
        help_text=_("Format: RO12345678 (6-10 digits after RO)"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("RO12345678"),
            }
        ),
    )
    registration_number = forms.CharField(
        max_length=50,
        required=False,
        label=_("Registration Number"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("J40/1234/2023"),
            }
        ),
    )
    is_vat_payer = forms.BooleanField(
        required=False,
        label=_("VAT Payer"),
        help_text=_("Customer is registered for VAT"),
        widget=forms.CheckboxInput(
            attrs={"class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500"}
        ),
    )
    vat_number = forms.CharField(
        max_length=20,
        required=False,
        label=_("VAT Number"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("RO12345678"),
            }
        ),
    )
    vat_rate = forms.DecimalField(
        max_digits=5,
        decimal_places=2,
        initial=21.0,
        required=False,
        label=_("VAT Rate (%)"),
        widget=forms.NumberInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "step": "0.01",
                "min": "0",
                "max": "100",
            }
        ),
    )

    # Billing Profile Information
    payment_terms = forms.IntegerField(
        initial=30,
        label=_("Payment Terms (days)"),
        widget=forms.NumberInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "min": "1",
                "max": "365",
            }
        ),
    )
    credit_limit = forms.DecimalField(
        max_digits=10,
        decimal_places=2,
        initial=0,
        label=_("Credit Limit (RON)"),
        widget=forms.NumberInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "step": "0.01",
                "min": "0",
            }
        ),
    )
    preferred_currency = forms.ChoiceField(
        choices=[("RON", "RON"), ("EUR", "EUR"), ("USD", "USD")],
        initial="RON",
        label=_("Preferred Currency"),
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
            }
        ),
    )
    invoice_delivery_method = forms.ChoiceField(
        choices=[("email", _("Email")), ("postal", _("Postal Mail")), ("both", _("Email + Postal"))],
        initial="email",
        label=_("Invoice Delivery Method"),
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
            }
        ),
    )
    auto_payment_enabled = forms.BooleanField(
        required=False,
        label=_("Auto-payment Enabled"),
        help_text=_("Enable automatic payment processing"),
        widget=forms.CheckboxInput(
            attrs={"class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500"}
        ),
    )

    # Primary Address Information
    address_line1 = forms.CharField(
        max_length=200,
        label=_("Address Line 1"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Example Street, no. 123"),
            }
        ),
    )
    address_line2 = forms.CharField(
        max_length=200,
        required=False,
        label=_("Address Line 2"),
        help_text=_("Apartment, suite, unit, building, floor, etc."),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Block A, Apt. 45 (optional)"),
            }
        ),
    )
    city = forms.CharField(
        max_length=100,
        label=_("City"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Bucharest"),
            }
        ),
    )
    county = forms.CharField(
        max_length=100,
        label=_("County"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Sector 1 / Cluj"),
            }
        ),
    )
    postal_code = forms.CharField(
        max_length=10,
        label=_("Postal Code"),
        help_text=_("Romanian postal codes are 6 digits"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("010101"),
            }
        ),
    )
    country = forms.CharField(
        max_length=100,
        initial="Romania",
        label=_("Country"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "value": _("Romania"),
            }
        ),
    )

    # Billing Address Control
    billing_same_as_primary = forms.BooleanField(
        required=False,
        initial=True,
        label=_("Billing address same as primary address"),
        help_text=_("Uncheck to specify a different billing address"),
        widget=forms.CheckboxInput(
            attrs={"class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500"}
        ),
    )

    # Billing Address Information (separate)
    billing_address_line1 = forms.CharField(
        max_length=200,
        required=False,
        label=_("Billing Address Line 1"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Example Street, no. 123"),
            }
        ),
    )
    billing_address_line2 = forms.CharField(
        max_length=200,
        required=False,
        label=_("Billing Address Line 2"),
        help_text=_("Apartment, suite, unit, building, floor, etc."),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Block A, Apt. 45 (optional)"),
            }
        ),
    )
    billing_city = forms.CharField(
        max_length=100,
        required=False,
        label=_("Billing City"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Bucharest"),
            }
        ),
    )
    billing_county = forms.CharField(
        max_length=100,
        required=False,
        label=_("Billing County"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Sector 1 / Cluj"),
            }
        ),
    )
    billing_postal_code = forms.CharField(
        max_length=10,
        required=False,
        label=_("Billing Postal Code"),
        help_text=_("Romanian postal codes are 6 digits"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("010101"),
            }
        ),
    )
    billing_country = forms.CharField(
        max_length=100,
        required=False,
        initial="Romania",
        label=_("Billing Country"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "value": _("Romania"),
            }
        ),
    )

    # GDPR Compliance
    data_processing_consent = forms.BooleanField(
        required=False,  # Don't enforce here, as it's already set
        label=_("Data Processing Consent"),
        help_text=_("Customer has given consent for personal data processing according to GDPR"),
        widget=forms.CheckboxInput(
            attrs={"class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500"}
        ),
    )
    marketing_consent = forms.BooleanField(
        required=False,
        label=_("Marketing Communications Consent"),
        help_text=_("Customer consents to receive marketing communications"),
        widget=forms.CheckboxInput(
            attrs={"class": "rounded border-slate-600 bg-slate-700 text-blue-600 focus:ring-blue-500"}
        ),
    )

    def __init__(self, customer: Customer, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.customer = customer

        # Pre-populate form with existing customer data
        if not self.data:  # Only populate initial if no form data is being processed
            tax_profile = customer.get_tax_profile()
            billing_profile = customer.get_billing_profile()
            primary_address = customer.get_primary_address()
            customer.get_billing_address()

            # Core customer fields
            self.initial.update(
                {
                    "name": customer.name,
                    "customer_type": customer.customer_type,
                    "company_name": customer.company_name,
                    "primary_email": customer.primary_email,
                    "primary_phone": customer.primary_phone,
                    "industry": customer.industry,
                    "website": customer.website,
                    "data_processing_consent": customer.data_processing_consent,
                    "marketing_consent": customer.marketing_consent,
                }
            )

            # Tax profile fields
            if tax_profile:
                self.initial.update(
                    {
                        "cui": tax_profile.cui,
                        "registration_number": tax_profile.registration_number,
                        "is_vat_payer": tax_profile.is_vat_payer,
                        "vat_number": tax_profile.vat_number,
                        "vat_rate": tax_profile.vat_rate,
                    }
                )

            # Billing profile fields
            if billing_profile:
                self.initial.update(
                    {
                        "payment_terms": billing_profile.payment_terms,
                        "credit_limit": billing_profile.credit_limit,
                        "preferred_currency": billing_profile.preferred_currency,
                        "invoice_delivery_method": billing_profile.invoice_delivery_method,
                        "auto_payment_enabled": billing_profile.auto_payment_enabled,
                    }
                )

            # Primary address fields
            if primary_address:
                self.initial.update(
                    {
                        "address_line1": primary_address.address_line1,
                        "address_line2": primary_address.address_line2,
                        "city": primary_address.city,
                        "county": primary_address.county,
                        "postal_code": primary_address.postal_code,
                        "country": primary_address.country,
                    }
                )

            # Billing address logic
            # Check if customer has a separate billing address
            from .contact_models import CustomerAddress  # noqa: PLC0415

            separate_billing_address = CustomerAddress.objects.filter(
                customer=customer, address_type="billing", is_current=True
            ).first()

            if separate_billing_address:
                # Customer has a separate billing address
                self.initial.update(
                    {
                        "billing_same_as_primary": False,
                        "billing_address_line1": separate_billing_address.address_line1,
                        "billing_address_line2": separate_billing_address.address_line2,
                        "billing_city": separate_billing_address.city,
                        "billing_county": separate_billing_address.county,
                        "billing_postal_code": separate_billing_address.postal_code,
                        "billing_country": separate_billing_address.country,
                    }
                )
            else:
                # Billing address is same as primary (default)
                self.initial.update(
                    {
                        "billing_same_as_primary": True,
                        "billing_address_line1": "",
                        "billing_address_line2": "",
                        "billing_city": "",
                        "billing_county": "",
                        "billing_postal_code": "",
                        "billing_country": "Romania",
                    }
                )

    def clean_company_name(self) -> str:
        """Require company name for companies"""
        customer_type: str | None = self.cleaned_data.get("customer_type")
        company_name: str | None = self.cleaned_data.get("company_name")

        if customer_type in ["company", "pfa", "ngo"] and not company_name:
            raise ValidationError(_("Company name is required for companies, PFA, and NGOs"))

        return company_name or ""

    def clean_cui(self) -> str:
        """🔒 Validate Romanian CUI format with ReDoS protection"""
        cui: str | None = self.cleaned_data.get("cui")
        if cui:
            # Security: Prevent ReDoS attacks with strict input length validation
            if len(cui) > MAX_RO_PREFIXED_ID_LENGTH:  # RO + max 10 digits
                raise ValidationError(_("CUI too long"))
            # Security: Use more specific regex pattern to prevent ReDoS
            if not re.match(r"^RO\d{6,10}$", cui):  # Romanian CUI is typically 6-10 digits
                raise ValidationError(_("CUI must be in format RO followed by 6-10 digits"))
        return cui or ""

    def clean_vat_number(self) -> str:
        """🔒 Validate VAT number format with ReDoS protection"""
        vat_number: str | None = self.cleaned_data.get("vat_number")
        is_vat_payer: bool | None = self.cleaned_data.get("is_vat_payer")

        if is_vat_payer and not vat_number:
            raise ValidationError(_("VAT number is required for VAT payers"))

        if vat_number:
            # Security: Prevent ReDoS attacks with strict input length validation
            if len(vat_number) > MAX_RO_PREFIXED_ID_LENGTH:  # RO + max 10 digits
                raise ValidationError(_("VAT number too long"))
            # Security: Use more specific regex pattern to prevent ReDoS
            if not re.match(r"^RO\d{6,10}$", vat_number):  # Romanian VAT is typically 6-10 digits
                raise ValidationError(_("VAT number must be in format RO followed by 6-10 digits"))

        return vat_number or ""

    def clean_website(self) -> str:
        """Validate website URL for SSRF prevention"""
        website: str | None = self.cleaned_data.get("website")
        if website:
            return SecureInputValidator.validate_safe_url(website)
        return website or ""

    def clean_postal_code(self) -> str:
        """Validate Romanian postal code format"""
        postal_code: str | None = self.cleaned_data.get("postal_code")
        country: str | None = self.cleaned_data.get("country")

        if country in ["România", "Romania"] and postal_code and not re.match(r"^\d{6}$", postal_code):
            raise ValidationError(_("Romanian postal codes must be 6 digits"))

        return postal_code or ""

    def clean_billing_postal_code(self) -> str:
        """Validate Romanian billing postal code format"""
        billing_postal_code: str | None = self.cleaned_data.get("billing_postal_code")
        billing_country: str | None = self.cleaned_data.get("billing_country")

        if (
            billing_country in ["România", "Romania"]
            and billing_postal_code
            and not re.match(r"^\d{6}$", billing_postal_code)
        ):
            raise ValidationError(_("Romanian postal codes must be 6 digits"))

        return billing_postal_code or ""

    def clean(self) -> dict[str, Any]:
        """Cross-field validation including billing address"""
        cleaned_data = super().clean()

        # Guard clause: if cleaned_data is None (validation failed), return early
        if cleaned_data is None:
            return {}

        billing_same_as_primary: bool = cleaned_data.get("billing_same_as_primary", True)

        # If billing address is different from primary, validate billing fields
        if not billing_same_as_primary:
            required_billing_fields = [
                "billing_address_line1",
                "billing_city",
                "billing_county",
                "billing_postal_code",
            ]

            for field_name in required_billing_fields:
                if not cleaned_data.get(field_name):
                    field_label = self.fields[field_name].label or field_name.replace("_", " ").title()
                    raise ValidationError(
                        _("'{field_label}' is required when billing address is different from primary address.").format(
                            field_label=field_label
                        )
                    )

        return cleaned_data

    def save(self, user: User | None = None) -> Customer:
        """Update customer and all related profiles"""
        data = self.cleaned_data

        # Update core customer
        self.customer.name = data["name"]
        self.customer.customer_type = data["customer_type"]
        self.customer.company_name = data["company_name"]
        self.customer.primary_email = data["primary_email"]
        self.customer.primary_phone = data["primary_phone"]
        self.customer.industry = data["industry"]
        self.customer.website = data["website"]
        self.customer.data_processing_consent = data["data_processing_consent"]
        self.customer.marketing_consent = data["marketing_consent"]
        if user:
            self.customer.updated_by = user
        self.customer.save()

        # Update or create tax profile
        tax_profile = self.customer.get_tax_profile()
        if not tax_profile:
            tax_profile = CustomerTaxProfile.objects.create(customer=self.customer)

        tax_profile.cui = data["cui"]
        tax_profile.registration_number = data["registration_number"]
        tax_profile.is_vat_payer = data["is_vat_payer"]
        tax_profile.vat_number = data["vat_number"]
        tax_profile.vat_rate = data["vat_rate"]
        tax_profile.save()

        # Update or create billing profile
        billing_profile = self.customer.get_billing_profile()
        if not billing_profile:
            billing_profile = CustomerBillingProfile.objects.create(customer=self.customer)

        billing_profile.payment_terms = data["payment_terms"]
        billing_profile.credit_limit = data["credit_limit"]
        billing_profile.preferred_currency = data["preferred_currency"]
        billing_profile.invoice_delivery_method = data["invoice_delivery_method"]
        billing_profile.auto_payment_enabled = data["auto_payment_enabled"]
        billing_profile.save()

        # Update or create primary address
        primary_address = self.customer.get_primary_address()
        if not primary_address:
            from .contact_models import CustomerAddress  # noqa: PLC0415

            primary_address = CustomerAddress.objects.create(
                customer=self.customer, address_type="primary", is_current=True
            )

        primary_address.address_line1 = data["address_line1"]
        primary_address.address_line2 = data["address_line2"]
        primary_address.city = data["city"]
        primary_address.county = data["county"]
        primary_address.postal_code = data["postal_code"]
        primary_address.country = data["country"]
        primary_address.save()

        # Handle billing address
        from .contact_models import CustomerAddress  # noqa: PLC0415

        billing_same_as_primary = data.get("billing_same_as_primary", True)
        existing_billing_address = CustomerAddress.objects.filter(
            customer=self.customer, address_type="billing", is_current=True
        ).first()

        if billing_same_as_primary:
            # Remove separate billing address if it exists
            if existing_billing_address:
                existing_billing_address.delete()
        else:
            # Create or update separate billing address
            if not existing_billing_address:
                existing_billing_address = CustomerAddress.objects.create(
                    customer=self.customer, address_type="billing", is_current=True
                )

            existing_billing_address.address_line1 = data["billing_address_line1"]
            existing_billing_address.address_line2 = data["billing_address_line2"]
            existing_billing_address.city = data["billing_city"]
            existing_billing_address.county = data["billing_county"]
            existing_billing_address.postal_code = data["billing_postal_code"]
            existing_billing_address.country = data["billing_country"]
            existing_billing_address.save()

        return self.customer


# ===============================================================================
# USER ASSIGNMENT FORM (for existing customers)
# ===============================================================================


class CustomerUserAssignmentForm(forms.Form):
    """
    🔗 Form for assigning users to existing customers
    Provides the same three options as customer creation
    """

    USER_ACTION_CHOICES: ClassVar[tuple[tuple[str, Any], ...]] = (
        ("create", _("Create new user account")),
        ("link", _("Link existing user")),
        ("skip", _("Skip user assignment")),
    )

    user_action = forms.ChoiceField(
        choices=USER_ACTION_CHOICES,
        widget=forms.RadioSelect,
        label=_("User Assignment Action"),
        initial="create",
        help_text=_("Choose how to assign a user to this customer"),
    )

    # Fields for creating new user
    first_name = forms.CharField(
        max_length=30,
        required=False,
        label=_("First Name"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("John"),
            }
        ),
    )

    last_name = forms.CharField(
        max_length=30,
        required=False,
        label=_("Last Name"),
        widget=forms.TextInput(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white placeholder-slate-400 focus:ring-2 focus:ring-blue-500",
                "placeholder": _("Doe"),
            }
        ),
    )

    # Link existing user
    existing_user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        label=_("Select Existing User"),
        help_text=_("Choose a user to link to this customer"),
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
            }
        ),
    )

    # User role in customer organization
    role = forms.ChoiceField(
        choices=CustomerMembership.CUSTOMER_ROLE_CHOICES,
        initial="owner",
        label=_("User Role"),
        help_text=_("Role this user will have within the customer organization"),
        widget=forms.Select(
            attrs={
                "class": "w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-md text-white focus:ring-2 focus:ring-blue-500"
            }
        ),
    )

    # Email options
    send_welcome_email = forms.BooleanField(
        required=False,
        initial=True,
        label=_("Send welcome email"),
        help_text=_("Send welcome email with password reset link to new user"),
        widget=forms.CheckboxInput(
            attrs={"class": "text-blue-600 focus:ring-blue-500 border-slate-500 bg-slate-700 rounded"}
        ),
    )

    def __init__(self, customer: Customer | None = None, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.customer = customer

        # Exclude users who are already members of this customer
        if customer:
            existing_member_ids = CustomerMembership.objects.filter(customer=customer).values_list("user_id", flat=True)

            # Update the queryset for existing_user field
            existing_user_field = self.fields["existing_user"]
            if isinstance(existing_user_field, ModelChoiceField):
                existing_user_field.queryset = User.objects.filter(is_active=True).exclude(id__in=existing_member_ids)

    def clean(self) -> dict[str, Any]:
        try:
            cleaned_data = super().clean()
        except AttributeError:
            # Handle case where cleaned_data doesn't exist yet
            return {}

        # Guard clause: if cleaned_data is None (validation failed), return early
        if cleaned_data is None:
            return {}

        user_action: str | None = cleaned_data.get("user_action")

        if user_action == "create":
            # Validate required fields for user creation
            if not cleaned_data.get("first_name"):
                self.add_error("first_name", _("First name is required when creating a new user"))
            if not cleaned_data.get("last_name"):
                self.add_error("last_name", _("Last name is required when creating a new user"))

        elif user_action == "link":
            # Validate existing user selection
            if not cleaned_data.get("existing_user"):
                self.add_error("existing_user", _("Please select a user to link"))

        return cleaned_data

    def save(self, customer: Customer, created_by: User | None) -> dict[str, Any]:
        """
        Process the user assignment
        Returns: Dict with assignment results
        """
        data = self.cleaned_data
        user_action = data["user_action"]

        if user_action == "create":
            # Create new user using customer's email
            return {
                "action": "create",
                "first_name": data["first_name"],
                "last_name": data["last_name"],
                "role": data["role"],
                "send_welcome_email": data["send_welcome_email"],
            }
        elif user_action == "link":
            # Link existing user
            return {"action": "link", "existing_user": data["existing_user"], "role": data["role"]}
        else:  # skip
            return {"action": "skip"}
