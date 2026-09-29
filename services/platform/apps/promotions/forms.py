"""Bound staff forms for promotion configuration and batch generation."""

from __future__ import annotations

from decimal import Decimal
from typing import Any, ClassVar, cast

from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import can_proceed

from .models import Coupon, GiftCard, PromotionCampaign, PromotionRule
from .pricing import PERIOD_MONTHS
from .validation import validate_offer, validate_tiers


class CampaignForm(forms.ModelForm):
    # Deliberately excluded from Meta.fields: ModelForm must never assign a protected FSM field.
    status = forms.ChoiceField(choices=PromotionCampaign.STATUS_CHOICES, required=False, label=_("Status"))
    transitions: ClassVar[dict[str, str]] = {
        "scheduled": "schedule",
        "active": "activate",
        "paused": "pause",
        "completed": "complete",
        "cancelled": "cancel",
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.initial["status"] = self.instance.status

    class Meta:
        model = PromotionCampaign
        fields = (
            "name",
            "slug",
            "description",
            "campaign_type",
            "start_date",
            "end_date",
            "budget_cents",
            "budget_currency",
            "is_active",
            "utm_source",
            "utm_medium",
            "utm_campaign",
        )
        widgets = {
            "start_date": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
            "end_date": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
        }

    def clean_status(self) -> str:
        target = self.cleaned_data.get("status") or self.instance.status
        if target != self.instance.status:
            method = self.transitions.get(target)
            if method is None or not can_proceed(getattr(self.instance, method)):
                raise ValidationError(_("This campaign status change is not allowed."))
        return str(target)

    def clean(self) -> dict[str, object]:
        data = super().clean() or {}
        if data.get("end_date") and data.get("start_date") and data["end_date"] <= data["start_date"]:
            self.add_error("end_date", _("The end must be after the start."))
        budget = data.get("budget_cents")
        if budget is not None and not data.get("budget_currency"):
            self.add_error("budget_currency", _("Choose the verified currency for this budget."))
        if budget is not None and budget < self.instance.spent_cents + self.instance.reserved_cents:
            self.add_error("budget_cents", _("The budget cannot be below amounts already spent or promised."))
        if (
            self.instance.budget_currency_id
            and data.get("budget_currency") != self.instance.budget_currency
            and (self.instance.spent_cents or self.instance.reserved_cents)
        ):
            self.add_error("budget_currency", _("A used budget cannot change currency."))
        return data

    def save(self, commit: bool = True) -> PromotionCampaign:
        campaign = cast(PromotionCampaign, super().save(commit=False))
        target = self.cleaned_data["status"]
        if target != campaign.status:
            getattr(campaign, self.transitions[target])()
        if commit:
            campaign.save()
            self.save_m2m()
        return campaign


class OfferConfigurationForm(forms.ModelForm):
    included_products: forms.ModelMultipleChoiceField[Any] = forms.ModelMultipleChoiceField(
        queryset=None, required=False, label=_("Eligible products")
    )
    excluded_products: forms.ModelMultipleChoiceField[Any] = forms.ModelMultipleChoiceField(
        queryset=None, required=False, label=_("Excluded products")
    )
    eligible_product_types = forms.MultipleChoiceField(choices=(), required=False, label=_("Eligible product types"))
    excluded_product_types = forms.MultipleChoiceField(choices=(), required=False, label=_("Excluded product types"))
    eligible_periods = forms.MultipleChoiceField(
        choices=[(key, key.title()) for key in [*PERIOD_MONTHS, "once"]],
        required=False,
        label=_("Eligible billing periods"),
    )
    tier_basis = forms.ChoiceField(
        choices=(("amount", _("Subtotal in cents")), ("quantity", _("Eligible quantity"))),
        required=False,
        label=_("Tier threshold"),
    )
    tier_values = forms.CharField(
        required=False,
        widget=forms.Textarea,
        label=_("Discount tiers"),
        help_text=_(
            "One threshold and discount per line, separated by a colon. Use 10000:10% for ten percent from 10000 cents, or 5:500 for 500 cents from five items. The highest qualifying tier applies."
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        from apps.products.models import Product  # noqa: PLC0415

        self.fields["currency"].help_text = _(
            "Required for fixed discounts, monetary limits, caps, and amount tiers. "
            "Verify the original currency when editing an existing offer."
        )
        for name in ("included_products", "excluded_products", "required_products"):
            if name in self.fields:
                cast(forms.ModelMultipleChoiceField, self.fields[name]).queryset = Product.objects.all()
        for name in ("eligible_product_types", "excluded_product_types", "required_product_types"):
            if name in self.fields:
                cast(forms.MultipleChoiceField, self.fields[name]).choices = Product.PRODUCT_TYPES
        restrictions = self.instance.product_restrictions or {}
        discount_type = self.fields["discount_type"]
        if isinstance(discount_type, forms.ChoiceField):
            discount_type.choices = [
                (value, label)
                for value, label in cast(list[tuple[str, str]], discount_type.choices)
                if value != "free_shipping"
            ]
        for field, key in (
            ("included_products", "product_ids"),
            ("excluded_products", "excluded_product_ids"),
            ("eligible_product_types", "product_types"),
            ("excluded_product_types", "excluded_product_types"),
            ("eligible_periods", "billing_periods"),
        ):
            self.initial[field] = restrictions.get(key, [])
        tiers = self.instance.tiers or []
        if tiers:
            self.initial["tier_basis"] = tiers[0].get("threshold_type", "amount")
            self.initial["tier_values"] = "\n".join(
                f"{tier['threshold']}:{str(tier['percent']) + '%' if 'percent' in tier else tier['amount_cents']}"
                for tier in tiers
            )
        for field in self.fields.values():
            if isinstance(field.widget, forms.SelectMultiple):
                field.widget.attrs["size"] = 5

    def clean(self) -> dict[str, Any]:
        data = super().clean() or {}
        restrictions = {}
        for field, key in (
            ("included_products", "product_ids"),
            ("excluded_products", "excluded_product_ids"),
            ("eligible_product_types", "product_types"),
            ("excluded_product_types", "excluded_product_types"),
            ("eligible_periods", "billing_periods"),
        ):
            values = data.get(field)
            if values:
                restrictions[key] = [str(getattr(value, "pk", value)) for value in values]
        if restrictions and data.get("applies_to_all_products"):
            self.add_error(
                "applies_to_all_products", _("Turn off all-products eligibility to use the selected restrictions.")
            )
        self.instance.product_restrictions = restrictions
        tiers = []
        for line in data.get("tier_values", "").splitlines():
            if not line.strip():
                continue
            try:
                threshold, value = (part.strip() for part in line.split(":"))
                tier = {"threshold": int(threshold), "threshold_type": data.get("tier_basis") or "amount"}
                if value.endswith("%"):
                    tier["percent"] = str(Decimal(value[:-1]))
                else:
                    tier["amount_cents"] = int(value)
                tiers.append(tier)
            except (ValueError, ArithmeticError):
                self.add_error("tier_values", _("Use threshold:percentage% or threshold:amount on each line."))
                break
        try:
            validate_tiers(tiers, data.get("discount_type", ""))
        except ValidationError as exc:
            self.add_error("tier_values", exc)
        self.instance.tiers = tiers
        return data

    def _post_clean(self) -> None:
        super()._post_clean()
        if not self.errors:
            try:
                validate_offer(self.instance)
            except ValidationError as exc:
                self.add_error(None, exc)


class CouponForm(OfferConfigurationForm):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        customer_target = self.fields["customer_target"]
        if isinstance(customer_target, forms.ChoiceField):
            customer_target.choices = [
                (value, label)
                for value, label in cast(list[tuple[str, str]], customer_target.choices)
                if value != "segment"
            ]

    class Meta:
        model = Coupon
        fields = (
            "code",
            "name",
            "description",
            "internal_notes",
            "campaign",
            "discount_type",
            "discount_percent",
            "discount_amount_cents",
            "free_months",
            "max_discount_cents",
            "min_order_cents",
            "min_order_items",
            "valid_from",
            "valid_until",
            "usage_limit_type",
            "max_total_uses",
            "max_uses_per_customer",
            "customer_target",
            "assigned_customer",
            "first_order_only",
            "applies_to_all_products",
            "is_stackable",
            "is_exclusive",
            "stacking_priority",
            "status",
            "is_active",
            "is_public",
            "currency",
        )
        widgets = {
            "valid_from": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
            "valid_until": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
        }
        help_texts = {"stacking_priority": _("Lower numbers apply first when offers allow stacking.")}

    def clean_code(self) -> str:
        code = self.cleaned_data["code"].strip().upper()
        existing = Coupon.objects.filter(code__iexact=code).exclude(pk=self.instance.pk)
        if existing.exists():
            raise ValidationError(_("This coupon code already exists."))
        return str(code)

    def clean(self) -> dict[str, object]:
        data = super().clean() or {}
        if data.get("discount_type") == "free_shipping":
            self.add_error("discount_type", _("Shipping discounts are unavailable for hosting services."))
        return data


class CouponBatchForm(forms.Form):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        from apps.billing.models import Currency  # noqa: PLC0415

        cast(forms.ModelChoiceField, self.fields["currency"]).queryset = Currency.objects.all()

    count = forms.IntegerField(label=_("Number of coupons"), min_value=1, initial=10)
    prefix = forms.RegexField(r"^[a-zA-Z0-9]*$", label=_("Code prefix"), max_length=10, required=False)
    name = forms.CharField(label=_("Name"), max_length=200)
    discount_type = forms.ChoiceField(
        label=_("Discount type"), choices=(("percent", _("Percentage")), ("fixed", _("Fixed amount")))
    )
    discount_percent = forms.DecimalField(
        label=_("Percentage"),
        required=False,
        min_value=Decimal(0),
        max_value=Decimal(100),
        max_digits=5,
        decimal_places=2,
    )
    discount_amount_cents = forms.IntegerField(label=_("Amount in cents"), required=False, min_value=0)
    currency: forms.ModelChoiceField[Any] = forms.ModelChoiceField(label=_("Currency"), queryset=None, required=False)

    def clean_count(self) -> int:
        from apps.settings.services import SettingsService  # noqa: PLC0415

        count = int(self.cleaned_data["count"])
        maximum = SettingsService.get_integer_setting("promotions.max_coupon_batch_size", 1000)
        if count > maximum:
            raise ValidationError(_("Create at most %(maximum)s coupons in one batch."), params={"maximum": maximum})
        return count

    def clean(self) -> dict[str, object]:
        data = super().clean() or {}
        if self.errors:
            return data
        if data["discount_type"] == "fixed" and not data.get("currency"):
            self.add_error("currency", _("Select the currency for a fixed discount."))
        coupon = Coupon(
            **{key: value for key, value in data.items() if key not in {"count", "prefix"}},
            usage_limit_type="single_use",
        )
        coupon.full_clean(exclude=["code"], validate_unique=False)
        return data


class GiftCardForm(forms.ModelForm):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        from apps.customers.models import Customer  # noqa: PLC0415

        cast(forms.ModelChoiceField, self.fields["purchased_by"]).queryset = Customer.objects.all()
        from apps.billing.currency_policy import get_selling_currency_policy  # noqa: PLC0415

        policy = get_selling_currency_policy()
        self.initial.update(currency=policy.currency_code, currency_revision=policy.revision)

    purchased_by: forms.ModelChoiceField[Any] = forms.ModelChoiceField(queryset=None, label=_("Purchaser"))
    currency_revision = forms.IntegerField(min_value=1, widget=forms.HiddenInput)
    payment_method = forms.ChoiceField(
        choices=(("bank", _("Bank transfer")), ("stripe", _("Customer card payment"))), label=_("Payment method")
    )

    class Meta:
        model = GiftCard
        fields = (
            "initial_value_cents",
            "currency",
            "card_type",
            "recipient_email",
            "recipient_name",
            "personal_message",
            "valid_until",
        )
        widgets = {
            "currency": forms.HiddenInput,
            "valid_until": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
        }

    def refresh_currency_for_review(self) -> None:
        """Re-render rejected input with current terms for an explicit resubmission."""
        from apps.billing.currency_policy import get_selling_currency_policy  # noqa: PLC0415

        policy = get_selling_currency_policy()
        data = self.data.copy()
        data[self.add_prefix("currency")] = policy.currency_code
        data[self.add_prefix("currency_revision")] = str(policy.revision)
        self.data = data

    def clean_valid_until(self) -> object:
        expires = self.cleaned_data.get("valid_until")
        if expires and expires <= timezone.now():
            raise ValidationError(_("The expiry must be in the future."))
        return expires


class PromotionRuleForm(OfferConfigurationForm):
    minimum_subtotal = forms.IntegerField(required=False, min_value=0, label=_("Minimum subtotal in cents"))
    maximum_subtotal = forms.IntegerField(required=False, min_value=0, label=_("Maximum subtotal in cents"))
    minimum_quantity = forms.IntegerField(required=False, min_value=1, label=_("Minimum eligible quantity"))
    customer_types = forms.MultipleChoiceField(choices=(), required=False, label=_("Customer types"))
    eligible_customers: forms.ModelMultipleChoiceField[Any] = forms.ModelMultipleChoiceField(
        queryset=None, required=False, label=_("Eligible customers")
    )
    required_products: forms.ModelMultipleChoiceField[Any] = forms.ModelMultipleChoiceField(
        queryset=None,
        required=False,
        label=_("Required product combination"),
        help_text=_("Every selected product must be present."),
    )
    required_product_types = forms.MultipleChoiceField(
        choices=(),
        required=False,
        label=_("Required product types"),
        help_text=_("The cart must contain every selected product type."),
    )
    first_order = forms.BooleanField(required=False, label=_("First order only"))
    publish_now = forms.BooleanField(
        required=False,
        label=_("Publish this verified offer"),
        help_text=_(
            "Publishing makes an active offer available for new checkouts. Existing quotes will be checked again."
        ),
    )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        from apps.customers.models import Customer  # noqa: PLC0415

        cast(forms.MultipleChoiceField, self.fields["customer_types"]).choices = Customer.CustomerType.choices
        cast(forms.ModelMultipleChoiceField, self.fields["eligible_customers"]).queryset = Customer.objects.all()
        for field, key in self.condition_fields.items():
            self.initial[field] = self.instance.conditions.get(key)

    condition_fields: ClassVar[dict[str, str]] = {
        "minimum_subtotal": "min_order_cents",
        "maximum_subtotal": "max_order_cents",
        "minimum_quantity": "min_items",
        "customer_types": "customer_types",
        "eligible_customers": "customer_ids",
        "required_products": "required_product_ids",
        "required_product_types": "required_product_types",
        "first_order": "first_order_only",
    }

    def save(self, commit: bool = True) -> PromotionRule:
        if self.cleaned_data.get("publish_now"):
            self.instance.published_at = timezone.now()
        return cast(PromotionRule, super().save(commit=commit))

    class Meta:
        model = PromotionRule
        fields = (
            "name",
            "description",
            "campaign",
            "rule_type",
            "discount_type",
            "discount_percent",
            "discount_amount_cents",
            "max_discount_cents",
            "applies_to_all_products",
            "currency",
            "valid_from",
            "valid_until",
            "is_stackable",
            "priority",
            "is_active",
            "display_name",
            "display_badge",
        )
        widgets = {
            "valid_from": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
            "valid_until": forms.DateTimeInput(attrs={"type": "datetime-local"}, format="%Y-%m-%dT%H:%M"),
        }

    def clean(self) -> dict[str, object]:
        data = super().clean() or {}
        conditions = {}
        from apps.customers.models import Customer  # noqa: PLC0415

        cast(forms.MultipleChoiceField, self.fields["customer_types"]).choices = Customer.CustomerType.choices
        cast(forms.ModelMultipleChoiceField, self.fields["eligible_customers"]).queryset = Customer.objects.all()
        for field, key in self.condition_fields.items():
            value = data.get(field)
            if value:
                if field in {"eligible_customers", "required_products"}:
                    value = [str(item.pk) for item in value]
                conditions[key] = value
        self.instance.conditions = conditions
        kind = data.get("discount_type")
        if kind == "percent" and data.get("discount_percent") is None:
            self.add_error("discount_percent", _("Enter the percentage discount."))
        if kind == "fixed" and data.get("discount_amount_cents") is None:
            self.add_error("discount_amount_cents", _("Enter the fixed discount."))
        if kind == "free_shipping":
            self.add_error("discount_type", _("Shipping discounts are unavailable for hosting services."))
        if data.get("valid_until") and data.get("valid_from") and data["valid_until"] <= data["valid_from"]:
            self.add_error("valid_until", _("The end must be after the start."))
        return data
